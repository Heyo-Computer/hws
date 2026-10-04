# app-lb

An application load balancer for [heyvm](https://heyo.computer) Firecracker/KVM microVMs,
built on [Pingora 0.9](https://github.com/cloudflare/pingora/releases/tag/0.9.0).

The 0.9 upgrade retains app-lb's routing and process lifecycle. It adopts
Pingora's default upstream hop-by-hop header sanitization (including headers
nominated by `Connection`), normalized valid WebSocket upgrades, and bounded
HTTP/2 defaults (100 concurrent streams and a 64 KiB decoded header list).
The existing TLS listener still does not advertise HTTP/2 via ALPN; this upgrade
does not enable a new listener protocol.
Arbitrary non-WebSocket HTTP upgrades are no longer passed through by default.
The `pg-fc-sql/1` upgrade is explicitly preserved for authenticated cross-region
PostgreSQL tunnels, including their initial JSON POST and bidirectional stream.
Other requests retain Pingora's default upstream header sanitization.
This dependency upgrade does **not** enable graceful binary replacement or
regional ingress evacuation; host updates still use the existing restart path.

The foreground process is the sole management owner: it holds the state lock,
admin API, discovery, autoscaling, ACME, authentication, and request reservations.
It supervises one forwarding subprocess, which owns the HTTP/TLS listeners and
streams request/response bodies. The private `--forwarding-worker` entry point
branches before management stores are opened; it is not an operator command.
Request decisions cross a versioned Unix-socket protocol in a mode-0700 directory.
Control frames are limited to 1 MiB. Request heads exceeding that limit after
encoding receive HTTP 431 before admission, rather than terminating a worker;
oversized manager-generated responses receive HTTP 500. Application response
bodies stream directly through the worker and are not subject to this limit.
Workers receive memory-only TLS snapshots, refreshed every five seconds, and
cannot persist them or issue certificates.

Completion releases the backend attempt and regional assignment; connection
failure releases only the attempt and never permits regional replay. A lost
request-control connection is not proof of drain: the manager retains its
reservations until explicit completion/cancellation or confirmed worker exit.
Cancelled HTTP tasks finish any pending control exchange before acknowledging
cancellation. A worker that loses management authority exits; the manager reaps
it before starting a replacement. On Linux, manager death also kills its worker.
New requests depend on the manager being available.

This is **not hot takeover**. A crashed worker interrupts its streams, and a
replacement starts only after it exits. Candidate readiness, listener handoff,
and zero-interruption regional ingress maintenance remain separate work. The
host updater still restarts the service; do not use this split as evidence that
updating a region's ingress is safe without traffic evacuation.

This directory was imported from the standalone
[`Heyo-Computer/app-lb`](https://github.com/Heyo-Computer/app-lb) repository
with its 28-commit author, timestamp, message, and ancestry history rewritten
under `app-lb/`. Generated runtime state and credential files
(`app-lb-auth-key` and `app-lb-state.json`) were removed from every imported
revision and are ignored here. Rewriting the paths and sanitizing those files
changed the imported commit IDs; the standalone repository remains the source
for old pull requests and original commit IDs.

Register a *deployment* — routing rules plus a backend — and app-lb routes HTTP traffic to it.
Deployments are registered at runtime over an admin API; multiple deployments coexist in one
process. A deployment is one of three kinds:

- **Managed** (`vm`): a VM template plus a scaling policy. app-lb boots and reaps a pool of
  microVMs to match load.
- **Static / `proxy_pass`** (`upstreams`): a fixed set of upstream addresses (`host:port` or
  `ip:port`) to forward to — another app or service. No VM lifecycle and no autoscaling; the
  upstreams are load-balanced least-in-flight with failover, and health-re-probed so a
  recovered upstream rejoins. See [Static / proxy_pass deployments](#static--proxy_pass-deployments).
- **Site** (`site`): a directory on the app-lb host, served straight off disk — no backend at
  all. What nginx's `root` or a CloudFront origin does. See [Static sites](#static-sites).

A deployment sets exactly one of `vm`, `upstreams` or `site`.

### Opt-in regional gateway transport

The `gateway` block adds explicit one-hop forwarding to a static deployment.
This is the transport building block, not automatic regional selection or fleet
management. Existing deployments remain unchanged. Both sides use one exact-host
route, preserve paths, and resolve a namespace-scoped secret through `auth`.
Before provisioning, require `X-App-Lb-Gateway: 1` from `GET /deployments`;
older binaries can silently ignore unknown spec fields.

Source example (normal application Host is preserved; upstream hostname supplies TLS SNI):

```json
{"id":"smoke-peer","routes":[{"host":"smoke.example"}],"upstreams":["https://eu1.example:443"],"health":{"path":"/health"},"gateway":{"mode":"forward","service":"smoke","region":"eu1","auth":{"secret":"gateway-forwarding"}}}
```

Destination example (the existing host ingress must deliver this Host to this route):

```json
{"id":"smoke-local","routes":[{"host":"smoke.example"}],"upstreams":["127.0.0.1:2227"],"health":{"path":"/health"},"gateway":{"mode":"local","service":"smoke","region":"eu1","auth":{"secret":"gateway-forwarding"}}}
```

`forward` requires HTTPS upstreams. `local` is peer-only and permits only plaintext
loopback host-port upstreams; it never chooses another region. Supply the same
gateway-role token through the existing secrets API on both hosts, backed by the
canonical HeyoSecret role configuration. Never put the value in a deployment spec.
Peer headers are validated and consumed before forwarding to the application;
application Authorization is independent. A second hop is refused with 508,
invalid/missing peer credentials with 403, and unresolved secrets with 503.
Forward health probes carry peer authentication and the application Host, require
2xx, and honor configured revision-header checks. In-flight accounting uses the
existing backend admission guards on each hop.

Do not point this peer-only destination route at a public local-serving route or
enable it on existing flattened discovery. Hierarchical discovery uses the separate
`discovery.regional` opt-in below. Fleet registration, coordinated gateway upgrades
and live two-region acceptance remain separate work.

Linux CI runs the isolated two-process regression with Python 3 and OpenSSL.
To run it separately:

```sh
cargo build --locked --manifest-path app-lb/Cargo.toml --features reqwest/rustls-tls-native-roots
python3 app-lb/testdata/gateway_smoke.py
```

The extra build feature lets Rustls health checks read the disposable test CA
from `SSL_CERT_FILE`, like the OpenSSL proxy. Normal public-CA builds need no
extra feature. The test never disables TLS verification or touches deployed
services. It checks request preservation, single POST delivery, peer admission,
WebSocket echo, and a held response body draining across spec replay while new
traffic uses another local backend.
Set `APP_LB_TEST_BINARY` to the absolute binary path when using a custom
`CARGO_TARGET_DIR`; otherwise the test uses `app-lb/target/debug/app-lb`.

The workload is checked in as `testdata/regional_app.py`, rather than depending
on a temporary app archive. Its region and immutable runtime revision are explicit
startup arguments; both are returned in JSON and `X-Heyo-Region` /
`X-Heyo-Revision` headers. `/health` is excluded from admission history,
`/admissions` returns the last 4096 requests, and `/held?hold=10&id=drain-1`
starts a response then holds its body for ten seconds. `--unhealthy` returns
503 for negative readiness checks. Only use disposable request data: the app
records paths and bodies; Authorization is hashed, never reflected verbatim.

```sh
python3 app-lb/testdata/regional_app.py --region eu1 --revision regional-gateway-v2 --port 8080
python3 -B -m unittest discover -s app-lb/testdata -p test_regional_app.py
```

The default bind is loopback for host-local tests. A managed VM must explicitly
bind its guest interface (for example `--bind 0.0.0.0`); only its owning gateway
uses the host-bound mapping. Cross-region traffic and readiness use authenticated
HTTPS gateways, not public VM ports. Use the same app artifact/revision in both
regions and inject the region at startup. This app does not register routes,
publish discovery, or grant itself serving weight. Rewriting the workload does
not enable the currently gated managed first-replica enrollment path below.

### Hierarchical discovery (local integration; not live acceptance)

`discovery.regional` contains `gateway_id`, `backend_server_id`, `environment` and
an `auth` secret reference for the peer role. The backend identity must match the
policy's gateway placement. It requires `discovery.region`, an explicit managed
`discovery.source`, and one exact-host route with preserved path; it cannot be
combined with the legacy `gateway` block. Both secret references are confined to
the deployment namespace. The authority is queried with `protocol=regional-v1`,
region, gateway ID and this runtime's boot UUID.

Cold starts return 503 until the authority authorizes that exact boot. One coherent
snapshot supplies immutable policy history, active generation, local membership and
a monotonic admission fence. Requests select a weighted region before a local backend
or a single HTTPS peer hop. Generation/environment/peer credentials are consumed at
the destination; application Host and Authorization are preserved. Regional requests
are never replayed against another assignment after a connect failure.

Assignments remain counted across snapshot/spec replay until the whole request or
stream finishes. The authenticated `discovery-status` response includes a `regional`
boot/operation envelope and sequenced preparation/adoption/drain report, with
`Cache-Control: no-store`. Operator maintenance or missing peer credentials prevents
preparation evidence. A changed runtime identity fences its predecessor rather than
resetting the predecessor's outstanding counters.

After 30 seconds without an accepted discovery snapshot, reports also set
`prepared=false`, blocking every Orchestrator policy/drain gate. Polling the admin
endpoint cannot renew that evidence. Last-valid routing and in-flight counters
remain intact during the outage; an accepted current snapshot renews evidence,
but an ignored older version does not.

Even a cold gateway reports authenticated admission metadata: protocol, environment,
host placement, namespace, routes and discovery authority, plus route conflicts,
maintenance and credential readiness. This lets the controller pin a configured
fleet without accepting caller-supplied boot identities. It does not establish the
absence of unregistered external ingress or authorize a gateway replacement.

The authenticated deployments collection advertises
`x-app-lb-regional-admission: 1`. Controllers must check this capability before
create-only cold enrollment; older gateways must not interpret a regional spec as
a legacy route. Enrollment does not grant traffic admission or replace an existing
route. Discovery and peer credentials remain separate namespace-local secret refs.

The Orchestrator `two_real_gateways_drain_through_authenticated_durable_barriers`
test combines real app-lb processes, verified peer TLS, authenticated reports and
disposable PostgreSQL. Set `APP_LB_TEST_BINARY` to the absolute path of the binary
built above and `ORCHESTRATOR_TEST_DATABASE_URL` to a disposable test database.
Public transition-admission APIs remain gated; do not edit shared DB rows to enable
this feature. These local checks do not establish live multi-region acceptance.

Of the heyvm drivers, only Firecracker and KVM are supported. This is not a limitation of taste: app-lb routes
directly to `SandboxInfo.guest_ip`, which the daemon only populates for tap-networked
Firecracker/KVM backends on a local daemon. A Libvirt VM would boot fine and then be
unroutable, so the driver is rejected at registration. The one other accepted driver is
`lxc`: an Incus system container from an OCI image, which app-lb creates through Incus
itself (`APP_LB_LXC_*`), not through heyvm.

## Requirements

- Linux with KVM (`/dev/kvm`)
- A running `heyvmd` daemon. With no `APP_LB_DAEMON_URL` set, app-lb prefers a
  unix socket when the daemon publishes a live one (`heyvmd --socket`), and
  otherwise uses `http://127.0.0.1:34099`
- `cmake` — a hard build dependency of `pingora-core`, via `flate2`'s `zlib-ng` backend

## Conditional candidate-first service rollout

For existing **stateless Firecracker services**, use `POST /deployments/:id/rollouts`
instead of destructive PUT/pull/mount replacement. First GET `/deployments/:id`:
its `rollout_revision` is an opaque persisted CAS token, distinct from the spec ETag.
Send `{ "operation_id": "release-123", "expected_revision": "<GET token>", "spec": <complete desired spec> }`.
IDs are 1–128 ASCII letters, digits, hyphens or underscores. Exact replay returns the
same operation, including terminal operations; conflicting payloads/revisions return 409.
GET `/deployments/:id/rollouts/:operation_id` reports `operation_id`, `deployment`,
`source_revision`, `target_spec_sha256`, `status`, `phase`, `readiness_verified`,
`previous_stopped`, `preparation_stage`, and `error`. Status is `running`, `succeeded`, `failed`, or
`reconciliation_required`. Admission is not rollout success.

Preparation uses the remaining persisted `scaling.boot_timeout_secs` rollout
budget (30–1800 seconds), not a separate two-minute limit. Restart does not reset
that deadline. The latest preparation stage is persisted while work runs and on
failure: for example `rootfs_manifest`, `blob_download`, `blob_http_403`,
`blob_digest_mismatch`, `daemon_image_import`, or `mount_unpack`. Deadline expiry
is reported separately from preparation failure. Diagnostics contain bounded
stage/status codes, not remote response bodies or credentials. Old operation
records without this field remain readable. A failed preparation never creates
a candidate or retires the serving generation.

Failed pre-cutover rollouts remain reserved until every attempted Firecracker
candidate has an authenticated host reclamation receipt. After cleanup progress
and final settlement are durable, GET adds `failure_settlement` with protocol
`failed-rollout-reclamation-v1` and the exact `reclaimed_candidate_ids`. A
missing field means cleanup is unresolved; older hosts without the receipt API
therefore retain the admission fence.

`target_spec_sha256` hashes compact JSON of the **requested normalized spec**, with
all object keys recursively sorted and array order preserved. A spec copied from
GET is already normalized (including secret-reference namespaces). Rootfs import
uses an operation-specific image alias in a separately recorded prepared spec;
that materialization does not change the requested-spec hash.

The desired spec must contain `artifact: { "store": "https://…", "ref": "<64 lowercase hex SHA256>" }`.
The ref identifies a rootfs blob or the canonical artifacts manifest containing
`rootfs.ext4`. Optional existing fields are `auth: { "secret": "id", "key": "token" }`,
`grow_gb`, `image_name`, and `strip_components`. Candidate preparation verifies
manifest and blob content and does not trust the catalog's name/size reuse check.
The current daemon catalog has no digest, so a preinstalled image alias without
pinned artifact metadata is **not sufficient**, even if the image name is unchanged.
Every code mount must be read-only with `ref` and `digest` set to the same blob SHA256.
Startup, environment and those mounts are applied together to the candidate.

Routes, namespace, owner, request authentication and maintenance mode must remain
unchanged. Workspace/archive-seeded VMs, writable mounts, non-Firecracker runtimes,
Cloud ingress and extra exposed ports are rejected. An HTTP health path and a
stable old serving pool (no pending/draining replicas) are required. Legacy writes
and jobs are reserved out while the operation runs or requires reconciliation.
The desired health check must include `expected_header: { "name": "x-heyo-revision", "value": "<exact lowercase Git SHA>" }`.
Readiness requires 2xx and exactly one matching response header, using a bounded
16 KiB parser that accepts fragmented headers. The service must emit an immutable
build-stamped identity, **not echo a deployment environment variable**: an old
baked-in listener must not pass when the new startup command fails. Missing/wrong
identity, redirects and even otherwise healthy 404 responses cannot pass a rollout.
Legacy health checks without `expected_header` retain their existing semantics.

app-lb's own admin `/healthz` also returns `x-heyo-revision`, compiled from
`HEYO_BUILD_GIT_SHA` (a full lowercase Git SHA; `unknown` for unstamped local
builds). Runtime environment variables cannot change this header. CI stamps
the validated source and includes a checksummed `REVISION` in the release bundle,
so a host-controller rollout can verify the intended build through the public
admin endpoint instead of accepting an old process's generic `ok` response.

The deployment's existing fsync/rename record stores the operation, unique allocation
intents, active generation, and exact retiring VM IDs. Candidates stay unrouted until
healthy. Cutover persists first, then fences admission on old backends and publishes
the candidate pool. Acquired requests drain until zero or `drain_timeout_secs`; only
then are recorded previous replicas stopped, **not destroyed**. Their records/disks
remain claimed, and old retained VMs cannot resume into the new generation.
Retirement relies on the daemon's stop acknowledgment: install a daemon that
propagates termination errors and preserves live handles on failure before
enabling rollouts. Older daemons that swallow stop errors cannot establish
`previous_stopped` reliably. Normal ephemeral rootfs cleanup performed by the
daemon on successful stop is unchanged; app-lb never purges the retained sandbox.

Restart reconciles attempted creates by exact recorded name, never by issuing another
create. Unknown allocations or ambiguous persistence retain both generations for
operator reconciliation. A failed candidate leaves the source serving; failed candidate
allocations are retained, not purged. Post-cutover stop/readiness failure is bounded by
the drain deadline plus five minutes and never reports `previous_stopped`. The record
requires one owning app-lb process, as the existing registry does; it is not a shared
multi-process database. Retained history requires explicit operator reconciliation
before deregistration. This endpoint does not migrate external ingress or coordinate
regions; the caller must wait for both success flags before rolling the next region.

## Correlated host executable rollout

### One-time native bootstrap over the existing managed command transport

An installed predecessor without the correlated helper uses a **separately
staged, validated new app-lb binary**, not a shell installer. No bootstrap is
enabled by a repository workflow alone. A root operator supplies a private
manifest through the existing management channel. The CI caller durably records
the intended submission/artifact and manifest hash before requesting its fixed
managed launcher. Successful legacy job/oneshot exit is **not** deployment success.

The new binary exposes these commands (one redacted JSON object on stdout):

```text
app-lb --bootstrap-host-update inspect /absolute/desired-config.json
app-lb --bootstrap-host-update admit /absolute/manifest.json INTENT_SHA256
app-lb --bootstrap-host-update replan /absolute/manifest.json NEW_INTENT_SHA256 EXPECTED_OLD_INTENT_SHA256
app-lb --bootstrap-host-update status /absolute/state/bootstrap.json INTENT_SHA256
app-lb --bootstrap-host-update apply /absolute/state/bootstrap.json INTENT_SHA256
```

`inspect` and `status` are read-only. `inspect` returns `source` and `files`
(path, SHA256 or null for absence, and mode). `status` returns `not_found` for
an absent journal; it never launches or attests a process. `apply` is internal
to the independently launched systemd oneshot. `admit` returns `protocol:
host-app-lb-bootstrap-v1`, `operation_id`, `intent_sha256`, `journal_path`,
`unit_name`, deployment/namespace, status, phase, source/target identities,
`readiness_verified` and error. Outputs never include config file contents.

The strict manifest schema is:

```text
{
  operation_id, helper_sha256,
  source: {disk_sha256, running_sha256,
           generation: {boot_id, pid, start_time}},
  config: <complete AFTER host Config shown below>,
  mapping_path: <absolute APP_LB_HOST_UPDATE_CONFIG path>,
  files: [{path, before_sha256: <SHA256 or null>, after_base64, mode}],
  target: {artifact_sha256, binary_sha256, revision}
}
```

`INTENT_SHA256` hashes UTF-8 compact JSON with recursively sorted object keys,
unchanged array order and no extra whitespace. Include every required field,
including null `before_sha256`; omit inactive file-action keys. `helper_sha256`
must equal `target.binary_sha256` and the
executing new helper's digest; it is **not** the predecessor digest. The exact
pinned bundle supplies `dist/app-lb`, `dist/REVISION`, and `dist/SHA256SUMS`
under the same 256 MiB/no-links/no-traversal archive rules as normal rollout.
The predecessor's disk and running digests must agree. Boot ID/PID/kernel
start-time bind the observed predecessor generation, not an alias or service
name alone. A predecessor already configured for normal host updates is refused.

`files` exactly enumerates `config.config_files` in order. Each file has `path`,
`before_sha256`, `mode`, and **exactly one** of:

- `after_base64`: explicit new bytes. Required for the non-secret mapping file,
  whose decoded Config must equal `config`. Also suitable for a new systemd
  environment drop-in. Modes are decimal 384 (0600) or 420 (0644).
- `preserve:true`: assert and back up existing bytes locally without rewriting
  the original. Requires its inspected non-null SHA and unchanged mode.
- `supervisor_environment:true`: derive an edit locally from the preserved
  original, append only `APP_LB_HOST_UPDATE_CONFIG` in the mapped program's
  environment, and preserve all other bytes/settings. Requires non-null SHA
  and unchanged mode. No existing secrets appear in the manifest or output.

The native Supervisor edit requires one effective, ungrouped `[program:name]`
definition. Its environment may continue on indented lines, including leading
commas and intervening blank/comment lines. Whitespace-prefixed `;` and `#`
inline comments follow Supervisor's ConfigParser rules (before quote parsing).
The edit appends before the final physical value line's comment, preserving
existing bytes and spacing. Other multiline settings, duplicate
sections/environment keys, missing separators, ambiguous quotes, pre-existing mapping
assignment, and colon delimiters are rejected. Mapping path characters are
restricted to ASCII letters/digits and `/_.-` to avoid interpolation/quoting
ambiguity. Other environment values and CRLF/LF endings remain untouched.
Use `preserve:true` for all other effective unit/include/env files. Never export
those files into CI job logs. Derivation is bound by the BEFORE hash, typed edit,
mapped process/path and authorized helper digest.

Unknown fields are rejected. Manifest and desired-config reads are bounded at
4 MiB, decoded/derived AFTER bytes total at 4 MiB, each BEFORE config file at
4 MiB, and file count at 32. Manifest must be owner-only. All paths and ancestors
must be root-owned, not group/world writable, with no symlinks or hardlinked
files. Stage under an operator-owned `/var/lib` or `/opt` tree, **not `/tmp`**.
Config targets must not overlap the executable or updater state directory.

Admission first durably fences `state_dir/bootstrap.json`, preserves original
executable/config bytes, modes and explicit absence, then launches exactly once
as `app-lb-bootstrap-<intent hash>`. Same-ID replay only reads the journal.
Different intent conflicts; a terminal unit is never recycled. File writes use
fsync and same-directory atomic rename. Systemd runs bounded `daemon-reload`
then the exact unit restart. Supervisor runs from `/`, requires one ungrouped
program, requires `reread` to report only that program changed, then issues
`update <program>` (not restart-only, `all`, or `supervisor.service`). No VM,
disk, workspace or unrelated program is touched. Original bytes are retained
indefinitely; no rollback, automatic relaunch, cancellation/unpin or partial
install resume is provided.

`replan` is the sole explicit exception to the different-intent conflict. It
requires the exact old intent in `reconciliation_required` / `preserving`, the
same operation, Config/state directory, source, mapping path and file actions.
Only helper/target identities may change. It verifies unchanged predecessor
generation/executable/config bytes and modes, intact backups and staged helper,
no unresolved normal operation, and successful `systemctl show` probes returning
exact `LoadState=not-found` values for both helper units. Errors or existing
terminal units are not absence. Executor exclusion covers inspection through
staging; the ledger CAS archives the old journal at
`state_dir/bootstrap/replans/<old-intent>.json` and atomically replaces the
active intent before further effects. Original backups and helpers remain pinned;
the new helper uses `state_dir/bootstrap/helpers/<new-intent>`. Output includes
`supersedes`. Exact replays only return state, including after interruption or a
lost launch reply. Running preservation, launch/install and uncertain phases
cannot be replanned. Never bypass a fence by changing state directories or IDs.

Only authenticated namespace-admin GET
`/deployments/:id/update/bootstrap/:operation_id` in the installed replacement
can persist success and release the normal-rollout fence. It verifies this exact
new mapped process, disk/running/compiled identities, effective mapping env,
all AFTER files/modes, preserved originals and public 2xx health with **one exact**
`x-heyo-revision` header. Native status cannot replace this attestation. Lost
launch replies, interrupted config/binary commits, and failed restarts stay
fenced; GET can reconcile only a fully verified replacement. Operators must
retain journals/backups and must not concurrently alter files or supervision.
This requires root, local durable filesystems, one controller owner and one
fixed operator-owned mapping/state directory per executable, executable helper
storage, systemd-run, and the same default Supervisor instance from `/`.
Multi-file changes are not one filesystem transaction: interruption may leave
partial configuration installed and require explicit operator reconciliation.
The mapped legacy `/update` POST remains blocked once configuration is active;
use authenticated bootstrap GET after replacement, not another legacy job.
Native status remains available through a separately authorized read-only root
management transport. A busy helper makes GET retryable, never successful.

### Subsequent unchanged-configuration updates

This is a separate operation from VM/service rollout. It replaces **only the
running host app-lb executable**, retaining its predecessor indefinitely. It
does not install bundled units/configuration/heyctl, recreate VMs, purge disks,
or change workspace state. Bootstrap this API/helper once through the existing
managed platform update process before enabling CI callers. Unstamped builds
(`x-heyo-revision: unknown`) cannot complete a correlated rollout.

Disabled by default. `APP_LB_HOST_UPDATE_CONFIG` must name an absolute,
operator-owned JSON file, inaccessible to workflow writes, for example:

```json
{
  "deployment": "app-lb-host-controller",
  "namespace": "default",
  "executable": "/usr/local/bin/app-lb-eu1",
  "process": {"kind": "systemd", "unit": "app-lb-eu1.service"},
  "state_dir": "/var/lib/heyo-eu1/app-lb/host-updates",
  "artifact_store": "https://artifacts.eu1.heyo.work",
  "health_url": "https://admin.eu1.heyo.work/healthz",
  "config_files": ["/etc/systemd/system/app-lb-eu1.service", "/etc/heyo/app-lb-eu1.env"]
}
```

These are example values, not defaults or a provisioning command. A Supervisor
installation instead uses `"process":{"kind":"supervisor","program":"app-lb"}`.
It restarts **only that program**, never `supervisor.service`. `config_files`
must explicitly enumerate all effective startup/unit/include/environment files;
their contents are hashed, never sent to CI. Do not list mutable deployment or
workspace state. Mapping/config changes and source binary drift invalidate the
conditional request. Supervisor requires its already-loaded configuration to
match these files; operators must not concurrently change/reload supervision.
The controller and independent helper must resolve the same default
`supervisorctl` configuration/socket; every supervisor command explicitly runs
from `/` in both processes. Non-default client layouts are unsupported, and
the reserved multi-program target `all` and option-like targets are rejected.

Supported hosts are Linux with local durable storage, one controller owning the
mapped executable, and permission to run `/usr/bin/systemd-run` and the mapped
`/usr/bin/systemctl` or `/usr/bin/supervisorctl` operation. Mapping, executable
directory, and state directory must be trusted root-owned locations. Pre-create
the state directory durably, on a filesystem that allows helper execution.
Symlink executables and arbitrary shell commands
are unsupported. No privilege changes or units are provisioned by this feature.
The supervisor-reported PID must be this app-lb process, not a wrapper/parent.

Authenticated namespace admins use GET `/deployments/:id/update/rollouts` for
`protocol:host-app-lb-v1`, `binary_sha256`, `config_sha256`, and mapped public
health/artifact URLs. POST the same path with:

```json
{
  "operation_id": "ci-host-stable-id",
  "expected_binary_sha256": "<GET source SHA256>",
  "expected_config_sha256": "<GET configuration SHA256>",
  "artifact_sha256": "<validated public bundle SHA256>",
  "binary_sha256": "<derived dist/app-lb SHA256>",
  "revision": "<exact validated 40-character Git SHA>"
}
```

GET `/deployments/:id/update/rollouts/:operation_id` returns the exact `request`,
deployment/namespace, status, phase, error and `readiness_verified`. IDs are
1–128 ASCII letters/digits/hyphens/underscores. Different replay payloads
conflict. The mapped deployment cannot use legacy uncorrelated `/update`.

Admission persists before staging or launch. Downloads use the configured
HTTPS public blob store, never redirects or workflow-selected URLs. Both CI
and app-lb verify the archive digest, unique regular `dist/app-lb`, exact
`dist/REVISION`, and `dist/SHA256SUMS`; links, special files, traversal,
duplicate identity entries, and expansion beyond 256 MiB are rejected.
Only the verified executable is written; tar paths are never extracted.

The operation retains `.previous` and `.candidate` bytes, syncs files and
directories, then launches a stable-name independent systemd helper using the
previous executable. The helper checks source process/configuration again,
records switch intent, atomically renames a same-directory executable, syncs,
and restarts only the mapped process. Completion requires a new process start
identity, exact running/on-disk executable hash, immutable compiled revision,
unchanged mapped configuration, and public 2xx health with that exact header.
Command success or generic health is never sufficient.

Interrupted staging/launch with no definitive helper evidence remains fenced;
replay **does not launch again**. A surviving helper can finish across HTTP
process restart; GET reconciles the replacement. Ambiguous switch/restart or
failure never triggers rollback, unit recycling, or VM deletion. CI cancellation
stops waiting, not accepted remote work. Inspect the recorded operation and
its stable helper unit before operator reconciliation; do not remove its ledger
to manufacture a retry. There is intentionally no force/unlock shortcut.

## Recover a retained workspace lineage

`POST /deployments/:id/workspace/recoveries` explicitly selects a stopped retained
VM as the source of a new workspace snapshot. It is not a VM restart or a data
merge. The operator must first decide that replacing the current snapshot with
this source is appropriate; the API verifies filesystem capture, not application
integrity (for example, JetStream message checks).

```json
{
  "operation_id": "recover-retained-source-1",
  "source_sandbox_id": "sb-exact-retained-id",
  "expected_snapshot": "<current 64-character lowercase SHA256>",
  "confirm_replace": true
}
```

Admission requires authenticated namespace-admin authority even when ordinary
CRUD is ungated. The deployment must have exactly one unresolved replacement
capture, an empty serving/pending/resumable pool, and no queued captures. The
source must have a unique durable seed record with a mount index, matching
remembered workspace namespace/path/store, and an exact stopped daemon record.
Unknown, running, foreign, or missing sources and stale snapshots fail closed.
The source need not have been seeded from the current snapshot: this explicit
operation is the only exception, and it does not rewrite its seed history.

GET `/deployments/:id/workspace/recoveries/:operation_id` returns the original
`request`, deployment/namespace, `status`, resulting `snapshot`, and `error`.
Status is `running` or `succeeded`; failures remain running with an error and
the creation fence intact. IDs are 1–128 ASCII letters/digits/hyphens/underscores.
Exact replay returns the same operation, including after restart/completion;
reuse with another payload conflicts. There is no unsafe cancel/unpin shortcut.

Recovery first persists intent and a permanent source pin, then captures and
verifies the stopped source. Snapshot files and the workspace record are synced
before atomically releasing the replacement fence. Restart retries read-only
capture if needed; uncertain writes never report success or permit placement.
The selected VM is never stopped, resumed, deleted, or added to the resumable
pool by recovery. Its pin survives completion and defeats even forced disk purge.
PUT/register/scaling and image/mount replacement commits are blocked while
recovery runs; deletion of a deployment with recovery history is refused.
One owning app-lb process is required for this local state directory.

Separately, `PATCH /disks/:id {"retain":true}` now also protects workspace
predecessors from post-capture replacement deletion, not just disk expiry.
Such predecessors remain stopped after replacement capture; ordinary unpinned
retirement and same-pool idle suspension retain their existing behavior. These
app-lb protections cannot prevent an out-of-band daemon/operator deletion.

## Run

```sh
cargo build --release
./target/release/app-lb
```

To run it as a managed, auto-restarting service, see the supervisord unit in
[`deploy/supervisor/`](deploy/supervisor/).

Configuration is environment-only:

| Variable | Default | Meaning |
| --- | --- | --- |
| `APP_LB_PROXY_ADDR` | `0.0.0.0:6188` | Proxy listener |
| `APP_LB_ADMIN_ADDR` | `127.0.0.1:9090` | Admin API listener |
| `APP_LB_STATE_PATH` | `app-lb-state.json` | Names the state *directory* — see below |
| `APP_LB_INSTANCE_LOCK` | `/run/app-lb/instance.lock` | Host-wide single-instance lock, so two app-lbs never manage the same daemon's sandboxes. A different path only for instances on separate daemons; `off` disables it |
| `APP_LB_SECRETS_PATH` | `app-lb-secrets.json` | Where stored secrets persist (written `0600`) |
| `APP_LB_SECRET_KEY` | *(unset)* | 32-byte hex key (or any passphrase) that seals the secrets file with AES-256-GCM |
| `APP_LB_TOKENS_PATH` | `app-lb-tokens.json` | Where minted [app-tokens](#app-tokens) persist (written `0600`; only hashes) |
| `APP_LB_AUTH_KEY` | `app-lb-auth-key` | Signing key for sign-in sessions; generated `0600` on first use |
| `APP_LB_GUARD_PATH` | `app-lb-guard.json` | Where [block rules](#response-actions) persist, so a restart does not unblock an attacker |
| `APP_LB_NAME` | `app-lb` | Display name in the dashboard header and page title |
| `APP_LB_DAEMON_URL` | *(auto: unix socket, else `http://127.0.0.1:34099`)* | heyvm daemon. Left unset, app-lb takes a unix socket when one is discoverable and alive — `HEYVM_SOCKET`, then `socket_path` in `~/.heyo/daemon.json` — and falls back to loopback TCP. Set this to name a non-default or remote daemon: an explicit address is always honoured as given, never traded for a local socket. The transport actually chosen is logged at startup |
| `APP_LB_DAEMON_API_KEY` | `HEYO_API_KEY` | Bearer credential for an authenticated heyvm daemon; use the HeyoSecret-backed host internal API key in deployments |
| `APP_LB_DISCOVERY_URL` | *(unset)* | Orchestrator base URL; setting it with the token enables service endpoint polling |
| `APP_LB_DISCOVERY_TOKEN` | *(unset)* | Bearer credential for Orchestrator discovery; must be set together with `APP_LB_DISCOVERY_URL` |
| `APP_LB_DISCOVERY_INTERVAL_SECS` | `5` | Positive interval between service endpoint snapshot polls |
| `APP_LB_DASHBOARD_PASSWORD` | *(unset)* | Set to gate the dashboard behind HTTP Basic Auth |
| `APP_LB_DASHBOARD_USER` | `admin` | Basic Auth username (only used when a password is set) |
| `APP_LB_DASHBOARD_AUTH` | `true` | `0`/`false` to leave the dashboard view tier open while the password keeps gating the CRUD API — for when your own sign-in (e.g. Google) fronts the pages |
| `APP_LB_ADMIN_AUTH` | `false` | `1`/`true` to extend the gate to the deployment CRUD API (needs a password) |
| `APP_LB_AUTH_URL` | *(unset)* | Base URL of the Heyo auth service. **Setting it enables [federated auth](#managed-mode-federated-auth-and-namespaces)**: a bearer that is not an app-token is resolved to namespace grants by `GET /api/auth/scopes`. Needs `APP_LB_ADMIN_AUTH=1` |
| `APP_LB_AUTH_CACHE_SECS` | `60` | How long a resolved grant is trusted before re-fetching (never past the token's own expiry). Also the ceiling on revocation latency |
| `APP_LB_AUTH_TIMEOUT_SECS` | `5` | Timeout for one scopes lookup. An unreachable auth service fails closed |
| `APP_LB_HOME_URL` | *(unset)* | The Heyo front end namespace users open the dashboard from (e.g. `https://heyo.computer/namespaces`). Linked from `/login` and when a [namespace session](#opening-the-dashboard-for-one-namespace) is refused or expires |
| `APP_LB_ONBOARDING_MCP_URL` | *(unset)* | Hosted MCP endpoint the dashboard's "Get started" card tells namespace users to install (e.g. `https://mcp.us2.heyo.work/mcp`). Unset leaves that step out. |
| `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` | `7776000` (90 days) | Longest lifetime a namespace admin may mint a token for; also the default when they ask for none. |
| `APP_LB_PUBLIC_IMAGE_CATALOG_URL` | *(unset)* | Cloud base URL serving `/public-images/{name}/meta`. Used to resolve the "Get started" fastcar spec's image download and digest. |
| `APP_LB_ONBOARDING_FASTCAR_IMAGE` | `fastcar` | Catalog name of the image that spec deploys. |
| `APP_LB_TLS_CERT` | *(unset)* | PEM cert path; set with `APP_LB_TLS_KEY`. The fallback cert when ACME is on |
| `APP_LB_TLS_KEY` | *(unset)* | PEM private-key path |
| `APP_LB_PROXY_TLS_ADDR` | `0.0.0.0:6189` | HTTPS listener (bound when ACME is on or cert+key are set) |
| `APP_LB_ACME_EMAIL` | *(unset)* | Let's Encrypt account contact; **setting it enables automatic certificates** |
| `APP_LB_ACME_DIR` | `/var/lib/app-lb/acme` | ACME account key and issued certificates (should be `0700`) |
| `APP_LB_ACME_DIRECTORY` | LE production | ACME directory URL — point at staging for testing |
| `APP_LB_ACME_WILDCARD` | *(unset)* | Comma-separated domains to cover with a **wildcard** cert (`sb.example.com` → also `*.sb.example.com`). Issued over DNS-01; needs the zone id below |
| `APP_LB_ROUTE53_ZONE_ID` | *(unset)* | Route 53 hosted zone where DNS-01 challenge records are written |
| `APP_LB_PUBLIC_IPS` | *(unset)* | Comma-separated public IPv4/IPv6 addresses of this LB, served by `GET /ingress` so a client can show the A/AAAA records a `routes[].host` needs. Informational only — app-lb never writes DNS |
| `APP_LB_AWS_BIN` | `aws` | The AWS CLI, used for the DNS-01 challenge and for [disk archives](#archiving-a-disk-to-s3) |
| `APP_LB_BUILD_DIR` | `/var/lib/app-lb/builds` | Git checkouts for image builds (one per deployment, `0700`) |
| `APP_LB_HEYVM_BIN` | `heyvm` | The heyvm CLI that builds guest images |
| `APP_LB_ART_BIN` | `art` | The `art` CLI that materializes a rootfs from a **local** artifact store; unused when `artifact.store` is a URL |
| `APP_LB_IMAGES_DIR` | `/var/lib/app-lb/images` | app-lb's own scratch for images on their way to the daemon: a pull is fetched here and a build writes here, then the result is uploaded into the daemon's catalog (`PUT /images/:name`) and removed. Nothing the daemon reads |
| `APP_LB_GIT_BIN` | `git` | The git binary used for checkouts |
| `APP_LB_MOUNTS_DIR` | `/var/lib/app-lb/mounts` | Where a [guest mount](#mounting-a-directory-into-the-guests)'s tree is unpacked before it is uploaded to the daemon as a tree (`PUT /trees/:id`). app-lb's own directory |
| `APP_LB_MOUNT_TTL_SECS` | `86400` (1 day) | How long a mount tree no deployment names survives. **`0` turns reclamation off** |
| `APP_LB_UPDATE_SHELL` | `/bin/sh` | Shell a static deployment's `update.commands` run through |
| `APP_LB_BUILD_TIMEOUT_SECS` | `1800` | Ceiling on one build step or update command, after which the child is killed |
| `APP_LB_HEYVM_HOME` | *(unset)* | `HOME` for the `heyvm` and `art` children (their own config), when it should differ from app-lb's. A build's output no longer depends on it: `MVM_DATA_DIR` is pointed at `APP_LB_IMAGES_DIR` for the build and the image is uploaded from there |
| `APP_LB_DISKS_PATH` | `app-lb-disks.json` | Where retention decisions persist |
| `APP_LB_DISK_TTL_SECS` | `604800` (7 days) | How long an unclaimed disk survives. **`0` turns expiry off** |
| `APP_LB_DISK_SWEEP_SECS` | `3600` | Gap between expiry sweeps (floor 60) |
| `APP_LB_DISK_ARCHIVE_BUCKET` | *(unset)* | S3 bucket for disk archives; **setting it enables archiving** |
| `APP_LB_DISK_ARCHIVE_PREFIX` | `app-lb/disks` | Key prefix inside the bucket |
| `APP_LB_DISK_ARCHIVE_ENDPOINT` | *(unset)* | `--endpoint-url` for an S3-compatible store |
| `APP_LB_DISK_ARCHIVE_ON_EXPIRE` | `false` | `1` to archive an expiring disk before reclaiming it |
| `APP_LB_DISK_ARCHIVE_TIMEOUT_SECS` | `7200` | Ceiling on one archive, after which `tar` and `aws` are killed |
| `APP_LB_TAR_BIN` | `tar` | The `tar` used to unpack a workspace capture and restore a bundle on this host. The daemon produces disk archives and workspace exports itself |
| `APP_LB_OBS_URL` | *(unset)* | Where app-obs listens (e.g. `127.0.0.1:9500`); **setting it enables log shipping** |
| `APP_LB_OBS_TOKEN` | *(unset)* | Bearer token for app-obs's `/ingest` — must match its `APP_OBS_INGEST_TOKEN` |
| `APP_LB_OBS_HOST` | `/etc/hostname` | Machine name stamped on every batch |
| `APP_LB_OBS_DEPLOYMENT` | `_lb` | Deployment id in app-obs for app-lb's *own* records — name it per host (`lb-us2`) when several LBs ship to one collector |
| `APP_LB_OBS_ACCESS_LOG` | `true` | `0` to stop shipping the per-request access log |
| `APP_LB_OBS_EVENTS` | `true` | `0` to stop shipping app-lb's own log events (and deploy-job output) |
| `APP_LB_SIEM` | `true` | `0` to turn [security monitoring](#security-monitoring) off entirely |
| `APP_LB_SIEM_QUEUE_CAPACITY` | `4096` | Observations buffered for analysis before new ones are dropped |
| `APP_LB_SIEM_ALERT_CAPACITY` | `512` | Alerts held in memory for `GET /security` |
| `APP_LB_SIEM_WINDOW_SECS` | `60` | Window every rate-based rule counts over |
| `APP_LB_SIEM_MAX_CLIENTS` | `16384` | Source addresses tracked at once (~2 MB at the default) |
| `APP_LB_SIEM_AUTH_THRESHOLD` | `8` | Authentication failures per window from one source before an alert |
| `APP_LB_SIEM_SCAN_THRESHOLD` | `30` | 4xx responses per window from one source before it reads as scanning |
| `APP_LB_SIEM_RATE_THRESHOLD` | `600` | Requests per window from one source before it reads as a spike |
| `APP_LB_SIEM_SUPPRESS_SECS` | `300` | Repeats inside this fold into the open alert instead of raising a new one |
| `APP_LB_SIEM_MAX_ALERTS_PER_MIN` | `60` | Hard ceiling on *new* alerts, for a distributed attack that cannot fold |
| `APP_LB_SIEM_SCAN_QUERY` | `true` | `0` to match signatures against the path only, never the query string |
| `APP_LB_SIEM_SHIP` | `true` | `0` to keep alerts local instead of sending them to app-obs |
| `APP_LB_GUARD_ENFORCE` | `true` | `0` for a dry run: [rules](#response-actions) match and count, nothing is refused |
| `APP_LB_OBS_QUEUE_CAPACITY` | `8192` | Records buffered before new ones are dropped |
| `APP_LB_OBS_BATCH` | `500` | Records per POST |
| `APP_LB_OBS_FLUSH_SECS` | `2` | How long a record may wait for a fuller batch |
| `RUST_LOG` | `info,app_lb=debug` | Log filter |

### Where state lives

Deployments persist as one file per deployment, in a directory beside the path
`APP_LB_STATE_PATH` names: `app-lb-state.json` → `app-lb-state.d/<id>.json`.
Each file holds the spec and the runtime state app-lb has to remember across a
restart.

One file per deployment rather than one file for all of them, because writing
every spec on every change is quadratic in a fleet: registering the thousandth
sandbox would rewrite the other 999 with it. Registering, editing and
deregistering are each a single file write or unlink, whatever the fleet size.

**Upgrading is automatic and one-way.** On first start with this version an
existing `app-lb-state.json` is imported and then renamed to
`app-lb-state.json.migrated`. It is renamed rather than deleted so a downgrade
still has the data, and so a second start cannot re-import deployments that were
deregistered in between — which would resurrect them. Nothing to run by hand;
the log says how many were migrated.

A file whose spec no longer validates is skipped with a warning and **left
alone**, because that file is the only copy of what somebody wrote. The startup
sweep that removes files no deployment claims stands down entirely when that
happens, for the same reason.

[Disk retention decisions](#disk-management) live in their own file
(`APP_LB_DISKS_PATH`, default `app-lb-disks.json`) and hold only what cannot be
re-derived from the filesystem: which disks are pinned, any note, and where each
one was archived. An entry back at its defaults is dropped rather than written,
so the file tracks decisions rather than growing a line per sandbox that ever
booted. A corrupt or unreadable file is logged and **not** fatal — the worst
case is a missed `retain` flag, and the sweep's other four guards still hold.

## CLI

[`heyctl`](heyctl/README.md) is a kubectl-shaped CLI over the admin API below — the same
operations without hand-written `curl`, plus saved server/credential contexts, tables, `$EDITOR`
round-trips and rollout waiting. It is a separate crate, so installing it doesn't pull in pingora
or the ACME stack.

```sh
cargo build --release -p heyctl

heyctl login --server 127.0.0.1:9090   # saves a context; prompts if the server is gated
heyctl create deployment demo --host demo.local --image nginx --port 80 --min 0 --max 4
heyctl rollout status demo
heyctl get deployments -o wide
heyctl scale demo --min 2 --max 8
heyctl restart demo                    # drain every VM; the autoscaler replaces them
heyctl drain stage us1.internal:8080   # stop new traffic, wait for in-flight to reach zero
heyctl uncordon stage us1.internal:8080
heyctl top                             # per-deployment CPU, memory, latency, 5xx

# Ship a rootfs through an artifact store, and boot it somewhere else.
heyctl artifact login http://10.0.0.4:8080   # saves a registry; prompts for the API key
heyctl artifact push --image web-v2          # a heyvm image, or a path to an .ext4
heyctl pull demo --wait                      # materialize it here and roll the pool

# Hand the guests a directory of data, from the same store.
art put corpus.tgz --tag corpus-2026-08      # a bundle, as a site's is
heyctl edit demo                             # add it under vm.mounts; the pull starts on save
heyctl mounts pull demo --wait               # or run one by hand
```

See [`heyctl/README.md`](heyctl/README.md) for the full command set, the context/credential
model, and which commands apply to managed versus static deployments.

## Admin API

```sh
# Register (or replace) a deployment.
curl -XPOST localhost:9090/deployments -H 'content-type: application/json' -d '{
  "id": "demo",
  "routes": [{"host": "demo.local"}, {"host_suffix": "apps.example.com"}, {"path_prefix": "/demo"}],
  "vm": {
    "driver": "firecracker",
    "image": "nginx",
    "port": 80,
    "size_class": "small",
    "ttl_seconds": 900
  },
  "scaling": {
    "min_replicas": 0,
    "max_replicas": 4,
    "warm_pool": 1,
    "target_concurrency": 10,
    "scale_to_zero_after_secs": 300,
    "cold_start_timeout_secs": 120,
    "drain_timeout_secs": 30,
    "boot_timeout_secs": 300
  },
  "health": {"path": "/", "timeout_secs": 2}
}'

curl localhost:9090/deployments          # list, with live VM state
curl localhost:9090/deployments/demo     # one deployment
curl -XDELETE localhost:9090/deployments/demo   # drain and reap every VM
# Remove only a proven-empty stale record (ETag copied from GET):
curl -XDELETE 'localhost:9090/deployments/demo/record' -H 'If-Match: "<sha256>"'
curl localhost:9090/healthz
curl localhost:9090/metrics              # metrics snapshot (JSON)
curl localhost:9090/certs                # issued TLS certificates and expiry
curl localhost:9090/security             # security findings + the block rules in force
curl localhost:9090/disks                # every per-sandbox disk on this host

# Unpack the deployment's guest mounts and roll the pool onto them. Started
# automatically on register/edit when a mount has no tree on this host.
curl -XPOST localhost:9090/deployments/web/mounts/pull

# Disk management. See "Disk management" — purging deletes gigabytes with no undo.
curl -XPATCH localhost:9090/disks/sb-abc123 -H 'content-type: application/json' \
  -d '{"retain": true, "note": "holds the demo database"}'   # pin against expiry
curl -XPOST localhost:9090/disks/sb-abc123/archive -H 'content-type: application/json' \
  -d '{"purge": true}'                                       # stream to S3, then reclaim
curl -XDELETE localhost:9090/disks/sb-abc123                 # reclaim now
curl -XDELETE 'localhost:9090/disks/sb-abc123?force=1'       # ...even if a deployment claims it
curl -XPOST localhost:9090/disks/sweep                       # run the expiry sweep now
curl -XPOST localhost:9090/disks/purge-orphans               # reclaim every orphan, at any age

# Refuse traffic. See "Response actions"; an empty match is rejected, and these
# rules are never applied to this admin API.
curl -XPOST localhost:9090/security/rules -H 'content-type: application/json' \
  -d '{"action":"block","match":{"client":"203.0.113.9"},"expires_in_secs":3600}'
curl -XDELETE localhost:9090/security/rules/5f295e1a86f2

# Edit a deployment in place (full spec). The pool is preserved unless the `vm`
# template changes, in which case the VMs are rebuilt.
curl -XPUT localhost:9090/deployments/demo -H 'content-type: application/json' -d @demo.json

# Scale: partial update of just the scaling policy (fields omitted are kept).
curl -XPATCH localhost:9090/deployments/demo/scaling -H 'content-type: application/json' \
  -d '{"min_replicas": 2, "max_replicas": 8}'

# Evict (delete) a single VM. The x-vm-id header / metrics give the sandbox id.
curl -XDELETE localhost:9090/deployments/demo/vms/sb-abc123            # graceful drain
curl -XDELETE 'localhost:9090/deployments/demo/vms/sb-abc123?force=true'  # kill now

# Drain a fixed regional/static upstream. The address is one encoded path segment.
curl -XPUT localhost:9090/deployments/stage/upstreams/us1.internal%3A8080/drain \
  -H 'content-type: application/json' -d '{"reason":"regional maintenance"}'
curl -XDELETE localhost:9090/deployments/stage/upstreams/us1.internal%3A8080/drain
```

Then: `curl -H 'Host: demo.local' localhost:6188/`

Responses carry an `x-vm-id` header naming the VM (or, for a static deployment, the upstream
address) that served them.

### Static / proxy_pass deployments

A deployment with an `upstreams` list (instead of a `vm` template) forwards matched requests to
a fixed set of upstream addresses — another app or service — like nginx `proxy_pass`. There is
no VM lifecycle and no autoscaling: the upstreams are load-balanced least-in-flight with
per-request failover, and the autoscaler health-re-probes them each tick (using the
deployment's `health` check) so a recovered upstream rejoins routing and a dead one is skipped.

```sh
curl -XPOST localhost:9090/deployments -H 'content-type: application/json' -d '{
  "id": "legacy-api",
  "routes": [{"path_prefix": "/legacy"}],
  "upstreams": ["10.0.0.9:8080", "backend.internal:8080"],
  "health": {"path": "/healthz", "timeout_secs": 2}
}'
```

Each upstream is a plaintext `host:port` (or `ip:port`), or an HTTPS origin URL such as
`https://ci.eu1.heyo.work:443`; a hostname is re-resolved per connection. HTTPS uses the URL
hostname for SNI and normal certificate verification while preserving the caller's original
`Host` header. HTTPS requires a DNS hostname, not an IP literal. URLs may contain only the origin (an optional `/` is allowed), with no credentials,
query, or fragment. To
change the targets, `PUT` the deployment with a new `upstreams` list (the backends are rebuilt).
Scaling (`PATCH .../scaling`) and per-VM eviction (`DELETE .../vms/...`) do not apply to a
static deployment and are rejected. Bare addresses remain proxied over **plaintext HTTP**.

Orchestrator can own membership while app-lb continues to own the local daemon and static
least-in-flight/failover behavior. A discovery-backed static spec may start empty:

```json
{"id":"cloud","routes":[{"host":"cloud.example.com"}],"upstreams":[],"discovery":{"service_id":"cloud"}}
```

Each poll atomically replaces only this spec's upstream list with healthy, non-draining
Orchestrator endpoints and persists the last good set. Failed or stale snapshots leave it intact.
The same deployment can be registered with
`heyctl create deployment cloud --host cloud.example.com --discovery-service cloud`.

To request regional membership, set `discovery.region`, for example
`{"service_id":"cloud","region":"eu1"}`. Require
`X-App-Lb-Discovery-Region: 1` from `GET /deployments` before provisioning it.
The watcher adds `?region=eu1` to the authority URL and requires an exact `region`
echo plus matching region on every endpoint. An old server ignoring the query,
a foreign endpoint, or an unplaced endpoint rejects the entire snapshot; the
last valid set remains. Empty regional sets retain the shared authority's version.
Changing region clears and fences cached membership before polling the new scope;
in-flight requests stay counted until completion. This is regional membership,
not regional traffic weights, per-host VM mapping, or the staged peer-drain protocol.
Legacy specs without `region` continue requesting the full endpoint set.

For managed configuration without host environment changes, include a source in the
deployment registered through the admin API:

```json
{"id":"example","routes":[{"host":"example.com"}],"discovery":{"service_id":"example","source":{"url":"https://orchestrator.example.com/orchestration/services/example/discovery","auth":{"secret":"discovery-reader","key":"token"}}}}
```

Provision `discovery-reader` through the existing secrets API from the service's
HeyoSecret-backed configuration. Its token is resolved in the deployment's namespace
on every poll, so rotation needs no restart. Specs and responses contain only the
reference. The source is persisted with the deployment and takes precedence over
`APP_LB_DISCOVERY_URL/TOKEN`; omitting it preserves those legacy defaults. The watcher
runs even without the environment defaults. Missing credentials or an unreachable
authority retain the last good membership. Changing an already-observed authority
is rejected; create a distinct deployment for an intentional authority migration.
`GET /deployments` advertises `X-App-Lb-Discovery-Source: 1` for callers that must
check support before registration.

`GET /deployments/:id/discovery-status` is on the same admin CRUD/auth tier as deployment
reads and returns the locally observed drain state:

```json
{"serviceId":"cloud","version":42,"upstreams":[{"peer":"10.0.0.9:8080","draining":true,"inFlight":1}]}
```

`version` is the last discovery snapshot whose deployment state was durably written (`null`
before the first successful write). `upstreams` includes current backends and withdrawn backend
generations until their already-admitted requests reach zero; entries with the same `peer` are
combined. A withdrawn generation is fenced from new admission before its snapshot can be
acknowledged. The endpoint returns `400 Bad Request` for a deployment without `discovery` and
`404 Not Found` for an unknown id.

`sourceUrl`, when present, is the exact Orchestrator discovery endpoint that supplied
the durably applied snapshot. It is persisted with `version`, not inferred from the
current environment. Legacy state acquires it after a successful poll. Once stamped,
a different discovery authority is rejected rather than mixing its version sequence
with the old one. Discovery redirects are not followed.

#### Active regional capacity probes

For hierarchical deployments, namespace administrators can POST to
`/deployments/:id/regional-active-probe`. The request binds `operationId`, `stepId`,
`epoch`, a fresh `challenge`, active policy `generation`, exact discovery `version`,
and the destination's `region`, `gatewayId`, `gatewayBootId`, `backendServerId`,
`deploymentId` and `revision`. The receipt echoes that request, source gateway/boot,
and the destination's gateway/boot and exact backend URL.

This probes the **active** policy even when a newer proposal is pending. Execution
identity correlates the result; it does not authorize using an inactive proposal.
The destination must have positive regional weight, open peer admission, eligible
discovery membership and an eligible local backend. The authenticated HTTPS peer
path issues a fresh configured health GET to the exact host-local mapping, checks
revision and the complete bounded response, and retains both regional and backend
request guards until completion. Both gateways revalidate the snapshot afterward.
Public requests cannot inject the internal probe header.

These receipts neither activate policy nor prove withdrawal/drain. Orchestrator
must verify every pinned source/destination pair within its durable probe epoch,
then recheck discovery, policy and gateway boots before publishing. A restarted
gateway or stale/partial receipt set cannot authorize publication. The separate
withdrawn-member probe contract retains its stricter drain barriers.

#### Cordoning and draining a static upstream

Health and operator intent are deliberately separate. A failed probe excludes an upstream until
it recovers. An operator drain excludes it until an operator removes that drain, even if every
probe succeeds in the meantime. Drain intent is stored in the deployment's runtime state, survives
an app-lb restart and a replay of the deployment spec, and is visible beside `healthy`, `draining`
and `in_flight` in the deployment and metrics responses.

```sh
# Stop new traffic and return immediately. Existing requests continue.
heyctl cordon stage us1.internal:8080 --reason 'regional maintenance'

# Do the same, but wait until in_flight reaches zero.
heyctl drain stage us1.internal:8080 --timeout 300

# A healthy upstream becomes selectable immediately. An unhealthy one waits for its probe.
heyctl uncordon stage us1.internal:8080
```

The safety rule is fail-closed: a first-time drain is rejected with `409 Conflict` unless another
upstream is both healthy and accepting. This prevents two simultaneous maintenance operations
from withdrawing all capacity; drain mutations are serialized per deployment so both requests
cannot race through the check. `--force` (API body `{"force":true}`) is the explicit escape hatch
for an intentional outage. Retrying an already-active drain is idempotent and does not need force.

`cordon` and `drain` both stop new selection at the same instant. The difference is only whether
the client waits for old requests to finish. A drain timeout does **not** reopen the upstream; the
safe failure mode is to leave it cordoned until `uncordon` is called.

### Static sites

A deployment with a `site` block has **no backend at all**: app-lb answers the
request itself, out of a directory on its own host. What nginx's `root` or a
CloudFront origin bucket does.

```sh
curl -XPOST localhost:9090/deployments -H 'content-type: application/json' -d '{
  "id": "docs",
  "routes": [{"host": "docs.example.com"}],
  "site": {"root": "/srv/docs/dist", "not_found": "404.html"}
}'
```

```sh
heyctl create deployment docs --host docs.example.com \
  --site-root /srv/docs/dist --site-404 404.html
```

| Field | Default | |
| --- | --- | --- |
| `root` | *(required)* | Absolute path to the directory to serve |
| `index` | `index.html` | Served for a directory. `""` makes those a 404 |
| `not_found` | *(none)* | Body for a 404, relative to `root`. Absent = plain text |
| `spa` | `false` | Serve `index` for any unmatched path, with a 200 |
| `cache_control` | `public, max-age=300` | `Cache-Control` on served files |

What you get: an index, a custom 404, content types, `ETag` with `304` on
`If-None-Match`, `Accept-Ranges` and byte ranges (so a paused download or a
seeking `<video>` works), `HEAD`, and a `301` from `/docs` to `/docs/` so
relative links resolve. Files are streamed in 64 KiB pieces rather than read
whole, so a large asset does not pin its own size in memory per concurrent
request.

What you don't: rewrites, redirects, per-location blocks, directory listings,
compression. A site that needs those wants a real web server behind a
`proxy_pass` deployment.

**Nothing outside `root` is ever served.** Every path component is checked before
the filesystem is touched — which rejects `..`, an encoded `%2e%2e`, an absolute
path and a NUL — and the resolved file is then confirmed to still be under the
root *after* symlinks are followed, which is the only way to catch a symlink
inside the root pointing out of it. A traversal is refused rather than
sanitised: quietly dropping a `..` would turn an attack into a successful read
of a different file.

`spa: true` is for single-page apps: any path matching no file is served the
index with a 200, so a client-side router owns the URL space. Off by default,
because it turns every typo into a 200. It never rescues a traversal.

**Deploying one.** A site takes an `update` block, the same as a static
deployment — commands run in a directory on the app-lb host:

```jsonc
"update": {
  "working_dir": "/srv/docs",
  "commands": ["git pull --ff-only", "npm ci", "npm run build"]
}
```

`heyctl update docs` runs them and then checks the site is still servable —
that `index` is actually in `root`. A build that exits 0 but writes its output
somewhere else fails the job, rather than leaving a deployment that 404s
everything. (`build` is rejected on a site: there is no image and no pool.)

This needs the toolchain on the app-lb host. The alternative is
[`artifact`](#pulling-a-site-from-an-artifact-store), which unpacks a bundle
somebody else built and needs nothing installed here — a site takes one or the
other, never both.

Scaling, eviction, `exec` and `shell` all do not apply and are rejected with a
message saying so. A site is only reachable through the proxy, so it needs at
least one route.

### Editing & scaling a deployment

`PUT /deployments/:id` replaces a deployment's spec **in place**. The path id
wins (the body's id can't retarget another deployment). Crucially, the running
pool is *preserved* whenever the `vm` template is unchanged — a scaling, route,
or health edit never disturbs live VMs; only a change to the `vm` block reboots
them, because the existing VMs were built from the old template. (This is unlike
`POST /deployments`, which replaces and tears the pool down unless create-only is requested.)

For safe bootstrap, send `If-None-Match: *` on `POST /deployments`. An existing id
returns **412 Precondition Failed**, checked under the deployment change lock before
mutation or teardown. A failed initial persistence returns an error rather than
claiming registration succeeded. `GET /deployments` advertises this support with
`X-App-Lb-Create-Only: 1`; clients must check it before relying on the header with
older servers. Requests without the header retain replacement semantics.
Create-only discovery registration also requires exact-host routes and rejects
overlap with another deployment's routes with **409 Conflict**. This prevents a
new deployment id from silently capturing existing production traffic.

`GET /deployments/:id` returns an `ETag` for the response's complete normalized
`spec`. To make a compare-and-swap update, send that exact value in
`If-Match` on `PUT /deployments/:id`. The comparison is made under the
deployment change lock before any fence, registry or persisted-state mutation,
or VM teardown; a stale tag returns **412 Precondition Failed** with no change.
Omitting `If-Match` retains the original unconditional replace behavior. Only
one exact strong tag is supported: wildcard, list, weak, malformed, uppercase,
or unquoted forms return **400 Bad Request**. A successful PUT also returns the
new `ETag`.

`DELETE /deployments/:id/record` is the metadata-cleanup endpoint. It
requires the exact current strong `If-Match` ETag and returns **409 Conflict**
unless the deployment is route-less, desires zero replicas, and has no live,
pending/provisioning, suspended, rollout-generation, workspace, discovery,
handoff, build/artifact/mount/host-update job configuration, job history, or
host-update mapping. Complete runtime and disk inventories
must confirm no remaining owned resources; unavailable inventories return **503**.
The check and removal fence autoscaler reconciliation, registry mutation,
allocation, and workspace lifecycle. Success removes only the
persisted and in-memory deployment record; it never tears down a VM or queues
disk/workspace cleanup. The separate path makes older servers reject the request
rather than ignore a safety flag. Ordinary `DELETE /deployments/:id` keeps its
existing drain-and-teardown behavior.

`DELETE /deployments/:id/retired-record` additionally permits **settled terminal
rollout history** and read-only release mounts for a managed Firecracker service.
It requires authenticated fleet-admin access and the current `If-Match` ETag.
First withdraw routes, scale to zero, drain, and explicitly clean up the approved
VM generations through the runtime/disk APIs. This endpoint never performs that
resource cleanup. Both ownership names and historical sandbox IDs must be absent
from complete runtime and disk inventories. Running, uncertain or unsettled
rollouts, correlated allocations, workspace state and job history remain blockers.
Before removing the registration it durably archives the exact spec and state to
`<state-dir>/retired/<sha256>.json`; these reports are not loaded as deployments.
Archive failure preserves the registration. Export this report to the operator's
audit store; the endpoint does not upload it to S3. It does not assert backend
retirement or prevent an external authority from recreating a deployment.

Before operational cleanup, also inventory references held outside this app-lb
(Orchestrator, Cloud, service routes and host configuration). This local endpoint
cannot prove that another authority no longer references a registration.

The tag is `"<hex>"`, where `<hex>` is lowercase SHA-256 of the compact JSON
bytes produced by first serializing the full normalized `DeploymentSpec` to a
`serde_json::Value`, recursively sorting every object's keys lexically, then
serializing that value. Array order is preserved. Sorting must be explicit even
when the default map implementation already sorts: transitive dependencies can
enable serde_json's `preserve_order` feature. Thus a Rust client must call
`spec_value.sort_all_objects()` on the GET body's `spec` before computing
`format!("\"{:x}\"", Sha256::digest(serde_json::to_vec(&spec_value)?))`; hash
the `spec` value, not the whole status response and not a client struct's field
order. This is concurrency detection, not a claim that a successful PUT is
durable or idempotent: existing persistence failures are logged after the
in-memory replacement, as before.

Set `maintenance: true` in that complete spec to return **503** on the
deployment's public routes before authentication or backend selection. This
preserves the VM pool and keeps the separate admin API, including exec,
available. Set it back to `false` to reopen traffic. This fences new requests;
it does not cancel in-flight requests or pause application background workers.
Use an app-lb binary that supports this field before relying on the fence.
Ready managed backends marked unhealthy after a connection failure are
re-probed by the autoscaler and rejoin routing only after health succeeds;
stopped VMs are not woken by that recovery check.

`PATCH /deployments/:id/scaling` is a **partial** update of just the scaling
policy: fields you omit keep their current values, so `{"min_replicas": 2}`
raises the floor without resetting `target_concurrency` or the timeouts. It
always preserves the pool; the autoscaler grows or drains it to match. Both
endpoints validate (e.g. `min_replicas > max_replicas` is a `400`).

### Evicting a VM

`DELETE /deployments/:id/vms/:sandbox_id` removes one VM from a deployment's
pool, as opposed to `DELETE /deployments/:id` which tears the whole deployment
down. The autoscaler boots a replacement on its next tick if the scaling policy
still wants the capacity, so this is "recycle this instance", not "shrink the
deployment" — to shrink, lower `max_replicas` instead.

- Default (**graceful**): the VM stops taking new requests, finishes its
  in-flight ones, and is reaped once idle or at `drain_timeout_secs`. Returns
  `202 Accepted` with `{"outcome":"draining"}`.
- `?force=true` (**immediate**): the VM is killed now; its in-flight requests
  fail over to another VM via the proxy's retry. Returns `200 OK` with
  `{"outcome":"killed"}`.

A still-booting (pending) VM is simply killed in either mode. Evicting the sole
VM of a `max_replicas: 1` deployment leaves a brief capacity gap until the
replacement boots (a request arriving in that window eats a cold start).
Unknown deployment or VM id is a `404`.

## Running things inside a VM

Two endpoints reach into a deployment's VM without going through the proxy.
They matter most for a deployment with **no routes at all** — an agent sandbox —
where they are the only ways in.

```sh
# One command. The guest's exit code comes back in the JSON.
curl -XPOST localhost:9090/deployments/sb-7f3a9c/exec \
  -H 'content-type: application/json' \
  -d '{"command":"ls -la /workspace","cwd":"/workspace"}'

# An interactive PTY, over a WebSocket.
heyctl shell sb-7f3a9c
```

| | |
| --- | --- |
| `POST /deployments/:id/exec` | `{command, cwd?, env?, timeout_secs?, wake?, sandbox_id?}` → `{sandbox_id, exit_code, stdout, stderr, output}` |
| `GET /deployments/:id/shell` | WebSocket upgrade; `?cols=&rows=&cwd=&wake=&sandbox_id=` |

**Which VM.** Without `sandbox_id` the pool chooses — a healthy backend, else
a VM that is up but has not passed its health check, else (with `wake`) one it
starts. With `sandbox_id` it is *that* VM or an error: `404` when the VM is
not in the deployment, `409` when it exists but cannot be used yet (not
started, or draining) — and nothing is woken, because naming a VM means
wanting to look at that one, not at a replacement. `heyctl shell web --vm
sb-7f3a9c` and the **Shell** button on a VM's row of the dashboard both use
it.

**From the dashboard.** Every VM deployment's card has a **Shell** button in
its header (the pool picks) and one on each VM row (that VM). It opens a
terminal in the page — a *line* terminal, built into the single self-contained
page so it works over an SSH tunnel: prompts, commands and their output,
`Ctrl-C`, `Ctrl-D`, arrow-key history, paste. Anything that paints the whole
screen (vim, top) wants a real emulator, and that is `heyctl shell`. The
socket rides the same origin as the page, so a Basic-auth or Google sign-in
carries over; when a proxy in front only knows the page, the terminal offers
to reconnect with an [app-token](#app-tokens) as `?app_token=`.

**Through the managed service.** Cloud's namespace door forwards the shell
too — `GET /namespaces/{ns}/lb/deployments/{id}/shell` is a WebSocket upgrade
bridged to this route, the caller's bearer forwarded in the header, so
`heyctl shell web` works against `server: https://server.heyo.computer/namespaces/team-a/lb`
with a `heyo_api_…` token exactly as it does against a local app-lb, and the
heyo SDKs expose it as `ns.deployments().shell("web")`. A federated caller
needs `admin` on the namespace: a shell is at least as powerful as editing the
spec that boots the VM.

Both are on the CRUD tier, so `APP_LB_ADMIN_AUTH=1` covers them. It should:
running a command in a VM is at least as powerful as editing the spec that boots
it.

**Both will start a VM.** `wake` defaults to true, so `exec` against a sandbox
that has scaled to zero boots or resumes one and waits for it, bounded by
`cold_start_timeout_secs`. That wait is the proxy's own cold-start path, which
means it also gets the autoscaler's preference for resuming a suspended VM over
booting a fresh one. Pass `wake: false` (or `--no-wake`) for a `409` instead,
when you want to know rather than wait.

**Both hold the VM for the session's life.** A command or an open shell takes an
in-flight slot exactly as a proxied request does. Without that, an unrouted
sandbox looks permanently idle — nothing else moves its activity clock — and a
deployment with `scale_to_zero_after_secs` set would reap the VM out from under
a live shell.

Why these are proxied rather than app-lb handing back a daemon address: only
app-lb knows which sandbox is currently serving a deployment id, only app-lb can
apply the admin gate, and only app-lb can wake a suspended VM. A client talking
to heyvmd directly would need daemon reachability and credentials, and would
still find nothing running.

An `exec` distinguishes two failures that look alike. A command that runs and
fails is `200` with a non-zero `exit_code`; app-lb failing to *run* it is a
`502`. The shell endpoint refuses **before** the WebSocket upgrade, so a bad
request is a real status code with a JSON body rather than a socket that closes
without saying why.

## Google sign-in

Any deployment can be put behind Google sign-in by adding an `auth` block. The
gate runs in the proxy, before a backend is chosen, so it works the same for a
managed VM pool and a static `proxy_pass` target — and the application behind it
needs to know nothing about OAuth. It sees only requests that got through.

```jsonc
{
  "id": "web",
  "routes": [{"host": "web.example.com"}],
  "upstreams": ["127.0.0.1:8080"],
  "auth": {
    "client_id": "1234-abc.apps.googleusercontent.com",
    "client_secret": {"secret": "google", "key": "client_secret"},
    "allowed_domains": ["example.com"],       // matched on the Workspace `hd` claim
    "allowed_emails": ["contractor@gmail.com"],
    "public_paths": [                         // bare strings mean scope "admin"
      {"path": "/healthz", "scope": "public"},
      {"path": "/hooks/", "scope": "public"}
    ],
    "session_ttl_secs": 43200,
    "base_path": "/__applb/auth",             // where app-lb's own endpoints live
    "forward_identity": true
  }
}
```

### Setting it up

1. In the Google Cloud console, create an **OAuth 2.0 Client ID** of type *Web
   application*, and register the redirect URI — `https://<hostname><base_path>/callback`,
   so with the defaults above: `https://web.example.com/__applb/auth/callback`.
   `heyctl describe deployment web` prints the exact string to paste.
2. Store the client secret. It is a [secret](#secrets), not a spec field:

   ```sh
   heyctl create secret google --from-stdin client_secret < ~/.google-oauth-secret
   ```
3. Add the gate:

   ```sh
   heyctl set auth web \
     --client-id 1234-abc.apps.googleusercontent.com \
     --secret google/client_secret \
     --allow-domain example.com \
     --public-path /healthz
   ```

The pool is untouched — the gate is proxy configuration, not part of the VM
template, so turning it on or off never restarts anything.

### What a request meets

| | |
| --- | --- |
| No session, browser | `302` to Google, then back to what was originally asked for |
| No session, API client | `401` + `{"error":…,"login_url":…}` — a redirect it would only mis-parse |
| Valid session | proxied, with `x-auth-request-{email,user,name}` |
| Signed in, not on the allow-list | `403` naming the account, and a link to sign in as someone else |
| A path under `public_paths` | proxied, gate skipped |

`<base_path>/login` starts a sign-in (useful as a "sign in" link, and after a
logout); `<base_path>/logout` clears app-lb's cookie. Logging out of Google
itself is deliberately not app-lb's business — it would sign the user out of
every other tab.

### How it works, and what that buys

The flow is the OAuth 2.0 authorization code grant **with PKCE**. Both cookies
are self-describing and signed with HMAC-SHA256 (`APP_LB_AUTH_KEY`, generated
`0600` on first use), so:

- **There is no session store** to grow, replicate or lose. A restart does not
  sign anyone out — the key is persisted.
- **A session is bound to its deployment**, so a cookie from one gated
  deployment is not a cookie for another with a narrower allow-list.
- **Tightening the allow-list signs people out.** Each session carries a
  fingerprint of the policy that admitted it; changing `client_id`,
  `allowed_domains` or `allowed_emails` invalidates every session issued under
  the old one, rather than leaving a removed user signed in until their cookie
  expires.

### Who may enter

Both lists take any number of entries and are **OR'd** — one match admits the
caller:

```jsonc
"allowed_domains": ["sarocu.com", "heyo.computer"],
"allowed_emails": ["contractor@gmail.com", "auditor@example.org"]
```

```sh
heyctl set auth web \
  --allow-domain sarocu.com --allow-domain heyo.computer \
  --allow-email contractor@gmail.com --allow-email auditor@example.org
```

Matching is case-insensitive, and a leading `@` on a domain is tolerated —
`@example.com` and `example.com` are the same rule.

**Domains are matched on the `hd` claim, not the email suffix.** Only `hd` says
the account is *governed by* that Workspace domain. A personal Google account
can carry any address a Workspace admin has not claimed, so trusting the suffix
would let `someone@yourcompany.com` in from an account you do not control.

Two consequences worth knowing:

- **A personal Google account has no `hd` at all**, so no `allowed_domains` entry
  can ever match it — list the address in `allowed_emails` instead. This is also
  the answer when a domain you own is not actually a Workspace domain: check with
  `dig +short MX <domain>`, and if the MX records are not Google's, every account
  there is a personal one as far as this claim is concerned.
- **A Workspace with several domains needs each domain that appears in `hd`.**
  Secondary domains generally report their own; for *alias* domains verify against
  a real sign-in before trusting it, since Google may return the primary domain
  instead. `allowed_emails` sidesteps the question entirely.

**An empty allow-list is rejected.** Gating behind "has a Google account" admits
most of the internet, which is a real thing to want and has to be said out loud:
`"allowed_domains": ["*"]`.

**Editing a list replaces it.** Every `--allow-domain`/`--allow-email` you pass
replaces that whole list rather than adding to it, so growing the list means
resending all of it. `heyctl edit deployment <id>` is the incremental
alternative — it opens the spec in `$EDITOR` and changes only what you change.

**Adding or removing an entry signs everyone out once.** The allow-list is part
of the policy fingerprint each session carries (see above), so a change bounces
every current user through Google and straight back in. Reordering the list or
changing its capitalisation costs nothing: the fingerprint sorts and lowercases
first, so only a real change to *who* may enter invalidates anything.

**The identity headers are stripped from every incoming request** to a gated
deployment before app-lb sets them, so a client cannot present its own
`x-auth-request-email`.

### One sign-in across several deployments

By default the session cookie is scoped to the hostname that set it. That is the
safe default and it has an obvious cost: opening `docs.example.com` and then
`api.example.com` — say from the [directory](#directory) — sends you back to
Google in between, because the second host has nothing to present.

Set `auth.cookie_domain` on both gates to make them one realm:

```json
"auth": {
  "provider": "google",
  "client_id": "…apps.googleusercontent.com",
  "client_secret": {"secret": "google-oauth", "key": "client_secret"},
  "allowed_domains": ["example.com"],
  "cookie_domain": "example.com"
}
```

One sign-in then covers every deployment under `example.com`, and the directory's
cards open without a round trip.

**A wider cookie is not a weaker check.** A session is still refused unless the
gate presenting it has a byte-identical policy — provider, client id, both
allow-lists, and this field. Two gates share a session only when either would
have admitted the same person anyway; a neighbour with a narrower `allowed_emails`
refuses the cookie and starts its own sign-in. Turning the realm on also changes
the fingerprint, so a host-only session cannot be replayed at a realm gate or
the other way round.

**What you are accepting.** A cookie scoped to `example.com` is sent to *every*
host under it, including ones app-lb does not serve. If anything else on that
domain is untrusted — a customer subdomain, a legacy box — this hands it a live
session cookie. `HttpOnly` keeps scripts off it; nothing keeps a server on that
domain off it. That is why it is opt-in and per-gate rather than a global
setting.

The value must have at least two labels and must be a parent of the hostnames the
deployment serves; registration refuses anything else, because a cookie the
browser silently discards produces a sign-in that loops forever with nothing in
any log to explain it. It is not checked against the public suffix list, so
`co.uk` is accepted and would simply never be sent — don't.

There is no way to widen a session across *different* registrable domains. That
is a browser rule, not an app-lb one.

### Limits

- **One provider.** Google only; `provider` exists so a spec written today still
  parses when there is a second.
- **The `Secure` cookie attribute follows the connection.** Over plaintext
  `:6188` the session cookie is not `Secure` — fine for a local trial, but a
  gate is only meaningfully protecting anything over HTTPS. Use the [TLS
  listener](#tls).
- **A path-routed deployment needs `base_path` under its prefix.** A deployment
  routed only at `/app` would 404 the provider's redirect to
  `/__applb/auth/callback`; set `base_path` to something like `/app/__auth`.
  Registration rejects the combination rather than letting the first sign-in
  discover it.
- **Sessions are not revocable individually.** Ending one specific person's
  access means removing them from the allow-list, which ends everyone's sessions
  (they simply sign in again). There is no session list to revoke from — that is
  the trade for having no session store.

- **A gate admits browsers and nothing else.** There is no way for a headless
  client to sign in with Google, so the gate refuses one rather than sending it
  somewhere it cannot go. The split is `Accept: text/html`
  (`proxy.rs`, `wants_html`):

  | Client | Unauthenticated request gets |
  | --- | --- |
  | a browser navigating (`Accept: text/html`) | `302` to Google |
  | anything else — curl, CI, heyctl, **and a page's own `fetch()`** | `401` + `{"error":"authentication required","login_url":"…"}` |

  The `login_url` is only useful to something that can open a browser. Put every
  path a machine calls in `public_paths` and protect those with a credential the
  machine can actually present — an API key, Basic auth — exactly as
  [`examples/artifacts-gated.json`](examples/artifacts-gated.json) does for the
  store's API.

  **`fetch()` from an already-signed-in page counts as a machine.** A browser
  sends `Accept: text/html` when *navigating*, but its XHR does not, so a page
  that loads fine can have every one of its background calls refused. app-lb's
  own dashboard is the worked example: gating it puts the page behind Google
  correctly, and then its `/metrics` poll — sent with `accept: application/json`
  — gets a `401` and no numbers ever appear. See
  [Putting the dashboard behind Google](#putting-the-dashboard-behind-google).

## Building images from a Dockerfile

A managed deployment can say where its guest image *comes from*, not just what it
is called. Add a `build` block, and `POST /deployments/:id/build` will get a
Dockerfile onto the app-lb host, hand it to `heyvm mvm build`, and — when that
succeeds — rewrite the deployment's `vm.image` to the image it produced, which
recycles the pool onto it.

Two places the Dockerfile can come from, and exactly one of them may be set:

| | `build.repo` | `build.store` |
|---|---|---|
| the recipe is | in a git checkout | a manifest in an artifact store |
| `build.ref` pins | a commit | a manifest digest — recipe *and* context |
| `build.ref` unset | follows the default branch | rejected; a store has no default |
| `build.auth` is | a git token | the store's `ART_API_KEY` |
| needs on this host | `git` | nothing extra |

Both run `heyvm mvm build` and both produce an image that did not exist before,
which is what separates either from [`artifact`](#pulling-images-from-an-artifact-store)
— there the digest names a finished rootfs and nothing is built at all.

```jsonc
{
  "id": "web",
  "routes": [{"host": "web.example.com"}],
  "vm": {"driver": "firecracker", "image": "web-3f2a1c8e9b0d", "port": 8080},
  "build": {
    "repo": "https://github.com/acme/web.git",
    "ref": "main",              // branch, tag or commit; omit for the default branch
    "dockerfile": "Dockerfile", // omit to let app-lb find one
    "context": ".",             // omit to use the Dockerfile's directory
    "image_size_mb": 768,       // omit to let heyvm size it from the image contents
    "auth": {"secret": "github", "key": "token"}   // omit for a public repo
  }
}
```

```sh
# Build the ref in the spec, and roll the pool onto the result.
curl -XPOST localhost:9090/deployments/web/build          # 202 + a job record

# Build a different ref, just this once. The spec's `ref` is left alone.
curl -XPOST localhost:9090/deployments/web/build -H 'content-type: application/json' \
  -d '{"ref": "v2.1.0"}'

curl localhost:9090/jobs                  # every remembered job, newest first
curl localhost:9090/deployments/web/jobs
curl localhost:9090/jobs/job-3f2a1c8e     # status, commit, image and log tail
```

The same job history covers the other two verbs —
[`pull`](#pulling-images-from-an-artifact-store) and
[`update`](#updating-a-static-deployment) — so `GET /jobs` is one listing of
everything that has changed a backend.

Builds are asynchronous — a `docker build` takes minutes, so `POST` returns `202`
with a record and the outcome is polled from `GET /jobs/:id`. One job runs per
deployment at a time; a second request while one is in flight is a `409`. Job
records live in memory, so they do not survive a restart — the durable outcome of
a build is the `image` in the persisted spec.

Retention is **per deployment**: the 20 most recent jobs each, under a 2000-job
ceiling for the whole LB. Per-deployment rather than one global cap, because a
global cap is a race and not a policy — one deployment pulling images in a loop
would evict everybody else's history, and the job you came to investigate is the
one already gone.

**Where it runs.** On the app-lb host: turning a Dockerfile into an ext4
rootfs needs a local `docker`, `mke2fs` (e2fsprogs) and `fakeroot`, and the
daemon's own build route has no live log. `heyvm mvm build` is run with
`MVM_DATA_DIR` pointed at `APP_LB_IMAGES_DIR`, so the image lands in app-lb's
scratch rather than anywhere the daemon reads; app-lb then uploads it into the
daemon's catalog (`PUT /images/<name>`) and removes the local copy. Nothing
about where the daemon keeps its images is assumed.

**Builds need the `docker` group.** `heyvm mvm build` shells out to `docker`,
whose socket is `root:docker` at `0660`, and the
[supervisord unit](deploy/supervisor/README.md) runs app-lb as a non-root user
that is not in that group — so the first build on a fresh host dies with
`permission denied while trying to connect to the Docker daemon socket`. Add it
(`usermod -aG docker app-lb`) and then **restart the program**, not just the
config: supervisord resolves the group list when it forks the child, so a
`reread`/`update` leaves the running process without it. Grant it only where
builds actually run — the socket starts containers as root on request, so the
group is root-equivalent and hands back most of what the non-root user was for.
A host that only [pulls images](#pulling-images-from-an-artifact-store) needs
none of this.

**Builds need a home directory, before they need anything else** — and the
service user does not have to have `HOME` set to end up with one. `docker` keeps
its client state in `$HOME/.docker`, but when `HOME` is unset it resolves the
home directory by reading `/etc/passwd` for its own uid instead of giving up. So
the home *string* comes from the passwd entry that `useradd` writes from
`/etc/default/useradd` (`HOME=/home` + the username), and `--no-create-home` —
what the [supervisord setup](deploy/supervisor/README.md) does — suppresses only
the `mkdir`, not the field. The result is a build that dies before reading a
single Dockerfile instruction with `Docker build failed: ERROR: mkdir
/home/app-lb: permission denied`: `/home` is root-owned, so the user cannot
create the home its own passwd entry names.

This bites under supervisord in particular because supervisord never sets
`HOME`. It copies its own environment to the child verbatim and reads the passwd
record only for uid/gid, so a supervisord started by systemd without `User=`
hands the child no `HOME` at all. The corroborating symptom is in app-lb's own
startup log — with `HOME` unset it cannot resolve the images directory either,
and warns `neither MVM_DATA_DIR nor HOME is set`.

Either give the user a real home
(`install -d -o app-lb -g app-lb /home/app-lb`) or set `APP_LB_HEYVM_HOME`,
which app-lb passes to the heyvm child as an explicit `HOME` and docker prefers
over the passwd lookup. It affects only the child's own configuration; the
built image is placed by `MVM_DATA_DIR`, as above, and uploaded.

**Image names carry the commit.** Each build produces `<name>-<short sha>`
(`<name>` defaults to the deployment id, override with `build.image_name`), so
the running spec answers "what is deployed?" with something you can look up in
the repo. Old images stay on disk — `heyvm mvm images` lists them, and pruning
them is manual.

**Finding the Dockerfile.** With `build.dockerfile` set, that path is used and a
miss is an error. Without it, app-lb looks for `Dockerfile` at the context root,
then searches up to three directories deep (skipping `.git`, `node_modules`,
`target`, `vendor`, `dist`, `.venv`). Exactly one match is used; several is an
error naming them, because picking one would make the deployed image depend on
directory iteration order.

**Editing `build` never disturbs running VMs.** It is not part of the `vm`
template — it says where the *next* image comes from. The pool moves when a build
finishes.

A static (`upstreams`) deployment cannot have a `build` block: it has no guest
image, it forwards to something somebody else runs. Its update path is
[`update`](#updating-a-static-deployment) instead, and declaring the wrong one is
rejected at registration.

### Building a Dockerfile out of the artifact store

The recipe does not have to live in a repo. `art dockerfile put` stores a
Dockerfile — and, optionally, the build context it copies from — as a
`heyvm.dockerfile.v1` manifest, and `build.store` points a deployment at it:

```jsonc
{
  "id": "web",
  "vm": {"driver": "firecracker", "image": "web-30fea8aa436f", "port": 8080},
  "build": {
    "store": "http://art.internal:8080",   // an `art serve` URL, or an absolute store root
    "ref": "web-rootfs",                   // a tag, or a manifest digest
    "image_size_mb": 4096,                 // omit to use the manifest's own default
    "auth": {"secret": "art", "key": "key"}  // the store's ART_API_KEY; omit if it is open
  }
}
```

Push one from a workstation and point a deployment at it:

```sh
heyctl artifact push-dockerfile ./Dockerfile --build-context . --tag web-rootfs
heyctl set build web --store http://art.internal:8080 --ref web-rootfs
heyctl build web --wait
```

**What this buys over a repo.** A git ref pins a commit and the Dockerfile is
whatever that commit happens to hold; a store ref resolves to a manifest digest
covering the recipe, the context *and* the build defaults together. So a build
can name its exact inputs, and a rollback is expressible — a tag moves, a digest
does not. It also builds a deployment whose source is not in a repo app-lb can
reach, without giving the LB a git credential.

**What it does not buy.** The build still runs here, and still takes as long as
`docker build` does. If the point is to stop building on every host, push the
*image* instead — that is [`artifact`](#pulling-images-from-an-artifact-store).

**The layout on disk.** The recipe lands in
`<work_dir>/<deployment>/.recipe/Dockerfile` and the context is unpacked into
`<work_dir>/<deployment>/.recipe/context/`, which is what `-c` is pointed at. The
directory is **emptied first**, and the archive is deleted after unpacking:
otherwise a file from a previous build could satisfy a `COPY` the current recipe
no longer ships — the same failure `git clean -xffdq` prevents on the repo path,
arriving by a different route. For the same reason the `Dockerfile` sits *beside*
the context rather than in it, so a `COPY` cannot reach it.

**Image names carry the manifest digest**, the way a repo build's carry the
commit: `<name>-<12 hex>`. Both are the input's identity, not the output's — a
`docker build` is not reproducible, so the image is named after what it was made
*from*.

**Context contents are refused, not sanitized.** The archive is unpacked under
the same rules as a site bundle: no absolute paths, no `..`, and no symlinks,
hardlinks or devices. `docker build` itself would allow a symlink; a build
context arriving over a wire is exactly the untrusted input that rule exists for.

## Pulling images from an artifact store

Building is one way to get a `vm.image`. The other is to pull one somebody
already built. An `artifact` block names a store and a reference;
`POST /deployments/:id/pull` resolves that reference to a rootfs blob,
materializes it as an `.ext4` heyvmd can boot, and rewrites `vm.image` — the same
ending a build has, without the build.

The store is [artifacts](https://github.com/sarocu/artifacts): content-addressed,
ext4-native, and already where `art heyvm import` keeps heyvm's base images.

```jsonc
{
  "id": "web",
  "routes": [{"host": "web.example.com"}],
  "vm": {"driver": "firecracker", "image": "web-1b9b737b73e2", "port": 8080},
  "artifact": {
    "store": "http://10.0.0.4:8080",   // an `art serve`, or an absolute store root
    "ref": "web-v2",                    // a tag, or a 64-hex digest
    "grow_gb": 8,                       // omit to keep the image at its stored size
    "auth": {"secret": "art", "key": "api_key"}   // omit for an ungated store
  }
}
```

```sh
# Pull the ref in the spec, and roll the pool onto the result.
curl -XPOST localhost:9090/deployments/web/pull           # 202 + a job record

# Pull a different ref, just this once. The spec's `ref` is left alone, which is
# what makes a digest here a rollback rather than a config change.
curl -XPOST localhost:9090/deployments/web/pull -H 'content-type: application/json' \
  -d '{"ref": "1b9b737b73e26aa4c55d7b609351fa51f0e21b0b6afbaa9ef9f4561dd18337d7"}'

# Re-fetch even if the image is already on disk.
curl -XPOST localhost:9090/deployments/web/pull -H 'content-type: application/json' \
  -d '{"force": true}'
```

Pulls share the job machinery with builds: `202` with a record, polled from
`GET /jobs/:id`, one job per deployment at a time. A record carries the `store`,
the `artifact` reference asked for, the `digest` it resolved to, and the `bytes`
transferred.

CI callers can opt into a durable, idempotent pull by supplying `operation_id`
and an explicit pinned SHA-256 manifest digest (tags are rejected in this mode):

```sh
curl -XPOST localhost:9090/deployments/web/pull -H 'content-type: application/json' -d '{"operation_id":"ci-run-42-web","ref":"1b9b737b73e26aa4c55d7b609351fa51f0e21b0b6afbaa9ef9f4561dd18337d7"}'
```

The identity is `(namespace, deployment, operation_id)`. Repeating identical
intent returns the same `202` job record, including after app-lb restarts;
changing the digest, `force`, or deployment template for that identity returns
`409` without starting work. Correlated records add `target_namespace`,
`intent_fingerprint`, `config_fingerprint`, `source_spec_fingerprint`,
`readiness_verified`, and `reconciliation_required`. `succeeded` requires the
desired replica count to be healthy in the exact replacement pool created by
this operation. The source spec is checked under the deployment mutation lock
before replacement; a concurrent edit is not overwritten. Non-VM and
zero-desired-replica targets are rejected before pulling. If app-lb
restarts during a correlated operation, it marks the durable job `failed` with
`reconciliation_required: true`; it never repeats a possibly destructive
rollout automatically.

Records are synced to `jobs/` beneath the configured per-deployment state
directory (for example `app-lb-state.d/jobs/`). Correlation records are not
evicted by the ordinary in-memory history limits. An unreadable ledger disables
new correlated pulls until repaired and app-lb restarted; it is never treated
as an empty ledger. Status persistence failures require reconciliation, not a
successful CI result. Legacy pulls retain their existing behavior.

**Two transports, chosen by how `store` is spelled.** They are not fallbacks for
each other — they are different situations:

| `artifact.store` | What happens |
| --- | --- |
| `http://host:port` | app-lb resolves and streams the blob itself, verifying the sha256 as it lands. One store feeds a fleet; no `art` binary needed on this host. |
| `/abs/path` | app-lb runs `art heyvm materialize`, which skips the blob's holes instead of copying its zeros. Needs the `art` CLI here (`APP_LB_ART_BIN`), and is dramatically cheaper. |

The difference is not small. Materializing a 48 MiB image from a local store
writes **48 KiB**; the same image over HTTP transfers all 48 MiB. A host running
its own store should name the path.

**The digest is verified on the way in.** A rootfs fetched over a network is what
the kernel boots, so the wire path hashes what arrives and refuses anything that
does not match the digest it asked for — the partial file is removed, the job
fails, and `vm.image` is untouched. The local path gets this for free, because
`art` hashes on materialize.

**Image names carry the digest.** Each pull produces `<name>-<12 hex>` (`<name>`
defaults to the deployment id, override with `artifact.image_name`). That is a
pure function of the content, so an image already on disk is proof the right
bytes are there and the fetch is skipped entirely — a re-pull of unchanged bytes
costs one round trip. The job still rolls the pool, because running VMs hold a
copy of whatever rootfs *they* booted from.

**A tag is resolved at pull time; a digest is not.** A deployment pinned to a tag
follows wherever that tag is moved, which is what makes `heyctl artifact push
--tag web-v2` a deploy. Naming a digest pins the bytes forever, which is what a
rollback should do.

**`grow_gb` is sparse.** The file is extended with `ftruncate`, so it costs no
disk until the guest writes; heyvm runs the `resize2fs` that lets the guest
filesystem use the room. Set it when the image was built small and the workload
needs space on `/`.

**Where it lands.** In the daemon's catalog, by upload: the blob is fetched
into `APP_LB_IMAGES_DIR` (app-lb's own scratch, default
`/var/lib/app-lb/images`), sent to the daemon as `PUT /images/<name>` — grown
there when `grow_gb` asks — and removed. Whether a pull is needed at all is
the daemon's answer too (`GET /images/<name>`), so a catalog on another host
is as good as one on this one.

**`build` and `artifact` are mutually exclusive.** Both rewrite `vm.image` when
they run, so a deployment holding both would have no answer to where the running
image came from. To do both, build on one host and
[`heyctl artifact push`](heyctl/README.md#pushing-an-image-to-an-artifact-store)
the result for the others to pull. A static (`upstreams`) deployment cannot have
an `artifact` block either, for the same reason it cannot have a `build`.

The CLI side is `heyctl pull` and `heyctl set artifact` (and `heyctl mounts pull`
for [guest mounts](#mounting-a-directory-into-the-guests)), plus
`heyctl artifact` for talking to the store itself — see
[`heyctl/README.md`](heyctl/README.md#artifact-stores).

### Pulling a site from an artifact store

A [site](#static-sites) reads the same `artifact` block, and it is the one deploy
path that needs **nothing installed on this host** — no git, no node, no bun, no
Docker. The bundle is a `tar` (or `tar.gz`) of the built site; app-lb fetches it,
verifies it, unpacks it and swaps it into `site.root`.

```jsonc
{
  "id": "marketing",
  "routes": [{"host": "example.com"}],
  "site": {"root": "/srv/marketing/public", "index": "index.html"},
  "artifact": {
    "store": "/srv/artifacts",
    "ref": "marketing-live",
    "strip_components": 1    // drop the `dist/` the bundle wraps everything in
  }
}
```

Build wherever you like — CI, a laptop, a VM — and push the result:

```sh
tar czf dist.tgz -C dist .                       # no wrapper: strip_components 0
art put dist.tgz --tag marketing-live            # or `art put -` from a pipe
curl -XPOST localhost:9090/deployments/marketing/pull
```

Everything above about tags, digests, transports and `force` applies unchanged.
What differs is the ending, and it is the better one: there is no image to name
and no pool to recycle, so a site pull has no cold start and no capacity dip. The
files are simply the files, and the next request reads the new ones.

**Nothing goes live until it is known good.** The order is fetch → verify digest
→ unpack *beside* the live tree → confirm the index is there → swap. Every way a
deploy can fail therefore fails with the previous site still serving, which is
the one thing `git pull && npm run build && mv -T dist public` cannot promise.
The swap itself is two renames in one directory, and the tree it replaces is kept
until the new one is in place.

**`strip_components` is the field you will need.** `tar czf dist.tgz dist` writes
every entry as `dist/…`, which would put the index at `<root>/dist/index.html`
and 404 the whole site. Set `1` to drop the wrapper — and if you forget, the job
fails *before* the swap with a message naming the directory it found and the
number to set. A bundle rolled with `tar czf dist.tgz -C dist .` needs nothing.

**A bundle may only contain files and directories.** Symlinks, hardlinks, devices
and any path with a `..` or a leading `/` are refused rather than sanitized —
whoever can write to the store decides what lands on this host. Permissions are
not taken from the archive either, so a bundle cannot ship something setuid.

**Re-pulls are free.** The deployed digest is recorded in `.<root>.artifact`
*beside* the root (never inside it, where it would be servable), so pulling a
digest already serving is a resolve and nothing else. `{"force": true}` unpacks
anyway.

**`update` and `artifact` are mutually exclusive on a site**, for the reason
`build` and `artifact` are on a VM: both write the files under `site.root`, so a
site with both has no answer to where what it serves came from. Build on this
host, or unpack a bundle built elsewhere. `grow_gb` and `image_name` are rejected
on a site (there is no rootfs to grow or name), and `strip_components` is
rejected off one (a rootfs is one file, and nothing unpacks it).

A site pull's job record carries `site_root` and `files` where a rootfs pull
carries `image`. `bytes` is what crossed the wire, so `0` from a local store is
normal — `art get` hardlinks the blob rather than copying it.

### Mounting a directory into the guests

The third thing an artifact bundle can become, and the only one that is neither
the image nor the site. A rootfs decides what the guests **run**; a `vm.mounts`
entry decides what they **hold**:

```jsonc
{
  "id": "search",
  "routes": [{"host": "search.example.com"}],
  "vm": {
    "driver": "firecracker",
    "image": "search-1b9b737b73e2",
    "port": 8080,
    "mounts": [
      {
        "path": "/data/corpus",           // absolute, inside the guest
        "store": "http://10.0.0.4:8080",  // an `art serve`, or an absolute store root
        "ref": "corpus-2026-08",          // a tag, or a 64-hex digest
        "strip_components": 1,            // drop the wrapper dir, as tar does
        "read_only": true,                // the default
        "auth": {"secret": "art", "key": "api_key"}
      }
    ]
  }
}
```

```sh
tar czf corpus.tgz -C corpus .
art put corpus.tgz --tag corpus-2026-08

curl -XPOST localhost:9090/deployments/search -d @search.json   # 201, and a pull starts
curl localhost:9090/jobs                                        # watch it land
```

Every replica boots with `/data/corpus` already populated, before the start
command runs.

**Why this is not just a bigger rootfs.** A corpus, a model, a seed database or a
bundle of assets moves on its own schedule. Welding it into the image makes a new
copy of it a new operating system: every host re-pulls gigabytes it already has,
and a rollback of one is a rollback of both. As a mount it is its own digest,
fetched once per host and shared by every deployment that names it.

**How it reaches the guest.** app-lb resolves the reference, verifies the blob
against its digest and unpacks it into a directory named after that digest under
`APP_LB_MOUNTS_DIR`, then uploads that tree to the daemon once
(`PUT /trees/<digest>`; the id is the content, so a second upload is a no-op).
The create body names the tree: at boot heyvmd builds each VM its own ext4
image from it (`mke2fs -d`) and attaches it as a virtio-blk device the guest
mounts at `path`. So the disk is per VM — no guest sees another's writes —
and the tree itself is only ever read. A tree the mount sweep reclaims here is
reclaimed on the daemon too.

**A mount is attached at boot, so `mounts` lives in the VM template.** Editing
the list recycles the pool, exactly as changing `image` or `size_class` does.
There is no hot-add.

**Nothing boots until the tree is here.** A mount with no `digest`, or one whose
digest names a tree this host does not hold, makes the autoscaler *refuse* the
create rather than boot a replica silently missing its data — the pool stays at
zero and the reason is on the job, the log and the deployment's feed. Registering
or editing a deployment in that state starts a mount pull by itself, so the usual
sequence is one call:

```sh
# Usually unnecessary — register/edit already starts one. This is for a tag that
# has moved, and for `force`.
curl -XPOST localhost:9090/deployments/search/mounts/pull      # 202 + a job record
curl -XPOST localhost:9090/deployments/search/mounts/pull -H 'content-type: application/json' \
  -d '{"force": true}'
```

**One job covers every mount**, sequentially — these are multi-gigabyte transfers
onto one disk, and eight at once makes all eight slower. The record's `mounts`
array carries a per-mount `digest`, `tree`, `files`, `bytes` and `unpacked`, so a
job still running says which mount it is on. `heyctl describe job <id>` renders
it a row at a time.

**The pool is recycled only if a digest actually changed.** Unlike a build or an
image pull — which recycle unconditionally, because a running VM holds a copy of
whatever rootfs it booted from and no name can prove otherwise — a mount tree is
content-addressed, and a running VM's copy was built from the same digest. An
unchanged digest therefore means the pool already has exactly these bytes. This
is what keeps the pull-on-every-registration from being a fleet-wide restart.

**Mounts are read-only by default, and writable is refused on `kvm`.** On
`firecracker` each VM's ext4 is its own and writes go nowhere else, so
`"read_only": false` is a writable scratch copy seeded from the bundle, discarded
with the VM. The KVM driver syncs a read-write mount image *back into the host
directory* when the VM stops — and that directory is the shared, content-addressed
tree every other replica boots from — so a writable mount there is rejected at
registration rather than left to corrupt it. For writable space that survives a
restart, use `vm.disk_size_gb`, which is a per-VM data disk at `/workspace`.

**What a path may be.** Absolute, no `..`, and drawn from `[A-Za-z0-9/._-]` —
it is interpolated into the guest's own mount command. Two mounts may not share a
path or nest one inside another (the guest mounts them in array order, so the
inner one would be hidden), and `/`, `/proc`, `/sys`, `/dev`, `/boot`, `/run` and
`/workspace` are refused: the first six belong to the guest's boot, and
`/workspace` is heyvm's data disk. At most 8 per deployment — heyvmd letters them
`/dev/vdb`, `/dev/vdc`, … and the ceiling is really the alphabet.

**Everything else works like the other two pulls.** Both transports (`art serve`
URL vs local store root), digest verification on the way in, tags resolving at
pull time while digests pin forever, `strip_components` for a bundle rolled with a
wrapper directory, and the same refusal to unpack symlinks, hardlinks, devices or
anything that escapes the destination.

**Trees are shared and reclaimed.** The directory name is the digest (plus
`-s<n>` when `strip_components` is set, because the strip changes the tree's
shape), so ten deployments mounting one corpus hold one copy of it. A tree no
registered spec names is reclaimed by a sweep every six hours, once it is older
than `APP_LB_MOUNT_TTL_SECS` — a day by default, against a week for
[VM disks](#disk-management), because a mount tree is re-fetchable from the store
it came from and a VM disk is not. Removing one costs running VMs nothing: they
already hold their own copies, and only the next create has to fetch again. The
age is measured from when the tree was unpacked, so what the window really
guarantees is that a tree a pull has just landed is never swept before the spec
that names it is written; an older tree becomes eligible as soon as nothing
names it. Set `0` to reclaim by hand instead.

### A workspace that outlives the VM

`vm.disk_size_gb` gives each replica a `/workspace` disk, and `idle_action:
retain` keeps it across scale-to-zero — but the disk belongs to the *sandbox*.
A rollout, a `serverctl restart`, a rebuild that recycles the pool, an edit to
the template: each boots a new sandbox with an empty `/workspace`, and the old
one's contents sit on the host until the disk sweep removes them. For an agent
harness whose sessions, cloned repositories and generated files all live there,
that is the state of the deployment, and it has to belong to the deployment.

`vm.workspace` does that:

```json
"vm": {
  "driver": "firecracker",
  "image": "fastcar",
  "port": 3000,
  "disk_size_gb": 40,
  "workspace": {
    "store": "https://art.example.com",
    "auth": { "secret": "art", "key": "api_key" }
  }
},
"scaling": { "min_replicas": 1, "max_replicas": 1, "idle_action": "retain" }
```

| Field | |
| --- | --- |
| `path` | Guest path. Defaults to `/workspace`, which is also the only path heyvmd sizes from `disk_size_gb` — elsewhere the image is 1.5× its content with a 2 GiB floor. |
| `store` | Where snapshots go: `s3://bucket[/prefix]` (via the `aws` CLI and its own credentials; `APP_LB_DISK_ARCHIVE_ENDPOINT` applies), an `http(s)://` `art serve`, or the absolute path of a local store. |
| `ref` | The tag the newest snapshot is published under in an artifact store. Defaults to `workspace-<deployment id>`. S3 keys by deployment id instead: `<prefix>/<id>/<digest>.tar.gz` plus a `latest` pointer. |
| `auth` | A secret reference for the artifact store, like `artifact.auth`. |
| `snapshot_interval_secs` | Recycle the replica for a snapshot at least this often (minimum `300`). Unset, a snapshot is taken only when the replica retires for another reason. See **Scheduled snapshots** below. |

What happens:

- **Seed.** When the autoscaler creates the replica it hands heyvmd the
  workspace's current tree on this host as a writable mount at `path`; the
  daemon builds the VM its own ext4 image from it (`mke2fs -d`) and mounts it
  before `start_command` runs. With no tree on this host yet, the newest
  snapshot is restored from the store first; with none there either, the
  workspace starts empty. An unreachable store is **not** "empty" — the pool
  waits and says why, because booting empty and then pushing would overwrite
  the real snapshot.
- **Capture.** When the replica retires for any reason — drained by a rollout,
  evicted, torn down by an edit or `delete`, suspended by `idle_action:
  retain` — app-lb runs `sync` in the guest, stops the VM, asks the daemon
  for the mount's contents (`GET /sandboxes/:id/mounts/export`: the daemon
  replays the image's journal with `e2fsck -p`, extracts it with `debugfs
  rdump` and streams a tarball), and points the deployment at the new tree. **The replacement is not created until that has
  landed.** That is the guarantee, and it is also the cost: a rollout of a
  workspace deployment has a gap of drain + capture + boot, which for a few
  gigabytes of repositories is a minute or two.
- **Push.** Each capture is bundled (`tar.gz`, named by its sha256) and sent
  to the store under `ref`, so the workspace survives the host too. A push
  that fails is retried on a backoff and never blocks the rollout — the tree
  the next VM needs is already here. A push is refused, loudly, if the store's
  tag has moved to a snapshot this host never saw (the deployment running
  somewhere else); nothing is overwritten.

`describe` shows where it stands:

```
Workspace
  /workspace          https://art.example.com (idle)
    Snapshot          9f2c1e7a4b30 — 4,812 files, 1.3 GB, captured from applb-fastcar-17 at 2026-08-22 10:14:02 UTC
    In store          9f2c1e7a4b30 at 2026-08-22 10:15:40 UTC
```

and `GET /deployments/:id` carries the same as `workspace`, including a
`blocked` line whenever the pool is at zero because of it (`workspace
capturing`, `workspace restore pending: …`).

To force a snapshot of a running replica, recycle it: `heyctl restart <id>`
drains it, the capture runs, and the autoscaler boots its replacement from the
result.

**Scheduled snapshots.** Without `snapshot_interval_secs`, a replica that runs
for days holds days of work that exist nowhere else: if its sandbox is lost
rather than retired — a host failure, or a sandbox destroyed out of band — the
workspace comes back from the last capture. With it set, the autoscaler does
what `heyctl restart` does whenever the replica's uptime reaches the interval:
drain, capture, then resume the same VM (`idle_action: retain`) or boot a new one
from the result. The clock is the replica's uptime, not the snapshot's age, so a
replica just booted from an old snapshot is not recycled straight away. Each
snapshot is an outage of drain + capture + resume — seconds to minutes, growing
with the workspace — so pick an interval that bounds the loss you can accept
(`21600`, six hours, is a reasonable start). The daemon can only export a
stopped VM's image, which is why this is a recycle and not a live copy.

Rules and caveats, each of which the spec validation enforces or the docs
above imply:

- `scaling.max_replicas` must be at most `1` and `warm_pool` must be `0`: one
  directory, one writer. Two replicas would each capture a divergent copy and
  the last to land would win.
- For a maintenance pause, set both `min_replicas` and `max_replicas` to `0`
  with `idle_action: retain` through the scaling API. This drains and stops the
  replica for workspace capture; incoming requests cannot wake it. Keep the
  deployment registered. Restore a ceiling of `1` to permit resume. A successful
  scaling response records the policy, not proof of a stopped executor: verify
  the exact runtime has stopped and workspace capture has settled before recovery.
- `driver` must be `firecracker`. The KVM driver syncs a writable mount back
  into the shared host tree itself when the VM stops, which is a different
  feature with different semantics.
- A mount may not sit on, inside, or around the workspace path.
- **Ownership is flattened.** app-lb extracts and rebuilds the tree as its own
  user, so inside the guest every file comes back owned by that uid. A
  workload that runs as root does not notice; one that checks ownership does —
  `git` refuses a repository owned by another user unless
  `safe.directory` says otherwise, and Postgres refuses a data directory that
  is not its own. Modes, symlinks and mtimes survive. Keep a database in the
  workspace only with that in mind; pointing `DATABASE_URL` at a server
  outside the VM is the better shape anyway.
- A capture is taken only from a VM seeded from the **current** snapshot. A
  replica of an older lineage — an orphan adopted late, a resume of a VM from
  before a rollout — is left stopped for a person rather than allowed to
  overwrite the newer state; `describe` names it and `/disks` lists its
  image. Purge it there once you have looked.
- The host keeps the current snapshot and the one before it under
  `APP_LB_WORKSPACES_DIR` (default `/var/lib/app-lb/workspaces/<id>/`), plus
  any bundle not yet pushed. app-lb's own directory: a replica is seeded from
  it by uploading the snapshot tree to the daemon (`PUT /trees/ws-<digest>`,
  once per snapshot) and naming it in the create body, and a capture comes
  back as the daemon's export stream. `e2fsprogs` is the daemon's business.
  `APP_LB_WORKSPACE_TIMEOUT_SECS` (default 3600) bounds one capture, push or
  restore.
- Deregistering the deployment captures and pushes its final state and leaves
  the host directory in place; registering it again restores from it.

## Updating a static deployment

A static deployment's backend is a process on some host — usually *this* host,
under supervisord or systemd. There is no image to build, so its update path is
the thing a person would otherwise ssh in and do: a working directory, and
commands to run in it.

```jsonc
{
  "id": "app-obs",
  "routes": [{"host": "obs.example.com"}],
  "upstreams": ["127.0.0.1:9600"],
  "health": {"path": "/healthz", "timeout_secs": 2},
  "update": {
    "working_dir": "/home/sarocu/Projects/app-obs",
    "commands": [
      "git pull --ff-only",
      "cargo build --release",
      "supervisorctl restart app-obs"
    ],
    "verify_timeout_secs": 60,   // 0 disables the post-update health check
    "timeout_secs": 1800,        // per command
    "env": {"CARGO_TERM_COLOR": "never"},
    "env_from": [{"secret": "obs", "key": "ingest_token", "as": "APP_OBS_INGEST_TOKEN"}],
    "auth": {"secret": "github", "key": "token"}   // for a private `git pull`
  }
}
```

```sh
curl -XPOST localhost:9090/deployments/app-obs/update   # 202 + a job record
curl localhost:9090/jobs/job-2c9d7d7d          # commands_run, verified, log tail
```

Same shape as a build: `202` immediately, one job per deployment at a time, and
the outcome polled from `GET /jobs/:id`. Each command is run through `sh -c`
(`APP_LB_UPDATE_SHELL`) with `working_dir` as its CWD, in order, and the first
non-zero exit stops the job — `commands_run` says how far it got.

**Nothing in the spec changes.** The upstreams are the same addresses; what moved
is the code answering on them. That is exactly why the job then **re-probes those
addresses** with the deployment's own health check, until they all answer or
`verify_timeout_secs` runs out. A job whose commands exited 0 but whose service
never came back is reported as *failed*, and says so:

```
every command succeeded, but 1 of 1 upstream(s) did not answer within 60s
(127.0.0.1:9600). The host has already been changed — check the service and its logs
```

The probe is a fresh one, not the autoscaler's cached `healthy` flag: a flag set
two seconds ago describes the process that was just replaced.

**The commands run as app-lb's user**, in app-lb's environment. Two things follow:

- The working directory has to be readable and writable by that user. app-lb never
  creates it — a typo that silently created an empty directory and ran `git pull`
  in it would be worse than an error.
- Restarting a service usually needs a little more. `supervisorctl` needs access
  to supervisord's socket (add the app-lb user to the socket's `chown` group in
  `supervisord.conf`); `systemctl restart` needs a polkit rule or a specific
  `sudo -n` entry. Grant exactly the one verb, not general sudo — the admin API
  is what triggers this.

`env_from` pulls values from the [secret store](#secrets) rather than putting them
in the spec, and `auth` supplies a git credential the same way a build does. A
managed (`vm`) deployment cannot declare `update`: its backends are microVMs, and
a directory on this host would update nothing.

### Durable autoscaler allocations

`vm.correlated_creates: true` opts managed VM autoscaling into the authenticated
heyvmd `/sandbox-creations/:operation_id` protocol. It defaults to false, is not
supported for LXC, and requires a daemon that supports durable creation receipts
plus app-lb's internal daemon credential. This is not a Cloud legacy-create
compatibility fallback.

Before dispatch, app-lb persists the operation identity, endpoint and request
digests. It persists the matching receipt before publishing pending capacity.
After a lost response or restart it only GETs that saved operation: it never
re-POSTs, follows redirects, substitutes a name match or times out into another
allocation. Unknown outcomes block ordinary deployment mutations and cleanup;
receipt-backed pending allocations remain reserved until the exact runtime is
observed running. Resolved request bodies and secrets are not written to the
allocation journal. Deployment deletion cannot discard correlated receipts.

This option covers **autoscaler creates only**, not rollout candidate creation.
It does not repair historical allocation completeness or prove that old queued
work at other ingresses has finished. Retirement still requires complete
allocation history, matching receipts, runtime observation and its other
existing reconciliation gates. Do not run older app-lb binaries against this
state directory: they do not honor these allocation reservations.

### Seeding `/workspace` from an archive

A pool of any size can start every replica from the same snapshot with
`vm.workspace_archive` — a gzipped tarball in the Heyo runtime object store,
named by the archive id cloud handed out when it was uploaded (the dashboard's
deployment form, or `POST /sandbox-archives/presign` → `PUT` → `finalize`) or
captured from a sandbox:

```json
"vm": {"driver": "firecracker", "port": 8080, "workspace_archive": {"archive_id": "ar-1a2b3c4d"}}
```

Cloud's namespace door checks the caller owns the archive and fills in the
object key (`s3_key`), and app-lb turns the create into the daemon's
from-archive create (`s3_archive_key`, unpacked at `/workspace`). A spec that
reaches app-lb with the id alone is refused — it will not guess at a key.
Nothing is captured back; that is what `vm.workspace` above is for, and the two
are mutually exclusive. Uploads through the cloud API are capped at 100 MiB.

### Secrets

A private repo needs a credential, and a deployment spec is the wrong place for
one — the admin API echoes specs back verbatim and the state file holds them in
the clear. So credentials are their own object, stored apart from deployments,
and a spec refers to one by name:

```sh
# Store one. Values go in and are never readable back out.
curl -XPOST localhost:9090/secrets -H 'content-type: application/json' \
  -d '{"id": "github", "description": "CI PAT for acme/*", "data": {"token": "ghp_…"}}'

curl localhost:9090/secrets          # ids, key *names*, and when each changed
curl localhost:9090/secrets/github   # the same, for one secret
curl localhost:9090/ingress          # {"ipv4": [...], "ipv6": [...]} — what to put in the A/AAAA record

# Rotate one key without resending the others (`null` removes a key).
curl -XPATCH localhost:9090/secrets/github -H 'content-type: application/json' \
  -d '{"data": {"token": "ghp_new…"}}'

curl -XDELETE localhost:9090/secrets/github   # 409 while a deployment still refers to it
```

There is deliberately no endpoint that returns a value. Nothing app-lb does
needs one: the builder resolves `build.auth` in-process, and a read-back would
turn the admin API into a credential store with a `GET`.

**Secrets are walled by namespace**, exactly as deployments are. A secret
carries a `namespace` (`default` when unset, and then omitted on the wire), the
same name may exist in two namespaces, and every reference in a deployment spec
— `build.auth`, `artifact.auth`, a mount's or workspace's `auth`, a gate's
`client_secret` or `jwt.secret`, and `env_from` — is bound to the deployment's
own namespace when the spec is registered, whatever the body said. A
namespace-confined credential (see *Federated auth and namespaces*) lists,
creates and changes only the secrets of the namespaces it reaches, at the tier
it holds there; a `view` grant reads key names, an `admin` grant rotates them.

```sh
# Store one in a namespace, then address it there. `?namespace=` is how the
# per-id routes say which wall they mean; the list narrows to the caller's
# reach when it is omitted.
curl -XPOST localhost:9090/secrets -H 'content-type: application/json' \
  -d '{"id": "db", "namespace": "team-a", "data": {"url": "postgres://…"}}'
curl 'localhost:9090/secrets?namespace=team-a'
curl -XPATCH 'localhost:9090/secrets/db?namespace=team-a' -H 'content-type: application/json' \
  -d '{"data": {"url": "postgres://rotated…"}}'
curl -XDELETE 'localhost:9090/secrets/db?namespace=team-a'
```

**Secrets reach a VM through `vm.env_from`**, never through `env_vars`:

```json
"vm": {
  "driver": "firecracker", "port": 8080,
  "env_vars": {"NODE_ENV": "production"},
  "env_from": [{"secret": "db", "key": "url", "as": "DATABASE_URL"}]
}
```

Each entry is resolved when a replica is created, so rotating the secret
reaches the next replica without re-registering the deployment; a missing one
fails the create (counted and fed like a missing mount) rather than booting a
guest without its token. `as` defaults to the key upper-cased, and a secret wins
over a literal of the same name.

The token reaches git through `GIT_ASKPASS` and the child's environment, never
through the URL or the command line — a credential in a remote URL lands in
`.git/config` and in every `ps` on the box. `build.auth` only applies to HTTP(S)
remotes; an `ssh://` or `git@` remote authenticates with the host's own key
material and should leave it unset.

**At rest**, secrets live in `APP_LB_SECRETS_PATH` (default
`app-lb-secrets.json`) with mode `0600`. Set `APP_LB_SECRET_KEY` and the file is
sealed with AES-256-GCM instead — ids, key names and values all — so a copied
backup of the state directory is not a copied credential:

```sh
APP_LB_SECRET_KEY=$(openssl rand -hex 32) ./target/release/app-lb
```

A 64-character hex value is used as the key directly; anything else is hashed to
32 bytes, so a passphrase works too. Setting the key on an existing plaintext
file adopts it and encrypts on the next write. Starting **without** the key that
sealed a file is a hard startup failure rather than an empty store — coming up
empty would let the next write destroy secrets that are perfectly good and merely
unreadable.

> A build runs `git` and `docker` on the app-lb host, and an update runs whatever
> the deployment's `commands` say, so an ungated admin API is a remote code
> execution surface. It binds loopback by default; set `APP_LB_ADMIN_AUTH=1`
> (with `APP_LB_DASHBOARD_PASSWORD`) before exposing it. app-lb warns at startup
> when it is open.

## Routing

A deployment's `routes` is an array of **rules**. The rules are the only knob
that decides which requests reach a deployment — matching is identical for
managed and static/`proxy_pass` deployments (the kind only changes what a matched
request is forwarded *to*). A request is routed to a deployment when **any** one
of its rules matches (rules are OR'd); within a single rule, **every** field the
rule sets must match (fields are AND'd).

A rule may set any combination of three fields:

| Field | Matches | Notes |
| --- | --- | --- |
| `host` | exact hostname | case-insensitive, port stripped |
| `host_suffix` | a domain and its subdomains | anchored at a label boundary |
| `path_prefix` | a leading path segment, e.g. `/api` | prefix, not exact |
| `strip_prefix` | `true` or `false` | removes this rule's path prefix before proxying; defaults to `false` |

- **`host`** — exact hostname match, e.g. `{"host": "demo.local"}` matches only
  `demo.local` (any port).
- **`host_suffix`** — **subdomain / wildcard** match. `{"host_suffix":
  "apps.example.com"}` matches the apex `apps.example.com` **and** any subdomain
  (`a.apps.example.com`, `x.y.apps.example.com`), anchored at a label boundary so
  `notapps.example.com` does **not** match. A leading dot is accepted and ignored.
- **`path_prefix`** — the request path *starts with* this string, e.g.
  `{"path_prefix": "/api"}` matches `/api`, `/api/v1`, and also `/apidocs` (it is
  a raw string prefix, not a path-segment match). The upstream sees the full
  original path by default. Set `"strip_prefix": true` when the upstream serves
  that route at `/`; `/api/x?full=1` is then forwarded as `/x?full=1`.

Fields combine within a rule. `{"host": "demo.local", "path_prefix": "/api"}`
matches only requests that are *both* for `demo.local` *and* under `/api`. Use
several rules in the array to express alternatives:

```jsonc
"routes": [
  { "host": "demo.local" },                          // exact host …
  { "host_suffix": "apps.example.com" },             // … OR any *.apps.example.com …
  { "host": "demo.local", "path_prefix": "/admin" }  // … OR /admin on that host
]
```

### Precedence — most specific wins

When more than one deployment's rules could match a request, the **single
most-specific rule across all deployments** decides — not registration order. The
tiers don't overlap:

1. an exact **`host`** rule beats
2. any **`host_suffix`** rule, which beats
3. any bare **`path_prefix`** rule.

Within a tier, a **longer** suffix or a **longer** prefix wins (e.g.
`host_suffix: "eu.apps.example.com"` outranks `host_suffix: "apps.example.com"`;
`path_prefix: "/api/v2"` outranks `/api`). A rule that sets both a host tier and a
path adds the two together, so `{host, path_prefix}` outranks the same host with
no path. Exactly-equal-specificity rules on two deployments are broken by
deployment id (lexicographic) so resolution is deterministic regardless of
registration order. This lets a specific carve-out (`{"host": "x", "path_prefix":
"/legacy"}` → an old backend) sit alongside a catch-all (`{"host": "x"}` → the
new backend) and win for its prefix only.

Host matching (exact or suffix) is case-insensitive, strips the port, and falls
back to HTTP/2's `:authority` when there is no `Host` header. A request that
matches no rule anywhere is a **404**. Every route must set at least one field —
an empty rule `{}` is rejected at registration.

### Deployments with no routes

`"routes": []` is legal for a **managed** deployment and means exactly what it
says: nothing reaches it through the proxy. It is still registered, still
autoscaled, and still reachable by id through the admin API.

That is the normal shape for an agent sandbox. A sandbox is worked on by
`heyctl exec` and `heyctl shell`, not by HTTP, and putting it on a
hostname it doesn't need means putting it on the internet. Exposure becomes an
explicit, reversible step:

```sh
heyctl create deployment sb-7f3a9c --no-route --port 8080 --size medium
heyctl set routes sb-7f3a9c --host sb-7f3a9c.sb.example.com   # expose
heyctl set routes sb-7f3a9c --none                            # withdraw again
```

Withdrawing a route does not disturb the VM — the deployment keeps running and
keeps its shell sessions; it simply stops matching requests.

A **static** (`proxy_pass`) deployment may not do this. The proxy is the only way
in, so an unrouted one would be unreachable by anything, and it is rejected at
registration. A sign-in gate on an unrouted deployment is rejected too: `auth`
runs on a proxied request, and there are none.

### Cloud URLs — a deployment on a machine with no public address

`routes` are this proxy's way in: a hostname the operator points at
`APP_LB_PUBLIC_IPS`. A laptop, an on-prem box or a cloud-lite fleet behind
NAT has nothing to point a hostname at. For those, a managed deployment can
ask the Heyo cloud for a URL instead:

```jsonc
{
  "id": "web",
  "routes": [],                       // or keep your own routes too
  "vm": { "image": "ubuntu-24.04-dev", "port": 8080 },
  "ingress": { "cloud": true, "public": true }
}
```

Registered through the cloud's namespace door (`/namespaces/{ns}/lb/…` — the
way the dashboard, the SDKs and a namespace-scoped `heyctl` reach a managed
app-lb), the answer carries the URL:

```jsonc
{ "spec": { "id": "web", … }, "url": "https://web-k3x9p2.heyo.computer", … }
```

Three parties each hold one end of it, and none of them holds another's:

| | in charge of | what it does |
| --- | --- | --- |
| **app-lb** | the VM | binds every *ready* replica's `vm.port` on the daemon (`POST /sandboxes/{id}/proxy`, tagged `{namespace, id}`) and withdraws the bind the moment the replica starts draining — before it is killed, so the URL never sends a request to a VM on its way out |
| **the daemon** | traffic | carries each bind exactly as it carries a single VM's URL, and reports it to the cloud with the tag attached |
| **the cloud** | routing | owns the deployment's subdomain and, per request, picks one of the current member binds to forward to — so the URL survives autoscaling, a replacement and a pool roll |

Nothing on that URL passes through this proxy: no `routes` match, no `auth`
gate, no block rule and no SIEM record — the request goes cloud → daemon →
VM. `"public": false` puts the cloud's own sign-in in front of it (the
namespace's owning account). Editing `ingress` is not a template change and
never recycles the pool; dropping it withdraws every bind and the URL.

A deployment scaled to zero, or whose replicas are still booting, has no
member behind the URL and the cloud answers 503 (a retrying page, for a
browser) until the first replica is ready. `GET /deployments/{id}` shows each
VM's bind as `vms[].subdomain` while it is in place.

Only a managed (`vm`) deployment can have one — a static deployment's
upstreams and a site's files are on no daemon to bind — and the spec is
rejected otherwise. On a self-hosted app-lb registered directly (not through
the cloud) the binds are still made, but no URL is minted; the daemon must be
registered with the cloud (`heyvmd`) for the binds to reach it.

## Directory

`http://<admin-addr>/` (default `http://127.0.0.1:9090/`) is a landing page: one
card per routable URL, linking to the deployment that serves it. It is the
answer to "what is running on this box, and where do I click", which the
dashboard answers only incidentally.

```
edge-1                                      Dashboard  Metrics  Theme
4 URLs across 3 deployments. 1 with nothing healthy behind it.

┌────────────────────────────┐ ┌────────────────────────────┐
│ api                 static │ │ private     sign-in    vm  │
│ http://api.example.com     │ │ http://private.example.com │
│ ● 2 of 2 upstreams up      │ │ ● 2 VMs ready              │
└────────────────────────────┘ └────────────────────────────┘
```

**Server-rendered**, unlike the dashboard: the page is complete in its first
response, works with JavaScript off, and holds no polling connection open. The
only script on it is the theme toggle. Reload to refresh.

The theme is stored in `localStorage` under one key shared by all four pages, so
a choice survives a reload and follows you between `/`, `/dashboard`, `/siem` and
`/storage` — a theme belongs to the operator, not to the page. It is re-applied
by a small script in `<head>`, before the body exists, so a stored preference
never costs a frame painted in the wrong theme. With storage unavailable (a
private window, or a page opened over `file://`) the toggle still works for the
session and falls back to `prefers-color-scheme`.

A card per *URL* rather than per deployment, because a deployment with three
hostnames genuinely offers three places to go. Links point at the **data plane** —
scheme, port and `path_prefix` included — which the page cannot infer from its
own address, since it is served by the admin listener on a different port. Same
derivation as the dashboard's `urls`.

The dot reports whether following the link right now would reach anything:

| Dot | Means |
| --- | --- |
| green | healthy backends, or a site (files on this host, so nothing to be down) |
| amber | a VM is booting, **or** the deployment is scale-to-zero and idle — the first request starts it |
| red | routable with nothing healthy behind it |

Scale-to-zero idling is deliberately not red. It is the configured state, and
colouring it as a fault sends people debugging a system that is working.

A **sign-in** badge marks a card behind [Google sign-in](#google-sign-in), so
following it may bounce through the provider. Said before the click rather than
after: it is the difference between "slow" and "broken". Set
[`auth.cookie_domain`](#one-sign-in-across-several-deployments) across the fleet
and that bounce happens once for the whole realm instead of once per card.

A deployment whose routes use only `host_suffix` or `path_prefix` names no single
hostname to link to, so it gets no card — and is listed by id underneath, with
that reason. Omitting it silently would make "why isn't mine here?" unanswerable
from the page.

Gated exactly like the dashboard: open by default, behind
`APP_LB_DASHBOARD_PASSWORD` when one is set, since it lists every hostname this
app-lb routes. A deployment-scoped [app-token](#app-tokens) sees only its own.

## Dashboard

Open `http://<admin-addr>/dashboard` (default `http://127.0.0.1:9090/dashboard`)
for a live view of the fleet — or [`/`](#directory) for a static index of what is
running, or [`/siem`](#the-security-console) to work through security findings. The dashboard shows: host and per-VM CPU/memory, per-deployment pool
utilisation and per-VM load, request latency (distribution + p50/p90/p99 and a
client-derived requests/sec), cold-start times, and autoscaling activity. It is
a single self-contained page — no external assets, so it works over an SSH tunnel
to the admin port.

`GET /metrics` returns the same data as JSON (host usage, a global rollup, and a
per-deployment breakdown), suitable for scraping into your own tooling.
Each deployment includes `routed`, which is false for registered agent
sandboxes with no data-plane route; fleet status consumers should not treat an
idle unrouted sandbox as withdrawn serving capacity.

The per-deployment breakdown can be scoped, which matters once the fleet is
large — the unfiltered response carries a row per VM and a full set of histograms
per deployment, and the dashboard polls it every two seconds:

| Parameter | Effect |
| --- | --- |
| `deployment=<id>` | Just this one |
| `prefix=<s>` | Only ids starting with `s` |
| `summary=true` | Drop the per-VM rows; keep pool counts and metrics |
| `limit=`, `offset=` | Page |

`host`, `fleet` and `global` always describe the **whole** LB regardless of these
— a filter narrows the table, not the system. `matched` reports how many
deployments passed the filter before paging, so a client can page without
guessing. The dashboard's deployment table has a matching filter box and pager,
which appear only when there is more than one page.

### Shared control-plane view

`/dashboard` defaults to the fleet overview on every gateway: shared applications
and the same explicitly configured regional observations. It does not poll or show
the entry gateway's local metrics, secrets, tokens, jobs or host inventory.
Each regional card links to that gateway's `/dashboard?view=local`, where existing
local controls remain available and the hostname identifies the selected gateway.
The overview does not sum regional pool counts as unique application capacity.

Configure an already-running gateway with fleet-admin GET and PUT at
`/control-plane/config`; these routes require authentication even when the admin
or dashboard gates are disabled. GET returns `revision`, `config`, and
`externally_managed`. PUT takes `{"expected_revision":0,"config":{"gateways":[],"control_plane":[]}}`,
using the revision from GET and the origin/secret-reference arrays described
below. Empty arrays explicitly disable that view. Secret-reference credentials
must already resolve in the gateway's secret store. Values are never part of this document.
Only unconfined fleet admins may read or replace the bindings; view-only,
deployment-scoped, and namespace-scoped tokens cannot change them.

The complete configuration persists atomically beside `APP_LB_STATE_PATH` with the
extension replaced by `.views.json`, then becomes visible to new requests without
restarting app-lb. Stale revisions return 409; after a lost response, GET the
current revision/config before retrying. Invalid input or unresolved credentials
leave the previous snapshot active. Restart fails on corrupt persisted data
rather than silently starting unconfigured. This is a single-owner local state
file, not replicated application state: install the same bindings on both
gateways and verify each against the shared authority.

Explicit startup files below override the corresponding persisted bindings and
make the configuration API read-only (PUT returns 409). Do not use the one-time
host bootstrap to modify an already-bootstrapped host's service configuration.

**Global applications** reads `GET /services`, which queries Orchestrator's
shared PostgreSQL inventory rather than any gateway's local registry. Configure
`APP_LB_CONTROL_PLANE_FILE` on each regional app-lb with a JSON array using the
same `id`, `region`, `url`, and `auth` fields shown below, but pointing to the
regional **Orchestrator HTTPS origins**. Use the same HeyoSecret-backed
`orchestrator/internal-api-key` service credential at both sources. Never expose
that credential to the browser. These origins must use the same authoritative
database; this setting does not replicate or reconcile separate databases.

Reads try origins in order and fail over on transport errors or HTTP 5xx.
Authentication errors, redirects, and invalid responses stop the read rather than
masking configuration errors. No mutations are replayed. Each page contains at
most 100 services, with `after` / `nextCursor` pagination; each page is a committed
database snapshot, not one snapshot across multiple pages. The dashboard shows
desired regions, recorded revisions/health/drain state, and latest regional
rollout phase. Missing discovery is unknown, not zero healthy capacity.

Both `/services` and `/fleet` require an authenticated fleet-wide view regardless
of whether the local dashboard is public. Database failure stays visible; there
is no fallback to local files or gateway metrics. This provides a common read
surface, not database HA or a global mutation API. Generic DNS failover still
requires surviving auth, secrets, storage, and ingress dependencies.

### Regional gateway view

For gateways sharing Heyo Auth, set `use_caller_auth:true` instead of `auth`:

```json
{"id":"us3-edge","region":"US","url":"https://admin.us3.example.com","use_caller_auth":true}
```

This explicitly trusts that HTTPS origin to receive the authenticated Heyo user's
bearer for read-only metrics requests. The token lives only in the request, never
the saved bindings or observation response. Only already-validated federated
callers are forwarded; local app-tokens and Basic passwords are not. Without a
Heyo session the observation reports sign-in required. The destination independently
checks current permissions. Choose exactly one credential mode per gateway; caller
credentials are forbidden for Orchestrator bindings, which retain their service key.
Install identical gateway bindings on both regions. Regional links may require
sign-in on that origin because session cookies remain host-only.

The dashboard's **Regional gateways** section reads `GET /fleet`. Configure
`APP_LB_FLEET_FILE` with the path to a JSON array of explicitly trusted gateways:

```json
[
  {"id":"us3-edge","region":"US","url":"https://admin.us3.example.com","auth":{"secret":"fleet-observer","key":"token"}},
  {"id":"eu1-edge","region":"eu1","url":"https://admin.eu1.example.com","auth":{"secret":"fleet-observer","key":"token"}}
]
```

Use a fleet-wide **view-only** observer token at each gateway, stored through
the existing secret API. For Heyo-managed installations, provision that observer
role through HeyoSecret-backed service configuration. References resolve in the
`default` namespace unless `auth.namespace` is explicit. A reference with
`auth.username` uses HTTP Basic authentication instead of bearer authentication.
Secret values never appear in the fleet file, browser, or observation response.
The file is read at startup; malformed or duplicate gateway definitions fail
startup rather than silently dropping a region. Only HTTPS origins are accepted.

This route always requires an authenticated fleet-wide view credential, even
with `APP_LB_DASHBOARD_AUTH=0`. Deployment/namespace-scoped callers cannot use it.
The configured gateways are queried concurrently with a five-second timeout,
no redirects, and bounded responses. Failed observations have `metrics: null`
and an explicit error, never zero capacity or retained healthy-looking counts.

These are independent gateway-local observations, **not** an atomic Orchestrator
snapshot, unique fleet capacity, admission membership, or proof of failover.
The same application can appear at several gateways. Local controls remain on
each gateway's linked dashboard; this view does not move lifecycle ownership
from Orchestrator or alter routing/maintenance gates.

### Fleet workloads, server drill-down and network

A control-plane app-lb (for example us2, fronting per-server app-lbs on us2, us4
and us5, each driving its own colocated `heyvmd`) rolls up the same configured
gateways into a global workload view. These are still **observations**: app-lb
does not place, scale or route anything across servers because of them.

The checked-in example is [`.heyo/fleet/fleet.json`](../.heyo/fleet/fleet.json):

```json
[
  {"id":"us2","region":"US2","url":"https://admin.us2.heyo.work/","auth":{"secret":"fleet-observer-us2","key":"token"}},
  {"id":"us4","region":"US4","url":"https://admin.us4.heyo.computer/","auth":{"secret":"fleet-observer-us4","key":"token"}},
  {"id":"us5","region":"US5","url":"https://admin.us5.heyo.computer/","auth":{"secret":"fleet-observer-us5","key":"token"}}
]
```

PUT the array as `config.gateways` at `/control-plane/config` on the
control-plane app-lb — that is what heyo's `scripts/provision-fleet.py` does as
it adds each server, and it keeps the list editable at runtime. (Pointing
`APP_LB_FLEET_FILE` at the file works too, but then the view is managed by the
file and `PUT /control-plane/config` answers 409.) Each gateway's
`fleet-observer-<id>` secret (key `token`, in the `default` namespace unless
`auth.namespace` says otherwise) holds an app-token minted **on that server**:

```sh
heyctl token mint fleet-observer --admin view --all-deployments -q
```

The token must be view tier and cover every deployment (`--all-deployments`, no namespace
wall), so that `covers_fleet()` holds on the target: a deployment- or
namespace-scoped observer sees only part of a server and the rollup would
silently under-count it. View tier is enough; the rollup never mutates. For
Heyo-managed installs, provision the values through HeyoSecret-backed service
configuration, never in the fleet file.

| Route | Who | Returns |
| --- | --- | --- |
| `GET /fleet/deployments[?namespace=]` | fleet view; or a namespace caller naming a namespace it may view | namespace × deployment rows, one cell per server |
| `GET /fleet/gateways/:id/metrics[?namespace=&offset=]` | same as above | one page (50) of one server's deployments with VM rows |
| `GET /fleet/network` | fleet view only | region → server → ingress + deployments + VMs |

`/fleet/deployments` pages through each server's
`/metrics?summary=true&limit=100&offset=…` (at most 20 pages per server; beyond
that the server reports `truncated: true`), concurrently across servers with a
15-second per-server deadline, and answers:

```json
{"configured":true,"fleet_view":true,"namespace":"team-a",
 "gateways":[{"id":"us4","region":"US4","dashboard_url":"https://admin.us4.heyo.computer/dashboard?view=local",
   "observed_at":1790000000,"generated_at":1790000000,"deployments":3,"truncated":false,
   "totals":{"ready":4,"pending":0,"draining":0,"desired":4,"in_flight":2},"error":null}],
 "rows":[{"namespace":"team-a","id":"web","kind":"vm","routed":true,"hosts":["web.example.com"],
   "health":"degraded","totals":{"ready":2,"pending":0,"draining":0,"desired":4,"in_flight":1},
   "cells":[{"gateway":"us4","region":"US4","ready":2,"pending":0,"draining":0,"desired":2,"in_flight":1,"health":"healthy","error":null},
            {"gateway":"us5","region":"US5","ready":null,"pending":null,"draining":null,"desired":null,"in_flight":null,"health":null,"error":"gateway unavailable"}]}],
 "totals":{"ready":4,"pending":0,"draining":0,"desired":4,"in_flight":2}}
```

A server that cannot be read keeps its `error` and contributes an error cell to
every row; it is never shown as zero capacity, and the other servers' rows are
unaffected. `health` is derived from pool gauges only (`healthy`, `degraded`,
`starting`, `draining`, `down`, `idle`), not from a probe. Totals are per-server
sums: each server runs its own VMs, so they are distinct backends.

Every remote document is deserialized into an allowlist: id, namespace, kind,
routed flag, exact routed hostnames, pool gauges, VM id/state/load, request and
latency counters, and ingress IP literals. Specs, env, upstreams, `urls`,
`account_id`, site roots and any field a gateway adds later are dropped. VM guest
addresses are returned only to fleet-wide callers.

A caller without fleet coverage (a namespace token or a confined Heyo grant) may
use `/fleet/deployments` and the gateway drill-down only with `?namespace=` for
a namespace it may view, and only against gateways configured with
`use_caller_auth:true`; its own Heyo identity is forwarded and the destination
checks it again. Service-credential gateways are never queried on its behalf:
they appear with `error: "fleet-wide view required for this gateway"` (403 on
the drill-down). `/fleet/network` and `/fleet` stay fleet-wide only.

On the dashboard, the control-plane view's **Workloads** section renders the
rollup: select a namespace to narrow (kept in the page URL as
`?fleet_namespace=`), a server column or cell to open that server's drill-down
in place. `/network` defaults to the global topology from `/fleet/network`
(polled every five seconds) and falls back to the local view when the fleet
view is not configured or not permitted; `?view=local` forces the local view
and the header links between the two.

After building the debug binary, `node app-lb/testdata/unified_dashboard.cjs`
checks real dashboard rendering with asymmetric observation/inventory fixtures,
default-versus-local polling, explicit drill-downs and unavailable-region display.
It requires Playwright and its Chromium browser; `PLAYWRIGHT_MODULE` may point to
an existing installation. `SCREENSHOT_DIR` optionally saves desktop, mobile, local
and unavailable captures. Rust fleet/authorization tests cover credential selection
and transport; the browser fixtures are not live multi-region acceptance.

### Sandboxes app-lb does not own

The host is one machine, and not everything on it is a pool. Sandboxes created
through `heyvm`, the cloud API or the desktop share its CPU and memory with
every deployment, and until now they were invisible here — app-lb only ever
looked at the VMs it named — so a loaded host next to a half-empty pool table
had no explanation on the page. `GET /metrics` now carries them as
`host_sandboxes`, and the dashboard lists them under **Host sandboxes** below
the deployments: id, name, image, guest IP, the daemon's latest CPU and memory
sample, uptime, the account billed for it, and its state. They are *reported,
not managed* — no drain, no kill, no adoption; a sandbox somebody made by hand
is not app-lb's to reap. The listing comes from the same daemon call the
reconcile tick already makes, so it costs nothing extra, and it is taken even
on a host with no VM deployments at all, which is exactly the host this view
was missing.

Ownership is the name rule (`applb-<deployment>-<nonce>`), so a sandbox is
never both in a pool and in this list. Stopped sandboxes are included — they
still hold a disk — with their state shown. `summary=true` empties the list
like the per-VM rows; it is never paged, a host holds at most a few hundred.

A host sandbox lives in no namespace, so in [managed mode](#managed-mode-federated-auth-and-namespaces)
the wall that scopes deployments has nothing to place it by. What it has is an
*account*: the daemon records which heyo account each sandbox is billed to, and
a namespace caller sees the host sandboxes billed to the accounts behind its
namespaces (through the cloud door, the one namespace the path names). A
deployment- or namespace-scoped app-token sees none. The operator, and any
`fleet:admin` grant, sees the host. [app-obs](../app-obs) reads the same field
and tails the live ones' logs under a reserved `_unmanaged` partition.

The page updates in place rather than redrawing. Deployment cards are keyed by
id and reused across polls, and the distribution bars and utilization gauges are
mutated rather than rebuilt — which is what lets their CSS transitions animate at
all, since a freshly-created element has no previous width to animate from. It
also means a poll no longer destroys text selection, hover, or the VM table's
horizontal scroll position every two seconds. A card whose numbers did not change
does no DOM writes.

Each deployment carries `urls` — its `host` routes as links a browser can
follow, which the dashboard renders next to the deployment name. They are built
server-side because the dashboard is served by the *admin* listener and knows
nothing about the data plane: the scheme follows whether TLS is enabled, a
non-default port is included, and a `path_prefix` is appended (linking the bare
host would 404 against that same deployment). A deployment with no `host` route —
a sandbox, or a `host_suffix`/path-only route — has no `urls`, and the dashboard
shows no link rather than one that goes nowhere.

`tracked_deployments` is a self-check: it counts deployments holding their own
counters, and should track the number registered. A figure that climbs past it
means metrics for deregistered deployments are not being released. (Their totals
are not lost when they are — a deregistered deployment's counters fold into
`global`, so traffic that happened keeps counting.)

Every object type the [CLI](#cli) addresses has a section on the page, so the
dashboard is a complete view of what app-lb holds rather than a metrics screen:

| Section | Shows | Source |
| --- | --- | --- |
| Security | authentication abuse, attack signatures and traffic anomalies, newest first, plus any [block rules](#response-actions) in force — links to the [console](#the-security-console) at `/siem`, where they can be acted on | `GET /security` |
| Deployments | pool gauges, per-VM load, **booting VMs with their age and daemon status** | `GET /metrics` |
| Certificates | issued hostnames, issuer, expiry, renewal state — plus routed hostnames that have *no* certificate yet | `GET /certs` |
| Secrets | ids, descriptions, key *names*, last update, whether the store is sealed | `GET /secrets` |
| Deploy jobs | recent builds and host updates, their result, and a live transcript | `GET /jobs` |

Two polling loops: the metrics view refreshes every 2s, and certificates, secrets,
jobs and security alerts — which change on human timescales — every 10s. The slow loop tightens to
2s while a job is running, since its record is the only progress there is.

The dashboard is also interactive:

- **Scale** (a form over min/max replicas, warm pool, and target concurrency →
  `PATCH .../scaling`) and **Edit** (a JSON editor over the full spec → `PUT`) on
  each deployment card, and **Drain**/**Kill** on each VM row (→
  `DELETE .../vms/:id`). A booting VM can be killed too.
- **Build** / **Update** on deployments that have a `build` or `update` block,
  which start the job and open its log.
- **New secret**, **Rotate** and **Delete** in the Secrets section. Values are
  write-only throughout: the API returns key names only, so a rotation sets new
  values rather than editing readable ones, and a delete that would break a
  deployment's build asks before forcing.
- **Log** on any job — the tail of its output, refreshing while it runs. This is
  the view for a build that is *hanging*: where it stopped is visible without
  waiting for it to fail.

While a form is open the cards stop re-rendering so an in-progress edit isn't
wiped, though the stat tiles keep updating live. These buttons call the admin CRUD
API — set `APP_LB_ADMIN_AUTH` (see below) to require the dashboard credentials for
them.

### Auth

The dashboard is open by default. Set `APP_LB_DASHBOARD_PASSWORD` to put HTTP
Basic Auth in front of both `/dashboard` and its `/metrics` data source (gating
the page alone would be pointless — the JSON carries the same data). The
username defaults to `admin`; override it with `APP_LB_DASHBOARD_USER`. A
browser prompts once and reuses the credentials for the metric polls.

```sh
APP_LB_DASHBOARD_PASSWORD=s3cret ./target/release/app-lb
curl -u admin:s3cret localhost:9090/metrics
```

By default only the dashboard view (`/dashboard` + `/metrics`) is gated;
deployment CRUD stays open. Set `APP_LB_ADMIN_AUTH=1` to extend the same gate to
the CRUD API — register/edit/scale/delete/evict **and** the reads that expose a
spec (env vars can hold secrets like API keys). It reuses the dashboard
credentials, so the dashboard's own write buttons keep working (the browser
replays the cached creds), and `curl` needs `-u`:

```sh
APP_LB_DASHBOARD_PASSWORD=s3cret APP_LB_ADMIN_AUTH=1 ./target/release/app-lb
curl -u admin:s3cret -XDELETE localhost:9090/deployments/demo/vms/sb-abc123
```

`APP_LB_ADMIN_AUTH` requires a password — enabling it without one is a hard
startup error, never a silently-open gate. `/healthz` is always open so probes
keep working.

The inverse split also exists: `APP_LB_DASHBOARD_AUTH=0` leaves the view tier
(`/`, `/dashboard`, `/metrics`, `/security`, …) open **while the password keeps
gating the CRUD API** (with `APP_LB_ADMIN_AUTH=1`) and minting app-tokens. This
is the setting for a dashboard fronted by its own sign-in — see
[Putting the dashboard behind Google](#putting-the-dashboard-behind-google) —
where a Basic prompt after the Google redirect is a second login for the same
door. With nothing in front, turning it off exposes the view tier, `/security`
included, to whoever can reach the admin listener; app-lb warns at startup when
the flag leaves a configured password gating nothing at all. The credentials are compared in constant time, but the admin
listener is plain HTTP — terminate TLS in front of it, or reach it over an SSH
tunnel, if it leaves localhost.

## Disk management

The daemon creates a directory of disk images per sandbox and only removes *some* of it when
the sandbox is deleted. On a host that has been booting VMs for a few months that is tens of
gigabytes nothing will ever reclaim. app-lb inventories it at `GET /disks`, shows it at
`GET /storage`, and reclaims it on a timer.

Where it accumulates:

| Path | What it is | When the daemon removes it |
| --- | --- | --- |
| `<data>/run/<id>/data.ext4` | The Firecracker `/workspace` data disk | On delete, but **only if** the sandbox was created with `disk_size_gb` |
| `<data>/run/<id>/snapshot/` | Memory/state checkpoint | On daemons **before heyvm 0.42.5**: never when there was no data disk — `destroy()` unlinked the directory only inside its `data_disk_path.is_some()` branch, so a sandbox without one left the dir behind for good. Fixed upstream (2026-08-03): the removal is derived from the id now |
| `<data>/kvm/<id>/` | The KVM driver's per-VM `rootfs.ext4` and `mount*.ext4` | On a *clean* delete, which removes the whole state dir. But these are ~1 GiB each, so anything that never got one — a crash, a lost daemon record, a VM nobody ran `heyvm rm` on — is the bulk of what is sitting there |
| `/tmp/{firecracker,kvm}-<id>-*` | The per-boot scratch | On a clean `stop`. A hypervisor that dies leaves it behind |

So the second row was a delete-path bug, fixed in heyvm 0.42.5 — but a fixed
daemon only cleans on delete, so directories leaked before the upgrade are never
revisited, and a host still running an older daemon keeps making more. The rest
is what a host looks like after months of VMs that did not all exit cleanly —
nothing was ever going to come back for it, which is what the sweep below is for.

app-lb never touches those paths itself. The daemon inventories its own directories
(`GET /storage`: every file under `run/<id>` and `kvm/<id>` plus the tmp scratch, with
allocated sizes), removes what it is asked to (`DELETE /storage/sandboxes/:id?parts=all|rootfs`,
refused while the sandbox is live) and streams an archive of a sandbox's state
(`GET /storage/sandboxes/:id/archive`). What app-lb adds is the one thing the daemon cannot
know: which sandboxes a deployment still expects to resume — and the retention policy, the
sweep and the S3 upload that hang off it.

Sizes are **allocated blocks**, not nominal size. A data disk is created sparse at its full
size, so 8 GiB of `data.ext4` is usually a few hundred MiB on the host; the page shows both.

### Alongside `heyvm prune`

`heyvm prune` is the daemon's own cleanup, and the two do not overlap — run both.

| | `heyvm prune` | app-lb |
| --- | --- | --- |
| `/tmp/{firecracker,kvm}-<id>-*` | **yes**, unconditionally | yes, but only for a sandbox that is not running |
| `/tmp/firecracker-configs/` | yes | no |
| `<data>/run/<id>/`, `<data>/kvm/<id>/` | **no** | **yes** — this is where the tens of gigabytes are |
| Base images in `<data>/images/` | with `--images` | no |
| Runs | when you run it | on a timer |

The `/tmp` overlap is the interesting one. `heyvm prune` deletes every matching file with no
liveness check, so running it while a Firecracker VM is up removes the rootfs that VM is
serving from. app-lb refuses to touch scratch belonging to a running sandbox, which is why it
still does that half itself rather than deferring to prune.

Note also that **`heyvm prune --images` can delete an image a deployment still needs.** It
keeps images referenced by a live or persisted *sandbox*, and a deployment scaled to zero has
neither — so its `vm.image` looks unreferenced. The next scale-up then fails to boot. Re-run
[`POST /deployments/:id/pull`](#pulling-images-from-an-artifact-store) or `build` to put it
back, or keep one replica warm on deployments whose images matter.

### Expiry

A disk that no deployment claims and nobody pinned is reclaimed once it has gone untouched for
`APP_LB_DISK_TTL_SECS` — **seven days by default**. This is on out of the box, so the first
thing app-lb logs at startup is how much it is about to delete:

```
WARN disk expiry is ON: up to 105 of 116 sandbox disks on this host are already older
     than the retention window and will be reclaimed by the first sweep, in 3600s.
     Open /storage to review them, mark the ones to keep as retained, or set
     APP_LB_DISK_TTL_SECS=0 to turn expiry off
     disks=116 eligible=105 gib=18
```

The first sweep is a full interval away, not immediate, so that warning arrives with time to
act on it. Four things hold a disk against expiry, at any age:

- **the sandbox is running** — never reclaimed, and `?force=1` does not override it
- **a deployment expects to resume it** — it is in that deployment's suspended list, which is
  what `scaling.idle_action: retain` means
- **marked retained** — an operator pinned it on `/storage` or through `PATCH /disks/:id`
- **the daemon could not be reached** — see below

That last one is the most important line in the feature. A daemon that is restarting answers
neither listing, every disk on the host then looks like residue, and one sweep would delete the
whole fleet's state. So the inventory reports `complete: false`, classifies everything as
`unknown`, and the sweep declines to run at all.

### Purging every orphan at once

Expiry waits out the TTL; orphans need not. `POST /disks/purge-orphans` — the **Purge
orphans** button on `/storage` — reclaims every disk the daemon has no record of, at any
age. The holds above still apply: a claimed or retained orphan is skipped and counted in
the response rather than forced through, and the whole operation declines when the daemon
is unreachable, for the same reason the sweep does.

### Archiving a disk to S3

With `APP_LB_DISK_ARCHIVE_BUCKET` set, a disk can be uploaded before it is reclaimed:

```sh
curl -XPOST localhost:9090/disks/sb-abc123/archive -H 'content-type: application/json' \
  -d '{"purge": true}'
```

The pipeline is `tar --create --sparse --gzip` → `aws s3 cp -`, with app-lb holding the pipe.
Streaming end to end and never one PUT: `aws s3 cp -` does a multipart upload, and `--sparse`
means `tar` skips the holes rather than compressing gigabytes of zeros. A 20 GiB sparse rootfs
becomes an object of tens of megabytes without either process holding it in memory.

app-lb sits in the middle of the pipe rather than letting a shell join the two, because there
is no shell to quote into, the byte counter behind the progress bar has to come from somewhere,
and a `tar` that outlives a failed upload has to be killed rather than left blocked on a pipe.

`purge: true` reclaims the disk **only** if the upload succeeds. The archive returns as soon as
it starts; progress arrives on `GET /disks` next to the inventory, which is what the page polls
anyway. `APP_LB_DISK_ARCHIVE_ON_EXPIRE=1` applies the same thing to the sweep.

The key is `<prefix>/<sandbox-id>/<unix-ts>.tar.gz`, timestamped so re-archiving never
overwrites the copy already in the bucket. Paths inside are relative (`run/<id>`, `kvm/<id>`),
so restoring is `tar -xzf` into a data directory. Credentials come from the `aws` CLI's own
chain — env, `~/.aws/credentials`, or an instance role — exactly as they do for DNS-01.

An archive killed by `APP_LB_DISK_ARCHIVE_TIMEOUT_SECS` abandons its multipart upload. A
lifecycle rule on `AbortIncompleteMultipartUpload` is the usual way to clean those up.

### Purging

`DELETE /disks/:id` asks the daemon to delete the sandbox — so its own cleanup runs and its
record goes away — and then removes whatever it left behind. A daemon that refuses, or that has
already forgotten the sandbox, is not fatal: residue is exactly what the daemon cannot see.

`?force=1` overrides the "a deployment expects to resume it" and "the daemon is unreachable"
guards, and drops the claim so the next scale-up does not spend a resume on a sandbox whose
disks are gone. It does **not** override the running check. Deleting disks out from under a
live hypervisor corrupts the guest rather than freeing anything, and the actual intent — stop
it, then reclaim it — is two clicks away on the dashboard.

Sandbox ids arrive as URL path segments and end up joined to `remove_dir_all`, so they are
validated against `[A-Za-z0-9_-]+` and *refused* rather than sanitized. Every path is then
constructed from the configured roots and that validated id, never taken from the inventory —
so no request, and no stale inventory, can direct a delete outside the two directories app-lb
manages.

**app-lb has to be able to write to the daemon's data directory.** Listing a disk needs only
read and traverse; *deleting* one needs write on the directory holding it. A host where heyvmd
runs as one user and app-lb as another (the supervisord unit runs it as `app-lb`) will happily
show the whole inventory and then be unable to reclaim any of it — the common shape is a data
directory at mode `755`/`775` owned by the daemon's user. Add app-lb's user to that group, or
give it ownership of `run/` and `kvm/`.

A purge that removes **nothing** while at least one path failed is a `500`, not a success with
`0` bytes freed — the disks are still there and still counted, and reporting that as a completed
purge is how a sweep comes to claim a thousand disks reclaimed on a host that never got emptier.
A *partial* failure stays a success: the bytes that went are gone, `removed` and `failed` both
come back on the response, and it logs at `warn` with the paths. A clean purge logs at `info`
with the count it actually removed.

### Reusing VMs instead of recreating them

The other half of the same problem: every new sandbox is a new directory. app-lb already
prefers resuming a suspended VM over booting a fresh one, but a VM it had *lost track of* — an
LB restart, a crash between the stop and the state write — used to be destroyed, and the next
scale-up would mint a new sandbox id while the old one's disks stayed on the host forever.

A `retain` deployment now takes those back instead, up to `max_replicas`; only the surplus is
destroyed. Reclaiming is deliberately limited to `idle_action: retain` — under `destroy` a
stopped sandbox is one this LB already decided it did not want, and taking it back would
quietly convert every deployment to `retain`.

Note what a resume does and does not preserve, because the daemon decides this and not app-lb:
a Firecracker sandbox keeps its `/workspace` data disk and **loses writes to its rootfs**,
because mvm-ctrl recopies the rootfs from the base image on every cold boot. The KVM driver
keeps a persistent per-VM `rootfs.ext4` and does not. Persistent state belongs under
`/workspace` either way.

### The console

`GET /storage` renders the inventory: totals, what is reclaimable right now, and a row per
sandbox with its state, size, age, when it expires or why it will not, and the files behind the
number. The buttons pin, archive and purge. It polls `/disks` every five seconds so an archive
in flight has a live progress bar.

The inventory is view-tier — the same credentials as `/dashboard` and `/metrics` — and every
route that *changes* something is CRUD-tier. Both are fleet-wide: a deployment-scoped app-token
is refused, because a disk inventory spans deployments and includes sandboxes no deployment
owns any more.

`~/.heyo/sandboxes/<id>/` is deliberately **not** touched. It is the daemon's own metadata
store, it is small (single-digit MB across a whole host), and deleting a daemon's persistence
records to reclaim 23 KB is not a trade worth making.

## Plugins

Plugins are optional capabilities compiled into app-lb that you switch on at
runtime from the **Plugins** page (`/plugins`) or with `heyctl plugins`. Each
one's `{enabled, config}` record lives in `app-lb-plugins.d/<id>.json` beside
the state file.

A plugin's routes live under `/api/plugins/<id>/…`. Reads are on the view tier
and actions on the CRUD tier, and every route answers 409 while the plugin is
disabled. If a plugin fails to start, it stays enabled and the failure shows
as `last_error` on its card.

Plugin configs never contain credentials. A config names a secret in app-lb's
secret store (`POST /secrets`) instead, and the plugin reads it at the moment
it uses it, so rotating the secret needs no re-apply.

```sh
heyctl plugins ls
heyctl plugins set pgfc -f pgfc.json --enable
heyctl plugins disable pgfc
```

### pg-fc databases (`pgfc`)

This plugin monitors and configures [pg-fc](../pg-fc) pools through their
JSON admin API. It shows:

- host health and schema counts by tier
- every schema, with start/stop/reboot/restore/reap actions
- dedicated databases: create one (the password is shown once, as a
  connection string) or revoke one
- the pooler's runtime settings
- maintenance passes, recent events and log tails

app-lb holds the pg-fc dashboard credential and calls pg-fc on the page's
behalf, so the browser never sees it. A 401 from pg-fc becomes a 502 naming
the misconfigured node, rather than looking like your session failed.

Store the password, then configure one entry per pooler:

```sh
heyctl create secret pg-fc --from-stdin password < pg-fc-password.txt
```

```json
{
  "nodes": [
    {
      "name": "local",
      "url": "http://127.0.0.1:34199",
      "user": "admin",
      "password": {"secret": "pg-fc", "key": "password"},
      "pg_host": "db.example.com"
    }
  ],
  "poll_secs": 15
}
```

- `url` is `PG_VM_POOL_DASHBOARD_LISTEN`.
- `pg_host` and `pg_port` (default 6432) only feed the connection strings
  the page shows; `pg_host` defaults to the host in `url`.
- A schema's Postgres log is read by running a command inside its VM, so that
  route sits on the CRUD tier with the actions.

### vapi inference (`vapi`)

This plugin watches and drives [vapi](https://github.com/Heyo-Computer/vapi)
gateways — the LLM inference server — through their OpenAI-compatible API and
their dashboard JSON. It shows:

- the model each gateway is serving, its uptime, queue depth and response-cache
  hit rate
- every registered worker: running and waiting requests against its concurrency
  limit, KV-cache utilisation, prefix-cache hit rate
- the gateway's admission settings (max queued requests, first-token and
  stream-idle timeouts, the response cache), changeable from the page
- a prompt box that runs a completion through app-lb

app-lb holds the vapi API key and calls the gateway on the page's behalf, so
the browser never sees it. A 401 from vapi becomes a 502 naming the
misconfigured gateway, rather than looking like your session failed.

The tier split is the point. Reading a gateway's stats is view-tier; running a
completion is CRUD-tier, because it occupies a worker, evicts other callers'
KV blocks and costs time on a GPU that has one of everything. Changing
admission settings is CRUD-tier too. One vapi key cannot make that distinction;
app-lb's two tiers can.

Store a key, then configure one entry per gateway:

```sh
heyctl create secret vapi --from-stdin api_key < vapi-key.txt
```

```json
{
  "gateways": [
    {
      "name": "local",
      "url": "http://127.0.0.1:8080",
      "api_key": {"secret": "vapi", "key": "api_key"}
    }
  ],
  "poll_secs": 15
}
```

- `url` is vapi's `gateway.bind`. `api_key` is one of its `[[auth.keys]]`, and
  can be omitted entirely when the gateway has none configured.
- Which key it is matters beyond access: vapi gives each key its own
  prefix-cache namespace, so calls made through this plugin share a cache with
  each other and with nobody else.
- The plugin's poller reads `/health` (open even with keys configured) and
  `/dashboard/stats` (not). A gateway that answers the first and refuses the
  second is reported as **up with an error**, so a wrong key sends you here
  rather than to the gateway.

This is a control plane, not a data plane. The proxy buffers whole responses
and refuses `"stream": true`; application traffic to a gateway belongs in a
static (`upstreams`) deployment, which streams, load-balances and health-checks
it like any other backend. Audio transcription (`/v1/audio/transcriptions`) is
not proxied either — a multipart upload of tens of megabytes is data-plane
work.

## Clients

| | |
|---|---|
| [`heyctl`](heyctl/README.md) | Rust — a client library *and* the kubectl-shaped CLI. `cargo install heyctl` for the CLI, `default-features = false` for the library. |
| [`heyctl` (npm)](sdk/typescript/README.md) | TypeScript — Node, Bun, Deno and browsers. |

Both speak the same wire contract, and both are checked against it: the fixtures
in `testdata/wire/` are written by app-lb's own response types, and each client
has a test asserting it understands every field in them. A field app-lb starts
sending fails a test in each client rather than going silently unread.

```rust
let lb = heyctl::Client::builder("127.0.0.1:9090").token(token).build()?;
let out = lb.exec("sb-7f3a9c", &ExecRequest::new("uname -a")).await?;
```

```ts
const lb = new Heyctl({ server: "127.0.0.1:9090", token });
const { stdout } = await lb.exec("sb-7f3a9c", "uname -a");
```

## App-tokens

Basic auth is one shared credential that cannot be scoped, cannot be revoked
without a restart, and cannot ride on a WebSocket upgrade from a browser. That is
fine for a person at a terminal and wrong for a program. An **app-token** is a
credential app-lb mints for itself: scoped, revocable, optionally expiring, and
accepted both by the admin API and by a deployment's own gate.

Tokens are how SDK clients authenticate. Basic auth stays, because you need some
credential to mint the first token.

```sh
curl -u admin:s3cret -XPOST localhost:9090/tokens -H 'content-type: application/json' \
  -d '{"name":"agent-runner","admin":"admin","deployments":["sb-7f3a9c"]}'
```

```json
{
  "id": "7f3a9c2b1e4d",
  "name": "agent-runner",
  "admin": "admin",
  "deployments": ["sb-7f3a9c"],
  "created_at": 1722400000,
  "token": "applb_7f3a9c2b1e4d_kJ8vQ2mN…"
}
```

**`token` is shown once.** Only `sha256(secret)` is stored, so there is no
endpoint that reads it back and no way to recover it — losing one means minting a
replacement and revoking the old one. Present it as a header:

```sh
curl -H "Authorization: Bearer applb_7f3a9c2b1e4d_kJ8vQ2mN…" localhost:9090/deployments/sb-7f3a9c
```

### Scope

Two axes, deliberately coarse.

| `admin` | What it reaches on the admin API |
|---|---|
| `none` | nothing — a credential for a deployment's gate and nothing else |
| `view` | `/metrics` and `/dashboard` |
| `admin` | everything, within `deployments` |

`deployments` is a list of ids, or `["*"]` for all of them. It governs both the
per-deployment admin routes (`exec`, `shell`, scale, evict, delete) and the
data-plane gate.

A token scoped to specific deployments is **refused the fleet-wide routes** —
creating deployments, listing them all, reading the secret store, and minting
tokens. That last one matters: minting is how you escalate, so a narrow token
cannot mint itself a wider one.

`/metrics` is the exception. Rather than refusing a scoped token it *narrows the
answer* — a token minted to drive one sandbox can watch that sandbox, and the
fleet rollup counts only what it can see.

Both scope fields default to nothing, so a forgotten field produces a token that
can do nothing rather than one that can do everything.

### Revoking and expiring

```sh
curl -u admin:s3cret localhost:9090/tokens                      # list; never shows a secret
curl -u admin:s3cret -XDELETE localhost:9090/tokens/7f3a9c2b1e4d
curl -u admin:s3cret -XPATCH localhost:9090/tokens/7f3a9c2b1e4d \
  -H 'content-type: application/json' -d '{"deployments":["sb-other"]}'
```

Revocation takes effect on the next request — verification is a lookup in the
store, not a signature check, which is exactly why tokens are opaque and stored
rather than self-describing and signed. `PATCH` re-scopes a token *without*
changing its secret, so narrowing a credential does not require redistributing
it. Pass `expires_in_secs` at mint for one that retires itself.

`last_used_at` is written when the store is next persisted for another reason
rather than on every request — a token on a hot path would otherwise turn each
call into a file write. So it lags, and a busy token can still read as unused.

Tokens live in `app-lb-tokens.json` (`APP_LB_TOKENS_PATH`), mode `0600`. Only
hashes are in it, so unlike the secret store there is nothing to encrypt.

### Gating a deployment with app-tokens

`auth.provider` takes one provider or several, and any one of them admits a
request — they are alternatives, not requirements:

```json
{
  "auth": {
    "provider": ["google", "app-token"],
    "client_id": "…apps.googleusercontent.com",
    "client_secret": { "secret": "google-oauth" },
    "allowed_domains": ["example.com"]
  }
}
```

That is the common shape for a sandbox hosting a UI: a person signs in with
Google, the agent driving it presents `Authorization: Bearer applb_…`, and
neither has to know the other exists. A token gets in when its `deployments`
scope names the deployment.

For a deployment only programs reach, `"provider": "app-token"` needs no OAuth
configuration at all — no `client_id`, no allow-list, since neither describes a
credential issued to a process. A browser landing on such a deployment gets a
`401` naming what would work rather than a redirect into a sign-in flow that does
not exist. Writing `client_id` on a gate that does not list `google` is a
validation error rather than a field quietly ignored.

A token admitted at the data plane forwards **no** `x-auth-request-*` identity
headers: a token is not a person, and putting a name upstream that belongs to
nobody would be worse than sending none.

### Gating a deployment with a JWT

The third provider, and the only one where app-lb holds no state at all. A
`google` gate issues a session; an `app-token` gate looks a credential up in its
own table; a `jwt` gate verifies a token **somebody else issued** and keeps
nothing. That makes it the right fit for an application whose users already sign
in elsewhere — and app-lb never becomes a second place identity lives.

```jsonc
{
  "auth": {
    "provider": "jwt",
    "jwt": {
      "secret":        {"secret": "heyo-auth", "key": "jwt_secret"},
      "algorithms":    ["HS256"],
      "issuer":        "auth-service",
      "audience":      "heyo-app",
      "subject_claim": "userId",
      "require":       {"role": ["user", "admin"]}
    }
  }
}
```

That block is the [Heyo auth API](https://github.com/Heyo-Computer) exactly: it
signs HS256 with `JWT_SECRET`, issues `auth-service` for `heyo-app`, and puts the
user id in `userId` rather than `sub`. Nothing about the gate is shaped around
it, though — the same block with `jwks_url`, `RS256` and the default `sub` fronts
an Auth0, Okta, Cognito or Keycloak deployment:

```jsonc
"jwt": {
  "jwks_url":   "https://example.auth0.com/.well-known/jwks.json",
  "algorithms": ["RS256"],
  "issuer":     "https://example.auth0.com/",
  "audience":   "https://api.example.com",
  "require":    {"permissions": "deploy:write"}
}
```

**`algorithms` is required and has no default.** This is the one field worth
understanding rather than copying. A JWT names its own algorithm in its header,
and the header is part of the token — which is to say, attacker-controlled. A
verifier that dispatches on it accepts two forged tokens: one with `alg: none`
and no signature at all, and one signed `HS256` using the gate's *public* key as
the HMAC secret, which anybody can compute because the key is public. app-lb
therefore lets the spec decide and never the token, and refuses at registration a
block that names an algorithm its key could not verify — a public key alongside
`HS256` is that attack written down as configuration.

**Where the key comes from** — exactly one of three, and the choice is about
rotation rather than security:

| Field | For | Notes |
| --- | --- | --- |
| `secret` | `HS256/384/512` | A secret-store reference. The same value *mints* tokens, so it is never a literal in a spec. Rotating it in the store takes effect on the next request. |
| `public_key` | `RS*`, `PS*`, `ES*` | An inline PEM (or a certificate). Public, so it is in the spec rather than the secret store — putting it there would imply it needs protecting. |
| `jwks_url` | `RS*`, `PS*`, `ES*` | The issuer's key set. Cached for ten minutes and refetched when a token names a `kid` it does not hold, so a rotation needs nothing done here. **`https://` unless it is loopback** — see below. |

A JWKS URL is held to a stricter transport rule than anything else app-lb
fetches, and the asymmetry is deliberate. A blob from an artifact store is
verified against a digest the spec names, so a tampered response is caught; a key
set *is* what everything else is checked against, so anyone who can rewrite that
response can mint tokens this gate accepts. Plaintext to another host is
therefore refused at registration — that is an authentication bypass, not an
eavesdropping risk. `http://127.0.0.1:8080/jwks` is allowed, for the same reason
OAuth carves out loopback redirect URIs: there is no path to be on.

**`require` is the allow-list**, and `allowed_domains`/`allowed_emails` are not:
those match a *Google* identity — the domain against the `hd` claim, for the
reasons in [Google sign-in](#google-sign-in) — and mean nothing for a token from
your own issuer. A gate that accepts `jwt` without `google` is **refused** if it
sets them, rather than looking guarded and letting everyone through.

`require` is more general anyway. A value or a list per claim, OR within a claim
and AND across them, and a claim that is itself a list is satisfied by containing
one of the wanted values — which is what makes every scope claim work:

```jsonc
"require": {
  "role":   ["admin", "owner"],   // role is one of these…
  "tier":   2,                    // …and tier is exactly 2 (a number, not "2")
  "scopes": "deploy"              // …and the scopes array contains "deploy"
}
```

An empty `require` admits any token the issuer signed for this audience. Unlike
Google's empty allow-list — where the population is everyone with a Google
account — that is precisely "a signed-in user of this product", and often the
whole intent.

**What is always checked**, before `require` is looked at: the algorithm is one
the gate named, the signature verifies, `exp` has not passed (and `nbf` has
arrived), `iss` matches exactly, and `aud` matches when the gate names one. A
token with **no `exp` is refused** — a credential that never expires is one this
gate could not revoke if it leaked, since it did not issue it. `leeway_secs`
covers clock skew, capped at 300.

**The identity goes upstream** as `x-auth-request-user`, `-email` and `-name`,
read from `subject_claim`, `email_claim` and `name_claim` — which is why those
are configurable, since `userId` and `sub` are both common. The subject is the
one claim a gate cannot do without, and a token missing it is refused rather than
arriving upstream as an anonymous user. Claims beyond those three are not
forwarded, deliberately: the token itself is still in the `Authorization` header,
so an application that wants more can read it, signed, from the request it
already has.

**A cookie, for browsers.** A page navigation cannot set a header, so a gate can
name a cookie to read the token from:

```jsonc
"jwt": { "…": "…", "cookie": "heyo_access_token" }
```

The `Authorization` header still wins when both are present — a request that sets
it is stating what it presents.

**Browser sign-in with existing Heyo Auth.** Add `login_endpoint` to the JWT
block to show an email/password form to unauthenticated browser navigations:

```jsonc
"jwt": {
  "secret": {"secret": "heyo-auth", "key": "jwt_secret"},
  "algorithms": ["HS256"],
  "issuer": "auth-service",
  "audience": "heyo-app",
  "subject_claim": "userId",
  "cookie": "heyo_access_token",
  "login_endpoint": "https://stage.heyo.computer/api/auth/login"
}
```

The gate posts credentials to that fixed endpoint and verifies the returned
JWT against the same issuer, audience, signature and `require` policy before
setting a host-only Secure/HttpOnly cookie. The form requires HTTPS, same-origin
POST and signed, short-lived login state. Passwords and refresh tokens are not
persisted; endpoint redirects are refused. Logout clears the access cookie.
Opening another sign-in page reuses the browser's unexpired CSRF nonce rather
than invalidating an open form. Each form retains its own local return path.
Machine clients still receive 401 and continue using their existing credentials.
An Auth service requiring CAPTCHA or another interactive challenge cannot use
this password form; those requirements are not bypassed. This is not Google SSO
or cross-domain session sharing. Existing bearer-only gates are unchanged unless
this field is configured. Deploy the updated app-lb binary before configuring it.

**Mixing providers** works as it does everywhere else. `["google", "jwt"]` is the
common shape for a product UI: a person opens it in a browser and signs in with
Google; the UI's own API calls carry the token the auth service gave it. Both are
alternatives, and neither knows about the other.

A refused token is logged and sent to [security monitoring](#security-monitoring)
as `gate-jwt` with the reason — expired, wrong issuer, bad signature. The caller
gets a bare `401`: which of those it was is exactly the feedback somebody probing
a gate is looking for.

### Declaring an identity once: auth providers

Written inline, a gate's identity is copied into every spec that needs it, so
rotating a client secret or tightening an allow-list means editing each one. An
**auth provider** is that identity half on its own, named and owned by a
namespace:

```sh
heyctl create auth-provider heyo -n team-a --preset heyo-jwks
heyctl set auth reports --provider-ref heyo --public-path /healthz
```

The deployment keeps only its route-scoped fields; `provider_ref` supplies the
rest. Resolution is live — app-lb reads the provider on every gated request — so
an edit reaches every deployment that names it at once, and re-signs the sessions
issued under the old policy rather than leaving a removed user signed in. A
reference that does not resolve **fails closed**: the request is refused, never
served ungated.

That provider holds nothing secret — it verifies the Heyo auth API's gate tokens
against the key set that service publishes — so it is safe to declare in a
namespace somebody else administers, which a shared-secret provider is not
(`--preset heyo` is the `HS256` form, and that key mints as well as verifies).

Neither preset is a coupling to one issuer: `--issuer` with `--jwks-url`,
`--public-key-file` or `--secret` describes any issuer at all, and `--login-url`
+ `--cookie` point a token-less browser at that issuer's own sign-in page. Full treatment, including the sign-in page contract
and what a customer running their own issuer needs:
**[AUTH_PROVIDERS.md](AUTH_PROVIDERS.md)**.

### Tokens in a URL

The shell WebSocket — and only the shell WebSocket — also accepts
`?app_token=…`. This exists for exactly one reason: a browser's `WebSocket`
constructor cannot set headers, so a query parameter is the only credential it
can carry. That is what makes a browser terminal possible at all.

Every other route can send a header, so every other route refuses a token in the
query string. A credential in a URL lands in access logs, proxy logs and browser
history, so mint short-lived tokens for this:

```sh
curl -u admin:s3cret -XPOST localhost:9090/tokens -H 'content-type: application/json' \
  -d '{"name":"terminal","admin":"admin","deployments":["sb-7f3a9c"],"expires_in_secs":120}'
```

### Putting the dashboard behind Google

Tempting, and it works for the *page* — but only if you also say which paths the
machines may take, because [a gate admits browsers and nothing
else](#limits).

The recipe is a static deployment fronting the admin listener
([`examples/app-lb-admin.json`](examples/app-lb-admin.json)) carrying an `auth`
block. Measured against exactly that, through the gated hostname:

```
                                          browser      fetch()/curl/heyctl
GET /dashboard   (Accept: text/html)       302 → Google
GET /metrics     (accept: application/json)                          401
GET /deployments (no Accept)                                         401
```

So a gate alone gives you a dashboard that loads, signs you in, and then shows
nothing — its `/metrics` poll is refused — while `heyctl` is locked out
entirely, since it cannot complete an OAuth flow and the `login_url` in the 401
body means nothing to it.

Both are fixed the same way: let the machine paths past the gate, and put a
credential the machine *can* present behind them.

```jsonc
// on the deployment fronting the admin listener
"public_paths": ["/healthz", "/metrics", "/deployments", "/secrets", "/jobs", "/certs"]
```

> **Scopes changed this recipe.** A bare `public_paths` string now means scope
> `admin`, and a listed path accepts only an app-token of that tier — not Basic
> auth and not the Google session. The machine credential for these paths is an
> admin-tier `applb_…` token (`heyctl token mint NAME --admin admin --all-deployments`), and `/healthz` needs an
> explicit `{"path": "/healthz", "scope": "public"}`. See
> [`docs/app-lb-auth.md`](../docs/app-lb-auth.md#public-paths-and-scopes).

```sh
# and on app-lb itself, so those paths are not simply open
APP_LB_DASHBOARD_PASSWORD=s3cret APP_LB_ADMIN_AUTH=1 APP_LB_DASHBOARD_AUTH=0
```

`/` and `/dashboard` stay behind Google; everything a machine calls passes the
gate and meets Basic auth instead. `APP_LB_DASHBOARD_AUTH=0` is what stops the
*second* sign-in: without it the page and its `/metrics` poll still answer 401
after the Google redirect, so every session starts with Google **and** a Basic
prompt for the same door. Google is the humans' credential here; Basic is the
machines'. **Set `APP_LB_ADMIN_AUTH=1` first and restart,
then add `public_paths`** — the other order leaves a window where a full CRUD
API, `/secrets` included, is on the internet with nothing in front of it. And
only turn `APP_LB_DASHBOARD_AUTH` off *after* the Google-fronted deployment is
live: the flag opens the view tier to whatever can reach the admin listener.

If you would rather not make that trade, don't: leave the hostname
browser-only and reach the API over an SSH tunnel
(`ssh -L 9090:127.0.0.1:9090 host`), which is what
[`heyctl`](heyctl/README.md#connecting) expects.

Two data sources feed it:

- **What the LB observes directly** — request latency and status from the proxy
  path; cold-start duration and scale up/down/reap from the reconcile loop;
  in-flight concurrency, pool occupancy, and serving uptime per VM. These
  counters are cumulative since process start; rates (requests/sec, VMs
  created/reaped per second) are derived by the dashboard by diffing polls.
- **What the daemon reports** — the autoscaler reads `GET /system/usage` once
  per reconcile tick (a daemon-side cached sample, so it's a cache read rather
  than a per-VM probe) for host CPU/memory and per-VM CPU% (percent of a core)
  and RSS. Only backends with a local host process are covered, which for
  app-lb's Firecracker/KVM-on-local-daemon constraint is all of them. Per-VM
  disk and network throughput are **not** exposed by the daemon and so are
  absent here.

### TLS

The proxy serves plaintext HTTP on `proxy_addr` by default. The HTTPS listener
binds `APP_LB_PROXY_TLS_ADDR` (default `0.0.0.0:6189`) *in addition to* it —
both run at once — and turns on when either ACME is enabled or a static
`APP_LB_TLS_CERT`/`APP_LB_TLS_KEY` pair is set. Setting only one of cert/key is a
hard startup error rather than a silent plaintext fallback. Upstreams stay
plaintext regardless — the guest IP is on a host-local tap network — so this is
TLS *termination* at the edge.

Certificates are chosen **per handshake from the client's SNI**, not fixed at
startup: the acceptor holds no certificate of its own and asks the cert store for
one on every connection. That is what lets a certificate issued seconds ago serve
without a restart. It also means the TLS stack is openssl rather than rustls —
pingora only supports handshake callbacks under openssl/boringssl — so the build
needs `libssl-dev` and links openssl alongside the rustls that heyo-sdk pulls in
through reqwest.

```sh
APP_LB_TLS_CERT=cert.pem APP_LB_TLS_KEY=key.pem ./target/release/app-lb
curl -k https://localhost:6189/ -H 'Host: demo.local'
```

#### Automatic certificates (Let's Encrypt)

Set `APP_LB_ACME_EMAIL` and app-lb obtains a certificate for every deployment
hostname itself, renewing 30 days before expiry:

```sh
APP_LB_PROXY_ADDR=0.0.0.0:80 \
APP_LB_PROXY_TLS_ADDR=0.0.0.0:443 \
APP_LB_ACME_EMAIL=ops@example.com \
./target/release/app-lb
```

Register a deployment with an exact `host` route pointing at a real DNS name and
the certificate arrives within seconds — no restart, no reload:

```sh
curl -XPOST localhost:9090/deployments -H 'content-type: application/json' \
  -d '{"id":"demo","routes":[{"host":"demo.example.com"}],"upstreams":["127.0.0.1:8080"]}'
curl -s localhost:9090/certs | jq   # hostname, expiry, issuer
```

Certificates and the ACME account key are cached under `APP_LB_ACME_DIR` and
reloaded on boot, so a restart involves no CA traffic at all.

Four things to know before enabling it:

- **Port 80 is required.** Let's Encrypt fetches HTTP-01 challenges on port 80
  and nowhere else, so `APP_LB_PROXY_ADDR` must be `0.0.0.0:80` (app-lb answers
  `/.well-known/acme-challenge/` itself, ahead of routing). app-lb logs a warning
  at startup if ACME is on and the proxy is bound elsewhere. Binding 80 and 443
  as the non-root `app-lb` user needs the bind capability:
  `setcap 'cap_net_bind_service=+ep' /usr/local/bin/app-lb`.
- **Exact `host` routes are covered per host; subtrees need a wildcard.** A
  `host_suffix` rule matches a whole subtree, and a certificate for a subtree is
  a wildcard — see [Wildcard certificates](#wildcard-certificates-for-a-fleet)
  below. A suffix no configured wildcard covers is served the static fallback
  certificate, and the gap is logged once per suffix.
- **Test against staging first.** Set
  `APP_LB_ACME_DIRECTORY=https://acme-staging-v02.api.letsencrypt.org/directory`.
  Production rate limits are per-account per-week; a misconfigured hostname in a
  retry loop can lock out issuance for every other hostname for hours. app-lb
  backs off exponentially per host (1 min doubling to 6 h) and **persists that
  backoff across restarts**, so a supervisor restart loop can't reset it and
  hammer the CA — but staging is still the right place to find out DNS is wrong.

  Switching between staging and production needs no manual cleanup: app-lb
  records which directory the cached state belongs to and discards the account
  and every certificate when it changes, logging why. That matters because
  neither would otherwise correct itself — a saved account reconnects to the
  directory baked into *its own* credentials regardless of this variable, and a
  staging certificate stays valid for months so it never comes up for renewal.
  The result would be untrusted certificates served indefinitely with nothing in
  the log. (State written by a version predating this check is left alone, since
  an upgrade isn't a change; the first run after upgrading records the current
  directory and acts on changes from then on.)
- **`APP_LB_TLS_CERT` becomes the fallback.** It is served for any SNI without an
  issued certificate of its own — a `host_suffix` deployment, or a hostname whose
  first issuance hasn't finished. With no fallback configured, such a handshake
  fails cleanly rather than presenting a certificate for the wrong name.

The `APP_LB_ACME_DIR` holds private keys and the account key; it should be mode
`0700` and owned by the user app-lb runs as. app-lb writes the files it creates
`0600`.

#### Wildcard certificates for a fleet

Per-host issuance stops working at scale, and not gradually: **Let's Encrypt
allows 50 new certificates per registered domain per week.** A fleet of agent
sandboxes on `<id>.sb.example.com` exhausts that on the first afternoon and then
locks out every other hostname on the account for the rest of the week.

One wildcard covers all of them:

```sh
APP_LB_ACME_EMAIL=ops@example.com \
APP_LB_ACME_WILDCARD=sb.example.com \
APP_LB_ROUTE53_ZONE_ID=Z0123456789ABCDEFGHIJ \
./target/release/app-lb
```

That issues **one** certificate covering `sb.example.com` and
`*.sb.example.com`, and it is renewed like any other. Exposing a sandbox is then
free of certificate work entirely — add the route and it is already covered:

```sh
heyctl set routes sb-7f3a9c --host sb-7f3a9c.sb.example.com
```

Pair it with a single wildcard `A` record (`*.sb.example.com → <lb-ip>`) and
exposing a sandbox needs **no DNS write either** — no per-sandbox Route 53 call,
which also keeps you clear of that zone's RRset limit and the 5-requests-per-
second change quota.

What to know:

- **Hosts under a configured wildcard are skipped by the per-host issuer.** That
  suppression is the point; without it the fleet queues an order per sandbox.
- **A wildcard covers exactly one label.** `*.sb.example.com` serves
  `a.sb.example.com` but not `a.b.sb.example.com`. Keep sandbox hostnames to a
  single label under the domain — a deeper one falls through to per-host
  issuance, which works but does not scale.
- **DNS-01 needs the `aws` CLI on the app-lb host** (`APP_LB_AWS_BIN`), the same
  way image builds need `heyvm` and pulls need `art`. It brings its own
  credentials — profile, instance role, `AWS_*` — which is the part worth not
  reimplementing. The IAM policy needs `route53:ChangeResourceRecordSets` and
  `route53:TestDNSAnswer` on the zone.
- **app-lb waits for the record to be answerable before telling the CA to look.**
  Route 53 reporting `INSYNC` is not the same as its nameservers answering, and
  the CA gets one attempt: a failed validation backs off *every* hostname on the
  account for hours. app-lb polls `test-dns-answer` — which asks the zone's own
  nameservers, exactly who the CA will ask — for up to 3 minutes, and refuses to
  proceed rather than spend an attempt on a record that is not there yet.
- **Serving is driven by the certificate, not the configuration.** A subdomain
  with no certificate of its own is served its parent's *only if that
  certificate actually carries a `*.` SAN*. A plain certificate for a parent
  domain is never served for a subdomain, which would be a name mismatch at the
  client.
- **Both names come from one order.** `sb.example.com` and `*.sb.example.com`
  are authorized at the same record, `_acme-challenge.sb.example.com`, so both
  digests are published as two values of one TXT RRset. Publishing them
  separately would have the second overwrite the first.

This HTTPS listener terminates TLS for **proxied deployment traffic** only. The
admin API and dashboard bind a *separate* plaintext listener (`APP_LB_ADMIN_ADDR`)
with no TLS of its own — to serve the dashboard over HTTPS at a DNS name, either
terminate TLS in a reverse proxy (nginx / Caddy) in front of `127.0.0.1:9090`, or
front it through this same proxy with a static/`proxy_pass` deployment: see
[`examples/app-lb-admin.json`](examples/app-lb-admin.json) and
[`examples/README.md`](examples/README.md). To bind the HTTPS listener on `443`
under the non-root `app-lb` user, grant the bind capability:
`setcap 'cap_net_bind_service=+ep' /usr/local/bin/app-lb`.

With ACME enabled that example gets simpler: give the admin deployment an exact
`host` route and its certificate is issued automatically like any other.

### Scaling

Desired replicas is `ceil(demand / target_concurrency) + warm_pool`, clamped to
`[min_replicas, max_replicas]`, where demand counts in-flight requests *plus* requests
waiting on a cold start.

Scale-to-zero applies only when both `min_replicas` and `warm_pool` are 0. A request arriving
at an empty pool is held (up to `cold_start_timeout_secs`) while a VM boots, rather than
failing — in practice a Firecracker VM is serving in ~1–2s. Scaling down marks a VM draining
so it finishes in-flight work, then retires it once idle or at `drain_timeout_secs`.

#### `idle_action` — destroy or retain

What "retire" means is a per-deployment choice, because a *sandbox* is not a
replica. Retiring one of four interchangeable web VMs should reclaim everything
it held. Retiring the single VM that is somebody's working directory should not.

| | `destroy` (default) | `retain` |
| --- | --- | --- |
| The VM is | killed | stopped |
| Sandbox record | gone | kept |
| `/workspace` data disk | **gone** | **kept** |
| Rootfs writes | gone | gone |
| Memory | gone | gone |
| Next scale-up | boots a fresh VM | resumes this one |

**Read the rootfs row again.** On Firecracker, `retain` does not preserve the
root filesystem, and app-lb cannot make it: mvm-ctrl gives each VM a private
rootfs copy under `/tmp`, removes it on `stop`, and **recopies it from the base
image on every cold boot**. The only thing that survives a stop is the
persistent data disk at `~/.heyo/run/<id>/data.ext4`, attached as `/dev/vdb` and
mounted at `/workspace` — and that disk only exists if `vm.disk_size_gb` is set.

(The KVM driver would behave differently — it keeps a per-VM
`~/.heyo/kvm/<id>/rootfs.ext4` across stop/start and reuses it if present — but
the autoscaler discards that copy right after suspending a replica, so both
drivers honour the same contract and a scaled-to-zero pool is not parking ~1 GiB
per idle VM. The daemon rebuilds the copy from the base image on resume. Making
Firecracker *preserve* a rootfs instead would be a daemon change, not one app-lb
can make — every boot goes through mvm-ctrl's `start_vm`.)

So a `retain` deployment is only meaningfully stateful when both hold:

```jsonc
"vm":      { "disk_size_gb": 20 },      // there is a /workspace to keep
"scaling": { "idle_action": "retain" }  // and it isn't thrown away when idle
```

with the sandbox's real state living under `/workspace`. Setting `retain` without
a data disk is allowed — it still saves a boot — but app-lb logs a warning at
registration saying it keeps nothing, because that combination is almost always
a mistake rather than a choice.

**Suspended VMs are tracked by app-lb, because nothing else can.** mvm-ctrl drops
a stopped sandbox from `GET /sandboxes`, so it is invisible to the fleet list the
autoscaler reconciles against, and its TTL does not run while it is stopped. Its
id is therefore written into the deployment's state file the moment it is
stopped. Deregistering a deployment destroys its suspended VMs, and a slow sweep
(every 5 minutes) reconciles any stopped VM of ours that no deployment claims —
the residue of a crash between stopping a VM and recording that we did.

**That sweep reclaims before it destroys.** A `retain` deployment that finds one
of its own stopped sandboxes unclaimed has, by definition, lost track of a VM it
asked to keep, and destroying it means the next scale-up creates a new sandbox
— new id, new directory under the daemon's data dir, fresh rootfs — while the
old one's disks stay on the host forever. So it is taken back into the
deployment's suspended list, up to `max_replicas`, and only the surplus is
destroyed. A `destroy` deployment's stopped VMs are still destroyed: that one
was already decided. Whatever *does* get destroyed leaves disks behind, which is
what [disk management](#disk-management) is for.

A scale-up prefers resuming a suspended VM over creating one, and not only to
save time: creating a fresh VM while one sits stopped would strand that VM's
`/workspace` and hand the caller an empty sandbox in its place.

#### When a boot never finishes

A VM is only added to the pool once the daemon reports it `Running`, it has a
`guest_ip`, *and* it answers its health check. The failure mode worth knowing about
is the third one: a VM whose guest boots but whose *server* doesn't — a wrong
`start_command`, an env var pointing at a directory that isn't there, a binary that
exits — looks perfectly healthy to the daemon and fails the probe forever.

Two things bound and expose that:

- **Progress logging.** Every still-booting VM is logged with its sandbox id, its
  age, the daemon's status, and what it is waiting on — on first sighting, on every
  status change, and every 30s thereafter. The `waiting_on` field is the diagnosis:
  *"the daemon has not reported it Running yet"* means wait, while *"the guest is up
  but has not answered GET /healthz"* means go and look at the guest. Once a boot
  outlasts `cold_start_timeout_secs` — the point at which it has already cost a
  request a 503 — the line becomes a `WARN`.
- **`boot_timeout_secs`** (default `300`). Past this the autoscaler logs an `ERROR`,
  kills the VM and creates a replacement, so a deployment retries visibly instead
  of sitting at zero replicas forever. It is deliberately much larger than
  `cold_start_timeout_secs`: a request gives up long before the VM does, because a
  boot that overran one caller's patience may still be the boot that serves the
  next one. Set it to `0` to wait indefinitely.
- **Failed boots back off.** Consecutive boot failures — timeouts and terminal
  statuses alike — delay the replacement, doubling from 30s to a 1h ceiling and
  resetting the moment any VM boots to healthy. Without this the reconcile loop
  replaced a doomed VM on its next 2-second tick forever, so a guest that could
  never become ready churned a fresh sandbox (and its disk directories) per
  cycle with no error state anywhere. The embargo is logged once when it is set
  (`backing off VM creation after failed boots`), and suppressed ticks log at
  `DEBUG`.

The count of abandoned boots is in `/metrics`
(`autoscale.boot_timeouts`) and on the dashboard's cold-start card, and booting VMs
appear as rows in each deployment's VM table with their age and status — so a stall
is visible without reading logs at all.

`ttl_seconds` is a backstop: VMs expire on their own if app-lb dies without reaping them. It
is renewed while app-lb is alive, and VMs from a previous run are re-adopted on startup
(matched by their `applb-<deployment>-<nonce>` name). VMs app-lb did not create are never
touched.

A VM whose name points at a deployment this LB's state does **not** hold is stopped, never
destroyed: its disk stays, `/disks` lists it, and the disk sweep reclaims it after
`APP_LB_DISK_TTL_SECS` like any other unclaimed disk. An LB with *no* deployments at all
touches nothing, because empty state is indistinguishable from the wrong state file. Both
rules exist because "ours but unknown" can also mean "another app-lb's": on 2026-09-29 a
second instance started by `app-lb --version` (arguments were ignored then) destroyed every
sandbox the live one served, workspaces uncaptured.

Only one app-lb runs per host. Startup takes `/run/app-lb/instance.lock` (the temp directory
when `/run` is not writable) and a second instance refuses to start, naming the holder.
`APP_LB_INSTANCE_LOCK` points it elsewhere — only for instances that talk to *different*
heyvm daemons — or `off`. `app-lb --version` and `--help` print and exit; any other argument
is refused without starting anything.

Booting a VM takes long enough that an admin request can delete or rebuild the deployment
while a create is still in flight. The autoscaler therefore re-checks, after every create and
promotion, that the deployment it is working on is still the registry's — and kills any VM the
replacement did not inherit, rather than leaving it running until its TTL. A pool-preserving
edit (one that doesn't change the `vm` block) carries its VMs over and keeps them.

## Managed mode: federated auth and namespaces

Everything above assumes the operator of app-lb is the operator of what runs
on it. A *managed* fleet is different: the machine belongs to a platform, and
the deployments belong to its customers, who never see the Basic credential and
should never be handed a fleet-wide token. What they have is the credential the
Heyo auth service already gave them — a JWT, or a `heyo_api_*` key — and what
they should reach is exactly the namespaces their account owns.

**A namespace-scoped key** is the credential to hand a CI job or a teammate's
`heyctl`: a `heyo_api_*` key the Heyo dashboard mints on a namespace's page
(`POST /api/api-keys` with `namespace` and `scope: admin|view`). The auth
service answers `GET /api/auth/scopes` for it with that one namespace at that
tier and never `fleet:admin`, whoever minted it, so app-lb sees a confined
grant; Cloud refuses the key anywhere but that namespace's door. Nothing in
app-lb tells the two apart — a wall is a wall — which is why revoking the key
in the dashboard is the whole revocation, bounded by `APP_LB_AUTH_CACHE_SECS`.

Set `APP_LB_AUTH_URL` (with `APP_LB_ADMIN_AUTH=1`, since only the gate consults
it) and the admin API accepts a third credential:

| Presented as | Resolved by | Reach |
| --- | --- | --- |
| Basic username/password | the startup config | the fleet |
| `Bearer applb_…` | the local token store | whatever the token was minted with |
| `Bearer <anything else>` | `GET {APP_LB_AUTH_URL}/api/auth/scopes` | the namespaces the auth service lists |

That is also the order of precedence: a local token is never sent upstream,
and the auth service is only asked about a bearer the store does not know.

With federation and the admin gate enabled, unauthenticated browser navigation
opens `/login`. Sign in using an existing Heyo email/password; Auth must return
`fleet:admin`. Heyo's platform administrator role is the authority across all
regional gateways, not an email allowlist or separate dashboard user database.
Configure each regional Auth origin against the same authoritative user store.

Browser sessions use a host-only `Secure`, `HttpOnly`, `SameSite=Strict` cookie.
Tokens are not stored in JavaScript/local storage, and passwords are sent only to
the configured HTTPS Auth service (HTTP loopback is supported for a colocated
issuer). Redirects are not followed with credentials. Serve the dashboard through
HTTPS, preserving its public `Host` header. Cookie-authenticated writes and
WebSocket upgrades require an exact same-origin HTTPS `Origin`; explicit Basic
or bearer API credentials retain their existing behavior. The dashboard provides
sign-out. Session expiry requires sign-in again; permission removal takes effect
within the existing bounded `APP_LB_AUTH_CACHE_SECS` cache lifetime.

Regional hostnames have independent browser cookies, but the same Heyo account
and role. A common dashboard hostname avoids separate regional sign-ins. Keep
Basic credentials as emergency operator access; they are not per-user accounts.

### What the auth service says

The scopes endpoint answers with a list of strings, and the grammar is the
whole contract:

| Scope | Meaning |
| --- | --- |
| `namespace:<name>:admin` | admin tier on every deployment in `<name>` — list, register, edit, scale, evict, exec, shell, build, pull |
| `namespace:<name>:view` | view tier only — the directory, `/metrics`, `/security`, list and get |
| `fleet:admin` | unconfined, as the Basic operator is |

A bearer with two namespaces is admin in one and view in the other exactly as
the list says; the tier is checked against the namespace of the deployment a
route names, not against the strongest tier the caller holds anywhere. Anything
else in the list is ignored with a debug log, so the auth service can grow new
scopes without breaking an older app-lb. A namespace that would not validate as
a spec's namespace is dropped rather than admitted.

A federated caller is confined in every way a [namespace token](docs/namespaces.html)
is: `GET /deployments` narrows to its namespaces (and takes `?namespace=` to
narrow further — `/metrics` takes the same filter), `POST /deployments` refuses
a spec naming a namespace it does not reach *and* refuses to re-register an id
that already lives in one, `PUT` refuses to move a deployment out, and the
fleet routes — tokens, secrets, workflows, `/jobs`, disks, block rules — are
closed. `default` is never a customer's: the auth service reserves the name, so
no grant contains it and unnamespaced deployments stay the operator's alone.

Deployment ids stay global. Two customers cannot both register `web`; the second
gets a 403 saying the credential cannot register that deployment, which is the
same message an out-of-namespace attempt gets, so probing does not reveal which.

### Who pays

Beside the scopes, the auth service names the account that owns each namespace:

```json
"namespaces": [{ "name": "team-a", "accountId": "3f7c…", "scope": "admin" }]
```

Every `POST /deployments` and `PUT /deployments/{id}` by a federated caller
stamps that account, and the caller's user id, onto the spec as `account_id`
and `user_id` — overriding whatever the body said, so a customer cannot bill
its namespace to somebody else. Both ride on every VM the autoscaler creates
for the deployment (top-level `account_id` / `user_id` on the daemon's
`POST /sandbox-deploy`), including the replacements it boots with no caller
present, so the sandbox is metered to the namespace's owner rather than to
app-lb's own daemon credential. The daemon honours the fields only from a
trusted caller: on a managed fleet `APP_LB_DAEMON_API_KEY` must be the daemon's
internal key or a platform-admin key, or every create is refused.

An operator, a local token or an ungated caller keeps what the body said —
usually nothing. A self-hosted app-lb therefore stamps nothing and sends
nothing; its specs and create bodies are byte-for-byte what they were. An auth
service that predates `namespaces[]` still works: the caller's own account is
used, with a warning, which is right for a user in one account and wrong for a
user in several.

### Opening the dashboard for one namespace

`/login`'s password form admits platform administrators only. A namespace
owner reaches the dashboard from Heyo instead: the front end asks the auth
service for a token confined to that namespace at the user's own tier
(`POST /api/auth/namespace-token`, one hour, no refresh), and posts it from a
form in a new tab to **`POST /login/handoff`** (`token`, `namespace`,
form-encoded). app-lb resolves the token like any bearer and, if the grant
reaches the namespace, sets it as the session cookie and navigates to
`/dashboard?namespace=<ns>`.

That page pins itself to the namespace: the picker and the fleet-wide sections
(global applications, regional gateways, certificates, namespaces, app-tokens,
deploy jobs) are hidden, and a view-tier grant gets no write controls. When the
token runs out the page says so and links back to `APP_LB_HOME_URL`; there is
no refresh here, by design.

The handoff is the one cookie write that is cross-site on purpose, so it skips
the origin check every other one has. The most a forged post can do is sign the
victim into the forger's own namespace, which the page names.

### Caching, and what it costs

Answers are cached by the SHA-256 of the bearer for `APP_LB_AUTH_CACHE_SECS`,
capped by the token's own `expiresIn`, so a dashboard polling `/metrics` costs
one upstream round trip a minute rather than one a second. Refusals are cached
too, briefly, so a bad token cannot turn app-lb into an amplifier against the
auth service. The price is revocation latency: a scope withdrawn upstream holds
here until the entry expires. The auth service being unreachable is a refusal,
not a pass — the gate fails closed, and the startup log says which URL it will
be asking.

Nothing here reaches the data plane. A deployment's own `auth` gate still takes
the providers it always did; a customer who wants their users signed in with
the same Heyo tokens wants the [`jwt` provider](#gating-a-deployment-with-a-jwt),
which verifies them locally.

## Fleets of sandboxes

app-lb's usual shape is a few dozen deployments, each a pool of interchangeable
VMs behind a hostname. A fleet of **agent sandboxes** inverts nearly all of that:
thousands of deployments, one VM each, mostly unrouted, stateful, and created and
destroyed all day. The pieces that make it work are documented in their own
sections; this is the shape they add up to, and why each is there.

One deployment per sandbox — see [`examples/sandbox.json`](examples/sandbox.json):

```jsonc
{
  "id": "sb-7f3a9c",
  "routes": [],                                  // no ingress; exec/shell only
  "vm": { "driver": "firecracker", "port": 8080,
          "disk_size_gb": 20,                    // /workspace, the part that survives
          "working_directory": "/workspace" },
  "scaling": { "min_replicas": 0, "max_replicas": 1, "target_concurrency": 1,
               "scale_to_zero_after_secs": 900,
               "idle_action": "retain" }         // stop when idle, don't destroy
}
```

```sh
heyctl create deployment sb-7f3a9c --no-route --port 8080 --disk-gb 20 \
  --idle-action retain --max 1 --target-concurrency 1
heyctl exec sb-7f3a9c -- ls /workspace
heyctl shell sb-7f3a9c

heyctl set routes sb-7f3a9c --host sb-7f3a9c.sb.example.com   # expose it
heyctl set routes sb-7f3a9c --none                             # take it back
```

| Need | What does it | Why not the obvious thing |
| --- | --- | --- |
| No public URL | [`"routes": []`](#deployments-with-no-routes) | A sandbox that serves nobody should not be on a hostname |
| Get inside it | [`exec` / `shell`](#running-things-inside-a-vm) | Proxied, so the gate applies and a sleeping sandbox wakes |
| Survive going idle | [`idle_action: retain`](#idle_action--destroy-or-retain) | Default `destroy` kills the disk, which *is* the sandbox |
| Keep state | `disk_size_gb` + `/workspace` | The rootfs is recopied from the image every boot |
| Expose one, sometimes | `set routes --host …` | Reversible, and disturbs neither the VM nor open shells |
| Certificates for all of them | [one wildcard](#wildcard-certificates-for-a-fleet) | Per-host issuance hits Let's Encrypt's 50/domain/week cap |
| DNS for all of them | one wildcard `A` record | Zero Route 53 calls per expose; no RRset or rate-limit ceiling |

### What scaling to thousands actually required

Four things in app-lb were fine for dozens and quadratic, unbounded, or simply
wrong for thousands. They are fixed, and worth knowing about because each has an
observable consequence:

- **State is one file per deployment**
  ([`app-lb-state.d/`](#where-state-lives)). Registering the thousandth sandbox
  used to rewrite the other 999 with it.
- **Routing is indexed by exact host**, not scanned, and the index is updated
  **incrementally**. Thousands of hostnames no longer cost a linear scan per
  request, and registering one deployment rebuilds only the buckets its own
  routes belong to instead of the whole index — which is what stopped the
  marginal cost of a create tracking the size of the fleet.
- **The reconcile loop runs concurrently** and skips deployments at rest without
  touching the daemon, so one slow VM cannot stall the fleet's tick.
- **`/metrics` is scopeable** (`?prefix=`, `?limit=`, `?summary=`) and the
  dashboard pages, because the unfiltered response is megabytes at this size.
  Per-deployment counters are released when a deployment is deregistered, so the
  metrics map no longer grows by one entry per sandbox ever created —
  `tracked_deployments` in the response is the check on that.

Measured on a release build, registering deployments through the admin API:

| | 100 registered | 2000 | 5000 |
| --- | --- | --- | --- |
| Marginal cost of one create | 0.25 ms | 0.30 ms | 0.56 ms |
| Register that many from empty | — | 0.6 s | 2.0 s |
| Route lookup (proxy) | — | 0.3 ms | 0.3 ms |
| Dashboard poll (`?limit=50`) | — | 1.7 ms / 68 KB | — |
| `/metrics` unfiltered, for contrast | — | 14 ms / 2.6 MB | — |

A write is still O(n) in the *shallowest* sense — copy-on-write means the
deployment map and the route index each get a fresh hash table per write, so a
few tens of nanoseconds per existing deployment. What it is no longer doing is
deep-copying every rule in the fleet and re-sorting the whole index, which is
what made a create storm genuinely quadratic. Readers stay lock-free, which is
the constraint that rules out mutating either structure in place.

### One host, and what that bounds

A single app-lb is a single heyvm host: `guest_ip` is only populated for a local
daemon, so every VM it routes to is on this machine's tap network. Thousands of
*deployments* is a registry question and works; thousands of *simultaneously
running* VMs is a host-RAM question and does not. `idle_action: retain` with
`scale_to_zero_after_secs` is what reconciles the two — a fleet of thousands with
tens awake, each waking in a resume rather than a cold boot.

## Shipping logs to app-obs

[app-obs](../app-obs) polls `/metrics` for numbers, but the *logs* it stores have
to be pushed to it. Set `APP_LB_OBS_URL` and app-lb pushes three streams:

```sh
APP_LB_OBS_URL=127.0.0.1:9500 \
APP_LB_OBS_TOKEN="$(cat /etc/app-obs/ingest-token)" \
app-lb
```

A bare `host:port` is fine — the scheme defaults to `http`, which is what
app-obs's ingest speaks. `0.0.0.0` is accepted too and read as this host, since
that is app-obs's *bind* address rather than anywhere you can send to; the
resolved endpoint is in the startup line, so check it there. A URL that cannot be
salvaged (`ftp://`, no host) logs an error at startup and leaves shipping off —
it never stops app-lb from serving, because a typo in the observability
configuration must not be able to take the data plane down.

- **An access log** — one record per request, attributed to the deployment that
  served it. For a static (`proxy_pass`) deployment this is the only log it will
  ever have, because there is no guest to run a shipper inside; for a VM
  deployment it is the only account of what the *proxy* saw, as opposed to what
  the application chose to write about itself.
- **app-lb's own events** at INFO and above — scaling decisions, boots that are
  taking too long, upstreams going unhealthy, ACME issuance, job outcomes. An event
  that names a deployment lands in that deployment's log, so a scale-up appears
  next to the traffic that caused it; everything else lands under
  `APP_LB_OBS_DEPLOYMENT` (`_lb` by default).
- **Deploy-job output** — every line an image build or host update writes,
  attributed to the deployment being deployed and tagged `source=job`. The job
  record served by `GET /jobs/:id` holds only a bounded tail, in memory, until the
  process restarts; this is the copy that survives, and the one to read when a
  build *hangs* rather than fails.

- **Security alerts** — one record per finding from
  [security monitoring](#security-monitoring), tagged `source=security`, with the
  triggering event's ECS fields flattened alongside. This is the durable copy;
  app-lb's own `GET /security` ring is bounded and does not survive a restart.

Records carry a `source` — `access`, `app-lb`, `job` or `security` — so the four
are separable inside one deployment's log.

### Naming the LB itself

app-lb's own records need a deployment id like everything else app-obs stores, and
by default it is the reserved `_lb`. Override it with `APP_LB_OBS_DEPLOYMENT` when
more than one app-lb ships to the same collector: otherwise both hosts' events
interleave under one name, and "which LB logged this?" is only answerable from the
batch-level `host` field.

```sh
APP_LB_OBS_DEPLOYMENT=lb-us2 app-lb
```

It applies to both streams that can lack a deployment of their own — app-lb's
events *and* the access-log records for requests that matched no route — so the
two never diverge. The value becomes a directory name in app-obs, so it is
validated at startup against the same rule app-obs uses (up to 128 characters of
`[A-Za-z0-9._-]`); a value app-obs would reject is refused here instead, because
app-obs answers a bad id by rejecting the whole *batch* it arrived in, taking
every other deployment's records with it. The resolved id is in the startup line:

```
INFO shipping logs to app-obs endpoint=… lb_deployment=lb-us2
```

The token must match app-obs's `APP_OBS_INGEST_TOKEN`. app-obs leaves ingest open
when *it* has none, so the failure worth anticipating is the other direction: an
app-lb with no token against a collector that wants one loses every record to a
401, which shows up as `failed` below rather than as anything app-obs can report.

### What a request record carries

```
GET /things 200 1.4ms
{"method":"GET","path":"/things","status":200,"duration_ms":1.416,
 "bytes":254,"host":"demo.local","client":"10.1.2.3"}
```

`backend` is the sandbox id for a managed VM and the `host:port` for a static
upstream — the same identity the `x-vm-id` response header carries. `status` is
`null` and the level is `error` when no response was written at all: every
upstream failed, or the cold start timed out. A failed request also carries
`error`.

**The query string is never logged**, only the path. A sign-in callback carries
the OAuth `code` there, and a shared log store is the last place a credential
should come to rest. The signed-in user's email is left out for the same reason —
a gated deployment receives the identity headers and can log what it needs of
them itself.

Requests that matched **no** deployment ship too, under `APP_LB_OBS_DEPLOYMENT`
with `"unrouted": true`. A wall of 404s for a hostname somebody expected to work is
invisible in a per-deployment view by construction, and it is one of the more
common things to have to diagnose. The cost is that internet background noise —
scanners probing `/wp-login.php` — accumulates there against app-obs's retention;
`APP_LB_OBS_ACCESS_LOG=0` turns the access log off entirely if that trade isn't
worth it.

### It is not a dependency of the data plane

Recording is a `try_send` into a bounded queue and nothing else: no lock, no
await, no I/O on the request path. Everything past that point is one background
task, and every way it can fail resolves to *losing telemetry*, never to holding
up a request:

- A **full queue drops** and counts what it dropped. A collector that has fallen
  behind must not turn into latency in somebody's application.
- A **failed POST discards its batch** instead of retrying. A retry queue is a
  memory leak with extra steps, and the records worth having are the ones still
  arriving.
- **app-obs being down is invisible to traffic.** It is logged once when shipping
  starts failing and once when it recovers — not once per batch — and the running
  count sits in `GET /metrics`:

```json
"obs": {"queued": 41201, "dropped": 0, "shipped": 41180, "failed": 21, "healthy": true}
```

`dropped` is the figure to watch, because it is the only trace those records
leave anywhere: raise `APP_LB_OBS_QUEUE_CAPACITY` if it climbs. Asking app-obs
instead cannot answer the question — nothing there can tell a quiet deployment
from a full queue.

### What is deliberately not shipped

**Only app-lb's own events.** pingora's, reqwest's and hyper's stay in stdout:
reqwest and hyper log *inside* the POST that ships the batch, so forwarding them
would be a feedback loop, and pingora's per-connection lines are free text with no
deployment to attribute them to. The supervisord log stays the complete record;
app-obs gets the part worth querying.

**DEBUG and below**, even though the default filter (`info,app_lb=debug`) emits
it — DEBUG is where the per-request routing chatter lives, which is a worse copy
of the access log. `RUST_LOG` still bounds what ships, since it decides what
app-lb logs at all.

## Security monitoring

app-lb sits at the edge of every deployment it fronts, so it already sees the
one stream a SIEM wants most: every request, with its source address, host,
path, status and latency. What it had no notion of was *malice*. Three things
follow, and this is what fixes them:

- **Authentication failure was invisible.** The admin gate answered a bad
  credential with a 401 and logged nothing, so a password spray against
  `/dashboard` left no trace anywhere.
- **Scanner traffic was noticed and thrown away.** `/wp-login.php` probes
  accumulate in the unrouted access log; nothing read them.
- **Anomalies were only visible to somebody watching** the right dashboard card
  at the right moment.

A fourth followed once the first three were fixed: **a finding with no answer to
"and now what?" is a notification, not a control.** So detection comes with
[response actions](#response-actions) — block an address, block a pattern of
traffic, take it back off — and a [console](#the-security-console) at `/siem`
where each alert carries its runbook and a rule that is already filled in.

It is **on by default** — unlike log shipping, it needs no external service to
be useful, and a security feature you have to remember to enable protects
nobody. `APP_LB_SIEM=0` turns it off. Enforcement is separate and stays on
regardless: a rule an operator created keeps working whether or not detection is
running.

Events are normalized through [`u-siem`](https://crates.io/crates/u-siem) into
ECS field names (`source.ip`, `url.path`, `http.response.status_code`), so an
alert stored in app-obs is queryable next to anything else ECS-shaped. Only the
crate's event model is used; the detection is app-lb's own, because `SiemRule`
matches one log at a time and two of the three rule families below need a
window.

### What it watches

**Authentication abuse.** Rejected credentials from the admin gate, the
data-plane app-token gate and the Google sign-in flow.

| Rule | Fires when | Severity |
| --- | --- | --- |
| `auth.brute-force` | `APP_LB_SIEM_AUTH_THRESHOLD` failures from one source in a window | high |
| `auth.spray` | the same, spread across four or more deployments | high |
| `auth.enumeration` | the same, against four or more distinct sign-in identities | high |
| `auth.scope-denied` | repeated 403s — a *valid* credential reaching past its scope | medium |
| `auth.signin-state` | a sign-in state/nonce mismatch; CSRF-shaped, so unwindowed | medium |

**Attack signatures**, matched in one pass over the request path and — see
below — the query string.

| Rule | Catches | Severity |
| --- | --- | --- |
| `web.rce` | `${jndi:`, `/bin/sh`, shell chaining | critical |
| `web.traversal` | `../`, `%2e%2e`, encoded variants | high |
| `web.sqli` | `union select`, `' or 1=1`, `sleep(` | high |
| `web.xss` | `<script`, `javascript:`, `onerror=` | medium |
| `web.secret-probe` | `/.env`, `/.git/`, `/wp-login.php`, `/phpmyadmin` | medium |

**Traffic anomalies**, per source address.

| Rule | Fires when | Severity |
| --- | --- | --- |
| `traffic.scanner` | `APP_LB_SIEM_SCAN_THRESHOLD` 4xx responses *across many distinct paths* | medium |
| `traffic.rate-spike` | `APP_LB_SIEM_RATE_THRESHOLD` requests in a window | medium |

The distinctness requirement on `traffic.scanner` is what separates enumeration
from one broken client retrying a single dead URL.

### Reading it

The dashboard grows a **Security** card above the deployment table, and an
**Alerts** tile beside the fleet totals so a critical finding is visible without
scrolling. The card links to the [console](#the-security-console) at `/siem`,
which is where a finding can actually be acted on. `GET /security` is the same data as JSON, behind the same gate as
`/metrics` — it names attacker addresses and the exact probes that reached the
fleet, so it is never open when `/metrics` is not.

```sh
curl -su admin:s3cret localhost:9090/security
curl -su admin:s3cret 'localhost:9090/security?severity=high&limit=20'
```

```json
{"enabled": true, "window_secs": 60,
 "alerts": [{"id": 41, "rule": "traffic.scanner", "severity": "medium",
             "title": "203.0.113.9 is probing for unserved paths",
             "client": "203.0.113.9", "deployment": "demo", "count": 214,
             "ecs": {"source.ip": "203.0.113.9", "url.path": "/wp-login.php",
                     "http.response.status_code": 404}}],
 "totals": {"medium": 11, "high": 3, "critical": 0},
 "stats": {"observed": 918273, "dropped": 0, "raised": 14,
           "suppressed": 4118, "tracked_clients": 118}}
```

Filter with `?severity=`, `?rule=`, `?deployment=` and `?limit=`. A
deployment-scoped [app-token](#app-tokens) gets its own deployments' alerts and
never the ones attributed to the LB itself — the set of addresses attacking the
control plane is fleet information.

**`count` is the occurrence tally, not an alert count.** Repeats with the same
rule, source and deployment fold into the open alert for
`APP_LB_SIEM_SUPPRESS_SECS`, so a scanner making ten thousand requests produces
*one* alert whose count climbs. Without that the ring would hold nothing but
that scanner, and app-obs would store ten thousand records saying the same
thing.

Every new alert also ships to app-obs under `source=security` when
`APP_LB_OBS_URL` is set, with the ECS fields flattened alongside — so the
in-memory ring is the live view and app-obs is the durable one. An alert about
the LB itself lands under `APP_LB_OBS_DEPLOYMENT`, like every other record that
names no deployment.

### The security console

`GET /siem` is the page the Security card links to. The card summarises; the
console is where a finding can be acted on, which is why they are two pages: the
dashboard has to stay glanceable, and this needs the full alert list, the ECS
fields behind each one, and buttons that change what the data plane does.

Each finding carries a **runbook** and, where one exists, a rule that is already
filled in:

```
high   SQL injection attempt in query parameter "id" from 203.0.113.9
       203.0.113.9   demo   /search   ATT&CK T1190   web.sqli

  ▾ Respond
    CHECK FIRST
      · Check the status this got: a 404 means it found nothing, a 200 means it
        did and the block is the second thing to do.
      · The alert names the parameter, never the value — app-lb does not store
        query strings. The upstream's own log is where the payload is.
    ACT
      [ Block 203.0.113.9 for 24 hours ]  Every request from 203.0.113.9 to the
                                          data plane is refused with a 403 for
                                          24 hours, then the rule expires on its
                                          own. The admin API is not affected.
      [ Block 203.0.113.9 on demo only ]  …
```

Each action carries a lifetime picker, pre-set to what the runbook suggested and
offering **Forever** as the last option. The confirmation states which one is
about to apply, and only `forever` gets an extra prompt of its own.

Below the findings, **Rules in force** answers the other question — whether any
of this is working:

```
ENFORCEMENT     ╭──╮                     519
   refused    ──╯  ╰──────                519 requests refused in the last 60 minutes
   exempted   ─────────────

Action  Matches                   Hits   Last 60m      Last     Expires
block   from 203.0.113.9          1,412  ▁▃▅█▅▃▁       30s ago  in 22h    [Change to…] [Set] [Remove]
block   path containing /wp-admin     0  no hits       —        never     [Change to…] [Set] [Remove]
allow   from 10.0.0.0/8              87  ▁█▁▃▁█▃▁      1m ago   never     [Change to…] [Set] [Remove]
```

That middle row is the one to act on: a rule being checked on every request and
refusing nothing. **Set** applies the chosen lifetime to an existing rule and
keeps its hit history, which re-posting the rule would reset.

Those buttons post the exact body shown, so what an operator reads and what the
server applies cannot drift. The advice is derived server-side and served on
`/security`, which means `heyctl`, a script or another client gets the same
answers rather than reimplementing them.

The console is **view tier**, like the dashboard — the browser's existing
credentials work. The buttons post to the **CRUD tier**, so a view-only
[app-token](#app-tokens) can read the console and cannot arm it. The page says so
when that happens instead of failing silently.

### Response actions

Detection is advisory and runs off the request path. Enforcement is
authoritative and runs *on* it. A rule is a conjunction of literal conditions —
all present ones must match, absent ones are not checked:

```sh
# Block one address for an hour.
curl -su admin:s3cret localhost:9090/security/rules -X POST \
  -H 'content-type: application/json' \
  -d '{"action":"block","match":{"client":"203.0.113.9"},"expires_in_secs":3600}'

# Block a probe path across the fleet, for a week.
curl -su admin:s3cret localhost:9090/security/rules -X POST \
  -H 'content-type: application/json' \
  -d '{"action":"block","match":{"path_prefix":"/wp-login.php"},"expires_in_secs":604800}'

# Never block our own monitoring, whatever else gets created later.
curl -su admin:s3cret localhost:9090/security/rules -X POST \
  -H 'content-type: application/json' \
  -d '{"action":"allow","match":{"client":"10.0.0.0/8"},"note":"internal monitoring"}'

curl -su admin:s3cret localhost:9090/security | jq .rules
curl -su admin:s3cret localhost:9090/security/rules/5f295e1a86f2 -X DELETE

# Change when a rule expires. `null` keeps it indefinitely; the hit history
# carries over, unlike re-posting the rule.
curl -su admin:s3cret localhost:9090/security/rules/5f295e1a86f2 -X PATCH \
  -H 'content-type: application/json' -d '{"expires_in_secs":null}'
```

`expires_in_secs` is **required** on that `PATCH` — omitting it is a 400, not
"forever". Making a block permanent by forgetting a field is exactly the
accident the field exists to prevent.

| `match` field | Matches |
| --- | --- |
| `client` | An address or CIDR: `203.0.113.9`, `203.0.113.0/24`, `2001:db8::/32` |
| `host` | The request's hostname, exactly |
| `deployment` | The deployment it routed to |
| `path_prefix` / `path_contains` | The path, literally |
| `method` | `GET`, `POST`, … |
| `user_agent_contains` | A substring of `User-Agent`, case-insensitively |

An `allow` rule beats a `block` rule whichever was created first, so
"block that /16 except our own health checker" needs no reasoning about
precedence during an incident. Rules are content-addressed: re-posting the same
conditions replaces the rule rather than stacking a second copy, which is how a
block about to expire gets extended.

Four things keep this from becoming the outage it was meant to prevent:

* **An empty match is refused.** `{}` is a conjunction of nothing, true of every
  request — one click would take the whole data plane down.
* **The admin API is never guarded.** However badly you block yourself out of
  the data plane, the page that deletes the rule is still reachable. Nothing
  should ever be added that changes this.
* **Rules expire by default.** Every action the console suggests carries a
  lifetime, because the realistic failure is not a missing block, it is a
  permanent one that outlives the attack and quietly breaks a customer months
  later. Client blocks are short — an address is a lease, and behind CGNAT it
  belongs to somebody else by tomorrow — and path blocks are long, because a
  path pattern never changes hands. A rule *can* be kept forever: the picker
  beside each action offers it, and the rules table can change an existing
  rule's lifetime. Both make you confirm, and only for `forever` — that is the
  one choice with no natural end.
* **`APP_LB_GUARD_ENFORCE=0` is a dry run.** Rules match, count hits and log
  `would have refused this request`, and nothing is turned away. That is how a
  broad rule gets deployed sanely: watch what it would have caught for an hour
  first.

Rules are **persisted** to `APP_LB_GUARD_PATH`, unlike alerts. A restart that
silently readmits an attacker somebody blocked during an incident is a worse
failure than losing the finding that prompted it.

#### Are the rules doing anything?

Every rule is scanned on every request that reaches the data plane, so a rule
that stopped matching is pure cost. `GET /security` reports hits per minute over
the last hour — per rule as `hits_recent`, and fleet-wide as `guard
.blocked_recent` / `guard.exempted_recent`, with `hits_bucket_secs` and
`hits_window_secs` saying how to read them. The console charts both: a headline
line of refusals, and a sparkline per rule.

An all-zero series is a **finding, not an absence** — the console says *no hits*
rather than drawing a flat line, because a rule refusing nothing is the one worth
removing. That is also the shape of a rule that never worked: a `client` block
that silently matches nothing on a dual-stack listener looks identical to an
attack that stopped.

Three properties worth knowing:

* **In-memory only.** The series describes this process, so it is absent from
  the persisted rule file and starts empty after a restart. `hits` — cumulative
  since the rule was created — is the number that survives, and the number to
  trust.
* **Approximate at bucket boundaries.** The ring is written from the request
  path under exactly the conditions where a lock is worst: a rule matching every
  request from an address currently flooding the LB. A hit landing while the ring
  rolls is dropped rather than paid for. Use `hits` for anything that has to add
  up.
* **Counted in the dry run too.** `APP_LB_GUARD_ENFORCE=0` charts what *would*
  have been refused, which is the point of the dry run.

**No regular expressions**, deliberately. A rule is written under time pressure
and evaluated on every request; a pathological pattern would turn the mitigation
into the incident. The regex-shaped matching lives in the detector, which runs
off the hot path and can afford it. With no rules configured the whole thing is
one `is_empty` check.

Two limits worth knowing: certificate renewal cannot be broken by a rule,
because an outstanding ACME `http-01` challenge is answered before the guard
runs; and a rule cannot stop an attack on the admin API, since that plane is
never guarded — the console says so on every auth finding rather than offering a
button that appears to work.

### The query string

app-lb otherwise **never logs the query string**, because a sign-in callback
carries an OAuth `code` there. Most SQL injection and XSS payloads, though, live
in a parameter *value* — so a path-only detector is blind to the attacks it most
needs to see.

The resolution is to **scan it and never store it**. The raw query reaches the
matcher as its own argument, is read, and is dropped with the observation; it is
not a field on the record type the access log is built from, so no code path
exists that could carry it to app-obs. On a match the alert records the
parameter *name* and nothing else:

```
web.sqli attempt in query parameter "id" from 203.0.113.9
```

The honest cost: the raw query now sits in a bounded in-process queue for a few
milliseconds, which it did not before. It never crosses a process boundary and
never reaches disk. `APP_LB_SIEM_SCAN_QUERY=0` removes even that, at the price
of most of the signature coverage.

### It is not a dependency of the data plane

The same contract as [log shipping](#it-is-not-a-dependency-of-the-data-plane),
enforced the same way: recording an observation is a `try_send` into a bounded
queue and nothing else — no lock, no await, no I/O, and no normalization on the
request path. Analysis happens on one background task, and every way it can fail
resolves to losing findings rather than to holding up a request.

Which makes the failure mode worth naming, because **a SIEM that has stopped
looking is indistinguishable from a quiet network**. Two counters say so out
loud, on `/metrics`, on `/security` and on the dashboard card:

- `dropped` — observations refused because the queue was full. Non-zero means
  detection is *sampling*; raise `APP_LB_SIEM_QUEUE_CAPACITY`.
- `clients_at_capacity` — the per-source table is full, so new addresses are not
  being tracked. Raise `APP_LB_SIEM_MAX_CLIENTS`.

That table is capped because an unbounded one would let an attacker with a
botnet choose how much memory app-lb allocates. At the cap it sweeps whatever
has aged out and then **drops the new observation rather than evicting a live
entry** — evicting the least-recently-seen is exactly what an attacker
engineers, by flooding fresh addresses until the entry counting their real
activity is the one that goes.

### What it deliberately does not do

**No `X-Forwarded-For` trust.** Detectors key on the socket peer only. Keying on
a client-supplied header would be an alert-spoofing and alert-flooding primitive
on an unauthenticated path. The consequence is that behind another proxy every
request appears to come from that proxy, and the per-source rules are only as
useful as that is.

**No credentials, ever.** An auth alert records the *scheme* (`basic`, `bearer`,
`none`) and never the password, the token, or a prefix of either — not even the
Basic username, since decoding it would mean parsing unauthenticated attacker
input on the failure path for no detection gain.

**No configuration auditing.** Who changed which deployment is a different
question with a different answer; the [deploy-job records](#shipping-logs-to-app-obs)
and app-lb's own events already cover it.

**No persistence — for findings.** The ring and the windows are in memory, so a
restart resets both. That is the right trade for a load balancer, and the reason
`APP_LB_SIEM_SHIP` defaults on: app-obs holds the copy that outlives the process.
[Block rules](#response-actions) are the deliberate exception and *are* written
to disk: losing a finding costs you a record of something that already happened,
while losing a rule readmits an attacker somebody blocked on purpose.

**No IPv6 escape by rotation.** Sources are keyed by /32 for IPv4 and by **/64**
for IPv6, because a /64 is a standard end-site allocation and an attacker
rotating within one would otherwise reset every counter for free.

One caveat about addresses: the admin listener defaults to `127.0.0.1`, so
control-plane alerts usually name a loopback address and it is the *count* that
carries the information. The address only means something when that port is
exposed directly.

## Design notes

Three constraints shaped this, each verified against the dependencies' source rather than
their docs:

- **Pingora fixes its service set at startup.** `Server::run_forever(self)` consumes the
  server, so dynamic registration cannot mean adding services at runtime. Every deployment
  lives in one `Registry` behind `ArcSwap`, and a single `ProxyHttp` routes across it.
- **`Sandbox::wait_for_ready` returning `Ok` does not mean healthy.** Its match has a
  `_ => return Ok(info)` arm, so `Stopped`/`Paused`/`ColdStored` all return `Ok`, and against
  a local daemon a broken VM surfaces as `Stopped` rather than `Failed`. A VM only joins the
  pool once it reports `Running`, has a `guest_ip`, *and* answers a probe.
- **`pingora-load-balancing` is deliberately not used.** Its selection algorithms
  (RoundRobin/Random/FNVHash/Ketama) cannot see in-flight counts, which is the signal both
  selection and autoscaling need here; `Backend::ext` is ignored for identity and
  `hash_key()` is `pub(crate)`. app-lb keeps its own pool with least-in-flight selection.

There is no event stream on the daemon, so the autoscaler polls (~2s), calling
`Sandbox::list()` once per tick — `Sandbox::info()` fetches that same full list and filters
client-side, so per-VM polling would be quadratic. A cold-start request nudges the autoscaler
directly rather than waiting for the next tick.
