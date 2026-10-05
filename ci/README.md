# ci

CI orchestration and a server-rendered dashboard for [heyvm](https://heyo.computer)
microVMs, with NATS JetStream as the job queue.

A machine becomes a runner by running `heyvmd` and joining a heyvm network.
There is no agent to install: this process discovers those hosts, opens an iroh
tunnel to each, and drives builds on them.

It is a sibling of [app-lb](../app-lb) and of queue-fn (a private repository) — same
conventions, same house style, different problem. app-lb keeps a pool of VMs warm
behind an HTTP data plane; queue-fn runs a command in one per event; `ci` runs a
workflow's worth of them per commit.

## Requirements

- **heyvmd** on every machine that should build, joined to one heyvm network
  (`heyvm network add-host`). `firecracker` and `kvm` are the supported drivers;
  `libvirt` is rejected at parse time.
- **Postgres** for run history, the job DAG and the VM pool.
- **NATS with JetStream** (`nats-server -js -sd /var/lib/ci-js`).
- Optionally **app-lb** for workflow objects and sign-in, **heyosecret** for
  secrets, and the **artifacts** store.

### SDK package

CI pins our public `heyo-sdk` 0.1.12 release, including the proxy
connection-lifecycle fix. Downloading it requires no publishing token or private
sibling checkout. Its source is maintained in `sdk-rs` in the Heyo repository;
CI does not carry a second source copy.

The published package comes from
[SDK source revision 4fd3e85](https://github.com/Heyo-Computer/heyo/commit/4fd3e85fb0d12d4537b4448824b8b43dc18827c6).
Its registry SHA256 matches the package verified before publication:
`880dffb6c86fab2a1b0a98efab9cb38f5a193c67a47a8037445ca9f21fcf8344`.
Cargo enforces that checksum through `ci/Cargo.lock`.

## Run

```bash
CI_HEYO_API_KEY=… CI_NETWORK=prod-runners \
CI_DATABASE_URL=postgres://…/ci CI_WEBHOOK_SECRET=$(openssl rand -hex 32) \
cargo run
```

Service configuration is environment-only. **A
misconfiguration is a startup exit, not a degraded service** — every error names
the variable to fix. See `deploy/supervisor/ci.conf` for the full set.

Validate workflow parsing and matrix/dependency planning without starting the
service or connecting to Postgres, NATS, or runners:

```bash
ci --check-workflows .ci/workflows/*.yml
```

This is a static check, not evidence that build commands or deployments work.

### Building and releasing the public CI system

Register `ci/system.yml` as the repository workflow to build the Linux CI service
and test/build the native agent on real Intel Mac and Windows hosts. Its platform
matrix also tests and builds app-lb (including heyctl), artifacts, HeyoSecret, and
Orchestrator. It uses the repository's assigned Linux network, not an us2 host
pin. Every validation job and matrix cell must pass before the release job.
The platform matrix starts after Linux CI validation, so a broken CI build stops
the pipeline before allocating the other platform build VMs.
Each Linux component uploads its own binary artifact with `REVISION` and checksums.
Linux tests and release compilation have separate steps with explicit 60-minute
limits: the two-hour job limit does not override the default 30-minute step limit.

The `ci-linux` artifact also supports branch deployment without a merge or rebuild.
On a CI runtime image, pin that successful run's artifact digest
as a read-only app-lb mount at `/opt/ci-release`, with `strip_components: 1`.
`deploy/start-artifact.sh` verifies `CI_EXPECTED_SHA` and `SHA256SUMS`, installs
the CI binary into the runtime, and executes CI directly on every boot. It never
calls a baked-in supervisor that might start or stop NATS. `CI_NATS_URL` is required;
NATS must run as an independent service with its own persistent JetStream volume.
It requires a separately mounted persistent state directory with a
`.managed-state` marker containing `ci-state-v1`; it refuses an empty or rootfs
fallback rather than silently losing CI history. Arguments are the release,
runtime, and state directories. This boot wrapper is included in new artifacts.
Self-deployment installs this CI-only boot command and refuses a missing or
loopback broker URL. It preserves the broker configuration rather than changing
or replacing NATS during CI deployment.

For a previously bundled installation, fence submissions and stop producers and
consumers before moving broker state. Inventory streams, consumers, pending
messages and acknowledgement positions; take a verified JetStream backup and
restore it into the independent broker's dedicated persistent volume. Preserve
account/subject names and credentials. Never concurrently mount CI's existing
writable workspace into the broker VM, and never copy a live JetStream directory
as if it were a consistent backup. Retain the old data untouched for rollback.
Verify the restored stream/consumer state and authenticated connectivity before
switching `CI_NATS_URL` and launching CI alone. After accepting new writes, the
old backup is no longer a lossless rollback target. Test CI restart with broker
identity, uptime and pending messages unchanged before reopening submissions.

For an existing rootfs-only installation, wait for jobs to finish, fence public
traffic with app-lb's 503 maintenance mode, and confirm no work remains before
stopping CI/NATS. Verify a private state export before changing the VM template.
Seed the managed workspace from that export.
Adding `vm.workspace` alone does not migrate rootfs data. Validate artifact mounts,
workspace capture/restore, and replacement ordering on the installed backend
before using this migration for live CI. Database access must survive a change of
VM address/interface; a firewall allowance tied to the retired VM is insufficient.
Branch promotion authorizes deployment of the tested artifact, not GitHub merge/tag writes.

### Instance maintenance

Both CI instances execute work. Authenticated admin maintenance requests apply
only to the addressed process boot; use `x-ci-target-boot` to reject a request
that reaches another boot. Keep `/maintenance` out of app-lb `public_paths`.

1. `POST /maintenance/{uuid}/pause` closes new admissions on this boot. Job claims
   recheck its durable drain state transactionally. Outstanding unclaimed queue
   deliveries return to NATS; the other region can claim them.
2. Existing jobs finish normally, including their durable VM cleanup.
3. `GET /maintenance` reports this boot's work. `POST /maintenance/{uuid}/quiesce`
   checks that its local work and job/cleanup obligations have finished. Neither
   request pauses the other region or grants VM replacement authority.
4. `POST /maintenance/{uuid}/resume` reopens this boot for the matching operation,
   unless platform retirement is pending. It cannot resume another operation.

### Runner drain across regions

Instance pause does not drain a server: the other CI instance can still place
jobs there. To empty a Linux runner without interrupting its running jobs, use
the authenticated admin API on either CI instance:

- `POST /maintenance/runners/{runner-id}/{uuid}/pause` durably closes that
  runner's job admission. Use the canonical runner ID, not its display name.
- `GET /maintenance/runners/{runner-id}` reports running jobs, outstanding host
  work, cleanup, and `drained`. Only an admission-closed runner with all three
  counts zero is drained. This is CI job drain, not permission to stop unrelated
  platform services or retire the CI app itself.
- `POST /maintenance/runners/{runner-id}/{uuid}/resume` reopens admission for the
  matching operation after recovery. It does not clear other host-upgrade fences.

Both CI instances must run a version implementing runner drain before using it;
an older executor does not check this admission state. Keep these routes behind
the admin identity gate, outside app-lb `public_paths`.

The shared database retains the drain across CI restarts. A runner-scoped lock
serializes it with job claims; there is no system-wide gate. Jobs already claimed
finish on their original server, including cleanup. Unclaimed jobs from new or
existing runs select a healthy, non-draining runner in the same network. Ready
dependent jobs do not wait for their entire run to finish on the drained server.
Unpinned jobs prefer their run's most recently used eligible server; this is a
preference, not a guarantee for simultaneous first jobs.

Use unpinned jobs, or `fallback: any` for a preferred host, for regional movement.
Movable jobs use the network's durable NATS queue. Strict host pins and named-VM
jobs remain pinned rather than silently executing on a different machine.
The queue carries job IDs; dependencies, outputs and ownership stay in the shared
database. Cross-job files must be published to shared artifact storage and
downloaded by the next job, not left on the previous job VM's disk.

`ci --inspect-executor` lists registered process boots without starting workers.
The old `--hold-executor-recovery` and `--transfer-executor-recovery` commands are
retired and fail explicitly. No singleton transfer is needed after a restart.
Existing unresolved jobs still require their own reconciliation; a new boot does
not steal them or delete their evidence.

Release and deployment default to disabled. A merge requires both
`RELEASE_ENABLED=true` and `RELEASE_SOURCE_SHA` equal to the exact submitted commit,
plus the HeyoSecret-backed `GIT_AUTH_TOKEN`. CI checks the captured base, requires
fresh successful validation, fast-forwards GitHub's default branch, and bumps
`ci/Cargo.toml`. This workflow publishes no Git tags or GitHub releases.
The source-diff guard permits only the five validated component directories and
their `.ci/`/`.heyo/` configuration; unrelated application changes remain rejected.

After the merge, `ci-linux-release` is rebuilt from the confirmed bumped tree and
contains CI, the Linux native agent, the artifact boot wrapper, `start.sh`,
`REVISION`, and checksums. It can be promoted through app-lb after the run finishes,
without making an installation depend on Orchestrator archive publication.
`DEPLOY_ENABLED=true` additionally enables the Orchestrator archive/deploy steps.
Configure `ORCHESTRATOR_URL`,
`SERVICE_OWNER`, a complete `SERVICE_SPEC`, and `ORCHESTRATOR_TOKEN` through the
workflow's HeyoSecret scope. The workflow inserts only the finalized archive ID
into that spec. The target must supply external Postgres/NATS and durable CI
workspace/log/artifact storage. This archive does **not** replace the stateful
CI/NATS bundle by itself: it contains no broker. For a new us3 installation,
`ci/Dockerfile.firecracker` packages CI only and `.heyo/regions/us3/ci.json`
defines the app-lb deployment with an explicit external broker placeholder.
Provision independent NATS before starting CI. Subsequent artifact promotions
retain the managed CI workspace, external database and broker configuration.

## Submitting a build

This repository's `ci` workflow only validates and produces an artifact.
`git submit --only ci` never merges or deploys. Once the installed platform meets
the prerequisites described under [coordinated submissions](#one-submission-across-validation-workflows-and-deployment),
an unrestricted submission also selects `.ci/workflows/regional-release.yml`.
That workflow owns the single merge after all selected validations pass, then
deploys sequentially to us3, eu1, and finally the CI controller. The merge uses
the registered HeyoSecret `GIT_AUTH_TOKEN`, with no version bump or tags. The
captured trunk must still match at publication; a moved trunk requires revalidation.

CI runtime changes also require `ci/deploy-controller`. It prepares a durable
release intent. A never-adopted app-lb deployment with all three application
lifecycle settings absent starts its scoped rollout directly, after the existing
repository, merged-release, artifact and deployment checks. An adopted application
records one release receipt and requests a regional update from Orchestrator.
Orchestrator freezes its configured regions and order, prepares every target,
and activates one at a time. Partial configuration is
an error, and removing configuration cannot bypass a recorded adoption. CI then
closes new submissions (HTTP 503) and lets existing jobs finish before
replacing the controller. The requesting job finishes first; the **run remains
running** until every configured target identifies the expected revision and
executable SHA256, reopens admissions, and completes the platform health bake. Documentation
and workflow-only changes need no controller replacement unless the release
workflow explicitly selects one. A passing validation run is not deployment
completion; inspect the coordinated release run.

Regional self-deployment is opt-in and supports **one retained-workspace
Firecracker CI app per region**. Both regions remain active normally and share
authoritative CI state. This does not implement database writer handoff.
Configure the following through the service's HeyoSecret-backed
configuration before enabling the workflow:

- `CI_CONTROLLER_DEPLOYMENT`: the app-lb deployment ID of this controller.
- `CI_CONTROLLER_REPOSITORY`: the only repository allowed to replace it.
- `CI_APPLICATION_ID`: when adopted, the shared application identity, normally `ci`.
- `CI_APPLICATION_ORCHESTRATOR_URL`: when adopted, the shared application authority origin.
- `CI_APPLICATION_LIFECYCLE_TOKEN`: a HeyoSecret-backed credential scoped to
  this application's update exchange. Orchestrator's binding references the same
  credential. It is not the app-lb admin, repository submit or native runner token.
- `CI_CONTROLLER_APP_LB_URL` and `CI_CONTROLLER_APP_LB_TOKEN`: its app-lb admin
  endpoint and a credential restricted to that deployment. These are separate
  from `CI_APP_LB_URL/TOKEN`, which enable workflow-object discovery; enabling
  self-deployment must not change how existing repositories find workflows.
- `CI_PUBLIC_URL`: must match the deployment's configured public URL.
- `CI_EXPECTED_SHA`: set by promotion; health also hashes the running executable.

Expose `/api/lifecycle` and its descendants through app-lb's public machine
paths. These endpoints require `CI_APPLICATION_LIFECYCLE_TOKEN` themselves:
`GET /api/lifecycle` advertises the configured identity, and
`GET/POST /api/lifecycle/updates/{id}` reads/activates a previously prepared
release intent. POST takes `{intentHash}` and cannot invent a release or artifact.
Orchestrator persists acceptance before calling POST; both acceptance and
activation reject changed replays. A prepared intent permits normal work and
cannot mutate app-lb without activation. Cancellation and the existing drain
deadline still apply. In-flight updates from an older binary retain their phase
and finish without creating a second operation.

Regional preparation uses `POST /api/lifecycle/updates/{id}/prepare` with
`{parentOperationId,operationId,applicationId}`. The addressed CI app derives the
release and artifact from its durable parent receipt and pins its own boot and
deployment; the caller cannot supply arbitrary executable bytes or VM identity.
Preparation does not close admissions. The drain deadline begins on activation,
not while waiting for an earlier region. The release job exits before preparation.
One generic receipt per real step remains intact; child completion cannot finish
the run before the regional parent completes its final bake.

Before enabling regional releases, install the protocol in every CI app and
Orchestrator, configure/adopt all regional bindings at the shared application
authority, and expose the authenticated lifecycle machine paths. Mixed old/new
instances must not be enabled as a regional target set. Existing singleton
updates remain supported for this initial installation. There is no fallback
from a refused regional request to a single-region replacement.

Treat installation, registration, and a verified regional release as separate
milestones. After installation, check each public `/healthz` revision and binary
hash, then check authenticated `/api/lifecycle` for the shared application ID,
the region's deployment ID, open admissions, and `regional-release-update-v1`.
Configure the same ordered `external_service_bindings` in both Orchestrators;
the order belongs to operator configuration, not the submitted workflow.
Register each current deployment through `/orchestration/services/adoptions`.
An identical replay through the peer Orchestrator must report `created: false`;
matching database names alone do not establish shared registration state.

The current protocol pins one `CI_APPLICATION_ORCHESTRATOR_URL` across CI
instances. Two active Orchestrators do not make that URL fail over automatically.
If it is unavailable, release observation waits; do not describe a successful
sequential CI update as proof of full-region-outage recovery. Keep `/maintenance`
behind operator authentication when exposing the token-protected lifecycle API.

Cancellation stops new activations and settles prepared children through
`POST /api/lifecycle/updates/{id}/cancel`. Already-submitted replacements remain
under observation until their outcomes are known; transport errors never mean
successful rollback. An unresolved replacement blocks advancement, not CI job
execution in the healthy peer. This retained-workspace protocol does not invent
a second candidate VM or perform database rollback.

The deployment must have min/max replicas of one, no warm pool, and exactly one
read-only `/opt/ci-release` artifact mount with `strip_components: 1`, using the
controller's HTTP artifact store. Its startup command must install that mounted
binary. Only the mount digest/ref and expected revision change during promotion;
database, NATS, workspace, routes and other service configuration are preserved.
The archive must contain `dist/ci`, `dist/REVISION` and `dist/SHA256SUMS` and come
from a successful job building the exact confirmed merged release.

**Bootstrap order matters:** first deploy app-lb's conditional deployment updates
(GET ETag / PUT If-Match), then install a CI controller supporting this action
through the existing drained deployment path, then enable the configured workflow.
An older controller cannot deploy its own first implementation of this action.
Missing capabilities or configuration fail the deployment rather than claim success.

`git submit --only ci --submit-empty` also remains validation-only: it cannot
retry controller replacement. Use the coordinated release policy for deployment;
do not treat an individual validation rerun or a successful artifact upload as
authorization to publish or as evidence that a replacement occurred.

The durable rollout waits for jobs, claimed/building VMs, unresolved host-work
obligations, native executions and other unresolved deployments. Expired leases
and terminal parent runs do not prove that a remote command stopped. Native
leases remain reserved after expiry; another runner cannot take over that job.
Unresolved execution blocks replacement until positively reconciled. No
historical rows are deleted to bypass this barrier.
Before the first replacement attempt,
`CI_MAX_JOB_SECONDS` bounds the drain; timeout or cancellation leaves the
controller unchanged and reopens submissions. After an ambiguous replacement
attempt, admission stays closed until reconciliation proves the outcome. Inspect
the run's service-deployment status and controller logs; do not clear the durable
barrier or retry a blind replacement. Cancellation after submission cannot undo
the external update, and the cancelled run stays cancelled after reconciliation.

```bash
./install-git-submit.sh                  # installs `git-submit` onto PATH

# From the dashboard's /repos page, which mints these two lines for you:
git config ci.endpoint https://ci.us2.heyo.work
git config ci.token    cis_019fca648a6e-00000002.…

git submit --dry-run    # show what would be sent
git submit              # submit HEAD
git submit pr59         # fetch and submit the exact head commit of GitHub PR #59
git submit --dirty      # include uncommitted tracked changes
git submit --only apps  # run one workflow file, skip the rest
```

The positional `pr<number>` selector fetches `refs/pull/<number>/head` from
`origin` into a temporary object store and submits that exact commit via
the same Git-patch descriptor path as `--ref`. It does not check out the PR or change
the current branch, index, or worktree, and it performs no GitHub write. A PR
selector cannot be combined with `--ref` or `--dirty`; malformed selectors and
PR refs that the remote cannot provide are rejected before submission.

`--only <workflow>` starts runs for just the workflow files it names and leaves
every other one alone. A selector is the file's path
(`.ci/workflows/app-lb.yml`), its basename with or without the extension
(`app-lb.yml`, `app-lb`), or the workflow's own `name:`, matched
case-insensitively; the flag repeats. Two edges are deliberate:

- **A named workflow runs even when its `branches:`/`paths:` filters would have
  declined** — naming it is the decision those filters exist to infer, the way
  a manual dispatch outranks a path filter. The response says so
  (`trigger filters bypassed by --only`) whenever that happened. The run is
  created with *unknown* changes, so job-level `if: changed(...)` conditions
  admit as well — otherwise the jobs would read the same diff that declined the
  workflow and skip to a green run that built nothing.
- **A selector that matches no workflow file fails the submit** rather than
  silently starting nothing, and one that names a workflow without `submit` in
  its `on:` list says exactly that.

The field rides the payload as `only`; a server older than this build ignores
unknown fields and would run everything, so upgrade the server before leaning
on it.

`git submit` does **not** upload a repository, bundle, or source archive. It
inspects the actual `origin`, chooses a full commit SHA the runner can fetch,
and sends only a binary full-index Git patch from that revision to the requested
target tree. A published commit is its own pinned base and has an empty patch.
Moving a branch after submission cannot change the checkout.

The runner owns checkout: it authenticates to `repository.url`, fetches the
exact `baseRevision`, applies the patch, and refuses the build unless the
resulting Git tree is exactly `targetTree`. Private repositories therefore need
checkout credentials configured for the CI runner/service (normally through
HeyoSecret). The submit token authenticates submission but is not repository
read access, and no checkout credential is embedded in the patch.

Local commits and `--dirty` work when an ancestor is currently published at
`origin`. The client checks advertised remote heads rather than trusting stale
`origin/*` refs, uses a private index for dirty tracked files, and never pushes
or changes HEAD/the user's index. If no published ancestor exists (including an
unpublished root-only repository), publish a base branch first. There is no
full-repository fallback; `--archive` exits with migration guidance.

The `git-patch` source descriptor carries the pinned base, expected tree,
binary patch, workflow YAML metadata, and known/unknown changed paths. A patched
checkout may have a synthetic commit SHA, so submitted `after` and checkout
commit identity can differ; **tree identity is the invariant**. For a published
submission, the original SHA is the base and the patch is empty.

Workflow metadata comes from the target Git tree (or private dirty target), not
arbitrary worktree files. Defaults are `.ci/workflows/*.yml` and
`.ci/workflows/*.yaml`. A repository using a registered custom workflow glob
must configure the corresponding client glob:

```bash
git config --add ci.workflowPath 'ci/workflows/*.yaml'
```

Only safe relative YAML paths are eligible. Each file is limited to 256 KiB and
the metadata total to 1 MiB. Python 3, Git, curl, and base64 are required.

## Registered repositories, and the token that submits

```bash
# On the dashboard: /repos → register a clone URL → Mint.
# It shows the token exactly once, with the two `git config` lines above.
```

A submit endpoint on the open internet is arbitrary code execution on a runner,
so what stands in front of it matters more than anything else here. There are two
credentials and the difference is not strength, it is **scope**.

`CI_WEBHOOK_SECRET` is one shared secret, HMAC'd over the body, handed to
everyone who submits from anywhere. It cannot be revoked for one repository, and
it cannot say *which* repository is submitting — so a submit's `repository` field
is something the server takes on trust.

A **repository token** is minted per registration, revocable on its own, and
*is* the statement of which repository the submit is for. A submit whose payload
names a different repository than its token is refused, which is what stops a
token for a repository somebody can push to from building any repository at all
— with this installation's secrets.

- **Stored as a SHA-256 digest, and shown once.** Verifying an HMAC would need
  the server to hold every key, and one read of that table is every repository's
  credential. A bearer inside TLS reverses the trade: the secret transits, and
  what is at rest cannot submit.
- **`ci_repo.workflow_path`** overrides `CI_WORKFLOW_PATH` for one repository. A
  workflow object still wins, being the more specific statement.
- **Pausing** a registration refuses its tokens without destroying them. The
  shared secret is unaffected — it belongs to no repository, so nothing about one
  can stop it. `CI_REQUIRE_REPO_TOKEN=true` turns it off entirely, which is where
  an installation lands once every repository has a token.

`/repos` is deliberately **not** in `public_paths`: it is a browser page behind
app-lb's gate, and admin-only on top of it. With `CI_ADMIN_EMAILS` unset it also
accepts a request carrying no identity at all — that is the local loop, where
there is no gate and no accounts — and startup warns about exactly what that
means.

## A workflow

```yaml
name: build
on: [submit]

jobs:
  build:
    uses: prod-runners/bigbox        # <network>/<runner>
    vm:
      driver: firecracker
      build:                         # or `image:` — see "Images" below
        dockerfile: deploy/image/Dockerfile
      size_class: medium
      cache_key_files:               # busts the warm VM when these change —
        - rust-toolchain.toml        # the toolchain, not Cargo.lock; see below
    strategy:
      matrix:
        target: [x86_64, aarch64]
      max-parallel: 2
    steps:
      - name: Build
        run: cargo build --release --target ${{ matrix.target }}
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          REGION: ${{ vars.REGION }}
      - uses: ci/upload-artifact
        with:
          name: bin-${{ matrix.target }}
          path: target/release/app
          # Optional, and only the `artifacts` sink keeps it: what a person
          # browsing that store sees beside the digest. Written as a *label* on
          # the blob and the manifest, never as a manifest annotation — a
          # manifest is addressed by its own hash, so wording in one would give
          # two builds of identical bytes two digests as soon as it changed.
          description: The app binary for ${{ matrix.target }}, release build.
          # Optional; `artifacts` sink only. Marks the stored blob public so
          # `{store}/blobs/{digest}` downloads with no credential — the link
          # is printed in the step log and shown on the run page. Nothing
          # else opens: tags, manifests and listings still need the key.
          public: true
          # Optional; `artifacts` sink only. A second, stable tag moved onto
          # this upload, so something downstream can follow the newest build
          # by name instead of being repointed at each run's own tag.
          alias: app-live

  deploy:
    uses: prod-runners              # any online host in that network
    needs: [build]
    if: ${{ needs.build.result == 'success' }}
    vm: { driver: firecracker, image: ubuntu:24.04 }
    steps:
      - run: ./deploy.sh
```

GitHub Actions' shape, with two departures.

**`uses:` places the job**, where GitHub has `runs-on:` selecting a label. That
is the point of the system: a job names the heyvm network and the machine it
wants, and membership of that network is what makes a host eligible.

```yaml
uses: default                       # the host this CI is running on
uses: prod-runners                  # any online host there that can run vm.driver
uses: prod-runners/bigbox           # that host; `vm:` builds a VM on it
uses: prod-runners/bigbox/sb-1a34   # that existing VM; `vm:` is unused and
                                    # every step is an exec into it
# absent                            # the repository's assigned network, any host
```

An unpinned job goes to the online compatible host with **the most free disk
space**, not the first host discovered. Driver eligibility uses
`GET /capabilities` on the daemon, learned once per host:
a macOS daemon that joined the network advertises `apple_container`/`apple_virt`
and is skipped by a `driver: firecracker` job instead of being handed a VM it
cannot boot. A *pinned* job gets the same check as a named error. A daemon too
old to answer `/capabilities` is given the benefit of the doubt.

Before each unpinned placement, CI reads `/storage` over its existing authenticated
daemon connection—the same free-space source app-lb exposes through `/disks`.
Missing, failed, or malformed capacity measurements exclude that host; a full host
is not treated as available merely because its heartbeat is online. Hosts must
have room for the declared data disk, twice the declared image-build rootfs size
(image plus VM copy), and 5 GiB of host headroom. Equal free space is broken by
runner ID, independently of discovery order. Explicit host/VM pins are unchanged.

This is a disk admission estimate, not a resource reservation or CPU/RAM load
balancer. Auto-sized/named images, build scratch space, and concurrent allocations
can require additional space. The check is conservative for warm VMs whose disks
already exist. It does not change queues, create a scheduler service, or require
an app-lb endpoint or configuration change.

**`uses:` carries everything needed to place the job**, and the third form is
why that matters. A sandbox does not record which host it is on — `SandboxInfo`
has no daemon field and there is no cloud-proxied exec — so `<network>/*/<vm>`
would force the orchestrator to interrogate every host in the network to find one
VM. Naming the node is refused-if-absent rather than guessed.

### Monorepos: not every workflow on every commit

`on: submit:` takes branch and path filters, and a workflow whose filters decline
a submit produces no run at all.

```yaml
on:
  submit:
    branches: [main, 'release/*']   # or branches-ignore
    paths:                          # or paths-ignore
      - 'packages/api/**'
      - Cargo.lock
```

```text
*      any run of characters within one segment; never crosses `/`
**     any number of whole segments, including none
?      exactly one character within one segment
```

`paths` builds when **any** changed path matches. `paths-ignore` skips only when
**every** changed path matches — one interesting file in a commit is enough to
build. `paths`/`paths-ignore` and `branches`/`branches-ignore` are each mutually
exclusive: GitHub allows a mixture and resolves it by pattern order within the
list, which is not readable off the file, so the combination is refused. A
leading `!` is refused for the same reason, naming `paths-ignore` instead.

A misspelled filter is a **parse error**, not a filter that quietly does nothing
— the same rule `stpes:` gets. This block used to be read and discarded, so a
workflow that said `branches: [main]` built every branch with nothing reporting
that it had.

The finer-grained form is a condition on one job, which is what a monorepo
usually wants — one workflow file, one run, and the packages that changed:

```yaml
jobs:
  api:
    if: ${{ changed('packages/api/**') }}
    ...
  web:
    if: ${{ changed('packages/web/**', 'packages/shared/**') }}
```

`changed()` runs the same matcher the `paths:` filter does, so a job condition
and a workflow filter cannot disagree about what a pattern covers. It is not
`contains(ci.changed_files, …)`, which on an array is an equality test and would
need the exact path of every file somebody might touch.

**The diff comes from the submitter's verified Git tree** and is recorded in the
durable source descriptor. Rename detection is off deliberately — a file moved
between two packages must rebuild both, not only the destination. The runner
reconstructs the exact base revision plus patch and verifies the target tree;
the CI service never expands a repository archive.

#### When the diff cannot be read

A root commit has no parent, and a base unavailable to the submitter cannot be
diffed. In these cases there is no answer, and **no answer matches every
filter** — the workflow builds.

The other direction is the failure worth designing against: unknown meaning
"nothing changed" is a CI system that quietly stops building and reports a green
tick on a commit nothing ran on. The same rule holds for `changed()`, which is
true when the diff is unknown, and for `paths-ignore`, which does not skip on
one. `ci.changes_known` and `ci.changes_reason` say which case a run is in.

A submit where every workflow declined is a **success with no runs**, not an
error: in a monorepo most commits touch one package, so most workflows correctly
build nothing. `git submit` prints the reason each one gave. Nothing matching the
glob at all is still an error — that is a mistake, not a decision.

### The `ci` expression scope

What commit a run is for, readable from any `if:` or `${{ }}`:

```text
ci.sha             ci.ref              ci.changed_files    (array)
ci.before          ci.branch           ci.changes_known    (bool)
ci.repository      ci.run_id           ci.changes_reason   (empty when known)
ci.workflow
```

Read from the run row rather than frozen onto each job's plan, unlike the network
assignment beside it. The two are not the same kind of fact: a repository can be
reassigned to another network mid-build, so the plan freezes that; the commit a
run is for is fixed by the durable descriptor and cannot move under a
redelivery. Freezing it anyway would copy a monorepo-sized path list onto every
job row.

### Images: `image:` or `build:`

```yaml
vm:
  image: ubuntu:24.04              # a public base, or a name the host already has

vm:
  build:                           # a Dockerfile in the submitted tree
    dockerfile: deploy/image/Dockerfile
    context: deploy/image          # defaults to the Dockerfile's own directory
    size_mb: 6144                  # rootfs size; absent = auto from the tree
```

The two are mutually exclusive and saying both is a parse error: a built image's
name is the hash of its Dockerfile and context, so an author-supplied one could
only disagree with it.

**`build:` builds the image on the runner, once, by the runner's own daemon.**
The first job to want it on a given host uploads the Dockerfile and its context
to heyvmd's `POST /images/build`, which runs the `heyvm mvm build` pipeline —
`docker build → docker export → mke2fs` — on the host and installs the result
into that host's image catalog. Every later job naming the same Dockerfile
boots straight from the image. Edit the Dockerfile, anything in its context, or
`size_mb` and the name changes, so the next run builds a new one — there is
nothing to remember to invalidate, and the host's docker layer cache keeps the
rebuild incremental.

It exists because the alternative was a footgun. `image: ci-rust` names a
rootfs that has to be built by hand with `heyvm mvm build` on every runner, and
a host that never had that run fails every job at VM creation — which, before
the `building` row above, looked exactly like a run nothing had picked up.

Because the build *is* `docker build`, docker's semantics apply in full —
multi-stage, `COPY --from=`, `ADD`, `ARG`, `.dockerignore`. `ci` does not parse
the Dockerfile; the runner daemon hashes and stages its verified local inputs.
What does not survive is
what `docker export` has never carried: **OCI metadata**. `ENV`, `CMD` and
`ENTRYPOINT` build fine and then vanish from the rootfs — an environment
variable steps need must be written to `/etc/profile.d` by a `RUN` (steps run
under `sh -lc`, which reads it), and the VM boots the kernel's `init=/init.sh`,
which must print `HEYVM_READY`. An image without an init script builds
successfully and then fails every boot; `.ci/image/ci/init.sh` is the contract.

The runner host needs `docker`, `mke2fs` and — when heyvmd does not run as
root — `fakeroot`. Each is checked by the build and named if absent, and the
failure lands on the job and on `/vms` like any other build failure.

Concurrency is settled twice, at two scopes. `ci_vm_image`'s upsert hands
exactly one *job* the build and tells the rest to wait, so ten jobs landing on
a cold host produce one build request and not ten; a claim whose lease has
lapsed is taken over, so a dispatcher that died mid-build does not block the
image for ever. And the daemon's route is idempotent by name — a second request
for an image already in the catalog answers `ready` without building — so even
a lost claim collapses into one docker build rather than two racing for the
same tag.

CI sweeps unused source-built base images without a cache-retention window,
separately from VM deletion. Each minute, CI considers at most one image per
served runner and refuses cleanup while that runner has active job work or
maintenance. Failed deletions stay recorded and retry after five minutes.

Deletion uses heyvmd's protected `POST /images/:name/evict` contract. The daemon
requires the source builder's matching ownership digest, serializes against
builds and VM creation across processes, and protects references from stopped
as well as running sandboxes. Busy, referenced, unmanaged, or uncertain images
are retained. Older daemons without this endpoint cannot reclaim images; a
404 is not a deletion receipt. Deploy compatible heyvmd on runner hosts before
expecting disk reclamation. Upgrade other CLI writers sharing that catalog too.

CI verifies cached images through the source builder before creating a VM, so
a missing file is rebuilt within the current job. Do not delete base-image
files directly on a live host or substitute `heyvm prune --images`: those
paths do not provide this ownership/reference-checking contract.

**A named VM is somebody else's machine**, and the executor treats it that way.
It is resolved on the pinned node by id or name, started if it is merely stopped,
and then every step execs into it. Nothing else about the normal path applies:
no fingerprint, no warm pool, no creation — and **no teardown**, so a long-lived
VM is not destroyed because the job's `vm:` block happened to say
`reuse: false`. Its TTL is left alone too; renewing it would be this app quietly
extending the life of something it does not own, which is worth knowing if a
build outlasts the TTL somebody else set.

The `vm:` block is inert for such a job. The schema still requires one — it is a
non-optional field — so it is written and ignored, and the run logs that it was.

`default` is the only form that names no network, and it is not the same as
omitting `uses:`: absent means the repository's assignment, while `default`
means this machine regardless.

**A pinned job does not silently migrate.** If its host is offline the job stays
queued for that host and fails after `CI_RUNNER_WAIT_SECS`, because the warm pool
is host-local — moving the job discards the cache the pin asked for and turns a
fast build into a slow one for reasons nothing reports. `fallback: any` opts in.

**A submit against an offline host warns rather than refusing.** The job sits on
that host's subject and runs when the host comes back — messages outlive the
absence of a consumer, and a durable created later binds with `DeliverAll`, so it
receives everything already queued rather than only what arrives after it. A
network blip is survivable by construction; refusing at submit would turn a
recovery into a lost submit. `git submit` prints the warning, and the run page
shows the wait.

That timeout matters more than it looks. Consumers are bound only for hosts that
are **online**, while `route_for` pins a job to its node whatever its status — so
a job pinned to a host that is not online goes to a subject nothing reads. The
wait is what turns that from a run stuck for ever with no steps and no error into
a failure naming the host it was waiting for. It is checked on the lease loop and
re-confirmed against the live pool first, so a host that comes back in the
meantime keeps its job.

### Timeouts start at pickup, not at submit

Every clock a job has — `CI_MAX_JOB_SECONDS`, the job's `timeout-minutes`, each
step's `timeout-minutes` — starts when a consumer **claims** the job off its
queue (`started_at`), never when it was submitted (`queued_at`). A runner's own
queue is consumed one job at a time, so N pinned jobs against one host form a
line: the first runs, and the rest wait their turn with their budgets untouched.
The network's shared queue **fans out** (bounded, currently 4): unpinned jobs
run on different runners concurrently instead of queueing behind whichever one
is mid-build. The run page shows the two clocks separately, as **Queued** (time
on the queue) and **Duration** (time since pickup).

Consumers reserve a worker slot before requesting one message in a finite,
blocking JetStream batch. They do not prefetch jobs into a local buffer: that
would start AckWait before a job has a worker to send progress acknowledgements,
allowing queued work to be redelivered and executed twice.

**Cancelling frees the queue immediately.** A cancelled job used to hold its
queue slot until the running step's own end — the daemon cannot abort an exec,
and the dispatcher waited for it — so a cancelled two-hour build read as
`running` on the networks page while everything behind it sat `queued`. The
dispatcher now abandons the wait within seconds (`CANCEL_POLL`), records the
step `cancelled`, releases the VM, and acks the message so it is not
redelivered. The command already running in the guest finishes on its own or
hits its in-guest timeout; its VM is repooled and swept normally.

`CI_RUNNER_WAIT_SECS` is **not** a bound on that line. It fails a job that has
waited for a runner that was never going to take it — a pinned host that is
offline, a subject with no consumer, a message some other instance consumed. A
job whose route has work in flight *and* a backlog behind it is waiting on
capacity, and the reaper leaves it alone however old it is. (It used to be
failed as "nothing consumed the queue", which is how several workflows submitted
against one backend produced one success and the rest timed out.)

If a deployment does want a cap on queue time, `CI_QUEUE_WAIT_SECS` is that cap
and nothing else: a job that has sat behind a busy runner longer than it is
failed with a message saying so. It is unset by default, which means no cap.

**`vm:` describes the machine.** GitHub gives you an opaque runner image; here
the author declares the driver, image, size and setup hooks — and, via
`cache_key_files`, what should invalidate the warm VM the next run would reuse.

`deny_unknown_fields` is on throughout, so `stpes:` or `timeout_minutes:`
(instead of `timeout-minutes:`) is a parse error naming the job, not a field that
quietly does nothing.

**CI-owned job VMs are deleted, not parked.** Success, failure and cancellation
all hand the VM to durable cleanup after diagnostic capture. The daemon must
confirm stop and deletion before CI forgets ownership. Failed cleanup retries
after controller restart. Legacy `vm.reuse` declarations still parse but do not
retain job VMs; existing idle caches are swept without a retention window.
Explicit existing-VM `uses:` targets and service/maintenance resources are not
ordinary disposable job VMs and remain under their owner's lifecycle.

**Debug reports go to private S3 storage, not retained VMs.** CI snapshots job
identity/revision, outcome, timestamps, operation IDs, all retained step logs,
and captured VM metadata/console into a transactional outbox before cleanup.
Console capture is bounded by `CI_VM_LOG_LINES` and 40 seconds; unavailable
diagnostics are recorded explicitly. Environment values, raw commands and
workspace contents are not exported. Known job secrets are redacted from the
console; if secret resolution fails, that console is omitted rather than leaked.

Configure `CI_S3_BUCKET`, optional `CI_S3_PREFIX` (default `ci`),
`CI_S3_REGION`, and `CI_S3_ENDPOINT`. This report destination is independent of
`CI_ARTIFACT_SINK`; regular artifacts can continue using the artifact service.
AWS credentials come from the standard AWS credential chain, provisioned through
the service's HeyoSecret configuration. Use a private bucket with public access
blocked. No public ACL or public URL is requested. Report keys are
`<prefix>/<run>/<job>/debug-<attempt>-<sandbox>.json`.

S3 failures retain the report in shared Postgres for bounded upload retries but
**never retain the VM**. After upload, the outbox releases its payload and keeps
the S3 receipt. The authenticated `GET /api/runs/{run}` response includes
`debug_reports` with upload state, URI and retry error. Missing S3 configuration
is reported as an error; it is not silently replaced with disk storage.

### This repository's own

`.ci/workflows/ci.yml` is one job that produces one thing: the release binary,
uploaded as the `ci` artifact. `cargo test` parses and plans every file in that
directory, so a typo in it fails here rather than at a submit somebody is waiting
on.

**Adding checks.** `cargo fmt --check` and `cargo clippy` are not in it, and the
reason is a trap worth naming: the setup hook installs rustup with
`--profile minimal`, which ships `rustc`, `cargo` and `rust-std` and **not**
rustfmt or clippy. A `cargo fmt` step against that toolchain fails with
`no such command`, which reads as a broken CI rather than a missing component.
Either drop `--profile minimal`, or add the components explicitly:

```yaml
- curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
- . "$HOME/.cargo/env" && rustup component add rustfmt clippy
```

The integration suite is a separate question: it needs Postgres, NATS and a
`heyvmd`, so it belongs on a runner provisioned with them rather than on a
default image.

## Networks

```bash
CI_NETWORK=prod-runners          # serve one
CI_NETWORK=prod-runners,lab      # serve two; the first is the default
CI_NETWORK='*'                   # serve every network on the account
```

`/networks` carries a **Queue** column: what is waiting on each host's subject
and each network's unpinned subject, read straight from JetStream. Exact rather
than sampled, because `WorkQueue` retention deletes on ack — the count *is* the
backlog.

The reading that matters is **`no consumer`**, flagged in red on a host that is
online. Consumers are bound only for online hosts while `route_for` pins a job to
its node whatever its status, so a job can be routed to a subject nothing reads.
That is what a stuck run looks like from the outside, and it used to be
answerable only by curling the NATS monitoring endpoint. On an *offline* host the
same state is expected and is stated rather than alarmed about. NATS being
unreachable is a banner, not a page of zeroes — an idle queue and an unreadable
one must not look alike.

`/networks` lists **every** heyvm network on the account with the hosts in each,
whether or not this instance builds for it, plus the daemons that joined no
network at all. That last list is there because "my runner isn't picking up
jobs" is otherwise a dead end: a registered daemon that never joined looks
exactly like one that was never registered.

**Add this host** joins the machine running `ci` to a network, which is
`heyvm network add-host` without needing a shell on that box. It is offered only
for a network this host is not already in, and it is admin-only behind the gate —
joining a host to a network unlocks host-shell access to it, so it is not a read.
Joining does not make this instance *serve* that network; the page says so when
the two differ, because finding out from a job that never runs is worse.

The member is posted by hand rather than through the SDK, because
`NetworkMemberKind` is `Local | Deployed` and has no `host` variant at all —
`heyvm network add-host` has the same problem and solves it the same way.

**What an instance serves is configuration, not discovery.** Jobs are sharded
onto one durable JetStream consumer per runner and per network precisely so
several orchestrators can run at once *as long as they own disjoint sets*. An
instance that silently served everything would eat another's work. `*` opts into
serving everything, which is right for the single instance most installations
run — as a decision that was made rather than one that happened.

Members are read per network, concurrently: the control plane has no
"all members everywhere" route and `NetworkInfo` carries no member count, so N+1
reads is the only shape available. Running them together makes a refresh one
round trip's worth of latency instead of N.

### Assigning one to a repository

A registered repository (`/repos`) can name the network its builds run in, stored
in `ci_repo.network`. The order of precedence, most specific first:

1. the job's own `uses: <network>/<runner>`
2. the workflow object's `network`, where app-lb has one
3. the repository's assigned network
4. the installation default — the first entry of `CI_NETWORK`, or the account's
   default network under `*`

The resolved network is **stamped into the stored job plan at submit time**, not
looked up when the job runs. A redelivery therefore runs where the job was
scheduled, and reassigning a repository mid-build does not move work onto
hardware that never warmed a VM for it — the same reason the expanded plan is
stored rather than recomputed.

**A submit naming a network this instance does not serve is refused at the
client**, with the network and the served list in the message. The alternative is
a run that exists, jobs on a queue nobody consumes, and no answer to "why is my
build stuck" short of reading a table.

The assignment is stored as the network's **name**, not its id: a name is what
`heyvm network create` took, what `uses:` spells, and what the dashboard shows,
so a hand-written query stays readable. The cost is that renaming a network in
heyvm orphans the assignment — which surfaces as a refused submit and a warning
on `/repos`, rather than as a build that quietly moves.

## Cancelling a run

`POST /runs/{id}/cancel`, from a button on the run page while there is something
to stop. It marks the run and every unfinished job `cancelled` — and that one
statement is the whole mechanism, because it covers work in each of the three
states it might be in without reaching a runner at all:

- **queued** — dropped when JetStream delivers it, since `run_job` refuses a job
  that is already terminal on entry;
- **about to start** — refused by `start_job`, whose `WHERE` clause excludes
  terminal statuses;
- **running** — noticed at the next step boundary.

**Cancellation is cooperative, and the limit is honest**: the daemon has no route
to abort an exec-operation in flight, so a step that has already started runs to
its own end or its `timeout-minutes`. What stops is everything after it. The page
says so next to the button rather than implying an instant kill.

A cancelled job stays cancelled. `continue-on-error` is about a step failing, not
about somebody stopping the run, so it does not convert a cancellation into a
success — and the executor does not write `failure` over it, which would make a
deliberate stop read as a broken build.

### Preparation failures do not hold the CI app's drain

New VM jobs record a preparation phase, then atomically cross into execution
before any VM acquisition, opening, or startup. If preparation returns an error
before that boundary, CI finishes the job (preserving cancellation) and releases
its CI-instance ownership. A confirmed source/build failure also releases the
runner-work record. Expired source records, lost replies and uncertain image
builds retain a `detached_preparation` runner-work record with the original boot
identity: they no longer block replacing the CI app, but still block maintenance
of the runner that may be doing preparation work. They cannot be automatically
retried as though no remote effects occurred.

Missing VM records are not evidence of this boundary. Existing claims from older
binaries remain conservative, and failures after the execution transition still
require verified VM cleanup. An outer task timeout or process death that prevents
preparation finalization also retains ownership; this change does not infer safe
cleanup from a timeout or add automatic recovery of legacy claims.

### VM cleanup survives a failed connection

After execution finishes, CI atomically records the terminal job outcome and a
`ci_vm_cleanup` obligation for its exact runner, VM and attempt. The same handoff
handles a VM acquired after its job was cancelled. The VM stays claimed until a
fresh daemon read confirms that exact VM is stopped. Non-reusable or corrupted
VMs also require confirmed removal before CI forgets their pool record.

Cleanup retries during normal operation and controller drain, including after
controller restart. A failed request evicts the cached runner connection and
records its error and next retry time. Each pass handles one due obligation with
a 20-second timeout; the background loop runs every 30 seconds. Concurrent
workers serialize on the durable obligation. Expired leases do not make these
VMs available to another job. Controller deployment messages name cleanup VMs
blocking drain; confirmed cleanup releases that barrier automatically.

Placement also evicts its cached runner connection when a capacity measurement
fails, so the next delivery redials instead of repeating a request over a dead
tunnel. A valid zero/low free-space reading does not evict the connection or
bypass the job's disk requirement.

Cancellation, failed-job status and lease age **do not authorize cleanup** on
their own. CI must have the executor's durable handoff and matching pool
ownership. Existing named/service VMs are excluded. Upgrade all dispatchers
sharing a VM pool before relying on this protection: older orphan-reclaim code
does not understand cleanup obligations. Legacy claims, interrupted acquisition
and crashes before handoff are not retroactively declared safe; they still need
ownership reconciliation. Do not clear their claims or delete VMs based only on
a `ci-` name or terminal job status.

## Re-running a run

Jobs without an explicit `if:` require every dependency to succeed. Failure,
cancellation, and skipped dependencies propagate through the entire dependent
chain before scheduling stops; matrix dependencies wait for every cell. An
explicit `if: always()` can still schedule cleanup, and independent jobs are
not skipped. A failed run cannot be rerun while those jobs are active.

For completed Linux `run:` commands, CI records the masked log and exit status
in one transaction. A temporary database outage retries only that transaction
for up to two minutes (within the existing job deadline), never the command.
Replaying a committed result does not duplicate its log. If recording still
fails, the job error explicitly reports a result-recording failure and the
known command exit code; it does not claim the command itself failed. This
bounded in-process retry does not add restart recovery or make pooler replacement
zero-downtime.

Two buttons on a finished run's page, and the routes behind them:

- **Run again** — `POST /runs/{id}/rerun`. Every job, from the top.
- **Re-run failed jobs** — `POST /runs/{id}/rerun-failed`, offered when the run
  failed or was cancelled. Every job that *succeeded* is carried over into the
  new run as finished, with its outputs, so `needs:` resolves and a deploy job
  can run again without rebuilding what built; everything else — failed,
  cancelled, skipped — is scheduled afresh. A carried-over job says so on the
  run page and on its own page, which links to the steps it did not run.

Both are the dashboard's manual trigger, and both are the answer to "the build
timed out on a cold cache": the re-run claims the same warm VM, and with it the
cache disk the first attempt spent its budget filling.

Machine callers can use `POST /api/runs/{id}/rerun-failed` with the same
`Authorization: Bearer <repository token>` used by `git submit`. No browser
login is required. The token must belong to the run's repository and remain
enabled and unrevoked. Read-path HMAC signatures cannot authorize this write.
The response is `202` with `runs`, `url`, and `warnings`, as for submission.
An active run or unresolved service deployment returns `409`; rerunning does
not bypass repository policy or release/deployment gates. If a request loses
its response, check `reruns` in `GET /api/runs/{id}` before posting again:
every accepted request creates a new run, not an idempotent reset.

Published releases use a separate **failed-jobs-only** retry path. The retry
atomically inherits the original job plans, source, published commit and frozen
validation/artifact membership. Successful regional jobs are carried over;
completed `ci/rollout-host-app-lb` and `ci/rollout-service` steps inside failed
Linux jobs retain their original deployment receipts and do not deploy again.
Failed service candidates must have confirmed reclamation before retry admission.
Other partially completed deployment actions require reconciliation rather than
blind replay. Full release reruns and unconfirmed publication are rejected.
Each release attempt admits at most one retry; further retries target the latest
failed descendant. Ordinary partial submissions remain validation-only.

**A re-run is a new run**, with `rerun_of` pointing at the one it re-plays and
the original's page listing what re-played it — never a reset of the old run.
Run and job ids name their logs and derive the step operation ids the daemon
reattaches to, and the failed attempt is what somebody will want to read beside
the one that passed.

**What it runs is the source the submit described.** The CI service never clones
or stores a repository credential during submission. It commits the immutable
revisions, patch and workflow descriptor in `ci_run_source` in the same Postgres
transaction as the run and jobs. The selected runner reconstructs and verifies
that tree using a freshly resolved job-scoped HeyoSecret. Release publication
also reads this shared descriptor before making its authorized temporary checkout.

`CI_WORKSPACE_DIR` holds local submission staging files, not accepted source
authority. On startup, retained `<run>.source.json` files for existing runs are
validated and imported into shared storage without deleting the originals.
Exact re-import is safe; conflicting or invalid descriptors stop startup instead
of replacing accepted history. Source reads, native-runner checkout and reruns
then use Postgres exclusively. A run without an imported descriptor reports the
missing source explicitly; it never falls back to a different revision.
An ordinary validation re-run goes through
the same path as a submit, with the run's own
workflow file as its `--only` selector, so it is planned, routed and given
secrets exactly as the original was. As with `--only`, the `on.submit` branch
and path filters do not apply — and the run inherits the original's recorded
change set, so job-level `changed()` filters decide as they did the first time.
Same authority as cancel: `CI_ADMIN_EMAILS` through app-lb's gate, when set.

## Legacy warm-pool bookkeeping

The following fingerprint and cache-management surfaces describe legacy pool
records. New execution is ephemeral as described above: it does not claim warm
VMs, park failed jobs, or wait a week to reclaim capacity. The existing pool
table remains the ownership ledger until deletion is confirmed.

```
fingerprint = sha256( canonical_json(vm block, minus cache_key_files)
                    ‖ for each path in sorted(cache_key_files):
                          path ‖ 0x00 ‖ sha256(contents)  — or an ABSENT marker )
```

A job claims an idle VM on its runner with a matching fingerprint, or builds one.
A claimed VM is stopped — that is how `release` leaves it — so the claim starts
it and waits for the boot, seconds against the minutes a fresh one costs.
Two decisions in there:

- **`cache_key_files` is stripped before hashing.** Otherwise editing the *list*
  would rebuild every VM even when every listed file is byte-identical.
- **A missing file hashes to an explicit marker.** Skipping it would make "no
  `Cargo.lock`" and "an empty `Cargo.lock`" indistinguishable, so *adding* a
  lockfile later would not bust the pool — the moment it most needs busting.

**List only what must retire the cache in `cache_key_files`.** `Cargo.lock`
is the obvious candidate and the wrong one for a cargo build: cargo fingerprints every unit by package id, features, profile and compiler, so
a lockfile bump rebuilds the crates that moved and relinks, while busting the
pool on it throws the whole `target/` away and pays the cold build for a
version number. A toolchain file belongs there — a new rustc rebuilds
everything anyway — and the image and the `vm:` block are already in the
fingerprint. `app-lb.yml` says the same at the site.

`/vms` shows the pool and answers the two questions worth asking of it. **Is
reuse working** — rows are grouped by host and fingerprint, and a fingerprint
appearing twice on one host is flagged `not reused`, because that is two VMs
where one would have done. **What was left behind** — each row carries the
outcome of the run that last used it, so a machine a failed build left in a
strange state is visible rather than inferred, and reusable-by-fingerprint is
exactly why that matters. **Is it the size it asked for** — each row carries
the class the job declared and, under it, what the runner's daemon reported
the VM was actually given (`GET /sandboxes/<id>`: its class name and the cpus
and memory behind it), read back every time this app creates, claims or
resizes the VM and stored on the row. A `xlarge` build quietly running on the
daemon's `small` default does not look like a slow build — it *is* a failed
one, 75 minutes later, with nothing to say why — so a VM the daemon reports
as smaller than the job declared is not built on. The dispatcher resizes it
back to the declared class once (in place, disks kept, so the cache survives)
and, if the daemon still reports it too small, fails the job on the spot
naming both sizes and what the resize did; the row says `got small (1 CPU,
2 GB) — too small` in red. The VM is parked rather than destroyed, so a
resize from this page is all a retry needs. Only smaller is refused: a VM
resized *up* here runs the build as the workflow expects and shows `— larger`.
A daemon too old to report sizing shows `size unreported`, which is a
finding about the runner, not a size, and is warned about rather than refused.

**Resize** is on every idle row. It changes the VM in place — the daemon
rewrites its cpus and memory and restarts it, disks kept — so the build cache
survives, which editing `size_class` in the workflow would not: that is part
of the fingerprint, and changing it retires the warm VM. Idle only, because
the restart would kill a job mid-step; the row is held out of the pool for the
duration and the new size is read back from the daemon rather than assumed.
The workflow's own class is left alone: this is an override, and the next
claim says so if the two disagree.

### Idle VMs are retired by this app, on its own clock

The daemon's TTL reaper skips stopped sandboxes, so a parked VM would keep its
disks for ever without something here to say when it is no longer wanted. The
lease loop sweeps, every tick, idle VMs on the hosts this instance serves that
are idle (the window is now zero and not configurable; `CI_VM_IDLE_SECS` no
longer exists) or carry a fingerprint no job has
touched in that window — the machine a retired `vm:` block or toolchain left
behind, sitting beside the one that replaced it. Claimed VMs are refused in the
query; `draining` keeps a taken VM out of circulation until the daemon confirms
it is gone.

Machine callers can reclaim one cache with
`POST /api/runs/{run_id}/cache/{sandbox_id}/destroy`, authenticated with that
repository's submit bearer token. Read-only HMAC signatures are not accepted.
The pool atomically checks that the VM is idle (or already eviction-requested),
belongs to a served runner, and was last used by a terminal job of this exact
run. Reuse by another run removes the old caller's authority. A conflict returns
409 without eviction; transport failure preserves the durable eviction intent.
Success is returned only after the daemon confirms removal and CI removes the
pool row. This does not authorize deleting service VMs or clearing maintenance
fences. Stopped caches also retain network allocations, not just disk space;
disk-pressure eviction alone does not guarantee room for service rollouts.

Disk pressure overrides this retention window during VM admission. Before
comparing compatible hosts (and for a pinned host), CI evicts that host's oldest
idle caches one at a time until measured free space meets the incoming job's
disk budget: its data disk, two declared rootfs copies, and 5 GiB host headroom.
Free space is read again after every deletion, and checked again before a cold
VM creation. Claimed, building, and already-draining VMs are never victims;
only CI pool rows on that host qualify. A failed deletion stays tracked as
draining and stops that cleanup attempt. An explicit, persisted eviction intent
makes the lease-loop sweep retry it after failures or controller restarts, even
if its fingerprint is still wanted. A failed eviction also discards that runner's
cached tunnel so the next attempt reconnects instead of reusing a dead loopback
connection indefinitely. Other runners and connections held by active VM
operations are unaffected. Deletion holds a database row lock across
the bounded daemon call and requires a follow-up not-found response before
forgetting the pool row. Resize operations also use `draining`, but carry no
eviction intent and are never selected for deletion. Pre-existing ambiguous
draining rows are not automatically adopted as eviction requests.

Host maintenance blocks new idle-cache evictions, but does not block retries of
already-requested evictions. Those deletions must finish while maintenance is
draining; otherwise maintenance and cleanup would wait for each other. Runner
scope, row locking, and runtime confirmation of removal still apply.

If no idle caches remain and space is
still insufficient, the host cannot admit a new VM. This is admission headroom,
not a disk reservation against concurrent allocations or unknown build scratch.

Firecracker network pressure uses the same bounded eviction policy. A `/24`
contains 64 `/30` TAP links, and stopped reusable VMs retain their link while
they remain cached (until the next idle sweep). When the backend
explicitly rejects a cold create with its "no usable /30 TAP subnet" capacity
verdict, CI atomically takes the oldest idle CI cache on that same runner,
destroys it, confirms that the daemon reports it absent, and retries the create
once. A failed deletion retains the pool record and stops recovery; CI neither
deletes another cache nor retries creation. Transport failures, timeouts, and
other ambiguous create errors never trigger eviction. Running or claimed VMs,
idle rows whose last owning job is not terminal, maintenance-fenced runners,
service VMs, caches on another runner, and anything outside CI's pool are not
eligible.

A claim that cannot *reach* a pooled VM — the tunnel, the daemon not answering
— hands the row back and fails the delivery so the ladder retries; discarding a
warm cache because the runner blinked is the most expensive thing this code can
do. A daemon that answers and does not know the VM, or cannot start it, is a
verdict: the VM is destroyed and a fresh one built. Destroyed rather than merely
forgotten, because a forgotten stopped VM is disk nothing will ever reclaim.

Runner connections retain ownership of their forwarding listener throughout
source preparation, image builds, VM execution, and teardown. Evicting a failed
cached connection makes subsequent work redial without closing the listener
under other active jobs. This does not recover a genuinely broken remote link
or replay a command whose outcome is unknown.

### A VM being created is on the page too

A row appears as `building` **before** the create is attempted, not once it
returns. That window is the longest silent stretch of a job — an iroh dial to the
runner, then a `POST /sandbox-deploy` that waits out `BOOT_TIMEOUT` (five
minutes) for a cold machine — and while it was unrecorded, `/vms` said "Nothing
is pooled" and the job row still said `queued` for the whole of it. A build that
was booting, a build whose VM creation was failing and being retried, and a run
nothing had picked up were three different things that all looked like nothing
happening.

The row is keyed on `building-<job_id>` because the daemon has not assigned a
sandbox id yet. **Nothing may treat that as one**: every query that reaches a
daemon filters on status, and `take_one_for_sweep` — the only one that took
anything not `claimed` — excludes `building` explicitly, so the page offers no
Destroy button and the server would refuse it anyway. The creating job clears the
row either way: `register` replaces it with the real one on success, and it is
deleted on failure. It is leased like a claim and renewed on the same timer, so a
slow boot is not swept out from under itself; a process that dies mid-create
stops renewing and the row is deleted by the loop that reclaims expired claims.
The half-created sandbox, if there is one, is left to its TTL, as it was before.

A job reaching a runner is also recorded before it has a VM. `ci_job.status`
becomes `running` with `runner_hd_id` set as soon as a consumer commits to the
job — `sandbox_id` and `fingerprint` stay null until there is a machine, which is
the honest reading. Two things depended on that being wrong: the run page showed
a build that was busy booting as not started, and `fail_jobs_waiting_for_a_runner`
could not tell an unclaimed job from one a live host was working on, so it would
fail the build and blame a host that was online. And each failed delivery now
writes its reason to the job row instead of only the fourth and last one — the
redelivery ladder is 60s, 5 minutes, then 15, so a workflow naming a VM image its
host does not have used to show an empty error for twenty minutes before anything
said why.

Cleanup destroys a single VM, or every idle one whose last run failed. Both go
through `take_for_sweep`'s pattern: the row is marked `draining` first, so a
concurrent claim cannot hand out a machine that is about to be killed, and it is
only forgotten once the daemon confirms the sandbox is gone — a row removed while
the VM survives is a VM nothing will ever clean up again. **A claimed VM is
refused**, in the query rather than only in the page, so cleaning up cannot fail
a live build from underneath. Everything is scoped to the hosts this instance
serves, for the same reason the sweep always was.

`ci_vm_pool.last_job` is kept after a claim is released. `claimed_by_job`
answers "who holds this now" and is nulled on release; it cannot answer "which
run left this behind", which is the question cleanup is asking.

The pool table survives a restart. Without it a crash orphans every VM until its
TTL, and the next run builds a second pool beside the one already sitting there.

### Lease expiry is not execution takeover authority

Each instance has a random startup identity and renews its VM leases. A missed
renewal can mean either process death or a network partition while the process
still drives a VM. It does not authorize reusing that VM.

Claiming a job atomically records `ci_host_work` and transitions the job to
`running`. A concurrent claim or queue redelivery cannot replace that owner.
While the obligation exists, lease expiry cannot repool its VM or delete a
pending-create record. Cancellation does not remove this evidence either.
Normal execution hands release to verified VM cleanup. Errors after a claim
retain the obligation and report that reconciliation is required instead of
automatically replaying potentially completed external effects. Errors before
claiming work still use the retry ladder.

The same rule applies to native runners: expiry rejects stale reports but does
not reassign the execution or free its runner capacity. These guards are
prerequisites for regional CI, not proof of regional failure survival.
Source and logs use shared storage. Linux job claims record the owning process
boot and serialize with that boot's drain transition. Other boots remain active.
Native callbacks retain their per-job lease-token checks and can be handled by
another active frontend; there is no singleton execution handoff.

`uses: default` resolves through **`daemon.json`** in `$MVM_DATA_DIR`, else
`~/.heyo` (override with `CI_DAEMON_STATE_PATH`) — heyvmd mints
`backend_id` there on first start and registers and heartbeats under it, so it is
the identity the cloud knows the machine by, and it is the same file
`heyvm network add-host` reads. The daemon's `/daemon/name` route is *not* the
authority: it returns `backend_server_id`, a different field fed by the
`BACKEND_SERVER_ID` environment variable, and trusting it pins jobs to an id the
cloud may have no live registration for — a queue with no consumer beside a
daemon that is perfectly healthy. `CI_DEFAULT_NODE` overrides everything.

For a fixed host, `CI_LOCAL_RUNNER` can name the daemon's direct base URL instead
of using Cloud discovery. `CI_LOCAL_RUNNER_TOKEN` supplies that daemon's bearer
credential when required; leaving it unset preserves unauthenticated local
development. Keep the credential in HeyoSecret-backed deployment configuration,
and use HTTPS or a trusted private host-to-VM network for this connection.
This mode does not register or move the host between Cloud installations.

`CI_VM_LEASE_SECS` (default 180) is the window between an instance dying and its
VMs becoming reclaimable; renewal runs at a third of it.

The same loop **renews the sandbox TTL of every VM it is running a job on**, and
that is a fix rather than a nicety: `CI_VM_TTL_SECONDS` defaults to an hour and
`CI_MAX_JOB_SECONDS` to four, while the TTL was only ever set at creation and
touched again when a VM was claimed or released. A build longer than the TTL had
its machine reaped mid-step, surfacing as a daemon error on a job doing nothing
wrong.

Only *claimed* VMs are kept alive. An idle one is stopped, outside the reaper's
reach, and retired by the idle sweep on its own clock; renewing it would be a
round trip per pooled VM per tick for nothing. It works while a step is running
because `Vm::renew_ttl` does not take the sandbox lock that `exec` holds; if it
did, the keepalive would queue behind the build it exists to protect.

## Workflow objects

```bash
heyctl create workflow build \
  --repo git@github.com:me/app.git \
  --network prod-runners \
  --path '.ci/workflows/*.yml'

heyctl get workflows
```

Stored by app-lb, polled by `ci`. An object points at a repository and a path
glob — the workflow itself lives in the repository it builds, versioned with the
code, so the object is a pointer rather than a copy that can drift.

Objects are matched on the **repository**, because `git submit` knows what it is a
clone of but not what somebody named the object; `git@github.com:me/app.git` and
`https://github.com/me/app` match. Several objects may name one repository —
`build` and `nightly` with different globs is legitimate — and each gets its own
runs, because each is an independent answer to "did this commit pass".

Without `CI_APP_LB_URL`, submits fall back to `CI_WORKFLOW_PATH` and the system
works with no objects at all.

## Secrets

`${{ secrets.X }}` and `${{ vars.X }}` resolve from heyosecret under
`ci/<workflow>/<environment>/`, where `<workflow>` is the workflow object's id
(or, without one, the registered repository's name) and `<environment>` is the
job's `env.CI_ENVIRONMENT`, defaulting to `default`.

**This process is the policy layer, because heyosecret has none.** Its token can
read, write and revoke every secret at every path; `readAccess`/`writeAccess` are
stored and returned but never enforced. So there is no configuration of
heyosecret that makes handing its token to a build safe. The orchestrator holds
it, resolves what a workflow is entitled to, and injects only the values.

heyosecret makes no secret/variable distinction, so the convention is its
`tags[]`: an entry tagged `public` becomes `vars.*` and is left in plain text;
everything else becomes `secrets.*` and is **masked on the write path** — before
a log line is persisted or streamed, so a secret never reaches disk in plain text
for someone to find later.

## Deploying it

A **static `proxy_pass` deployment with an `update` block**, like app-obs — see
`deploy/ci.json`. The orchestrator holds long-lived iroh tunnels and a Postgres
pool, and app-lb's update flow re-probes upstreams after the commands run, so "it
exited 0 but never came back" is a failed deploy rather than a green one.

```bash
heyctl apply -f deploy/ci.json
heyctl update ci
```

Identity comes from app-lb: `x-auth-request-user` (the stable Google `sub`, and
the primary key), `-email`, `-name`. app-lb strips those unconditionally before
setting them, so they are trustworthy — but only on a gated deployment.

**An app-lb gate admits browsers and nothing else.** The split is
`Accept: text/html`, so curl, `git submit`, *and a page's own `EventSource`* all get
`401 {"error":"authentication required"}`. Hence `public_paths` covers
`/api/submit` (which verifies its own HMAC) and `/api/stream/` (which carries a
short-lived, job-scoped token minted by the page that opens it — and that page
was fetched through the gate).

app-lb has no roles, so `ci` keeps its own `ci_user` table keyed on the subject,
seeded from `CI_ADMIN_EMAILS`. Promotion from that list is sticky; dropping off
it does not demote, so a role granted in the UI survives an env change.

## Design notes

### Steps do not use the SDK's exec

`heyo-sdk`'s `Commands::run` posts `{command, cwd, env}` and never sends
`timeout_secs` — `CommandRunOptions::timeout` bounds the *HTTP client*, not the
guest. The firecracker serial path then caps every command at 30 seconds, which
no build survives. So steps go through the daemon's own
`POST /sandboxes/{id}/exec-operations`, which does take a guest timeout.

That route is also **idempotent by `operationId` and persisted**, and step ids are
derived from the run and job key rather than minted. So a JetStream redelivery
re-posts the same step and *reattaches* to the operation already running instead
of building twice.

### Source reaches the guest through exec, in chunks

Neither `Files::write` nor the daemon's upload route reaches a Firecracker guest:
both write into a host-side *mount*, which a sandbox does not have — the call
fails with `Mount not found: /workspace (available mounts: [])`. They also cap at
10 MB. Exec is the only transport that works on every backend.

The chunk size is measured, not chosen. The daemon renders a command as
`env … sh -lc '<script>'`, so the script is one argv entry and Linux's
`MAX_ARG_STRLEN` bounds it. Probed against a real guest: 32 KiB succeeds, 128 KiB
returns `bash: /usr/bin/env: Argument list too long`.

Anything reading *out* of a guest must end its output with a newline. The serial
path frames output with newline-delimited markers, so `base64 -w0` — one
unterminated line — hangs the operation in `running` forever.

### Artifacts leave the guest the same way, in chunks

`ci/upload-artifact` packs its `path` to a tarball in the guest, then reads the
tarball out through exec and `base64` — the daemon's file routes do not reach a
guest path in that direction either. The read is chunked (`dd … | base64`, 1 MiB
of raw bytes per exec) because the output side has no argv limit but does have a
clock: on firecracker every byte crosses the emulated serial console, and one
exec for the whole tarball meets one fixed guest timeout. At a flat 600 seconds
that held app-lb's artifact and not app-obs's, whose two binaries carry arrow and
parquet. Chunked, each exec has its own timeout regardless of the artifact's
size, and the whole transfer is bounded by the step's `timeout-minutes` — so a
genuinely enormous artifact fails as the step's timeout, with the chunk count in
the log, rather than as a daemon-side kill with a thousand lines of base64.

`alias:` is the moving half of an artifact's name. Every upload is tagged
`ci-<workflow>-<run>-<job>-<name>`, which addresses that one build for as long
as the store keeps it and is exactly wrong for "serve the newest": a deployment
pinned to `ci-…-00000004-release-retail` keeps serving that build until somebody
repoints it by hand, which is how a site ends up months behind its pipeline.
With `alias: retail-live` the run also moves that tag onto the manifest it just
stored, so a deployment names `retail-live` once and each pull takes the last
green run. The alias fails the step if it cannot be set — unlike a label, it is
what a deployment *resolves through*, and a run that stored bytes while leaving
the alias on the previous build has published nothing. `ci-` is refused as a
prefix, so an alias can never overwrite a per-run tag, and the name is validated
rather than mangled: `retail live` is an error, not a silent `retail-live`.

`public: true` on the step asks the `artifacts` sink to mark the blob public
once it is named: `PUT /public/{digest}`, which opens anonymous `GET`/`HEAD
/blobs/{digest}` for that digest and nothing else. The resulting
`{CI_ARTIFACT_URL}/blobs/{digest}` is logged as `[ci] public link: …`, recorded
in `ci_artifact.public_url`, and shown on the run page. A store too old to have
the route fails the step with the fix in the message rather than storing a
private artifact under a workflow that promised a public one; the disk and S3
sinks have no public links and say so in the log instead. Note that
`.ci/install.sh` resolves *tags*, which stay behind the key — the public link is
for whoever was handed it.

Both directions end with a hash check. Every chunk exec exiting 0 says the shell
ran; the sha256 says the bytes are the ones the guest holds, and a mismatch
(`UploadCorrupted`, `DownloadCorrupted`) is treated as a corrupt guest and the VM
destroyed rather than repooled.

### Job subjects are sharded per runner

`WorkQueue` retention deletes on ack, so the stream's depth *is* the backlog. The
cost is that JetStream permits only one consumer per subject, which is why
queue-fn documents itself as single-instance. Sharding the subject by runner
sidesteps it: one durable consumer per runner, filters that never overlap, and
several orchestrators can run at once as long as they own disjoint runner sets.

Two disjoint spaces, and the `r`/`n` segment is load-bearing:

```
<prefix>.job.r.<runner_id>     pinned to one host
<prefix>.job.n.<network_id>    any online host in that network
```

Without it, a network named like a runner would produce overlapping filters and
two consumers would silently eat each other's work.

**Postgres commits before NATS does, so the publish has a rollback.**
`queue_job` moves a job `pending → queued` and only then publishes; a failure in
between would leave a row claiming to be queued with nothing on the queue, and
nothing reconciling the two — a job that never runs and never errors. So a failed
publish returns the job to `pending`, which makes the scheduler's own retry the
repair. `Nats-Msg-Id` collapses a duplicate, so retrying is safe even when the
message did land after all.

One publish failing does not abort the rest: the run's other jobs are still
scheduled, because one unreachable subject should not hold up a whole run.

`advance_run` is otherwise driven only by a submit and by jobs finishing, so a
run whose jobs *all* failed to publish would have nothing left to nudge it. The
lease loop re-runs the scheduler for any active run with a pending job —
idempotent by construction, since `queue_job` only moves a job that is still
pending and a job waiting on `needs:` simply is not ready.

A queue message carries **ids only**. The expanded plan lives in `ci_job.plan`,
so a redelivery runs exactly what the original delivery would have, even if the
branch moved underneath it.

### Connecting to it

```bash
CI_NATS_URL=nats://127.0.0.1:4222      # comma-separated for a cluster
CI_NATS_SUBJECT_PREFIX=ci              # namespaces both streams and every
                                       # subject and durable consumer name
```

The prefix is interpolated verbatim, so it is charset-checked at startup —
`[A-Za-z0-9_-]`. Two installations sharing a NATS server need different prefixes
or they share a work queue.

For a broker exposed through an HTTPS ingress, set `CI_NATS_URL` to its
`wss://host/path` endpoint. The ingress must support WebSocket upgrades and the
broker must enable its WebSocket listener; an ordinary HTTPS URL is not a NATS
transport. CI selects the AWS-LC Rustls provider before opening TLS connections,
so WSS also works when dependencies enable both Rustls crypto providers.
Regional instances of the same CI app must share the database and NATS prefix;
using WSS does not provide broker failover or transfer job-execution ownership.

**Four ways to authenticate, and exactly one may be set.** They are not a
precedence order: naming two is a startup error, because guessing which an
operator meant is how a process authenticates as the wrong principal.

| | |
|---|---|
| `CI_NATS_USER` + `CI_NATS_PASSWORD` | Both or neither. A user alone is not a token, and either half alone is refused rather than guessed at. |
| `CI_NATS_TOKEN` | A bare token. |
| `CI_NATS_CREDS` | Path to a `.creds` file, read at startup. An unreadable path is a startup error, not a fallback to anonymous. |
| `CI_NATS_NKEY` | An nkey seed. |

Userinfo in the URL (`nats://user:pass@host`) still works and is the last
resort: any of the above overrides it, and startup **warns** when a credential
arrives that way, because a URL is visible in shell history, process listings and
container specs. The credential lives in `nats_auth::NatsEndpoint`, which has a
hand-written `Debug` that cannot print it — so a `{:?}` on `Config` cannot leak a
password. Only the sanitized server list is ever logged.

One trap specific to this deployment: the NATS **system** account is not a
substitute for a real one. JetStream cannot be enabled on it, so a `sys` login
connects successfully and then fails on the first stream.

### `ack_wait` is short, and the job says it is still running

A dispatcher extends its claim on a message with `AckKind::Progress` every 20
seconds for as long as a job runs, so `ack_wait` is 60 seconds rather than a
ceiling derived from `CI_MAX_JOB_SECONDS`. A build of any length is safe while
its dispatcher is alive, and one that *dies* releases its job in about a minute
instead of holding it for the whole job budget.

**`backoff[0]` and `ack_wait` are one setting.** nats-server overrides `ack_wait`
with the first entry of the backoff ladder whenever a ladder is set — verified
against a live server, not inferred. The ladder here used to start at one second
while `ack_wait` was configured as four hours, so the configured value was
discarded and every running job became eligible for redelivery a second after it
started; with `max_deliver` at four, a healthy build could burn all four
deliveries while doing nothing wrong, leaving a dispatcher that died with no
redelivery left to recover it. CI now leaves broker `BackOff` empty and uses
explicit delayed NAKs for application failure retries. This also avoids older
NATS servers rejecting a backoff list with unlimited delivery.

Binding also **reconciles an existing consumer**: JetStream returns the durable
that is already there and ignores the config passed with it, so an upgrade would
otherwise keep the old window and none of this would take effect. CI updates
acknowledgement timing and the delivery limit in place through create-or-update, without
deleting the consumer or discarding pending acknowledgements.

Transport delivery is unlimited: returning an unstarted job during drain does
not count as a failed execution. Migration 044 adds a per-job `preclaim_failures`
counter; only actual pre-claim errors increment it, atomically with the ownership
check. The fourth such failure marks the job failed. Retry delays follow that
counter, not the NATS delivery number. The existing queued-job waiting timeout
still applies; unlimited delivery does not promise an unlimited queue lifetime.

### Active CI instances, scoped job ownership

Every registered CI boot may execute work; no global owner is selected or
consulted. HTTP mutations are handled locally with their existing authentication.
Linux jobs atomically claim a row with their boot and attempt; another boot cannot
attach a VM, complete that attempt, or create its cleanup intent. Cleanup workers
consume durable intents with `FOR UPDATE SKIP LOCKED`. Shared deployment
reconcilers coordinate on the specific operation ID, not the whole CI system.

Claim rejection carries its transactional reason: a later resume cannot turn a
drain-rejected delivery into an acknowledgment of unclaimed work. Pre-claim retry
diagnostics and final failures update only jobs that are still unclaimed; a losing
regional delivery cannot overwrite the winning boot's status or error.

Managed retirement closes admission only on the addressed boot. Its existing
jobs finish and clean up while the peer continues taking new work. The retirement
receipt requires no local effects or owned job obligations, and a ready approved
survivor outside the retiring region. No authority transfers to that survivor:
it was already active. Retired boots cannot begin effects.

App-lb-managed CI keeps the existing `ci/deploy-controller` action. Application
acceptance/activation is required for adopted deployments, not never-adopted
installations with no application lifecycle settings. This does not migrate VM
ownership. Replacement pins the source boot, drains only
that boot, and conditionally updates the same app-lb deployment. Other regions
keep admitting work. Concurrent replacements are serialized per app-lb authority
and deployment, not globally. The old boot retires before the update request;
its replacement reconciles the saved intent and verifies the exact binary before
opening admissions. A lost response is reconciled, never treated as success.

Configured application authority and persisted adopted operations retain their
authenticated acceptance requirement. All three lifecycle settings must either
be absent on a never-adopted deployment or form a complete valid configuration.
This protocol does not install itself into older binaries. Orchestrator's regional
application update API owns release sequencing; CI observes its durable result.
Historical rollouts without a pinned source boot remain inspectable
and require explicit reconciliation; they are not silently adopted or completed.
An original process lost before submitting its update likewise requires explicit
reconciliation rather than letting a new boot replace an unidentified predecessor.

Configure `source.applicationLifecycle` in managed service metadata with `port`
and `tokenSecretPath`; resolve `CI_APPLICATION_LIFECYCLE_TOKEN` from that same
per-app HeyoSecret and configure `CI_APPLICATION_ORCHESTRATOR_URL`. Orchestrator
injects `HEYO_SERVICE_ID`, `HEYO_DEPLOYMENT_ID` and `HEYO_REGION`. CI exposes
authenticated `/api/lifecycle` identity and asynchronous
`/api/lifecycle/retirements/{commandId}` command/status endpoints. Transport uses
raw streaming bodies and base64url-no-pad metadata capped at 16KiB; this is not a
16MiB body envelope. The native artifact endpoint retains its separate 512MiB
limit. Full large-artifact transport parity has not been tested.

**This is not a completed or deployed managed two-region application.** The
legacy and v3 hierarchical managed controllers execute the pre-withdrawal barrier.
New managed deployments capture immutable per-endpoint creation recipes with
versioned secret references before creation and bind authenticated runtime receipts.
Lifecycle rollback creates fresh baseline identities; it cannot reactivate retained
retired boots. Existing endpoints without proven recipes fail closed. Scalar
previous metadata and `envRefCount` are not a creation recipe.

Managed `ci/deploy-controller` requires `with.archive-id` from the existing
publish/promote-service-archive path for the confirmed release SHA. It records an
intent, lets the release job finish, then asynchronously submits the ordinary
Orchestrator managed update. The CI run remains pending until platform bake and
exact boot/runtime verification of every regional target complete. An uncertain
submission replays the same operation and command. This does not use the old
direct app-lb self-replacement dispatcher. Composed full-stack acceptance remains
outstanding; the external-service binding is still single-deployment and must not
be used to label the singleton as a two-region service.

**Upgrade boundary:** old binaries do not participate in the new operation locks
or boot-scoped claims. Do not assume arbitrary mixed-version reconciliation is
safe. Finish or explicitly settle their outstanding operations and stop old
execution before enabling concurrent new execution. Preserve shared state and
existing VM identities; do not delete owner/job records to force a cutover.
Migrations 041/042 are additive; 043 scopes active rollout uniqueness to one
app-lb authority/deployment. Historical singleton tables remain for diagnosis,
but new processes neither read nor write their ownership state. This change alone
does not deploy two regional CI apps or prove database/NATS regional failover.

The exact-runtime Cloud transport must never wake stopped instances, retry, follow
redirects or silently substitute another backend. The public client checks echoed
backend identities and CI checks the target boot; existing Cloud exec/proxy is not
a fallback. Private backend safety verification and composed real-process/live
acceptance remain required. See the single acceptance checklist in
`docs/design/MULTI_REGION_DESIGN.md` for local evidence and remaining gates.

### Migrations

`migrations/*.sql` are re-executed on every startup with no tracking table —
heyosecret's approach. Every statement must be idempotent; additive changes are
`ALTER TABLE … ADD COLUMN IF NOT EXISTS`, because the `CREATE TABLE` above is a
no-op once the table exists.

**They are compiled into the binary.** `build.rs` embeds every `.sql` in the
directory, in filename order, so a deployed `ci` cannot be separated from its
schema. It used to read `CI_MIGRATIONS_DIR` at startup, which made the schema a
second thing to deploy, and the one time the two came apart the failure was a
binary refused by Postgres on its first query for a column its own migration
adds — not at startup, where a missing file would at least have been loud.
`CI_MIGRATIONS_DIR` remains for running *additional* SQL from disk, after the
embedded set and logged as such — never instead of it, so a stale setting left
in a supervisor conf cannot shadow the binary's schema. Unset is the default
and the right setting for every deploy.

Two things make that actually safe. **A Postgres advisory lock**, because
`CREATE TABLE IF NOT EXISTS` is *not* concurrency-safe — two sessions both find
the table absent and the loser dies on `pg_type_typname_nsp_index`, and two
instances starting together is normal here. And **a `lock_timeout` with retries**,
because `ALTER TABLE` needs `ACCESS EXCLUSIVE` on a table a live dispatcher is
inserting into; without a bound, a rolling deploy hangs a starting instance
behind a long build.

### An iroh ticket is bearer-equivalent

`mvm-ctrl/docs/cross-machine-hardening.md` is explicit: the `hey-proxy/tcp/0`
ALPN accepts any peer that knows the ticket, and the daemon cannot verify the
peer. A runner daemon with no `JWT_SECRET` therefore hands a host shell to
anyone who has seen a ticket that may have transited a log. Every tunnel is
probed once, unauthenticated, and a daemon that answers is refused —
`CI_ALLOW_UNAUTHENTICATED_RUNNERS=true` downgrades that to a warning for a
local-only loop.

### Storage

Postgres holds runs, jobs, steps, source descriptors, artifact metadata and the
pool. Step logs use a separate shared chunk table, so status queries do not fetch
log bodies. Appends and byte counts commit atomically; native completion commits
its logs with the completion evidence. Retention deletes shared chunks and clears
their metadata in one transaction. Database failures are not empty logs.

When upgrading from local log storage, drain and stop the old controller before
starting the new binary with access to its retained log paths. Startup imports
those files into Postgres without deleting the originals. Missing or unreadable
files block startup. Once imported, another regional instance needs no local log
files. Do not mix old disk-writing controllers with shared-storage controllers
or roll back the binary without a compatible log-storage plan. This storage
change alone does not authorize a second executor or prove regional failover.

### Operator-owned release policy

`CI_RELEASE_POLICIES` optionally supplies a YAML (or JSON) mapping from repository
URL to an operator-owned release policy. Inject it through the service's
HeyoSecret-backed configuration, outside repository workflow secrets, using
`ci-controller/release-policies` as the canonical configuration path. CI does not
read this policy from the submitted checkout. All regional CI apps must receive
the same configuration before using this mode.

Each policy contains `workflow_path` (the stable identity shown on the run),
`workflow` (the `on: release` YAML), `service_targets`, and optional `placements`.
Candidate `on: release` files are ignored for enrolled repositories; deleting or
renaming one does not remove the operator policy. Candidate validation workflows
remain candidate-owned. Partial submissions remain validation-only.

`submission_mode` defaults to `merge_and_deploy`, preserving existing behavior.
An operator can set `submission_mode: merge_only` to admit only the existing
unconditional `ci/merge-release` job after all submission validations succeed.
Deployment jobs and their target lookups are excluded from that submission;
the submitted source cannot select this mode. The retained job and policy digest
are persisted, so changing policy does not rewrite already admitted runs.
This option does not defer validation builds or create a daily build scheduler.
Do not enable it until operators are ready for automatic per-submit deployment
to stop. Update all regional CI apps before changing shared policy.

### Immutable release catalog (foundation)

The catalog is separate from `ci_release`, which records publication to Git.
`POST /releases` registers explicitly selected artifacts from one successfully
published and fully validated submission. It returns a bundle ID, a manifest
SHA256 and the manifest. `GET /releases` lists up to 100 bundles; pass the last
bundle's ID as `before` to continue. Both routes use the existing dashboard
admin/origin checks. Keep them behind app-lb's identity gate, **not** in
`public_paths`; authenticated browser requests use `Accept: text/html` even
though these endpoints return JSON. No repository submit token grants access.

Example registration body (IDs and workflow/artifact names come from CI):

```json
{
  "name": "2026-10-05.1",
  "publication_run_id": "the-successful-publication-run",
  "components": {
    "cloud": {
      "workflow": ".ci/workflows/cloud.yml",
      "artifact": "cloud-linux",
      "job": "build-linux"
    }
  }
}
```

CI resolves the immutable revision, artifact ID, producer, digest, size and
storage location from its own records. Registration rejects failed/incomplete
validation, unpublished source, artifacts outside that submission, ambiguous
producers, missing digests and runner-local disk artifacts. Concurrent identical
registrations return the same bundle; reusing a repository's release name for
different contents fails. A manifest cannot be edited through the API. Database
references prevent deletion of its artifact provenance. External artifact-store
retention must also retain catalog-referenced blobs; a database reference alone
does not prevent S3 lifecycle expiry or operator deletion.

Registration alone does **not** deploy a bundle, alter an environment's current
version, implement rollback, or add UI controls. A bundle only covers its
explicitly selected components. Path-filtered submit builds must not be
presented as a complete daily platform release. The build-only path below
freezes the revision and builds the configured component set independently.
Environment promotion must reuse those exact artifacts.
Stage automatic policy and production manual policy will be operator-owned;
manual deployment in an automatic environment needs an explicit hold/resume so
automation cannot immediately overwrite the operator's selected version.

### Manual and daily release builds

`CI_RELEASE_BUILDS` is an opt-in, operator-owned YAML map keyed by repository.
It selects the build workflows and their exact artifact producers, not deployment
targets. It does not change `git submit` or enable environment promotion.
Example (the workflow scope, network and component names must match the installation):

```yaml
https://github.com/Heyo-Computer/hws.git:
  workflow_id: public
  git_ref: refs/heads/main
  network: platform
  daily_utc_minute: 120 # 02:00 UTC; omit for manual builds only
  components:
    ci:
      workflow: .ci/workflows/ci.yml
      job: release
      artifact: ci
```

An admin can `POST /release-builds` with
`{"repository":"https://github.com/Heyo-Computer/hws.git","name":"2026-10-05.1","revision":"<full merged SHA>"}`.
Omit `revision` to freeze the configured branch tip observed at admission.
The SHA must be an ancestor of that branch, not an unmerged PR. Repeating a name
returns the same build; a name cannot select a different revision. Retry a failed
build under a new name. `GET /release-builds` returns recent builds, errors and
the existing CI run IDs. Both routes require dashboard admin identity and origin
checks, just like `/releases`; they must remain behind app-lb authentication.

The daily scheduler admits at most one `daily-YYYY-MM-DD` build per repository
after its UTC cutoff. Multiple CI instances use the same unique database row;
there is no global CI execution lock. After downtime it admits today's build
using the branch tip at recovery, not a fabricated historical midnight revision.
It does not backfill missed dates. Configure every instance with the same policy.

Admission atomically stores the exact source descriptor, policy, run membership
and expanded job plans. Existing CI scheduling and recovery execute those jobs.
Submit path filters do not reduce the build: every configured workflow runs,
with `changed()` evaluating against an unknown/full change set. Other job and
step conditions still apply; a skipped required producer cannot seal a release.
These workflows may run build/test shell and `ci/upload-artifact`, but not
deployment/publication builtins. Build admission strips upload aliases so it
cannot move `latest`. Explicit public download flags are preserved because host
self-update consumes public digest URLs; this does not select a running version.
Shell commands are trusted merged repository code and must themselves be build-only.

Only complete successful results produce a version-2 catalog bundle. It records
the exact revision, build ID and every component's digest, size and provenance.
CI adds dedicated `release-*` artifact-store tags as garbage-collection roots
before committing the bundle. Pin failures leave the build retryable without
rebuilding. A failed job or invalid producer fails only that release build.
The database retains artifact provenance; ordinary build-tag cleanup must not
delete release tags. Releasing these roots needs an explicit retirement policy,
not the short-lived build-artifact age limit.

This path currently requires `CI_ARTIFACT_SINK=artifacts`. Disk and S3 sinks fail
admission because they do not implement verified release retention. Older
version-1 catalog registrations do not acquire these pins automatically and must
not be treated as retained releases. No shared policies are changed by installing
this code; activation and environment promotion are separate steps.

### Environment promotion of retained releases

`CI_RELEASE_ENVIRONMENTS` is an optional operator-owned YAML map keyed by named
environment. Each entry contains `repository`, `workflow_id`, `mode` (`manual`
by default, or `automatic`), optional `network`, `workflow`, `service_targets`
and `placements`. Targets and placements use the existing mappings described
below. Environment names are installation-wide and each belongs to one repository;
use distinct names such as `hws-stage` and `retail-stage`. This is not an atomic
multi-repository release.

The embedded workflow uses `on: promotion`, with unconditional non-matrix jobs
forming one sequential `needs` chain. Supported actions are `ci/rollout-service`,
`ci/rollout-host-app-lb`, `ci/promote-service-archive`,
`ci/host-heyvm-maintenance` and `ci/deploy-controller`. Build, merge, shell and
bootstrap actions are refused. Artifact actions specify literal `workflow` and
`artifact` inputs from the retained bundle. Region order comes from the operator
workflow, not hardcoded region names or submitted repository changes.

Admin `POST /release-promotions` accepts
`{"environment":"hws-stage","bundle_id":"<catalog ID>","request_id":"<unique request>"}`.
Admission validates the retained version-2 manifest and artifact selection,
freezes the operator plan, and creates ordinary persisted CI jobs. Repeating the
request returns the same run; reusing its ID for a different bundle is refused.
One environment permits one promotion at a time; unrelated environments and CI
jobs are not locked. `GET /release-environments` shows policy mode, current and
previous successful bundles, active run, automation hold and recent history.
These endpoints use the same admin identity and origin checks as release builds.

Automatic mode selects the latest ready build by **build admission time**, not
completion time. An older slow build cannot displace a newer completed build.
Manual promotion holds automation, including in automatic environments. Failure
also holds automation and leaves the last successful bundle unchanged. A failed
partial rollout may leave mixed service revisions: inspect its deployment records;
the current bundle is the last complete success, not a live inventory claim.
Existing managed rollout recovery must settle before the active run is cleared.
Admin `POST /release-automation` takes `{"environment":"hws-stage","held":true}`
to hold future promotions. `held:false` resumes automatic policy only when no
promotion is active; it does not convert manual policy into automatic policy.
An active rollout finishes normally while held. Retrying a failed promotion uses
a new request ID; automation does not silently repeat an attempted release.
The app-lb control panel's `/releases` page exposes these controls and rollback
by promoting the previous retained bundle. Re-deploying the current bundle does
not erase the previous distinct rollback target. No rebuild occurs on rollback.

### Release target resolution

The operator workflow uses existing actions with logical aliases:

- `ci/rollout-service`: `with.target` resolves through `service_targets`, whose
  entries contain the existing service rollout target fields (`url`,
  `deployment`, `namespace`, `mount_path`, `revision_env`, `start_command`, and
  `working_directory`). Do not repeat those values in the action.
- `ci/promote-service-archive` and `ci/host-heyvm-maintenance`: `with.target`
  resolves through the existing trusted host-maintenance mapping. That **one
  mapping** owns Cloud URL, Orchestrator URL, archive owner, runner, and backend.
  In particular, a US host may be managed by an EU Cloud authority. Do not infer
  the API endpoint from the region name or repeat `url`, `runner`, or `user-id`.
- `ci/rollout-host-heyvmd` and `ci/bootstrap-host-heyvm` retain their existing
  target aliases. `placements` maps their **job IDs** to maintenance aliases for
  the coordinator host. Admission rejects a missing coordinator or one on the
  host being replaced, rather than waiting until deployment to discover it.

Admission validates the complete policy and resolves its targets before creating
any run. Each release job stores the expanded instructions, a policy/target
digest, and non-secret host mapping snapshots in its existing JSON plan. Restart
and published-release retry reuse those plans, not newly loaded policy YAML.
Before merge, CI rechecks host mappings and resolves the policy's credential
expressions. Host operations also refuse changed mappings at execution. No
credential values are stored in the policy snapshot.

This does **not** add a global execution lock, an active/standby role, or a new
coordinator. Region sequencing is the release's existing `needs` DAG. Other CI
runs continue independently. The DAG orders one release, not separate concurrent
releases; existing per-target conflict checks still apply. This policy mechanism is not a sandbox for hostile
repository code; validation credential scoping remains a separate responsibility.

[`deploy/regional-release-policy.example.yml`](deploy/regional-release-policy.example.yml)
is a region-neutral example for the private Heyo repository. Region names, count,
endpoints, coordinator placements and sequence are operator configuration, not
built-in US/EU choices. Adding China or another region requires its target mappings
and jobs in this operator policy, not Rust changes or candidate workflow edits.
The example completes Cloud, heyvm and heyvmd in each configured region, followed
by mandatory public-health sampling before the next region starts.
The sampling requires HTTP 200, not redirects;
it supplements the existing exact deployment receipts and is not proof of
zero-downtime failover. It uses normal maintenance, not the legacy bootstrap flag.
Confirm installed updater capability before provisioning this example. Runtime
variables must not be used to switch between bootstrap and maintenance mid-run;
choose that path in the operator policy itself.

Migration order: install and verify compatible CI code one configured region at a time; provision
the reviewed policy identically through HeyoSecret; then submit the private
revision normally. Keep existing repository release YAML until policy activation
is confirmed, then remove that duplicate. Do not resubmit the old conflicting
release in the transition. Existing admitted runs retain their original plans;
cancel an unmerged obsolete release and submit anew rather than rewriting it.
Without a policy entry, repositories retain the existing workflow behavior.
Invalid configured policy is an admission error, never a fallback to candidate
release YAML. Live API reachability, permissions, and health can still change
after admission; these checks do not promise that deployment cannot fail.

### One submission across validation workflows and deployment

A repository can define exactly one trusted workflow with `on: release`, alongside
its `on: submit` validation workflows. CI persists the selected validations and
the release run together. The release run waits for every selected validation;
failed, cancelled, skipped, carried-over, or error-tolerant evidence blocks it.
The membership survives controller restarts. `git submit` prints a submission
completion link; the submit response's `submission` field identifies this release
run, and its run-status response includes the validation run IDs in `validations`.
Individual successful validation runs do **not** mean deployment has finished.

The release workflow must have one unconditional merge job containing only
`ci/merge-release`, with `manifests: '[]'` and no tags. Every deployment job must
depend on that merge, directly or transitively. This preserves the exact validated
commit and lets deployment reuse its artifacts. A `ci/deploy-controller` step must
be last and its job must depend on all other release jobs. Sequence regional
deployments with `needs`; a failed regional job then prevents the next one.

Validation workflows in a coordinated submission cannot contain merge or deploy
actions. `--only`, explicit workflow selections, and individual reruns are
validation-only and cannot publish or deploy: the `on: release` workflow is not
planned for them at all, so its jobs' placement (a host pinned in a network this
instance does not serve, say) cannot refuse the submit. The submit client computes changed
paths across the full trunk-to-feature diff, including earlier feature commits.
For a failed deployment of an already-merged revision, reconcile its remote
operation first, then use a full `git submit --submit-empty --ref <revision>`.
This creates fresh validation runs and a new coordinator rather than rewriting
the failed run or substituting evidence in its frozen validation membership.

This repository's `.ci/workflows/regional-release.yml` sequences public app-lb
and Orchestrator updates as `merge → us3 → eu1 → controller`. The three build
workflows are validation-only; a coordinator change selects all three so every
referenced artifact is built from the same submission. Component-only changes
select only their matching deployments, including CI when the shared host-bundle
parser changes. Private Auth/Cloud/heyvm deployment remains a separate repository
workflow. NATS is not part of CI's artifact or replacement.

Before activating coordinated submissions, both regional app-lb hosts must have
the verified native bootstrap and correlated rollout APIs installed, the CI
controller must support the rollout actions, and service rootfs artifacts must
be pinned. Provision repository-scoped `CI_HOST_APP_LB_TARGETS` entries named
`app-lb-us3` and `app-lb-eu1` with each host's exact deployment/namespace/public
health mapping. The registered workflow resolves `GIT_AUTH_TOKEN`,
`APP_LB_US3_TOKEN`, and `APP_LB_EU1_TOKEN` through its HeyoSecret-backed secrets;
no values belong in YAML. The existing controller-deployment mapping owns the
final CI replacement. Until these prerequisites are verified, use only
validation-only submissions such as `git submit --only ci`; a pushed workflow
or passing build does not establish regional deployment readiness.

For artifact reuse, `ci/download-artifact` accepts `with.workflow` naming the exact
validation workflow path. CI resolves it only within this submission's frozen,
successful membership, never from an arbitrary run ID or a latest-artifact tag.
`ci/promote-service-archive` takes `workflow`, `artifact`, optional producer `job`,
and `path` naming a packaged tarball inside that artifact, plus Orchestrator `url`,
`token`, `user-id`, and archive `name`. It verifies the artifact digest, uploads the
selected bytes through the service archive API, and records release provenance.
Its outputs are `archive-id` and `sha`; pass the archive ID to `ci/deploy-service`.
Package runtime dependencies and startup scripts during validation, not deployment.
`ci/deploy-controller` also accepts `workflow` for its validated binary artifact.

This follows the private CICD contract: all validation, then merge, then required
deployments, with controller replacement last. Host-daemon maintenance is a
separate contract: it must stop new placement, drain leases, release its own job
sandbox before waiting, update, verify, and uncordon. A generic service deployment
does not implement that host maintenance protocol.

Install a controller supporting `on: release` **before** migrating live workflows.
Older controllers do not coordinate this trigger. Existing standalone workflows
remain supported; the repository's bootstrap CI workflow retains its own release
steps until that migration. These engine capabilities do not by themselves enable
or verify a production two-region rollout.

### Host heyvm maintenance (opt-in)

`ci/host-heyvm-maintenance` must be the last step of a CI-owned VM job, with no
`continue-on-error` on the action or job. It requires the normal publication gate,
a confirmed merged release, and a successfully published service archive from
that exact release. Arbitrary external archive IDs cannot authorize maintenance.
Publication records the archive owner, compressed archive digest, and SHA256 of
the unambiguous regular ELF `heyvm` executable inside the archive; Cloud's
`sha256` refers to **that executable**, not the tarball.

The operator must configure `CI_HOST_MAINTENANCE_TARGETS` as a JSON object:

```json
{"eu1":{"repository":"https://github.com/your-org/your-repo.git",
  "runner_hd_id":"hd-app-lb-runner-id","backend_server_id":"cloud-backend-id",
  "cloud_url":"https://cloud.example","orchestrator_url":"https://orch.example",
  "artifact_user_id":"archive-owner","target":"stage-eu1-host-heyvm","region":"eu1"}}
```

When the environment variable is absent, the controller reads the same JSON
from the fixed HeyoSecret path `ci-controller/host-maintenance-targets`. An
explicit environment value takes precedence. Repository workflow secrets cannot
replace this operator-owned mapping.

Runner `hd` IDs and Cloud `backendServerId` are **different namespaces**. The
mapping explicitly attests their association and the archive database/storage
association: Orchestrator's `CLOUD_INTERNAL_URL` must use the **same Cloud archive
database and storage** as `cloud_url`. CI cannot discover or prove this from a
public hostname. `target` is an opaque daemon-layout selector, not a revision;
the current daemon supports the legacy `stage-eu1-host-heyvm` layout only. Do not
infer that a us3 host supports it from the region name.

```yaml
- uses: ci/host-heyvm-maintenance
  timeout-minutes: 30
  with:
    runner: eu1                     # trusted mapping alias, not either backend ID
    url: ${{ vars.CLOUD_URL }}       # must equal the mapping's cloud_url
    token: ${{ secrets.CLOUD_KEY }}  # direct secret reference, re-resolved on restart
    archive-id: ${{ steps.publish.outputs.archive-id }}
```

CI durably fences claims and placement on that runner only, stops/releases its own
job VM before draining other running jobs and active pool leases, then uses
`POST /internal/mvm-ctrl/backend-servers/host-heyvm/upgrades` with a persisted
64-character `maintenanceId`. It reconciles through singular
`GET /internal/mvm-ctrl/backend-servers/host-heyvm/upgrade/{maintenanceId}`. HTTPS
is mandatory and bearer redirects are disabled. No idle/service VMs are deleted
to accelerate drain. Queued work retains its delivery and retry budget; unpinned
work can select another runner. The step, job and run do not succeed on admission.
Only an exact `completed` operation with matching backend, target, archive owner,
archive ID, executable digest and operation identity releases the fence.
Both `host_heyvm_upgrade` and Cloud's operation-bound
`host_heyvm_upgrade_receipt_v1` receipts use these checks; unknown types fail closed.

Cancellation, timeout, missing identity, changed configuration and terminal
failure **retain the CI cordon**, even if Cloud uncordons its own backend. An
expired/unknown lease blocks drain rather than proving the VM stopped. Operators
must reconcile the persisted operation and host before explicitly repairing an
unresolved fence; this action has no automatic failure-unlock or force option.
`ci_host_work` records each claimed delivery/runner until verified release.
Cancelled VM acquisition, interrupted delivery, or failed stop can leave durable
drain evidence requiring operator reconciliation; terminal job status alone is
not proof that host work stopped. Retries cannot clear another delivery's record.
Deadlines include VM release and drain, survive restart, and cap HTTP retries.

When Cloud completed an upgrade but CI rejected its receipt, a repository submit
bearer can POST `/api/runs/{run_id}/maintenance/{operation_id}/recover`.
Recovery GETs the original Cloud operation, checks every identity and the trusted
mapping, and requires the original published release. It never POSTs an upgrade.
Only a failed run with this one failed job and no unresolved execution is eligible;
cancelled runs or skipped jobs that previously executed are refused. Recovery
records the original error and receipt in `ci.host.maintenance.recovered.v1`,
marks the proven operation successful, releases its fence and resumes untouched
skipped jobs in the same run. Existing logs, attempt IDs and status events remain.
A repeated call does not repeat maintenance or recovery. This is distinct from
`rerun-failed`: a published-release retry preserves its original publication,
but cannot authorize a new merge or bypass unresolved maintenance.

Deploy the new Cloud endpoint **and every Cloud worker's cross-instance operation
locking** before enabling this action. Older Cloud cannot execute the plural POST,
and CI never falls back to the legacy non-idempotent singular POST. This feature
does not authorize any production host upgrade or establish regional readiness.
All CI dispatchers sharing these runners must also run this fencing-aware engine;
drain or explicitly reconcile work started by older engines before enabling it.

### Standalone validation, merge, version bump, build and deployment

The opt-in [release workflow example](release-example.yml) connects these stages
using built-in actions. It is outside `.ci/workflows/` and does not enable live
publication automatically. Use only trusted registered workflows with explicitly
granted HeyoSecret credentials; branch protections and repository permissions
still apply. No action creates a GitHub release. Component tags require an
explicit `with.tags` policy.

- `ci/merge-release` requires successful, fresh validation jobs in `needs`,
  including every matrix cell and every declared validation step. Skipped,
  carried-over or error-tolerant validations cannot authorize publication.
  `with.manifests` is a JSON array of `package.json`/`Cargo.toml` paths;
  `with.token` is the Git HTTPS credential. The public submit client separately
  captures `repository.defaultBranch` and `repository.releaseBaseSha` from
  `origin/HEAD` and its remote-tracking tip. Fetch trunk before submission. That
  base must be an ancestor of the submitted source, and target trunk must still
  equal that base at publication. The submitted feature branch is not advanced.
  Missing release metadata prevents release publication but does not prevent
  ordinary builds.
  Publication fast-forwards target trunk to the source plus a deterministic
  version commit, never merges unvalidated concurrent trunk changes. Resubmit and
  revalidate if trunk moved. Use the Git-patch submission format; legacy bundles
  and `--archive` are rejected.
- Changed components receive a major bump for breaking changes, minor for
  conventional `feat` commits, otherwise patch. Unchanged components are omitted.
  Explicit package versions and adjacent Cargo/npm lockfiles are supported;
  inherited Cargo workspace versions are rejected. Empty changes produce no
  extra version commit. Outputs are `sha`, `ref`, and JSON-string `versions`.
- Optional `with.tags` maps declared manifests to tag prefixes, for example
  `'{"ci/Cargo.toml":"ci-v"}'`. Only changed manifests produce tags. CI pushes
  lightweight component tags and the version commit atomically, with exact-ref
  leases. Conflicting tags or moved trunk refuse publication; retries reconcile
  the same candidate and never overwrite a tag at a different commit. Existing
  workflows without this field remain tagless.
- CI persists the candidate before pushing. A lost acknowledgement can retry
  only that same candidate, never generate another version bump. The run page's
  **Release** section and authenticated `/api/runs/{run_id}/release` distinguish
  prepared, uncertain, and confirmed publication and show both source/release SHAs.
- `ci/checkout-release` makes the runner fetch and check out the confirmed
  release commit directly from Git. Use its `sha` output for build stamps.
  Build jobs must run this explicitly, then
  build/package from those files. Original `ci.sha` remains the validated source.
  Native Intel Mac and Windows jobs support the same action through a
  lease-fenced command to fetch that exact release commit themselves.
- `ci/publish-service-archive` uploads an already-built tarball (`with.path`,
  relative to the job working directory) using Orchestrator presign, upload,
  and finalize APIs. It also requires `url`, `token`, `user-id`, and `name`.
  It records the finalized archive's release SHA and returns `archive-id` and
  `sha`. The job must have completed `ci/checkout-release`. This is distinct
  from the generic artifact sink; a deployment cannot substitute its tag/URL.
- In release workflows, `ci/deploy-service` accepts only an archive recorded
  for this run's confirmed release and the same Orchestrator. The revision guard
  and deployment UI use the release SHA, not the pre-bump source SHA.

Archive APIs lack idempotency keys: a retry can leave an extra uploaded archive,
but failed/uncertain finalization never authorizes a deployment. Publication,
release and deployment state write NATS outbox events transactionally. These
actions do not change app-lb, namespaces, existing VM pages, or Retail.

### One-time native heyvm host bootstrap

Host installer failures retain timestamped exception frames and allowlisted service
observations in the operation journal. Service-check failures identify the failed
check, observed systemd state, executable paths and process-group members when
available. The original failure is persisted before rollback; rollback failures
are recorded separately. Launcher logs also emit `HEYO_HOST_UPDATE_FAILURE` and
`HEYO_HOST_ROLLBACK_FAILURE` JSON records. These omit command arguments, environment
values, subprocess output and arbitrary exception messages. Existing historical
failures cannot acquire observations that were not recorded at the time.

Explicit bootstrap recovery can also investigate a `rollback_failed` receipt.
It releases the runner only after read-only verification proves that the saved
predecessor files and running executable match, the backend identity is healthy,
and the runner reconnects. The original failed run and host journal remain
unchanged; the recovery is recorded separately as `rollback_verified`.

`ci/bootstrap-host-heyvm` is a release-only, final-step action used to install the
managed host heyvm service before normal host maintenance is available. It accepts
only `target`, a direct `${{ secrets.NAME }}` app-lb namespace-admin `token`, and
the frozen validation `workflow` and `artifact` names. The coordinator must run in
a CI-owned VM on a runner other than the target. The artifact must have been
uploaded as a public artifact to CI's configured HTTP artifact sink and contain
exactly one `*heyvm.tar.gz` with exactly one ELF `heyvm`.

Set `CI_HOST_HEYVM_BOOTSTRAP_TARGETS`, or preferably store the same JSON at the
operator-only HeyoSecret path `ci-controller/host-heyvm-bootstrap-targets` (the
environment variable wins):

```json
{"eu1":{"repository":"https://github.com/Heyo-Computer/heyo.git","app_lb_admin_url":"https://eu1.heyo.computer/app-lb-admin","app_lb_deployment":"app-lb-eu1","app_lb_namespace":"default","runner_hd_id":"target-runner-id","backend_server_id":"eu1-backend-id","executable":"/usr/local/bin/heyvm","unit":"heyvm.service","state_dir":"/var/lib/heyvm-host-update","config_json_path":"/etc/heyvm-host-update.json","systemd_drop_in_path":"/etc/systemd/system/heyvm.service.d/host-update.conf","local_health_url":"http://127.0.0.1:4455/health","target_alias":"eu1","region":"eu1"}}
```

Prerequisites are app-lb's authenticated admin launcher and job-history APIs, a
namespace-admin token in the workflow secret named by `token`, the target runner
registered with this controller, and a confirmed merged release whose exact
successful frozen validation produced the artifact. Delivery is durably armed
before its single launcher POST; restart recovery only adopts exactly one update
job. Cancellation, timeout, mapping drift, missing identity, ambiguous launcher
history, failure, or rollback retain the target fence. Only an exact authenticated
success receipt uncordons it.

The coordinator polls `/deployments/{launcher}/jobs` and selects the persisted
job ID, preserving namespace-scoped access. It does not require fleet-wide
`/jobs/{id}` access. Missing or duplicate job IDs and mismatched deployment or
job-kind identities retain the fence; the selected job still requires the exact
success receipt before uncordoning.

The initial eu1 installation is explicitly a **one-time** use: run one release job
with `target: eu1`, verify its deployment event reaches `passed`, then use normal
`ci/host-heyvm-maintenance` for subsequent upgrades. Do not rerun bootstrap to
repair a retained fence; reconcile the persisted operation and launcher job.

### Managed heyvmd rollout

`ci/rollout-host-heyvmd` uses the same durable coordinator, runner fence, drain,
single app-lb launcher delivery, receipt reconciliation, and explicit recovery
contract as `ci/bootstrap-host-heyvm`. Its inputs are the same closed set:
`target`, direct `${{ secrets.NAME }}` `token`, frozen validation `workflow`, and
public `artifact`. Unlike the bootstrap action, it selects the exact root
`heyvmd` ELF from the validated inner `heyvm-*-unknown-linux-gnu-x86_64.tar.gz`;
it never installs or renames `heyvm`.

The trusted operator mapping remains at
`ci-controller/host-heyvm-bootstrap-targets`. A heyvmd target adds the required
`process_manager`, whose only accepted values are `systemd` and `supervisor`.
`unit` is the existing systemd unit (for example `heyvmd-eu1.service`) or the
existing Supervisor program name (for example `heyvmd-ci`). `executable` must be
the existing `/usr/local/bin/heyvmd`. All other fields are unchanged from the
mapping above; config/drop-in paths remain required for schema compatibility but
are not read or modified by heyvmd rollout. The action does not modify units or
VMs.

Systemd `KillMode=process` remains required for heyvm. For heyvmd only,
`KillMode=control-group` is also accepted when the unit's cgroup and every child
cgroup contain only its main daemon PID. Missing cgroup evidence or any other
process blocks the operation. Local-runner development mode cannot verify a
regional tunnel and is rejected for daemon rollout.

The installer durably journals and retains the previous binary, verifies the
predecessor disk/running identity, atomically replaces only the daemon binary,
restarts through the selected manager, and verifies changed PID/start time plus
the exact disk and `/proc/PID/exe` hashes. Failure restores and restarts the old
binary; rollback failure is terminal and retained. A local health response alone
cannot release the fence: after the exact launcher receipt, CI evicts its old
runner tunnel and must establish a fresh authenticated tunnel probe to that
runner. Failed reconnection keeps the operation polling and the runner fenced.

Complete operator mapping examples (replace identities and URLs with the trusted
values for each region) are:

```json
{
  "heyvmd-eu1": {"repository":"https://github.com/Heyo-Computer/heyo.git","app_lb_admin_url":"https://eu1.heyo.computer/app-lb-admin","app_lb_deployment":"app-lb-eu1","app_lb_namespace":"default","runner_hd_id":"<eu1-hd-id>","backend_server_id":"<eu1-backend-id>","executable":"/usr/local/bin/heyvmd","unit":"heyvmd-eu1.service","state_dir":"/var/lib/heyvmd-host-update","config_json_path":"/etc/heyvmd-host-update-unused.json","systemd_drop_in_path":"/etc/systemd/system/heyvmd-eu1.service.d/host-update-unused.conf","local_health_url":"http://127.0.0.1:<eu1-backend-port>/health","target_alias":"heyvmd-eu1","region":"eu1","process_manager":"systemd"},
  "heyvmd-us3": {"repository":"https://github.com/Heyo-Computer/heyo.git","app_lb_admin_url":"https://us3.heyo.computer/app-lb-admin","app_lb_deployment":"app-lb-us3","app_lb_namespace":"default","runner_hd_id":"<us3-hd-id>","backend_server_id":"<us3-backend-id>","executable":"/usr/local/bin/heyvmd","unit":"heyvmd-ci","state_dir":"/var/lib/heyvmd-host-update","config_json_path":"/etc/heyvmd-host-update-unused.json","systemd_drop_in_path":"/etc/supervisor/conf.d/heyvmd-host-update-unused.conf","local_health_url":"http://127.0.0.1:<us3-backend-port>/health","target_alias":"heyvmd-us3","region":"us3","process_manager":"supervisor"}
}
```

The parent release workflow invokes one final step per target with this input
shape: `uses: ci/rollout-host-heyvmd`, `with.target` equal to the mapping key,
`with.token` a direct app-lb namespace-admin secret expression, and
`with.workflow` / `with.artifact` naming the frozen validation artifact that
contains both Linux executables.

After restarting the service, bootstrap retries transient health connection
failures and HTTP 502/503/504 responses for 30 seconds. A reachable endpoint with
the wrong backend identity still fails immediately. It also waits up to 30 seconds
for systemd activation and temporary heyvmd child processes to finish; the daemon
must still be the sole control-group member before verification succeeds.
For `Type=simple`, an active unit can still be running
`/usr/lib/systemd/systemd-executor` before it executes the configured service.
That transient process is retried within the same deadline, never accepted as
the service. An incorrect configured executable or any other unexpected running
executable is still rejected. The same check applies during rollback.
Rollback journals retain
the original exception type and installer source line, plus a separate rollback
failure when applicable; command arguments and exception messages are not logged.

For a failed attempt whose installer succeeded or restored its predecessor, explicitly invoke
`POST /api/runs/{run_id}/bootstrap/{operation_id}/recover` with that repository's
submit bearer token. This is a production scheduling-state change, not a status
query. It requires the original terminal launcher receipt and unchanged trusted
target mapping, then launches a fresh **read-only** app-lb verification job to check
the host journal, active executable, config, drop-in, permissions, environment,
and health identity. It never downloads or reinstalls the binary or restarts the
service. Missing history, drift, or conflicting operations retain the fence.

Successful recovery atomically releases this operation's fence and emits
`ci.host.bootstrap.recovered.v1` in the run's `/events` API. The original failed
run, job, step, and deployment history remain failed; the recovery response and
audit event are the evidence of recovery. Repeating a completed recovery returns
`already_passed` without running another verification job. A verified rollback
returns `rollback_verified` and supersedes the failed bootstrap operation, allowing
a new attempt without marking the original deployment successful. Recovery checks
the exact predecessor files, permissions, executable hashes, stable process, and
backend health; a `rollback_failed` journal cannot release the fence. Repeating a
completed rollback recovery returns `rollback_verified` without another verifier.
A request interrupted
before commit retains the fence; inspect events before retrying. Verification
launcher records are retained for audit, not automatically deleted.

### Host app-lb executable rollout

`ci/rollout-host-app-lb` is a release-only action with `target`, secret `token`,
`workflow` (frozen validation workflow path), and `artifact` (bundle name).
Job/step `continue-on-error` is rejected for this action.
It does not accept paths, service names, commands, revisions, or digests from
the workflow. The operator supplies `CI_HOST_APP_LB_TARGETS` as JSON. When
that environment variable is absent, the action reads the same JSON from
the fixed HeyoSecret path `ci-controller/host-app-lb-targets`, using the
controller's existing HeyoSecret configuration. This operator-owned path is
outside workflow secret prefixes; job variables cannot select or override it.
Missing or invalid configuration refuses the rollout. Explicit environment
configuration takes precedence, including invalid values (no fallback).

Example mapping:

```json
{
  "eu1": {
    "repository": "https://github.com/Heyo-Computer/heyo-public.git",
    "url": "https://admin.eu1.heyo.work",
    "deployment": "app-lb-host-controller",
    "namespace": "default",
    "health_url": "https://admin.eu1.heyo.work/healthz"
  }
}
```

This example does not enable a target or release workflow. The host requires
the matching operator-owned [host update mapping](../app-lb/README.md#correlated-host-executable-rollout)
and bootstrapped correlated API/helper support. API and health URLs require
HTTPS; redirects are never followed. Host and CI must agree on the configured
artifact store and public health URL. The validated blob must be public for
the helper's credential-free pinned download.

The action uses successful frozen artifact membership at the exact confirmed
merged SHA, verifies the bounded bundle and derives its executable digest from
`dist/app-lb`, `dist/REVISION`, and `dist/SHA256SUMS`. It stores the immutable
request, original executable/configuration hashes and deadline in Postgres
before POST. Secrets and live host configuration are not persisted.

Every reconciliation first GETs the same operation ID. Admission and systemd
launch success do not complete a job: CI requires exact operation identity,
verified replacement completion and a separate public 2xx health response with
the exact immutable `x-heyo-revision`. Cancellation/deadline fences late success
and prevents further admission, but does not roll back already accepted work.
An uncertain helper launch/switch remains blocked for operator reconciliation,
never retried as a different operation or through legacy commands.

This action does not provide regional ordering by itself. Parent release jobs
must use sequential `needs` edges and must not tolerate rollout failure. No
repository workflows are enabled by this primitive.

#### Preparing the initial native bootstrap manifest

`ci --prepare-host-bootstrap plan.json inspection.json app-lb.tar.gz manifest.json`
is an offline operator command. It does not load CI service configuration or
connect to Postgres, NATS, or a host. It prepares a private, atomically published
manifest without overwriting an existing file, and prints only its path,
canonical SHA256 and `prepared` status. Preparation is **not deployment or
release authorization**.

The plan contains `operation_id`, the expected 40-hex build `revision`, the exact
native host `config`, `mapping_path`, and `files`. Each file has `path`, numeric
`mode`, and exactly one of `after_base64`, `preserve: true`, or
`supervisor_environment: true`. Omit inactive keys. Do not supply `before_sha256`:
the command derives it from the native `inspect` response. The ordered file list
must match both `config.config_files` and the inspection, including the mapping
file. That mapping requires explicit non-secret `after_base64` bytes that decode
to the same `config`. Literal modes are 384 (0600) or 420 (0644); preservation
and the native Supervisor edit require the inspected existing mode.

Use `preserve` or the native Supervisor edit for secret-bearing files; never
copy their contents into `after_base64`, inspection output, or logs. The command
retains hashes and typed edits without reading the original host file contents.
It verifies the supplied bundle's revision and executable checksum, derives the
artifact/helper/executable digests, and emits compact recursively sorted native
manifest JSON. JSON inputs/output are bounded to 4 MiB and 32 config files;
the shared host-bundle parser enforces archive limits.

Obtain the bundle from trusted CI evidence and the inspection from an authorized
native host inspection; this offline command cannot authenticate their source
or establish that the inspection is still current. Native admission must still
check root ownership, paths, current source generation, all file hashes and
loaded service identity. Delivery/reconciliation is a separate bootstrap step:
this command does not send or retry legacy update POSTs. After replacement, use
the authenticated bootstrap-operation GET for completion, not the mapped legacy
update endpoint, which is deliberately disabled.

`ci --check-host-bootstrap TARGET manifest.json INTENT_SHA256` performs that
completion check once, without loading the CI database or broker. `TARGET` must
exist in operator-owned `CI_HOST_APP_LB_TARGETS`; supply its namespace-admin
credential through `CI_HOST_APP_LB_TOKEN` from the managed secret configuration,
not a command argument. Existing operator Basic credentials are also supported
through `CI_HOST_APP_LB_USER` and `CI_HOST_APP_LB_PASSWORD` when no bearer token
is supplied; no new token or access-control change is required. These credentials
are sent only to the mapped admin endpoint, never public health or artifacts.
The manifest bytes must match the previously recorded
hash and the target's deployment, namespace and public health URL.

The command checks the authenticated native receipt's operation, intent, source,
target, journal and helper-unit identities, completed status, and verified
readiness; it then independently requests public health without credentials and
requires one exact revision header. Both requests forbid redirects and have
timeouts; the receipt is capped at 64 KiB. Only verified completion exits zero.
Missing/old endpoints, busy helpers, mismatched receipts and unavailable health
exit nonzero without sending any POST, changing IDs, or retrying installation.
It can be rerun for the same manifest/intent. The native GET can persist success
and release its fence; this is an authenticated reconciliation action, not an
unauthenticated status probe. Initial launch delivery remains separate.

`ci --deliver-host-bootstrap TARGET inspect plan.json app-lb.tar.gz inspect-delivery.json`
registers an operation-specific static launcher and invokes the pinned native
inspection. Save its JSON output as the inspection input above. Poll with the
**same command and journal** if the job is still running. Then prepare the
manifest and invoke
`ci --deliver-host-bootstrap TARGET admit manifest.json app-lb.tar.gz admit-delivery.json`.
This uses the same managed target/token configuration as completion checking.
Only use public artifacts tied to successful trusted CI evidence.

This is an explicitly authorized bootstrap operation, not an ordinary release
fallback. One designated coordinator owns each operation and its journals; no
other writer may alter its launchers. Each phase gets a new, never-reused static
deployment ID with an exact `.invalid` hostname, maintenance 503, and an
unresolvable upstream. It creates no VM and changes no existing service route.
The fixed transport requires root and Python 3, downloads without credentials or
redirects, verifies the exact archive/executable, writes only root-owned staging
files, and invokes native `inspect` or `admit`. It never installs a service or
restarts a process itself. Preserve/native edits keep existing secrets on-host;
never put secret literal bytes in these logged launcher recipes.

The caller fsyncs its immutable recipe before registration and `delivery_armed`
before its single update POST. Matching existing recipes are not rewritten;
conflicts fail closed. An armed phase is GET-only on every later invocation,
even if a crash happened before sending or the response was lost. Keep the
journals and launchers; do not generate a new journal/ID to retry uncertainty.
A crashed coordinator also leaves a local lock directory for explicit operator
reconciliation. A successful legacy job is only transport evidence: use
`--check-host-bootstrap` to attest the actual replacement and release its fence.

For an explicitly reconciled failure **before launch**, the delivery CLI accepts
`ci --deliver-host-bootstrap TARGET replan NEW_MANIFEST BUNDLE NEW_DELIVERY_JOURNAL EXPECTED_OLD_INTENT_SHA256`.
The native replan capability must be present in the pinned bundle. It requires
the same operation/source/config/files and checks the old exact intent,
`reconciliation_required/preserving` phase, unchanged originals, intact backups,
and absence of a launched helper. Only helper/target artifact identity changes.
It archives the old record under the same state directory and preserves its
backups. This is not permission to retry an ambiguous launch or switch, change
the source assertions, or choose a fresh state directory to bypass a fence.

### Service deployments

For candidate-first updates of existing stateless app-lb services, use
`ci/rollout-service` in a release workflow. It reuses a successful validation
bundle at the exact merged SHA, rather than rebuilding after merge. Inputs are
`url`, secret `token`, `deployment`, `namespace`, `mount-path`, `revision-env`,
`workflow` (the validation workflow path), and `artifact` (its uploaded bundle
name). The HTTP artifact bundle must contain `dist/start.sh` and all runtime
dependencies. The script must run from its release directory, not assume
`/workspace`. CI mounts the verified bundle read-only with one path component
stripped, executes `<mount-path>/start.sh`, and sets the requested revision
environment variable. Existing routes, runtime settings and secret references
are preserved; a conflicting secret revision override is refused.
When adding the first release mount, CI reuses the rootfs artifact's auth
reference only when both artifacts use the same store URL (ignoring trailing
slashes). Existing mount credentials are preserved. A different store needs an
explicitly configured release-mount auth reference; credentials are never copied
across stores. Only secret references, not their values, enter the rollout intent.

The token must be a direct `${{ secrets.NAME }}` reference. After cancellation,
deadline expiry, or controller restart, CI keeps polling the exact persisted
operation using the original job's workflow/environment secret scope, including
while draining. Only a matching terminal app-lb receipt releases the drain fence;
failed operations additionally require a durable `failed-rollout-reclamation-v1`
settlement proving candidate resource reclamation. CI records that evidence in
the deployment event and `settled_failure` phase; a legacy `failed` status alone
does not satisfy handoff. This requires backend reclamation support before
app-lb can settle failures with candidate allocations.
Missing operations, authentication failures, identity mismatches and ambiguous
remote outcomes remain unresolved. Recovery never starts a candidate or rewrites
the original run/job result. An operator upgrading a controller that predates this
reconciler can run `ci --reconcile-service-rollout RUN_ID OPERATION_ID` with the
controller's configured database and HeyoSecret bindings. This uses the same
receipt-only recovery path, without migrations, job admission or broker startup.

This action requires app-lb's conditional candidate rollout API, a pinned
rootfs artifact, pinned read-only mounts and an HTTP readiness path. Catalog
image names alone cannot prove rootfs identity. Workspace/writable deployments
and alternate ingress are not supported by this rollout path. Upgrade app-lb
before enabling the action; CI never falls back to stop-first mutation APIs.
CI sets `health.expected_header` to `x-heyo-revision` with the exact release SHA.
The service must return that identity stamped into its build, not echoed from
runtime environment variables. A generic healthy response from an old listener
must not authorize cutover. app-lb requires a 2xx status and the exact header.

CI persists the source revision, source/target configuration hashes, exact
artifact and deadline before submission, without storing live secrets. Queue
replay first looks up the exact operation. A missing operation can be submitted
again only while the original source revision and configuration still match;
app-lb must deduplicate that operation ID. Admission is not success: CI waits
for identity-matched `succeeded`, verified readiness and previous-generation
retirement. Cancellation or timeout stops waiting, not the remote operation.
Reconcile an uncertain operation before submitting a replacement. Chain
regional jobs with `needs` so the next region cannot start before this verified
completion; a parallel job graph does not provide sequential regional CD.

For an existing app-lb VM deployment, use `ci/publish-rootfs` followed by
`ci/deploy-app-lb`. Publication takes `path` (a relative raw ext4 file) and
`image` (its image name), and requires the HTTP artifacts sink. Its outputs are
`manifest`, `blob`, `size`, `store`, and `sha`. Release workflows must publish
from a job that ran `ci/checkout-release` at the confirmed release commit.

`ci/deploy-app-lb` takes `url`, `token`, `deployment`, `namespace`, `manifest`,
and `store`. It accepts only a manifest recorded by a successful publication
step in this run; a cross-job producer must also have succeeded. The target
must already exist with the matching namespace and artifact store. app-lb must
support durable correlated pulls (`operation_id`); older servers are rejected.
CI waits for app-lb to verify the exact replacement's health, and records the
operation in the same Deployments UI and NATS outbox as service deployments.
Cancellation or uncertain transport stops waiting, not the remote rollout;
resuming the same step reconciles its operation instead of creating another.
These actions do not register services, merge branches, or publish tags.

`ci/deploy-service` runs an asynchronous service rollout through Orchestrator's
existing `POST /orchestration/services/deployments` API. It does not create VMs,
implement routing, or change app-lb's namespace model. The existing CI run page
has a **Deployments** section with service, operation ID, exact revision, phase,
status, errors, and the last observation time. Refresh the page for new status.
`GET /api/runs/{run_id}/deployments` uses the same repository-scoped authentication
as other run reads.

The action takes `with.url` (Orchestrator base URL), `with.token` (resolved from
the workflow's HeyoSecret-backed secrets), and `with.spec` (a JSON string in the
existing snake_case service format). HTTPS is required except on loopback;
redirects are not followed. No installation-wide credential is automatically
granted to a workflow. Orchestrator currently requires an **internal API key**,
so enable this only for trusted service-deployment workflows; this is not yet a
tenant-scoped customer deployment credential.

```yaml
# Steps within a trusted deployment job, after its build/validation dependencies.
- uses: ci/deploy-service
  timeout-minutes: 15
  with:
    url: ${{ vars.ORCHESTRATOR_URL }}
    token: ${{ secrets.ORCHESTRATOR_TOKEN }}
    spec: >-
      {"id":"example-api","user_id":"service-owner",
       "vm":{"driver":"firecracker","image":"ubuntu","port":8080},
       "deploy":{"archive_id":"${{ needs.build.outputs.archive_id }}"}}
```

`deploy.archive_id` must identify a finalized **Orchestrator service archive**,
uploaded through its existing archive APIs. It is not a `ci/upload-artifact`
tag/digest; use `ci/promote-service-archive` to transfer a validated submission's
packaged archive, or `ci/publish-service-archive` for a standalone release build.
Use the repository-owned service spec for real startup, health, route, and
secret-reference settings. The action overwrites `deploy.deployment_id`, `async`,
and `revision_guard` with its stable step identity and the CI run's repository,
branch ref and full SHA (the confirmed release SHA for release workflows);
`force` is always false. The remote branch must still
point at that revision when Orchestrator checks it. Workflow dependencies and
secret permissions remain the admission boundary; the action does not merge a
branch or create a release.

Before POST, CI commits an operation ledger row and NATS outbox event together.
Orchestrator does not deduplicate POSTs, so repeated execution of the **same
step** only polls that operation ID. A changed request for that step is rejected.
Lost responses, 404s, and status lookup failures never cause a second POST.
Only an identity-matched terminal Orchestrator status marks a rollout passed or
failed. Cancellation/timeout stops CI waiting, not the remote rollout; the UI
keeps its last known status and warns that it may continue. Re-running a run
with unresolved deployment records is refused. Automatic reconciliation after
a finished/cancelled run, and an operator reconciliation UI, remain follow-up
work; queue replay of an unfinished action resumes GET polling with resolved
workflow credentials. Do not erase unknown operation records to retry them.

### Durable execution events

Postgres is authoritative for run, job, and step state. Each authoritative
status mutation writes a `ci_event_outbox` row in the **same transaction**. A
single background publisher reads those rows, publishes to
`<CI_NATS_PREFIX>.evt.<run_id>.<job_key|run>`, waits for JetStream's PubAck, and
only then marks the row published. NATS outages therefore delay notifications;
they do not roll back execution state or cause work to execute again. Job
subjects and their work-queue retention are unchanged.

The JSON envelope is version 1 and contains `version`, stable UUID `id`, history
cursor `revision`, repository scope (`repo_id`), exact Git `sha` and `git_ref`, `transitioned_at`, `type`
(`ci.run.status.v1`, `ci.job.status.v1`, `ci.step.status.v1`, `ci.artifact.published.v1`,
`ci.release.status.v1`, `ci.service_archive.published.v1`, or `ci.deployment.status.v1`), `run_id`, and
nullable `job_id`, `job_key`, and `step_id`. `status` and `error` remain top-level
for existing dashboard consumers. The same UUID is sent as `Nats-Msg-Id` on
every retry. A crash after PubAck and before the database update can redeliver
the same event after JetStream's duplicate window, so consumers must deduplicate
by `id` and tolerate at-least-once delivery. Events are retained by JetStream
for 24 hours; the outbox currently has no automatic archival/pruning policy.
The authenticated `GET /api/runs/{run_id}/events?limit=50&before=<revision>` API
uses the same repository bearer token or path-HMAC semantics as other run reads,
returns 404 across repository boundaries, and caps pages at 100 events.
The authenticated browser run page also renders an **Event timeline** beside
Release and Deployments, with 50 records per page, older/newest navigation,
transition errors, and NATS publication attempts/errors. It reads the same
durable records; publication status is not approval to release or deploy.
Revisions order history, not concurrent
transaction commits or NATS delivery. Consumers must re-read authoritative
state rather than assuming receipt order determines the latest state.

`ci.artifact.published.v1` records a successful sink upload and its artifact row
in the same transaction as the event. Its `artifact` object contains `id`,
`name`, `sink`, `digest`, `size_bytes`, `uri`, and nullable `public_url`. The
upload step ID is the idempotency key: concurrent retries produce one row and
one event; a retry with different recorded metadata fails instead of replacing
the publication. History reads return the complete NATS envelope with additional
`publication` delivery metadata, so reconciliation does not lose commit or
artifact identity. Existing artifacts are retained without synthetic events.

A publication is **not a release or deploy approval**. Uploads can precede a
later test failure or cancellation. CD must independently check exact-revision
validation, merge/release admission, and required artifacts. Use the digest to
identify immutable content, not a mutable tag in `uri`. New disk uploads also
record SHA256; legacy disk records may omit it. Disk storage is still local to
the CI service, not a shared deployment store. A sink write and Postgres
cannot share a transaction: a crash between them can leave an unrecorded blob;
an upload retry reconciles through the sink before recording publication.

Linux jobs can use `ci/download-artifact` with `name` and a relative file `path`
to download an earlier successful job's stored archive in the same run. Declare
the producer in `needs`; set `with.job` to its expanded job key if multiple
producers used the same artifact name. Missing, ambiguous, unfinished, or failed
producers are refused. Downloads verify size and SHA256 when recorded, preserve
the uploaded tar.gz bytes, and do not unpack them. Disk, S3 and `artifacts` stores
support downloads. S3 reads are restricted to the configured bucket/prefix.
Downloading an artifact
does not make it an approved release or service archive.

This is CI execution history, not deployment authorization. The release actions
above separately gate publication and the release-artifact handoff. Automatic
reconciliation of uncertain deployments after finished runs remains outstanding.
Native Intel Mac and Windows execution is available through the separate
[native runner protocol](NATIVE_RUNNERS.md), with durable leases and fenced
results/artifacts. Real-host testing remains a cutover prerequisite; local
executor tests do not establish Windows or Intel Mac installation readiness.
Neither a Linux cross-build nor an event saying tests passed substitutes for it.

**A run's page also carries each job's VM log** — the machine's own console as
its daemon saw it, read from `GET /sandboxes/{id}/logs` and captured *before* the
VM is released, because a job with `reuse: false` destroys it on the next line.
It is recorded as a step at index `-2`, the same trick checkout uses at `-1`: it
needs a row, a file and a place in the UI, and a step is already all three. That
also puts it inside the retention sweep rather than somewhere the sweep would
miss. Capturing it never fails a job — by then the steps have decided the
outcome, and a green build must not go red because a diagnostic could not be
fetched.

**Logs are swept after `CI_LOG_RETENTION_DAYS`, default 2.** Nothing else prunes
them, and an orchestrator that fills its disk stops being an orchestrator. The
sweep is driven by rows rather than by walking the directory, so it converges —
once a run's paths are nulled it is not offered again — and it is batched, since
a first pass over months of history would otherwise be one burst of unlinks on
the disk a build is writing to. **The rows stay**: a step that ran and its exit
code are the run's history, and dropping those with the bytes would make an old
run look as though it never happened. `CI_LOG_RETENTION_DAYS=0` keeps everything,
which is a decision about disk somebody should make on purpose.

## Tests

```bash
cargo test                                    # unit; no services needed

CI_TEST_DATABASE_URL=postgres://…/ci_test \
CI_TEST_NATS_URL=nats://127.0.0.1:4222 \
  cargo test -- --ignored --test-threads=1    # integration
```

The integration tests want Postgres, NATS with JetStream, and a local `heyvmd`.
The end-to-end test boots a real VM, runs a workflow, proves the VM is reused on
a second run and rebuilt when a `cache_key_files` entry changes, then destroys
it. `CI_TEST_DRIVER=kvm` switches drivers; firecracker is the default because
`kvm` re-execs the daemon's own binary and fails whenever that path has been
rebuilt.

Leftover streams from a run that was killed mid-test:

```bash
CI_TEST_STREAM_PREFIXES=citest cargo test -- --ignored delete_leftover
```

## Status

Working: workflow parsing and planning (matrix, `needs`, `if`, `max-parallel`),
branch and path filters with the `changed()` condition, runner discovery, the VM
pool, the job queue, `git submit` with per-repository tokens, secrets with
masking, disk, S3 and `artifacts` sinks, the dashboard with live logs, and workflow
objects.

Not built yet:

- **Composite `uses:` actions.** Artifact, release and deployment actions above are built in. Fetching
  an `action.yml` from a repository is a different feature with a different trust
  model.
- **Triggers other than `submit` and `release`.** `on: [schedule]` parses, but a
  submit only runs files whose `on:` includes `submit`; the rest are skipped
  (logged server-side, or refused when named with `--only`).
- **`heyctl set workflow`.** Create, get and delete exist; editing means
  re-creating with the same id.
