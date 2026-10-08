# orchestrator

Heyo's control plane for sandboxes, services, and agent-driven workflows.

The orchestrator owns the source of truth for what should be running where. Other services hand it work — CICD asks it to spin up a sandbox to run a job, Cloud asks it to deploy a service — and the orchestrator plans, persists, and reconciles those requests against a backend (mvm-ctrl) that actually moves VMs. It also drives the agentic workflows used to compile parent jobs (discovery / planning / review / patch) against pluggable LLM providers.

`/health` returns `x-heyo-revision` from **build-time** `HEYO_BUILD_GIT_SHA`
(`unknown` for unstamped builds). Runtime deployment environment variables remain
diagnostic metadata, not proof of which binary answered. The public CI workflow
stamps the validated Git SHA and packages a relocatable `start.sh` with migrations
for a read-only release mount. These artifacts alone do not activate regional CD.

The opt-in [regional service rollout API](docs/regional-rollouts.md) persists
region-by-region drain, replacement, observation, and rollback gates. It requires
existing discovery-routed ingress and an observer for every app-lb instance;
it does not by itself activate whole-region infrastructure upgrades.

## How it fits with CICD and HeyoSecret

```
                ┌────────────────────┐        ┌─────────────────────┐
   developer    │                    │        │                     │
   ──────────▶ │   cicd  (:4450)    │ ◀────▶ │   native runners    │
   git submit   │  - ingests submits │ lease  │  (Intel Mac, Win)   │
   trigger-build│  - plans CI jobs   │ +runs  │   cicd-runner-agent │
                │  - reports status  │        │                     │
                └─────────┬──────────┘        └─────────────────────┘
                          │ POST /orchestration/resources/deployments
                          │ GET  /orchestration/resources/archives/{id}
                          ▼
                ┌────────────────────┐
                │ orchestrator(:4446)│        ┌─────────────────────┐
                │  - plans & persists│ ──────▶│   mvm-ctrl backend  │
                │  - reconciles      │  POST  │  (libvirt / FC /    │
                │  - agent workflows │  /run  │   apple_container)  │
                └──┬───────┬─────────┘        └─────────────────────┘
                   │       │
       envRefs:    │       │ blue/green cutovers,
       resolve     │       │ deploy state, cloud
       secrets     │       │ internal callbacks
                   ▼       ▼
       ┌───────────────────┐   ┌─────────────────────┐
       │ heyosecret(:port) │   │   cloud (internal)  │
       │  - encrypted KV   │   │  - users / billing  │
       │  - audit history  │   │  - service routes   │
       └────────┬──────────┘   └──────────┬──────────┘
                │                         │
                └───────────┬─────────────┘
                            ▼
                  ┌─────────────────────┐
                  │ platform Postgres   │
                  │ shared database with│
                  │ service-owned tables│
                  └─────────────────────┘
```

The services are independent processes but can share one PostgreSQL database. Each service owns its tables and migrations; separate database URLs remain supported for standalone installations.

- **CICD** is the entry point for source — it receives signed `git submit` payloads, plans `.heyo/ci.yml` jobs, and either leases them to native runners or asks the orchestrator to spin up a sandbox. It calls the orchestrator over HTTP for `resources/archives/*` (upload/download workspace tarballs) and `resources/deployments/*` (launch + exec + stop the sandbox running the job).
- **Orchestrator** never talks to the backend hypervisor directly during a request — it persists the desired state, then a reconciler loop drives `mvm-ctrl` to converge. When deploying a Heyo-managed *service* whose manifest references secrets (`envRefs`), it calls **HeyoSecret** to materialize them just-in-time using the `heyosecret-client` crate.
- **HeyoSecret** is a small KV with versioning, audit history, and AES-GCM encryption at rest. Only the orchestrator (and other internal services) holds the `HEYOSECRET_INTERNAL_API_KEY`; tenant code never sees it.

Service rollouts keep the previous healthy deployment active while the candidate converges. The controller retries Cloud state and health reads with capped backoff under one deployment deadline and requires candidate and app-lb route health to remain successful for 10 seconds. It prefers the candidate's internal endpoint for readiness and upstream routing: the public sandbox URL can require end-user authentication and return 401 for an otherwise healthy service. Legacy `url` and public endpoints remain fallbacks when no internal endpoint is supplied. Only persisted terminal state or the deadline is failure; deployment events are diagnostics, not a liveness signal.

## Public service deployment boundary

The public VM workflow deploys only Orchestrator, HeyoSecret and app-obs.
app-lb runs on the host and is not a VM deployment target, including for
`service=all`. app-obs still connects to the existing app-lb admin endpoint.
Automatic selection requires a change under the service's source paths or its
`.heyo/services/<service>.json` declaration;
shared workflow/environment edits and empty change lists select no services.
Use an explicit service dispatch when only shared deployment settings change.

The receiver-only prerequisite uses the flat request and selects Orchestrator
alone. This JSON caller workflow must wait until that receiver upgrades. Before any
receiver rollout, ensure host app-lb discovery does not depend on the retiring
Orchestrator VM's port. Verify discovery through a stable endpoint and preserve
the existing host proxy; do not recreate app-lb to upgrade the receiver.

## Layout

- `src/main.rs` — boot, route table, reconciler spawn.
- `src/config.rs` — `ORCHESTRATOR_*` env loading, per-phase agent overrides, backend capability defaults.
- `src/handlers/` — `orchestration.rs` (threads, templates, archives, resource deployments, approvals), `service_deploy.rs` (Heyo-service deployment and placement), `service_discovery.rs` (durable endpoint membership and drain intent), `internal.rs` (deploy lifecycle callbacks from the backend).
- `src/orchestration/` — `runtime.rs` (step execution), `reconciler.rs` (background loop that converges desired vs. observed state), `adapters.rs` (backend / cloud / heyosecret glue).
- `src/agent.rs` — agent phase orchestration and per-phase provider routing.
- `src/llm.rs` — public multi-provider LLM and tool-execution adapter for Anthropic, OpenAI, Mistral, and Gemini.
- `src/entities/`, `src/repositories/`, `src/db/` — SeaORM entities and queries against the orchestrator Postgres.
- `migrations/` — SQL migrations applied at startup.

## Getting started

### 1. Postgres

The orchestrator needs access to PostgreSQL. It can use a shared platform database or a dedicated database; the local example defaults to `postgresql://postgres:password@127.0.0.1:5432/orchestrator_db`. Migrations under `migrations/` run automatically at boot via `db::init_database`.

### 2. Configure

```
cp .env.example .env
```

Fill in at least:

- `DATABASE_URL` — orchestrator Postgres.
- `JWT_SECRET` — must match the value CICD and Cloud use to sign internal calls.
- `CLOUD_INTERNAL_API_KEY` (the orchestrator's own internal API key; `INTERNAL_API_KEY` also works) + `CLOUD_INTERNAL_URL` — for the orchestrator → cloud callbacks. Multi-word `ORCHESTRATOR_*` names such as `ORCHESTRATOR_CLOUD_INTERNAL_URL`, `ORCHESTRATOR_AGENT_MODEL` or `ORCHESTRATOR_DB_MAX_CONNECTIONS` are not read from the environment; set those keys in the TOML config file.
- `ORCHESTRATOR_AGENT_API_KEY` (or the provider-specific `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `MISTRAL_API_KEY`) — for the agentic workflow phases.

Set `ORCHESTRATOR_PROXY_BASE_DOMAINS` to a comma-separated list of wildcard proxy base domains when backend deployment URLs must be probed through `ORCHESTRATOR_BACKEND_API_URL` instead of public DNS.

Rolling replicas are an explicit discovery-routed traffic mode. Configure `ORCHESTRATOR_DISCOVERY_ROUTED_SERVICES` with a comma-separated allowlist. A replicated request must include the service's stable `route`; Orchestrator verifies that route through the active app-lb backend, rewrites ingress to that backend, and only then drains a previous replica. Asynchronous retirement persists drain intent but does not stop an old replica until the parent rollout has recorded success, so Orchestrator can safely roll itself. `replicaRegions` may assign each desired replica to a region and must contain exactly `desiredReplicas` entries. Optional `deploymentEnvironment` (nonempty, at most 64 characters) requests Cloud environment filtering and is required when `placementPool` is present. Orchestrator passes both fields to Cloud and requires the placement response to confirm the exact environment and region, plus the pool when requested. The environment is durably and immutably bound to an occupied service ID; use distinct service IDs for staging and production. Existing unscoped requests remain supported, but an occupied legacy service ID cannot be silently adopted into a scoped environment. app-lb itself must never be in the discovery-routing allowlist.

Retirement authority cannot carry across a newer replica rollout. Cleanup requires the owning rollout to remain current and successful, as well as an expired drain and a non-active target. An unfinished rollout remains protected even after its lease expires; lease expiry permits a new rollout claim, not deletion of the old instance. Deployment and retirement hold the same PostgreSQL per-service advisory lock, and retirement rechecks eligibility under that lock before making a Cloud stop/delete call. Different services can progress independently; concurrent operations on the same service must retry after the current operation finishes.

Migration `034` records `previous-retire-cancelled` events when an active deployment changes back to a target of earlier retirement work. This is atomic with the state update, including direct recovery SQL, and does not rewrite historical rollout results. Moving away from that deployment later cannot revive the cancelled retirement. Obsolete cleanup is deliberately left ineligible rather than guessing whether its target is safe to delete; the current rollout must own any fresh retirement. Direct database recovery still requires quiescing deployment/cleanup first: a trigger cannot recall a Cloud deletion already in flight. Older Orchestrator binaries do not participate in the new lock/cancellation protocol, so mixed-version operation is not a substitute for that recovery precaution.

PostgreSQL regression tests use an isolated, rolled-back schema and two independent connection pools: `ORCHESTRATOR_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54329/postgres cargo test --locked --manifest-path orchestrator/Cargo.toml retirement_ -- --include-ignored`. Point this only at a disposable local database. The tests cover reactivation, superseded legacy cleanup, unfinished/expired leases, completed rollout and drain gating, and same-service exclusion in both directions.

Workflow step claims lock the step row before checking readiness and inserting an attempt, so concurrent instances cannot both claim the same ready step. Run its disposable-PostgreSQL regression with `ORCHESTRATOR_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:54329/postgres cargo test --locked --manifest-path orchestrator/Cargo.toml concurrent_step_claim_creates_one_running_attempt_postgres -- --ignored`. The dedicated `.ci/workflows/orchestrator.yml` runs this check and packages the tested release binary and migrations; it does not merge or deploy.

The public-service workflow accepts `HEYO_SERVICE_REPLICA_REGIONS` as a comma-separated list such as `EU,US`, which sets both `replicaRegions` and `desiredReplicas` for every allowlisted service. `HEYO_SERVICE_PLACEMENT_POOL` is optional; use `platform` after the intended shared hosts have registered in that pool. Manual dispatches may provide `discoveryRoutedServices`, `replicaRegions`, `placementPool`, and `serviceDriver` without changing the CICD service environment; omitted inputs retain the configured environment values and existing single-region behavior. `HEYO_SERVICE_REPLICAS` remains available as either one count or a per-service map such as `heyosecret=2,orchestrator=2`; when both settings are present, their counts must agree. The existing host app-lb must already contain the discovery-backed route definitions; this workflow does not install or replace it.

For a first-time activation without a config bootstrap race: first deploy compatible Cloud and heyvm versions, then verify that Cloud records one EU and one US host in the target environment and pool `platform`, with distinct node IDs. Deploy the compatible receiver before activating its discovery allowlist. Then set `ORCHESTRATOR_DISCOVERY_ROUTED_SERVICES=app-obs,heyosecret,orchestrator`, `HEYO_SERVICE_REPLICA_REGIONS=EU,US`, and `HEYO_SERVICE_PLACEMENT_POOL=platform`; workflow-dispatch `orchestrator` once with `bootstrapDiscoveryRouting=true`, then workflow-dispatch `all`. The bootstrap request leaves Orchestrator on its existing singleton route while loading the allowlist into the active process. The full VM rollout then runs app-obs → HeyoSecret → Orchestrator, using the existing host app-lb ingress. Do not repeat this bootstrap for an environment with discovery already active. Phase 1 keeps one app-lb ingress while placing one replica of every discovery-routed service in EU and one in US.

If you plan to deploy services with `envRefs`, also set:

- `ORCHESTRATOR_HEYOSECRET_URL` (or `HEYOSECRET_URL`)
- `ORCHESTRATOR_HEYOSECRET_INTERNAL_API_KEY` (or `HEYOSECRET_INTERNAL_API_KEY`)

If the backend (mvm-ctrl) runs on a different host or OS than the orchestrator, set `ORCHESTRATOR_BACKEND_API_URL` so capabilities (`targetOs`, supported drivers) come from `GET /capabilities` instead of the orchestrator's local defaults.

### 3. Run

```
cargo run --locked --manifest-path orchestrator/Cargo.toml --bin orchestrator
```

Listens on `ORCHESTRATOR_SERVER_PORT` (default `4446`). Health check: `GET /health`.

Container build:

```
docker build -f orchestrator/Dockerfile -t heyo-orchestrator .
```

### 4. Wire CICD to it

In CICD's environment, point `CICD_ORCHESTRATOR_URL` at this service (e.g. `http://127.0.0.1:4446`). CICD will then POST workspace archives and resource deployments into `/orchestration/*` whenever a submit needs a cloud sandbox.

## Key routes

- `POST /orchestration/threads` — start an agent workflow thread.
- `POST /orchestration/parent-jobs/compile` — compile a parent job spec.
- `POST /orchestration/resources/archives` (and `/presign`, `/finalize`) — upload workspace tarballs CICD will run jobs against.
- `GET  /orchestration/resources/archives/{archive_id}` — stream an archive back (used by CICD to fetch debug artifacts).
- `POST /orchestration/resources/deployments` — request a sandbox; reconciler converges it.
- `POST /orchestration/resources/deployments/{id}/exec` — run a command inside.
- `POST /orchestration/services/archives/presign` (and `/finalize`) — authenticated direct upload for large Heyo-managed service archives; pass the finalized `archiveId` to the service deployment request.
- `POST /orchestration/services/deployments` — deploy a Heyo-managed service using the snake_case app-lb-style service format described below. **Breaking change:** old flat camelCase requests are rejected, not converted or accepted through aliases.
- `POST /orchestration/services/adoptions` — internal-key authenticated adoption of an existing application. The request pins `{serviceId,deploymentId,sourceRolloutRevision,artifactDigest,applicationRevision,binarySha256,runtimeSandboxId,runtimePort}`. Registration verifies the app-lb spec ETag, retained workspace, singleton VM, immutable artifact, public health identity and authenticated application lifecycle capability. It creates the shared app identity without replacing the running VM.
- `POST /orchestration/services/{service_id}/updates` — preserves the singleton `{operationId,intentHash}` contract and accepts a durable regional command `{apiVersion:"regional-v1",operationId,release:{runId,targetRevision,artifactDigest,binarySha256}}`. The caller cannot choose targets or bake time. Acceptance transactionally freezes configured binding order, identities, and adoption evidence before external work. The restartable dispatcher prepares every child before activation, then checks the healthy peer and activates/bakes one region at a time. Regional bake duration is `regional_application_bake_seconds` (default 30).
- `GET /orchestration/services/{service_id}/updates/{operation_id}` — returns the regional parent and ordered per-target lifecycle observations, bake timestamps, and errors. This uses the same application-scoped lifecycle credential as creation.
- `POST /orchestration/services/{service_id}/updates/{operation_id}/cancel` — durably requests orderly stop. Unactivated children are cancelled through CI; an activated child remains outcome-unknown until its ordinary lifecycle result settles.
- `GET /orchestration/services?after=<service_id>` — internal-key authenticated shared inventory for regional control-plane views. Returns up to 100 services and `nextCursor`, including desired replicas/regions, recorded discovery membership, and latest regional rollout phase. Each page uses one read-only repeatable-read transaction. Missing discovery is `null`; database failure returns 503, never a local-file fallback. Deployment metadata and credentials are excluded.
- `GET  /orchestration/services/{service_id}/discovery` — authenticated, versioned endpoint membership for app-lb, including each endpoint's region when known. Rolling deploys publish and health-gate one candidate, drain one old replica, and repeat. A failed candidate leaves the remaining healthy set serving. `retirePrevious=false` only adds capacity up to `desiredReplicas`.
- `POST /internal/deployments/lifecycle` — callback from the backend reporting deploy state transitions.
- `POST /orchestration/approvals/{approval_id}/decide` — gate an in-flight workflow.

### Registering the existing CI controller

Configure `external_service_bindings` in Orchestrator's configuration file, or
use `ORCHESTRATOR_EXTERNAL_SERVICE_BINDINGS_JSON` as a fallback. An explicit
file value, including an empty list, wins. Each binding supplies `service_id`,
`authority` (app-lb admin origin), `namespace`, `region`, `deployment_id`,
`health_origin`, `token_secret_path` (app-lb admin), and
`lifecycle_token_secret_path` (the application's lifecycle exchange credential).
Both credential fields are HeyoSecret references, not values.
The caller cannot choose a remote authority or supply its credential.

Several deployments may share a region, with distinct deployment IDs for the
service. First appearance determines region order; deployments within each
region keep their configuration order. All deployments in one region must
finish and bake before the next region starts. The accepted target list is
frozen: do not change bindings during an active update. A server enrollment
alone does not add a binding, change replica counts, or move running workloads.
Deploy the compatible CI receipt reader before configuring repeated regions.

Register each configured canonical service binding against its retained regional deployment
after reading its current app-lb spec and public `/healthz` identity. Do not use
the legacy private `cicd` definition, invent a Cloud archive ID from a workspace
digest, or replay a captured VM identity after a controller update. Registration
requires a new service identity with no Cloud-managed state or operation history.
It creates no VM and does not change the current app-lb routes, workspace,
database, NATS consumers, artifacts, warm pool, or runner records.

Once adopted, CI submits the immutable release receipt to Orchestrator. Orchestrator
freezes the configured regions first, then calls each region's idempotent
`POST /api/lifecycle/updates/{child}/prepare`; preparation must not drain.
The child ID is exactly `ci-region-` plus lowercase SHA-256 hex of the compact JSON
array `[parentOperationId, authority-with-trailing-slashes-trimmed, deploymentId]`.
CI loads the durable shared parent and derives the release and its own deployment.
Never-adopted app-lb CI with all application lifecycle settings absent retains
its direct, release-authorized self-update path; partial configuration is rejected,
and removing configuration cannot bypass a previously recorded adopted update.
CI remains the
executor of job/lease draining and exact-binary verification; app-lb remains the
executor of retained-workspace replacement. Orchestrator never creates a second
CI VM through the Cloud archive path. Existing Cloud creation, regional rollout
and delayed-retirement guards prevent competing writers.

Shared Apps exposes the accepted update's phase, target revision, CI run and
last observation time. An unreachable controller is reported as unknown, not
successful. Job logs and release history remain in CI. This path does not provide
active-active CI, regional failover, automatic rollback, or recovery independent
of a controller that cannot boot. Registration attestation is historical evidence,
not continuous runtime health.

Regional lifecycle identity must advertise `regional-release-update-v1`, open
admissions, and report application, deployment, authority, boot, revision, and binary.
Configuration drift from the frozen ordered bindings blocks reconciliation.

For regional baking, a passed child lifecycle status must include
`result: {applicationRevision,binarySha256,runtimeSandboxId,admissionsOpen}`. Orchestrator
requires `applicationRevision` to equal the parent target revision, then compares all three
identities with the live `/healthz` headers and app-lb singleton VM on every bake sample.
`admissionsOpen` must be `true`; app-lb must also report an idle workspace and a healthy,
non-draining singleton. CI must derive this result from the completed rollout and current
executor admission state rather than echoing the prepared intent.

Install the lifecycle-capable CI and Orchestrator versions before adoption, and
configure CI's `CI_APPLICATION_ID`, `CI_APPLICATION_ORCHESTRATOR_URL`, and
HeyoSecret-backed `CI_APPLICATION_LIFECYCLE_TOKEN`. Add `/api/lifecycle` to CI's
app-lb public machine paths; the endpoint requires its own scoped bearer. Do not
delete the active `ci-eu1` deployment to clean inventory: deployment DELETE can
also destroy suspended VMs that are absent from the ordinary VM list. Inventory
cleanup must first establish that no runtime, workspace or route references the
record.

### Service deployment files

Service configuration lives in [`.heyo/services`](../.heyo/services). The workflow
loads a file, fills in the build artifact, target host/region and revision, then
submits it. Install the receiver-only upgrade before activating this workflow;
see the breaking-change rollout below.
Application environment variables remain application settings; there is no change
to Orchestrator's own process-config loader.

The request has `{ id, user_id, account_id?, vm, routes?, health?, scaling?, deploy }`.
It uses app-lb's field names with an Orchestrator-only `deploy` operation section.
It is a supported subset, not a promise that every app-lb lifecycle feature works
through Orchestrator. Unknown fields and unsupported features fail explicitly.

| Section | Supported behavior |
| --- | --- |
| `vm` | Required `driver`, `image`, primary `port`; optional `open_ports`, `start_command`, `working_directory`, `setup_hooks`, `size_class` (default `small`), `ttl_seconds`, `env_vars`, `env_from` |
| `vm.env_from` | `{ "secret": "orchestrator", "key": "database-url", "as": "DATABASE_URL" }` resolves active HeyoSecret path `orchestrator/database-url`. Default key is `token`, default environment name is uppercased key. Secrets override matching `env_vars` literals, as in app-lb. Explicit namespaces and duplicate secret target names are rejected. No secret values in the file. |
| `routes` | Zero or one exact `host` with optional `path_prefix` and `strip_prefix` (default false). Existing Traefik renderer cannot represent wildcard/hostless/multiple routes, so these are rejected. |
| `health` | HTTP `path` (default `/`), same port as the VM, positive `timeout_secs` (default 2) for each candidate probe. Templates specify 5 to preserve existing deployments. TCP and a different health port are unsupported. |
| `scaling` | Fixed `min_replicas == max_replicas`, 1–16. Omit for direct single-candidate execution. Dynamic autoscaling options are rejected, not silently ignored. |
| `deploy` | Operation metadata: `deployment_id`, `name`, `async`, `archive_id` / `archive_bytes_base64`, `archive_name`, `region` (default `local`), `placement_pool`, `replica_regions`, overall `health_timeout_seconds` (default 180), retirement flags, `drain_seconds` (default 10), `metadata`, `revision_guard` |
| `deploy.ingress` | Traefik-specific `entry_points`, `cert_resolver`, `priority`, `pass_host_header`, `backend_url`; requires a route |
| `deploy.host_mounts` | Existing host bindings `{ host_path, sandbox_path, read_only }`, with absolute, traversal-free paths. CICD's persistent run directory uses this. These are not app-lb's artifact-backed `vm.mounts`, which remain unsupported. |

`deploy.revision_guard` uses `repository_url`, `ref`, `expected_sha`, and optional
`force`. `deploy.retire_previous` defaults to true; `retire_previous_async` and
`delete_previous` default to false. Secrets continue to resolve through HeyoSecret;
Cloud's internal VM allocation protocol and deployment response/status formats are
unchanged. `health.timeout_secs` is not the overall rollout deadline and does not
change the separate post-cutover route health check.

### Breaking-change rollout

The deployment workflow loads host-keyed defaults from
`.heyo/deployment-environments.json` before constructing requests. Staging's
verified existing policy is `heyosecret,orchestrator`, one replica each, with no
explicit replica-region list or placement pool. Nonempty dispatch/CI settings
override these defaults. A pool is optional; when absent, Cloud uses its existing
regional allocation policy. The same discovery-service list is passed into the
replacement Orchestrator, so the upgrade does not silently disable discovery.
Other hosts receive no staging defaults. No server IDs are selected by this file.

The PR #55 receiver deployment failed before cutover: the installed CICD runner
overwrote `GITHUB_ENV` defaults with empty job environment values. Load the
host-keyed defaults inside the deployment Python process, before constructing
the request, so recovery does not require a CICD upgrade first. The new-format
Orchestrator is now serving staging. The PR #58 deployment was rejected with HTTP
422 because the workflow still sent the flat `serviceId` request. Public callers
now load `.heyo/services/{service}.json` and send `id`, `vm`, `routes`, `health`,
`scaling`, and `deploy`; no old-format fallback is supported.
Shared workflow edits alone select no services, and app-lb remains host-managed.
Run `python3 .heyo/test_deployment_environment.py` for offline regression checks.

Both public and private service-deployment workflows must move with this interface.
The public workflow covers HeyoSecret, Orchestrator and app-obs; the private
companion covers Cloud, CICD and Retail. No dual-format server is provided.

1. Submit the receiver-only change first. Its unchanged workflow sends the old
   request to the running old receiver, which deploys the new Orchestrator binary.
   Only `orchestrator/` changes, so the workflow selects only Orchestrator. The
   resource allocation API used by CICD and deployment status responses are unchanged.
2. Wait for that deployment to finish and the public Orchestrator health endpoint
   to report the new revision. Do not run unrelated service deployments during
   this transition: old callers cannot deploy to the new receiver.
3. Submit the public caller migration, then the private caller migration. Both
   require the new receiver. Do not resubmit the receiver-only revision after
   cutover; further Orchestrator deployments must use the migrated caller.

This is a coordinated breaking cutover, not a dual-format compatibility period.
If the first deployment fails before cutover, diagnose it while the old receiver
still serves; do not advance the callers. After cutover, use the new callers.
No deployment or infrastructure change is performed by preparing these PRs.

Receiver validation: `cargo test --locked --manifest-path orchestrator/Cargo.toml`.
Offline validation: `python3 .heyo/services/test_service_specs.py` executes the
workflow with mocked network/build calls. `SERVICE_SPEC_BASELINE_REF` optionally
compares against an old-workflow Git revision. `SERVICE_SPEC_FIXTURE_DIR` exports
synthetic payloads; use the same directory for the private caller tests and the
Rust contract test to validate all six VM service requests.

### us3 app-lb deployment

`app-lb.us3.json` is an inert bootstrap spec: no public routes, zero replicas,
and a commit placeholder. `Dockerfile.firecracker` builds and tests the locked
Rust source from the public repository root. It includes migrations and a serial
guest init; app-lb launches the daemon with resolved `env_from` secrets.

Before registering it, replace the build ref with the verified public commit,
provision a region-isolated database, and deliver its URL and existing JWT/internal
keys through app-lb secrets backed by HeyoSecret. Do not reuse `orchestrator_db`
for us3: it holds eu1 service state and retirement history even though its Postgres
host is in us3. Startup runs migrations and immediately processes pending events,
expired step leases, and eligible previous-deployment stop/delete intents.

Build through `POST /deployments/orchestrator-us3/build` on the existing us3
app-lb, inspect the returned job, then set one minimum replica. Attach the existing
Heyo JWT gate and `orchestrator.us3.heyo.work` route only after readiness. Machine
API paths must retain Orchestrator's own bearer authentication. This adds an app;
it does not replace app-lb or change retail/login.

A healthy `/health` does not prove CD works. Configure and verify regional
`CLOUD_INTERNAL_URL`, `ORCHESTRATOR_BACKEND_API_URL`, proxy domains, and optional
`ORCHESTRATOR_NATS_URL`/`ORCHESTRATOR_NATS_ENABLED` before accepting deployment
jobs. Cloud must accept the configured internal key and allocate the us3 backend.
The current Orchestrator also reads Cloud's `deployed_sandboxes` table directly:
regional Cloud must use this region's database and populate its deployment state.
Pointing an isolated Orchestrator at staging Cloud does not satisfy that contract.
Keep staging/eu1 dependencies explicit until those services are regionalized;
do not call a health-only installation an independent region.

The app-lb host needs Docker for image builds. If Postgres is protected by the
existing per-VM allowlist, grant each candidate's exact IP and tap interface
access to port 6432 before expecting database readiness. Retain existing rules;
do not open the database publicly. A replacement VM needs its own grant, so this
bootstrap setup is not unattended rollout readiness. Keep a candidate's boot
deadline long enough to establish that access, then restore the normal deadline.
