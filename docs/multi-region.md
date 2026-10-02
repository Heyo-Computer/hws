# Multi-region

This page explains how HWS runs one platform across more than one region, such as `us3` and `eu1`: how regions are modelled, which component holds which authority, how a regional drain, upgrade, verify, restore and bake works, and which parts are implemented as opposed to proven in a live two-region deployment.

## Model

A **region** in HWS is a placement label, not a separate installation with its own identities. The same string appears everywhere a location matters:

| Where | Field | Example |
| --- | --- | --- |
| Orchestrator service deployment | `deploy.region`, `deploy.replica_regions[]`, `placement_pool`, `deployment_environment` | `"replica_regions": ["us3", "eu1"]` |
| Orchestrator discovery endpoints | `endpoints[].region` | `"region": "eu1"` |
| Orchestrator observers | `discovery_observers[].region` | `region = "eu1"` |
| app-lb discovery | `discovery.region` | `{"service_id": "cloud", "region": "eu1"}` |
| app-lb gateway transport | `gateway.region` | the destination region (`forward`) or this region (`local`) |
| app-lb fleet and control-plane views | `region` on each gateway binding | `"region": "US"` |

Nothing registers a list of valid regions. A region exists because hosts in it are registered with Cloud and app-lbs in it are configured with that label. Use the same spelling in every one of these places.

Each component owns one kind of authority:

| Component | Owns | Does not own |
| --- | --- | --- |
| heyvm (per host) | Running VMs, local resource observations | Anything about other hosts |
| Cloud (not in the hws repository) | Host registry, region/pool-constrained allocation, reservations | Traffic policy |
| [Orchestrator](orchestrator.md) | Desired service state, per-region replica slots, **service discovery**, rollout plans and progress | Per-request routing |
| [app-lb](app-lb.md) (one or more per region) | Local routing, local backend admission, in-flight counts, drain reports | VM placement for orchestrator-owned services, global policy |

Three rules hold the model together:

1. **One authority.** Every orchestrator instance, in every region, must use the **same authoritative PostgreSQL database**. Rollout plans, discovery versions and service locks live there. Two orchestrators with independent databases, or with replicated copies that happen to share a database name, do not coordinate. They are two platforms.
2. **One discovery source.** Every app-lb that routes a service reads that service's membership from the same orchestrator discovery URL. app-lb records the source URL with each applied version and refuses to switch to a different authority for an existing deployment.
3. **One credential per role.** Regions do not get their own identities. Use one canonical HeyoSecret credential for each operator or service role, for example the orchestrator internal key, the app-lb admin observer, the discovery reader and the gateway peer role. Deliver it to each region. Do not mint per-region variants of the same role, and do not fold unrelated roles into one shared credential.

```text
                          ┌───────────────── shared PostgreSQL ─────────────────┐
                          │  service state · discovery sets · rollout plans      │
                          └────────▲──────────────────────────────▲──────────────┘
                                   │                              │
                        orchestrator (us3)              orchestrator (eu1)
                                   │   discovery (same URL, same versions)
              ┌────────────────────┴───────────┐     ┌────────────┴───────────────────┐
  client ──►  │ us3 ingress → app-lb (us3)     │     │ eu1 ingress → app-lb (eu1)     │ ◄── client
              │   ├─ local VMs (us3)            │     │   ├─ local VMs (eu1)           │
              │   └─ admin API: discovery-status│     │   └─ admin API: discovery-status│
              └────────────────────────────────┘     └────────────────────────────────┘
                     ▲ observer polls (drain evidence) from the orchestrator ▲
```

## Building blocks

The table lists each multi-region capability, how you opt in, and its state in the code.

| Capability | How you use it | State |
| --- | --- | --- |
| **Replicas pinned to regions** | `deploy.replica_regions` in the orchestrator service spec, one entry per replica. Cloud must confirm the region, and the environment and pool when you request them. | Implemented |
| **Region-scoped discovery** | `GET .../discovery?region=eu1` returns only that region's endpoints, with the shared `version`, and echoes `region`. In app-lb, set `discovery.region`. app-lb rejects any snapshot that omits the echo or contains a foreign endpoint. | Implemented |
| **Managed discovery source** | app-lb `discovery.source {url, auth}` with an app-lb secret reference. It needs no host environment variables and is persisted with the deployment. | Implemented |
| **Drain evidence** | app-lb `GET /deployments/{id}/discovery-status` reports the applied version and in-flight counts per upstream, including withdrawn ones. The orchestrator polls it on every configured observer. | Implemented |
| **Regional rollout** | `POST /orchestration/services/regional-rollouts`. It runs a durable per-region drain, candidate, restore and bake plan with rollback. | Implemented (opt-in) |
| **Shared inventory** | Orchestrator `GET /orchestration/services`. Set app-lb `APP_LB_CONTROL_PLANE_FILE` to the orchestrator origins to get a **Global applications** view. | Implemented, read-only |
| **Fleet view** | app-lb `APP_LB_FLEET_FILE` or `PUT /control-plane/config`, served at `GET /fleet`. Example: [`.heyo/fleet/fleet.json`](../.heyo/fleet/fleet.json). | Implemented, observation only |
| **One-hop gateway transport** | app-lb `gateway {mode: forward, local; service; region; auth}` on a static deployment. It carries authenticated HTTPS forwarding to a peer app-lb, which serves locally only. | Implemented and tested with two local processes. Not live. |
| **Hierarchical routing** (weighted region selection, then a local backend or one peer hop) | orchestrator `PUT .../regional-policy`, app-lb `discovery.regional`, `protocol=regional-v1` | Integrated and tested locally. **Admission and activation APIs are closed. Do not set regional policy on a live service.** |
| **Global artifact store** | `art serve` with `ART_S3_BUCKET`: every region's store is a cache of one bucket, which holds tags, manifests and blobs and is their backup. Tags written in one region are visible in the others within `ART_TAG_TTL`; `If-Match` tag writes are compare-and-swap across regions; bucket GC runs under a lease. See [artifacts](artifacts.md#global-store). | Implemented and tested against a local S3 API with two daemons. Not live: the bucket and the `artifacts-s3` secret are not provisioned |
| **Regional release workflow** | [`.ci/workflows/regional-release.yml`](../.ci/workflows/regional-release.yml): merge, then us3, then eu1, then poolers, then the CI controller | Sequential per-region app-lb candidate rollouts. See below. |

## Setting up a service in two regions

These steps use the implemented pieces: discovery-routed replicas behind each region's existing app-lb. They assume Cloud has hosts registered in both regions, and in the target environment and pool if you use them.

1. **Point every orchestrator at the same database.** Every orchestrator must use the same `DATABASE_URL`, the same internal key, and the same `ORCHESTRATOR_DISCOVERY_ROUTED_SERVICES` allowlist. Include your service in that allowlist.
2. **Provision credentials once, in HeyoSecret.** You need:
   - the orchestrator internal key, which is also what discovery readers present
   - an app-lb admin token for observers
   - a gateway peer token if you use gateway transport

   Copy each into app-lb secrets on **both** regions' app-lbs under the same IDs. See [HeyoSecret](heyosecret.md#app-lb-env_from-and-secret-key-references).
3. **Configure observers.** List every app-lb that can admit traffic for the service, at least one per target region, in the orchestrator TOML file (or `ORCHESTRATOR_DISCOVERY_OBSERVERS_JSON`). To have the orchestrator register the discovery route for you, set `ingress_url`, `discovery_url` (identical on all observers) and `discovery_token_secret`. See [orchestrator](orchestrator.md#discovery-and-app-lb).
4. **Deploy.** Submit the service spec with a stable route, fixed `scaling` and `deploy.replica_regions`, for example `["us3", "eu1"]`. On first deployment the orchestrator does two things before it records an ingress baseline. It creates the discovery-backed app-lb route on each observer, create-only with a read-back. Then it waits until **every** observer attests the same source, membership and version.
5. **Verify.** Check that `GET .../discovery` shows endpoints in both regions, and that each app-lb's `discovery-status` reports that version. Requests through each region's ingress should succeed.

Do not add `app-lb` itself to the discovery allowlist. app-lb is host-managed and is not a VM deployment target.

## Regional rollout: drain → upgrade → verify → restore → bake

A regional rollout replaces a service's revision **one region at a time**. It withdraws each region from routing before creating anything there. Start one with the internal API key:

```json
POST /orchestration/services/regional-rollouts
{
  "operationId": "example-rev-42",
  "deployment": {
    "serviceId": "example",
    "userId": "heyo-system",
    "archiveId": "<immutable archive id>",
    "desiredReplicas": 2,
    "replicaRegions": ["us3", "eu1"],
    "envRefs": ["DATABASE_URL=heyosecret://example/database-url@active"],
    "route": {"host": "example.example.com", "pathPrefix": "/", "stripPrefix": false}
  },
  "minimumServingReplicas": 1,
  "bakeSeconds": 300,
  "drainTimeoutSeconds": 120,
  "runtimeByRegion": {"eu1": {"driver": "libvirt", "image": "ubuntu:24.04", "sizeClass": "small"}}
}
```

`deployment` uses the orchestrator's internal camelCase deployment request, not the snake_case service file. Admission rejects the request unless all of the following hold:

- `deployment.archiveId` names an immutable archive. `archiveBytesBase64` is not accepted.
- Secrets come only through `envRefs`. Plaintext `env` is rejected.
- `deletePrevious` is false, so old replicas stay available for rollback.
- `desiredReplicas` equals the length of `replicaRegions`, and there are at least two distinct regions.
- `minimumServingReplicas` is between 1 and `desiredReplicas - 1`, and the replicas **outside every region** can meet it on their own.
- `bakeSeconds` is between 1 and 86400, and `drainTimeoutSeconds` is between 1 and 3600.
- The route matches the service's established, discovery-routed route. The rollout never changes ingress.
- Observers are configured in every target region.
- No other rollout or lifecycle operation holds the service.

A retry with the same `operationId` is idempotent only if the payload is identical.

The orchestrator compiles and stores a fixed plan before it runs anything. Regions run in the order they first appear in `replicaRegions`, so `["us3", "eu1"]` upgrades us3 first. For each region, the plan runs these phases:

| Phase | What must be true to advance |
| --- | --- |
| `preflight` | Fresh probes show enough healthy capacity **outside** the region to meet `minimumServingReplicas` |
| `exclude_region` | The whole region is removed from discovery for this service, as a new discovery version |
| `wait_drained` | **Every** observer has applied that version and reports zero in-flight requests to the withdrawn upstreams |
| `create_slot` / `creating` | Deterministic candidate IDs are created, one per replica slot in the region. A durable `creating` marker is written first. |
| `probe_candidates` | Candidates pass health checks |
| `mark_old_draining` | Old members of the region are marked draining. They are retained, not stopped. |
| `restore_region` / `wait_restored` | The region returns to discovery with the candidates, and every observer adopts that version |
| `bake` | Repeated probes stay healthy for `bakeSeconds`. The bake clock restarts after any gap in observation. |

After the last region, `verify` checks the final state and the operation ends `passed`. Poll `GET .../regional-rollouts/{operationId}` for `status` (`running`, `blocked`, `passed` or `rolled_back`), `phase`, `regions`, the pinned `slots`, per-item progress and the latest 100 events.

What the rollout guarantees:

- **No new admissions to a withdrawn region before its upgrade.** Candidates are created only after every observer confirms the drain. Elapsed time alone never counts as a drain.
- **Durable progress.** The cursor, per-item progress and transition events are committed together in PostgreSQL. A restarted controller resumes the stored plan. It does not recompile one.
- **No duplicate candidates after a restart.** If a restart happens during creation, the rollout adopts only an exactly matching healthy discovery member. Otherwise it **blocks** rather than creating a second one.
- **Pinned topology.** The observer set is saved at admission, so removing an observer from configuration cannot skip its gate.
- **Blocking, not guessing.** Any failed gate, observer error or expired timer sets `status=blocked`. The operation keeps its lock on the service. `POST .../resume` retries the gate with fresh timers.
- **Rollback.** `POST .../rollback` works on an active or blocked operation. It restores the retained old endpoints under fresh health checks and observer drain gates, and restores the saved service state. Candidates are kept, but excluded. Rollback of a completed operation is not offered, because it could overwrite a later one.

What it does **not** do:

- It does not stop or delete old VMs. Cleanup is a separate, deliberate step.
- It does not upgrade app-lb, restart hosts, fail over databases or move background workers. HTTP drain does not quiesce an application's background work. Your application must tolerate old and new replicas running at the same time.
- It does not register or change routes, and it does not change regional weights.

## Other maintenance is separate

An application rollout says nothing about whether it is safe to restart the region's app-lb or another regional dependency. Treat these as separate operations:

| Operation | Current mechanism | Gap |
| --- | --- | --- |
| app-lb binary on a host | `ci/rollout-host-app-lb` in the regional release workflow, one region at a time | Updates in place with verification and rollback fences. There is no side-by-side candidate with ingress hand-off yet, so an update can briefly interrupt that region's traffic. |
| Stateless app-lb services (for example the orchestrator itself) | `ci/rollout-service`: app-lb candidate-first rollout inside one region's app-lb | Region-local. It does not withdraw the region from other regions' routing. |
| Whole host or region | None automated | Needs an external health-aware entry point with both regional ingresses as origins, plus failover for stateful dependencies such as the database writer. Neither is provided by HWS. |

For any of these, move traffic away first, perform the maintenance, verify that the region has recovered, and only then restore traffic. Do not use a regional rollout's success as evidence that host maintenance is safe.

## Regional routing policy (draft)

`PUT /orchestration/services/{id}/regional-policy` stores explicit weights and gateway inventory in the same versioned discovery set:

```json
{"expectedVersion": 17,
 "policy": {"version": 1, "regions": [
   {"region": "us3", "weight": 2, "gateways": [{"id": "us-a", "backendServerId": "host-us", "url": "https://us.example.com"}]},
   {"region": "eu1", "weight": 1, "gateways": [{"id": "eu-a", "backendServerId": "host-eu", "url": "https://eu.example.com"}]}]}}
```

`expectedVersion` must equal the current discovery generation, which is 0 for a new set. A stale value returns `409`. `"policy": null` clears the draft. This write stores **intent only**. It does not activate routing. While it is set, the legacy rollout executors refuse to deploy the service, and flat app-lb consumers refuse policy-bearing snapshots. **Do not set it on a live service.** The hierarchical consumer and the staged activation, adoption and drain gates exist in code, but their public admission remains closed.

## Repository files

| Path | What it is |
| --- | --- |
| [`.heyo/regions/us3/`](../.heyo/regions/us3/README.md) | Inert app-lb templates (zero replicas, no routes, commit placeholder) for adding CI, the artifact store (a cache of the global store) and Cloud to a new region alongside an existing one. The README lists the HeyoSecret paths to deliver as app-lb secrets and the order of checks before you publish a route. |
| [`heyosecret/app-lb.us3.json`](../heyosecret/app-lb.us3.json), [`orchestrator/app-lb.us3.json`](../orchestrator/app-lb.us3.json) | The same kind of template for HeyoSecret and the orchestrator |
| [`.heyo/fleet/fleet.json`](../.heyo/fleet/fleet.json) | Example gateway list for app-lb's fleet view (observation only) |
| [`.heyo/deployment-environments.json`](../.heyo/deployment-environments.json) | Host-keyed defaults (discovery allowlist, replica counts) loaded by the service deployment workflow |
| [`.ci/workflows/regional-release.yml`](../.ci/workflows/regional-release.yml) | Release pipeline: merge, then us3 (host app-lb, orchestrator), then eu1, then the Postgres poolers, then the CI controller. Each stage runs only when its paths changed and only after the previous stage succeeds. |
| [`.ci/workflows/regional-drain-validation.yml`](../.ci/workflows/regional-drain-validation.yml) | Validation only. It builds app-lb and runs the orchestrator's two-real-gateway drain test against a disposable PostgreSQL. It does not deploy. |

The templates refer to a region's own database, for example `orchestrator_us3`. A template with a separate database is a **separate platform**, not one half of a shared one. Before you treat two regions as one system, make sure both regional orchestrators use the same authoritative database.

## Proving it works

Two healthy endpoints, a green release run, or sequential regional deployments do **not** show that the two-region system works. Test the platform with a disposable application before you trust it with real services such as CI. [`app-lb/testdata/regional_app.py`](../app-lb/testdata/regional_app.py) is built for this. It returns its region and revision in JSON and in the `X-Heyo-Region` and `X-Heyo-Revision` headers. It records the requests it admitted, at `/admissions`. It can hold a response open (`/held?hold=10`) and can report itself unhealthy (`--unhealthy`).

```sh
python3 app-lb/testdata/regional_app.py --region eu1 --revision rev-a --bind 0.0.0.0 --port 8080
```

A two-region acceptance run should show all of the following:

- The same immutable revision runs in both regions. Both app-lbs consume the same discovery authority. Requests succeed through both regional ingresses and through the normal application hostname.
- Continuous requests run throughout withdrawal, confirmed in-flight drain, upgrade, health verification, restore and bake, first for us3 and then for eu1. There are **zero failed requests**, and `/admissions` on the withdrawn region shows no new admissions after withdrawal.
- The surviving serving path does not depend on the drained region's ingress.
- An unhealthy candidate is left excluded. A controller restarted mid-rollout resumes the same operation with one candidate per slot. Rollback restores the retained revision without losing serving capacity.
- Regional infrastructure maintenance, such as an app-lb restart, is tested separately: traffic moved away, recovery verified, then restored.

Keep one checklist with the evidence for each item. Record what is deployed, what is merely configured, and which live tests you actually ran.

## Status

Implemented and covered by unit tests and local integration tests:

- region-pinned replicas
- region-scoped discovery
- managed discovery sources
- observer drain evidence
- the regional rollout API, with durable plans, blocking, resume and rollback
- the shared inventory and fleet views
- the one-hop gateway transport
- the hierarchical policy and discovery machinery

The local tests include real app-lb processes and a disposable PostgreSQL.

Not yet proven in a live two-region deployment:

- the full drain, upgrade, verify, restore and bake sequence across us3 and eu1 under continuous traffic with zero failed requests
- unhealthy-candidate, controller-restart and rollback behaviour against live regions
- two regional orchestrators demonstrably sharing one authoritative database and fencing each other's operations
- regional forwarding through the gateway transport between real regions
- hierarchical weighted routing (its public admission and activation remain closed)
- app-lb upgrades without interruption. Host app-lb updates still restart in place.
- whole-host or whole-region maintenance and failover. There is no external failover entry point, and there is no database writer failover.
- CI as a regional application with shared state and coordinated job ownership

Until those gates pass, treat multi-region HWS as a set of working, opt-in building blocks rather than a verified active-active platform.
