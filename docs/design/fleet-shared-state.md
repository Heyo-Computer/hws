# Fleet shared state: one app-lb across hosts

Status: proposal, 2026-10-13 (revised the same day: Postgres via pg-fc replicas; customer databases durable through S3; us4 rolled in without disrupting us5). Nothing here is implemented.
- Scope: a *fleet* of app-lb hosts that act as one tenant surface, starting with us4 and us5.
- Supersedes, for the fleet scope only, the rule in `MULTI_REGION_DESIGN.md` § Proposed architecture: "do not turn app-lb into a scheduler and do not build a second service registry beside Orchestrator discovery". The reasons are in § Relation to the multi-region design.
- The us3/eu1 regional platform and its gates are unchanged.

## Goal

A customer deploys once and gets one hostname. A request may arrive at any fleet host. That host serves it from a local VM, or forwards it once to the peer that has capacity or holds the workload.

The customer cannot tell which host served the request:
- tokens, namespaces, secrets, plugins and certificates work on every host;
- `heyctl` and the dashboard work against any host;
- losing one host loses only the workloads pinned to it.

## Problem

Today one app-lb is one island. Each item below has its consequence directly beneath it.

- **Every tenant record is a local file.**
  - Covers deployment specs (`app-lb-state.d/`), namespaces, tokens, secrets, auth providers, workflows, plugin records and installs, postgres ownership, guard rules and ACME certificates.
  - None of it replicates.
  - The only cross-host path is `token_authority`, which mirrors fleet-token hashes one way (`fleet.rs`, `tokens.fleet.json`).
  - Consequence: a us5 token is meaningless on us4.
- **app-lb drives one daemon.**
  - `APP_LB_DAEMON_URL` holds a single URL.
  - Managed backends are addressed by host-local tap guest IPs (`vm.rs`).
  - The ownership of a sandbox is encoded only in its name, `applb-<deployment>-<nonce>`.
  - The reconcile paths (`adopt_existing`, `kill_unclaimed`, `sweep_suspended`) treat every `applb-*` VM on that daemon as theirs.
  - Consequence: two app-lbs on one daemon destroy each other's fleet, which is the 2026-09-29 incident.
- **The peer path forbids pools.**
  - Gateway forward mode only applies to static deployments: `DeploymentSpec::validate` rejects `gateway` together with `vm`.
  - Local mode refuses direct clients.
  - `regional-v1` has one-hop routing, a generation fence and no replay, but its admission is closed on live services.
- **Per-host certificate issuance breaks under two A records.**
  - HTTP-01 challenges live in an in-memory `ChallengeTable`.
  - Let's Encrypt may validate against the other host.
- **The autoscaler only sees local demand.**
  - `desired = ceil((in_flight + waiters) / target_concurrency) + warm_pool`.
  - With two hosts, `min_replicas` and `warm_pool` each double, and each host scales to zero on its own.

## Design

### 1. Split every record into fleet state and host state

Fleet state is authoritative in one shared Postgres (§2). Host state stays in local files, exactly as today.

| Record | Fleet | Host |
|---|---|---|
| Deployment | `spec`, `upstream_drains`, `discovery_version`, `route_handoff`, `placement` (§4) | `suspended`, `create_attempts`, `rollouts`, `active_prefix`. Becomes a per-host file keyed by deployment. |
| Namespaces, auth providers, workflows | all | — |
| Tokens | records, hashes, revocation, expiry | `last_used_at`. Flushed to fleet state at most every 60 s. |
| Secrets | sealed values | — |
| Plugins | record, config, per-namespace installs, `postgres.json` ownership | plugin probe status |
| Guard | rules | hit counters |
| ACME | account, certificates and keys (sealed), backoff, pending HTTP-01 challenges | — |
| Images, disks, workspaces, jobs, build and site dirs, `views.json`, locks | — | all |
| Pools, in-flight, cold-start waiters, metrics, feed | — | in memory, as today |

Two keys must be identical on every fleet host. They are delivered as one HeyoSecret credential per role, never minted per host:
- `APP_LB_SECRET_KEY` seals secrets and certificate keys.
- `APP_LB_AUTH_KEY` signs data-plane sign-in cookies. With it shared, a session cookie minted on us4 verifies on us5 with no lookup.

### 2. The fleet store

**The store is one authoritative PostgreSQL that app-lb talks to directly.** It is not a replica per host, and it is not reached through Orchestrator.

The schema is `fleet`:
- one table per record kind above;
- every row carries `(key, body jsonb, revision bigint, updated_at, updated_by)`;
- `revision` comes from one sequence for the whole schema.

**Writes**
- Every mutation is a compare-and-swap: `UPDATE … WHERE key = $1 AND revision = $2`.
- The admin API returns 409 with the current record on conflict, as the fleet view's `expected_revision` already does.
- Multi-record changes run in one transaction. Examples are a namespace delete cascading to its secrets and tokens, and a plugin install writing a secret.

**Change feed**
- The revision sequence is the feed: `SELECT … WHERE revision > $cursor ORDER BY revision`.
- Each app-lb polls every 1 s, and also wakes on `LISTEN fleet_changes`, so latency is usually under 100 ms.
- Deletes are tombstones, kept 7 days.

**Local snapshot**
- Today's file stores become a materialized cache of the fleet tables, written with the same write-then-rename code.
- The data plane reads only the in-memory view of that cache. There is never a database round trip per request, consistent with `MULTI_REGION_DESIGN.md` § Route to a region.

**Loss of the database**
- Each app-lb keeps serving from its last snapshot.
- Mutations return 503 with `fleet store unavailable`.
- Revocations stall. The admin API and `heyctl whoami` report the snapshot's age.
- A cold-started app-lb with no snapshot and no database refuses to start reconciling. It serves nothing rather than inventing state. This is the same rule as a cold gateway in the regional design.

**One storage seam.**
- A `FleetStore` trait with `get`, `list`, `put_cas`, `delete_cas`, `transaction` and `changes_since`.
- A `FileStore` implementation keeps single-host app-lb exactly as it is, and stays the default.
- A `PgStore` implementation is selected by `APP_LB_FLEET_DATABASE_URL`.
- The stores convert behind this trait:
  - the uniform object-directory stores (`NamespaceStore`, `AuthProviderStore`, `WorkflowStore`, `PluginStore`, postgres `Ownership`);
  - `Registry` persistence (`persist_one`, `forget`, `load`, `archive_record`);
  - the whole-file stores (`SecretStore`, `TokenStore`, guard). Sealing stays above the trait.
- app-lb gains its first database client: `tokio-postgres` plus `deadpool`, with no ORM.

**Where Postgres runs: pg-fc, one writer, read replicas on some hosts.**
- The fleet database is a pg-fc dedicated database with physical streaming replicas on other hosts. pg-fc already has peers and an operator-driven physical handoff.
- Replicas are not required on every host. The fleet is expected to grow, and an app-lb needs neither a local replica nor exact replication on its node.
- Which connection is used for what:
  - **Writes, CAS reads and leases** go to the writer (`APP_LB_FLEET_DATABASE_URL`).
  - **The change feed** reads from the nearest replica, if one exists (`APP_LB_FLEET_READ_URL`), otherwise from the writer.
- Replica lag is harmless to the feed: the cursor is a revision, so a lagging replica delivers the same changes slightly later.
- `NOTIFY` is not delivered on a hot standby. A host that follows a replica therefore polls (1 s) and does not `LISTEN`.
- Writer failover is operator-driven promotion of a replica, the same pg-fc handoff used for databases today. It is not automatic. The local snapshot is what keeps traffic flowing while the writer is down.

**Leases.** Fleet-wide singletons hold a row lease with a fencing epoch:
- the placement controller (§4);
- ACME issuance and renewal;
- the token expiry sweep;
- retired-record GC.

A holder that cannot renew within its TTL stops acting before the TTL ends. Every write it makes carries the epoch, and stale epochs are rejected.

### 3. Hosts and the one-daemon invariant

**Membership**
- A fleet table `hosts` holds one row per app-lb.
- Each row has: `host_id` (`APP_LB_NAME`), `peer_url` (`https://<host_id>.fleet.<domain>`), `boot_id`, `state` (`active` / `draining` / `maintenance`), labels, capacity, and a heartbeat every 5 s.
- A host is *live* when its heartbeat is newer than 15 s.

**The invariant from the 2026-09-29 incident is kept and made explicit:**
- **an app-lb only creates, adopts or kills VMs on its own daemon**;
- no host ever writes another host's host-state files;
- no host calls another host's heyvm.

**Shared registry interaction with reconcile.** A shared registry means every host now "knows" every deployment. `adopt_existing` and `kill_unclaimed` therefore stay scoped by the local daemon listing, which they already are, and gain one rule:
- a deployment whose placement (§4) gives this host zero replicas is drained and reaped locally;
- it is never adopted.

Sandbox names stay `applb-<deployment>-<nonce>`. Uniqueness across hosts is not needed, because names are only ever read against their own daemon.

### 4. Placement: where a deployment's VMs run

A new spec field, defaulting to `spread`:

```json
"placement": { "mode": "spread" | "pinned", "hosts": ["us4", "us5"], "home": "us5" }
```

**`spread`**
- For stateless workloads.
- Replicas may run on any live host in `hosts` (default: all).

**`pinned`**
- For any deployment with host-bound state:
  - `vm.workspace` or `mounts`;
  - `idle_action: retain`, or any `disk_size_gb` disk the workload expects to outlive a VM;
  - a pg-fc database;
  - `vm.build` images that were never pushed to the artifact store.
- All replicas run on `home`.
- Validation rejects `spread` for these, so a customer cannot be silently split from their data.
- Moving `home` is an explicit operation (§8), never automatic failover.

**The placement controller**
- One instance, the lease holder from §2.
- It writes `placement_targets(deployment, host, desired, generation)`.
- Every tick (2 s), it reads per-host demand reports. Each host publishes `(deployment, in_flight, waiters, ready, booting)` into `host_demand` at most once a second, only for deployments whose numbers changed. It then computes fleet-wide desired replicas with today's formula, applied once for the fleet instead of once per host.
- It assigns those replicas:
  - `min_replicas` and `warm_pool` count once for the fleet;
  - spread replicas go round-robin across live hosts, preferring the host with the most demand;
  - a host in `draining` or `maintenance` gets zero.
- It never creates VMs. Each host's existing autoscaler reconciles its own daemon to `placement_targets[deployment, self]`. Its `desired` input changes from a local computation to that row.

**Without a controller**
- If the lease lapses, hosts keep their last target.
- One exception covers scale-from-zero: a host holding a waiter for a `spread` deployment whose targets are all zero may boot one local replica on its own authority. This is the cold-start path the customer actually waits on.
- The controller absorbs that replica on its next tick.

**Rejected: each host autoscales on local demand only.**
- It is simple, and it is what two independent app-lbs would do today.
- But `min`/`warm`/`max` double, both hosts cold-start the same idle app, and a host with no local traffic drains replicas that the peer is forwarding to.

### 5. Request path

```diagram
client ─DNS (both A records)─▶ app-lb A (ingress)
                                   │ route + guard + auth gate (fleet snapshot)
                       ┌───────────┴───────────────┐
                       ▼                           ▼
              local ready backend          peer app-lb B (one hop, HTTPS)
               (fewest in-flight)              │ re-admit + auth gate
                                               ▼
                                     B's local backend / cold start on B
                                     (never forwards again)
```

**Ingress host A**
- A runs `RequestControl::decide` as today: ACME, route, guard, maintenance, auth gate. All of it reads the fleet snapshot.
- Rejects (401, 403, guard blocks) happen at the edge and never cost a hop.

**Selection** extends `RequestState::next_peer`:
1. **Local** if A has a ready backend under `target_concurrency`. This is today's fewest-in-flight choice.
2. **Peer** if a live peer reports ready backends for the deployment, from the peer view below. Prefer the lowest utilisation, `in_flight / (ready × target_concurrency)`.
3. **Pinned elsewhere:** if the deployment is `pinned` to another host, forward to `home` even with zero ready backends, so `home` holds the cold start.
4. **Cold start on A** if A's placement target is above zero, or the scale-from-zero exception applies. The request waits as today.
5. **Otherwise** 503 with `Retry-After`.

**Peer view**
- Each app-lb serves `GET /fleet/v1/pool` on its peer listener. The response is per-deployment `ready`, `in_flight`, `draining` and `accepting`, plus `boot_id` and a monotonic sequence.
- Every peer polls it every 1 s.
- A connect failure or 5xx marks the peer unavailable at once. This is the same passive health that `proxy.rs` already applies to backends.
- This is pool state, not tenant state. It never goes through Postgres, so the data plane needs neither the database nor the controller to route.

**The hop**
- The transport is the existing gateway forward machinery, generalised:
  - HTTPS on 443 to `peer_url`;
  - SNI is the peer name, with a certificate from the fleet store;
  - TCP and TLS sessions are pooled.
- Headers added:
  - `x-heyo-fleet-hop: <origin host_id>`;
  - `x-heyo-fleet-token`, one fleet peer credential;
  - the original `Host`.
- `X-Forwarded-For` and `X-Forwarded-Proto` are set at the first hop, which nothing in app-lb sets today. The peer trusts them only from a fleet hop.
- Requests are never replayed once bytes may have reached the peer, as in `regional-v1`. A connect failure before any byte is sent falls back to step 4 or 5.
- WebSocket and other upgrades pass through as they do to a local backend.

**Receiving host B**
- B admits a request carrying a valid fleet token, by constant-time compare as `gateway::admit` does.
- **It then re-runs the auth gate from its own snapshot.**
  - This is cheap, because tokens and session keys are fleet state.
  - It means a forged hop header buys nothing beyond the fleet token.
  - B strips `x-auth-request-*` on every fleet-hop request, whether or not the deployment has `auth`. That closes the passthrough gap found in the current gateway local mode.
- B selects only local backends, or holds a local cold start.
- A request that already carries `x-heyo-fleet-hop` is never forwarded again, whatever B's pool looks like. Exactly one hop, no counter needed.

**Demand accounting.** A forwarded request counts in B's in-flight and waiters, because B is where it waits. A does not count it. Fleet demand is therefore counted once.

**Rejected: route straight to the peer's published VM port.**
- heyvm publishes every managed VM's port on `0.0.0.0` with an unrestricted PREROUTING DNAT. This skips the peer app-lb.
- It is plaintext across the internet, and it bypasses the peer's in-flight accounting, drain and cordon.
- Separately: those published ports, and heyvm's `:34099`, should be firewalled to loopback on every fleet host now. app-lb uses guest IPs and does not need them.

### 6. Ingress, DNS and TLS

**Names**
- Fleet tenant hostnames are `<name>.<fleet domain>`. The domain is `heyo.work` names or a new fleet zone; this is an open question.
- Their DNS holds one A record per active host.
- Custom domains CNAME to a fleet name.
- Per-host names (`*.us5.heyo.work`) keep resolving to their host, for operators and debugging.

**DNS is the coarse layer only**
- Health-checked records (Route 53 health checks on `/fleet/v1/healthz`) drop a dead host within TTL plus the check interval.
- **DNS is not the drain mechanism.** A host being drained keeps answering and forwards every request to the peer (§7) until its DNS weight has been zero for longer than the TTL. Only then does it stop accepting.
- This is how the AGENTS.md gate is met: "the surviving serving path must not depend on the drained region's ingress".

**Certificates**
- Certificates and the ACME account live in the fleet store, sealed with `APP_LB_SECRET_KEY`.
- Only the ACME lease holder issues and renews. Every host loads certificates from its snapshot into the SNI callback.
- HTTP-01 challenge tokens are written to the fleet store before the order is finalised. Any host answers `/.well-known/acme-challenge/*` from its snapshot, falling back to a direct database read on a miss.
- Fleet wildcards use DNS-01 through the existing Route 53 path in `dns.rs`.

### 7. Host lifecycle

**Drain a host**
1. Set `hosts.state = draining`. The controller moves its placement targets to zero and adds replicas on peers.
2. DNS weight for the host goes to 0.
3. The draining host keeps answering, and forwards to peers while their new replicas come up. It reaps its local replicas only after `draining` replicas finish in-flight work and the peer reports enough `ready`.
4. After TTL plus margin with no direct client traffic, the host enters `maintenance`.

**Restore**
- Set `active`, then DNS weight, then the controller rebalances.
- `pinned` deployments are not moved by a drain. Their home host's drain waits for an operator to move them (§8), or accepts their downtime explicitly.

**Infrastructure maintenance on a host** (app-lb binary, heyvm, reboot) uses the same drain. As in the regional design, a successful app rollout does not prove that app-lb restarts are safe. This is tested separately (§9).

### 8. Pinned workloads and moving them

- Moving a `pinned` deployment's `home` is an explicit two-phase operation: snapshot or copy its host-bound state to the new home (workspace push to the artifact store, or a customer database restored from S3), then flip `home`.
- It is not automatic. Automatic failover of stateful workloads needs storage that outlives a host. That belongs to a later design.

**Customer Postgres databases are not replicated live.** Durability comes from two existing or small additions:

- **S3 cold storage.** pg-fc's existing archive path (`PG_VM_POOL_S3_*`, `PG_VM_POOL_ARCHIVE_AFTER_SECS`) already writes an idle database to S3 and thaws it on demand. That archive is the database's durable copy.
- **Periodic snapshots** for databases that stay up long enough never to go idle. These are new. pg-fc snapshots any database whose uptime since its last archive exceeds a threshold, and uploads it to the same S3 location.
  - Each snapshot must be crash-consistent: `pg_basebackup`, or an `fsfreeze` plus XFS reflink copy of the data disk.
  - The snapshot interval is the database's recovery point.

Consequences:
- A customer database is `pinned` to the host running it. Host loss means restoring the last archive or snapshot from S3 onto another host. Writes since that point are lost, and the docs must state the recovery point plainly.
- Because the durable copy lives in S3 and not on a peer, the restore target can be any host. No pairing between hosts is needed as the fleet grows.
- Live replicas stay available per database through pg-fc peers. They are an opt-in for databases that need a tighter recovery point, not the default.
- The postgres plugin's ownership map (database to namespace) becomes fleet state, so whichever host restores a database still knows who owns it.
- CI's runner hosts, pg-fc and anything driving the local heyvm stay host services. Their app-lb deployments are `pinned`.
- Remote and artifacts are already S3-authoritative, so they can run `spread` once each runs one instance per host against the shared buckets.

### 9. Images

- A `spread` deployment's image must be obtainable on every host.
- Artifact deployments already are: content-addressed images pull per host on first placement.
- `vm.build` deployments must push their built image to the artifact store, and peers pull by digest. Until a build has been pushed, validation forces `pinned` to the building host.
- Image catalogs, warm sets and offload stay per host.

## Relation to the multi-region design

`MULTI_REGION_DESIGN.md` keeps app-lb as a regional data plane, with Orchestrator, its shared Postgres and Cloud allocation as the control plane. This design deviates deliberately, for the fleet scope:

- **The store is app-lb's own schema, not Orchestrator.**
  - Tenant records are app-lb's data model.
  - Routing them through Orchestrator would need Cloud allocation, `internal_url`s and the closed `regional-v1` admission before a single namespace could be shared.
  - The *rule* is kept: one authoritative Postgres, never per-host copies treated as authority.
- **app-lb becomes the scheduler for its fleet.**
  - The scheduling is narrow: one leased controller writes per-host replica counts, and each host only acts on its own daemon.
  - There is no second *service discovery* registry: pool state moves peer-to-peer and is never stored.
- **Reused as-is:**
  - one hop, no replay, and no re-selection at the destination;
  - HTTPS through the existing ingress with a dedicated peer credential;
  - serving the last valid snapshot when authority is lost;
  - one credential per role;
  - drain proven by acknowledgement, never by elapsed time.
- **Not reused: `regional-v1` weighted region choice.** Selection here is by where capacity is, not by policy weights.
- **Convergence.** If Orchestrator later becomes the fleet's control plane, `FleetStore` is the seam. Its tables can move under Orchestrator's database without changing the data plane.

## Credentials (one per role, in HeyoSecret)

| Role | Used by |
|---|---|
| `app-lb-fleet/db` | every app-lb → fleet Postgres (one role; no per-host users) |
| `app-lb-fleet/peer` | fleet hop and `/fleet/v1/pool` |
| `app-lb-fleet/secret-key` | `APP_LB_SECRET_KEY` on every host |
| `app-lb-fleet/auth-key` | `APP_LB_AUTH_KEY` on every host |
| `app-lb-fleet/dashboard` | the operator dashboard password, now fleet-wide |
| `heyvm/<host>/operator` | stays per host. It is a different role: each host's daemon key, never presented across hosts. |

us4 and us5 today hold separately generated dashboard passwords and keys. Convergence uses us5's existing values: they are loaded into HeyoSecret as the fleet values and delivered to us4. us5's credentials do not rotate. us4's are discarded, since nothing depends on them yet.

## Phases: us4 as a shadow until it serves alongside us5

us5 serves production traffic the whole time. us4 is a **shadow**: it runs the fleet code and holds a one-way, read-only copy of us5's tenant state. It serves no production hostname and creates no VMs for us5's deployments.

us5 is touched only in phase 5, and only after phase 4 proves app-lb restarts drop nothing.

### Phase 1: storage seam, deployed to us4 only

A pure refactor: no database, no on-disk change, no behaviour change. Single-server app-lb keeps its exact files, so an older binary still reads the state after a rollback.

**`app-lb/src/fleet_store.rs`** (std only, so the importer binary can compile it)
- Two traits:
  - `Collection`: records under string keys, with `get`, `list`, `put` and `delete`;
  - `Document`: one record, with `read` and `write`.
- Every write takes an `Expect` (`Any`, `Absent` or `Revision`) and returns a revision. For files, revisions are counted in memory and mean nothing across processes.
- `FileCollection` and `FileDocument` reproduce today's behaviour exactly:
  - the same paths, temp-file-then-rename, and fsyncs where they were (the registry's file and directory syncs, and durable directory creation);
  - credential files are `0600`, and the ACME directories `0700`.
  - The one deliberate difference: certificates and the ACME account are now restricted *before* any bytes are written, as secrets and tokens already were. The final files are the same.
- `Layout` resolves every path from the same `APP_LB_*` variables and defaults as `main`. A test pins it to `Config`'s defaults and the stores' own directory functions.

**Stores moved behind it**
- Each store keeps its serialization, validation and in-memory view.
- Every existing constructor keeps its signature and builds file-backed stores. A new `with_*` constructor takes another backend.

| Store | Backed by |
|---|---|
| `NamespaceStore`, `AuthProviderStore`, `WorkflowStore` | `Collection` |
| `PluginStore`, including installs | `Collection` |
| `SecretStore` | `Document` (sealing stays above it) |
| `TokenStore` | `Document` (the `tokens.fleet.json` mirror stays a host file) |
| `Guard` | `Document` |
| postgres `Ownership` | `Document` |
| `Registry` records | `Collection`, synced |
| `Registry` retired archive | `Collection`. A content-addressed copy, where it was a hard link: same bytes, same path. |
| `CertStore` | Two `Collection`s, chains and keys |
| ACME account and backoff | `Document` |

**Left as host files on purpose**
- the registry's legacy single-file migration;
- the controller lock;
- the ACME directory stamp and its reset;
- the token mirror;
- the auth signing key.

**Moved to the phases that first use them**
- The `StoredDeployment` fleet/host split moves to phase 2. Its only consumer is `PgStore`, and splitting the file now would change the on-disk format for nothing.
- The `placement` spec field moves to phase 3, where the importer first marks deployments pinned. Adding it earlier would publish an API field that does nothing.
- `transaction` and `changes_since` move to phase 2 with `PgStore`.

**`app-lb-fleet-import`** (`src/bin/`, its own binary)
- It compiles only `fleet_store`, so it cannot start a server, reach heyvm or take the instance lock.
- `--dry-run` is required, unknown arguments are refused, and nothing is written.
- It reports per-kind counts and every unreadable record. It never prints a secret value, token hash or key.

**Tests**
- All existing tests pass unchanged: 1,134 in app-lb, 156 in hws (`--all-features`, wire goldens included) and 27 in heyctl.
  - The 13 `host_update::bootstrap` tests fail the same way on main in a non-root checkout.
- New tests:
  - the file store's semantics (round trip, suffix filtering, compare-and-swap, key safety, modes, the injected post-rename failure);
  - a golden test driving every store over one root, asserting the exact file tree, modes and bytes;
  - a test that a tree written the old way loads without anything being written;
  - the `Layout` pin.

**Exit criteria**
- The new app-lb is deployed to us4.
- `smoke-us4` serves through HTTP and HTTPS, with no certificate re-issued.
- `heyctl get deployments` is identical before and after the restart.
- State files are unchanged by the restart alone.
- The importer's dry run over us4's state reports every record.

**us5:** nothing. It keeps running its current binary.

### Phase 2: fleet store on us4

- `PgStore`, the `fleet` schema and migrations, the revision feed with `LISTEN`, the local snapshot, and leases with fencing epochs. Enabled by `APP_LB_FLEET_DATABASE_URL`.
- `transaction` and `changes_since` on the traits.
- The `StoredDeployment` split. Fleet fields go to `PgStore`; host fields (`suspended`, `create_attempts`, rollouts, `active_prefix`) go to `<state>-host.d/`. The file store keeps writing the combined record.
- pg-fc on us4, holding the fleet database as its writer.
- Live tests on us4:
  - stop the database for 10 minutes under load, with zero failed requests and mutations returning 503;
  - kill a lease holder;
  - force a CAS conflict.

### Phase 3: shadow us5

- us4 follows us5's tenant state one way, read-only. Credentials converge on us5's values, delivered through HeyoSecret.
- The importer runs on us5 as a read-only process. It reads us5's state directory, never writes it, never starts app-lb, and pushes into us4's fleet database over TLS.
- The `placement` spec field arrives here, modelled in `heyctl/src/types.rs` with the wire goldens updated. Existing deployments default to `pinned` on their current host.
- Every us5 deployment arrives `pinned` to us5, so us4's placement target for it is zero and us4 creates nothing.
- Gate, on us4 with test hostnames (`--resolve`, no DNS change):
  - a us5 namespace token, secret and sign-in cookie work on us4's admin API, dashboard and data plane;
  - us4 forwards one request for a us5 app to us5's ingress as a plain static upstream.

### Phase 4: restarts that drop nothing

- Hand the listening sockets over in place, or keep the proxy worker alive across a management restart.
- Prove it on us4 under continuous load, with zero failed requests and held streams surviving.
- Without this, phase 5 does not start.

### Phase 5: us5 joins

1. Deploy the fleet build to us5 in file mode. It does nothing until enabled.
2. Run the final import, then switch us5 to the fleet store. Add a read replica on us5.
3. us5 keeps its certificates, keeps the renewal lease and keeps its files for rollback.

Gate: zero failed requests on us5 production names across each restart.

### Phase 6: serve together

1. Enable the fleet hop (`APP_LB_FLEET_FORWARD=1`), us4 first.
2. Enable the placement controller and opt-in `spread`: the smoke app, then new stateless apps, then remote and artifacts.
3. Add fleet certificates and dual-A DNS on a test name, then on the fleet domain. `*.us5.heyo.work` keeps pointing at us5 only.
4. Run live acceptance (§ Gates). Only after it passes do new deployments default to `spread`.

**Rollback**
- Before phase 5, rollback means not enabling the change.
- After phase 5, restart us5 in file mode on its kept files, then replay into them any changes made since the switch, using the change feed.

## Gates

Each row needs a discriminating live test and recorded evidence. Unit tests do not satisfy a row.

| Gate | Evidence |
|---|---|
| [ ] Shared authority | Both hosts' `changes_since` cursors advance from the same database. A CAS conflict on concurrent writes from us4 and us5 is reported, not merged. |
| [ ] Revocation | A token revoked on us5 is refused on us4 within 2 s. With the database stopped, the documented staleness is reported by `whoami`. |
| [ ] Store outage | Fleet Postgres stopped for 10 min under continuous requests: zero failed requests, and mutations 503. |
| [ ] One hop | Requests to us4 for a us5-pinned app succeed. A forged `x-heyo-fleet-hop` without the token is refused. Forcing B's pool empty yields 503, never a bounce. |
| [ ] Drain us5 | Continuous requests through both ingresses during drain → upgrade → restore → bake: zero failures, no admissions to drained backends, and the surviving path does not use us5's ingress. |
| [ ] Drain us4 | Same, the other way. |
| [ ] Controller restart | Kill the lease holder mid-scale: no duplicate replicas, targets converge, and the epoch fences the old holder. |
| [ ] Unhealthy candidate and rollback | A `spread` rollout whose candidate fails health stops on both hosts and rolls back, with serving capacity preserved. |
| [ ] app-lb restart | Restarting app-lb on one host (infrastructure maintenance, not app rollout) with traffic moved away first: zero failures. |
| [ ] Never cross-daemon | Audit both heyvm logs across all gates: no host created, adopted or killed a VM on the other host's daemon. |

## Open questions

- **Customer database snapshots:**
  - the snapshot interval, which is the recovery point;
  - the method (`pg_basebackup`, or `fsfreeze` plus reflink);
  - how far back S3 retention goes.
- **The fleet tenant domain**, and whether existing `*.us5.heyo.work` customer routes are migrated or kept host-scoped.
- **Whether us2** joins this fleet, or stays a separate single host.
- **The staleness bound** after which a host should refuse authenticated requests rather than serve from an old snapshot (revocation versus availability).
