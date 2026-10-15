# Fleet shared state: one app-lb across hosts

Status: proposal, 2026-10-13 (revised the same day: Postgres via pg-fc replicas; customer databases durable through S3; us4 rolled in without disrupting us5). Phase 1 is built and deployed to us4 (hws #272). Phase 2 is built and live on us4 in fleet mode, with its gate passed (2026-10-14, § Phase 2). Phase 3 is built and us4 shadows us5, gate passed (2026-10-14, § Phase 3). Phase 4 is built and restarts drop nothing on us4, gate passed (2026-10-14, § Phase 4). Phase 5: us5 and us4 are one fleet, writer on us5 (2026-10-14, § Phase 5).
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
- The fleet database is a pg-fc dedicated database with replicas on other hosts. pg-fc already has peers, continuous **logical** replication, and an operator-driven physical handoff. Logical replication does not carry sequences, so promoting a replica must first set `fleet.revision` past `max(revision)` (open question below).
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
- The `placement` spec field moves to phase 3, where the importer first marks deployments pinned. Adding it earlier would publish an API field that does nothing. (Done in phase 3.)
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

Built as specified, with the differences called out. Single-server app-lb is unchanged: with `APP_LB_FLEET_DATABASE_URL` unset it opens no connection, writes no new file and builds every store exactly as phase 1 does.

**`fleet_pg` (`PgStore`)**
- tokio-postgres with a four-connection deadpool, TLS through postgres-openssl (openssl is already app-lb's TLS stack). No ORM.
- **One table, not one per kind.** `fleet.records(kind, key, body bytea, revision, updated_at, updated_by)`. The feed is one ordered index scan, and a transaction spans kinds without a union. Bodies are `bytea`, the exact bytes the stores write, so the snapshot is byte-for-byte a single server's files.
- Revisions come from one sequence. **Every write transaction first takes one advisory lock and holds it to commit**, so revisions become visible in allocation order and the feed can never skip a slow commit. Writes are admin mutations; serializing them costs nothing that matters.
- Compare-and-swap on every write (`Expect::Revision` or `Expect::Absent`; a tombstone counts as absent). Deletes are tombstones with a revision of their own, collected after seven days by the `tombstone-gc` lease holder.
- `LISTEN fleet_changes` from a trigger, plus a one-second poll.
- Leases `(name, holder, epoch, expires_at)`: TTL 15 s, renewed every 5 s, and the holder stops acting 3 s before the TTL would lapse. A write made under a lease carries its epoch, and the transaction refuses it unless that lease is still held at that epoch.
- `fleet.migrations`, applied under an advisory lock so two hosts starting together do not race.
- Calls from synchronous store code go through one worker thread that owns the pool, bounded by `APP_LB_FLEET_TIMEOUT_MS` (default 5000); on a multi-thread runtime the wait uses `block_in_place`.

**`transaction` and `changes_since`** are on a `Transactional` trait in `fleet_store`, implemented by `PgStore` only. A single server's files have no other writer and no caller relies on a multi-file write being atomic, so the file store does not pretend to.

**`fleet_sync` (fleet mode)**
- Every fleet-state store is built over a `FleetCollection` or `FleetDocument`. A write goes to the database first, as a compare-and-swap against the revision this host last saw; only when it commits is the local file written, with the phase 1 file code. Reads never touch the database.
- The files are the local snapshot. `app-lb-fleet-snapshot.json` beside the state file records the feed cursor and each record's revision.
- **Seeding.** The first host to reach an empty database writes its records in one transaction and marks it seeded. A later host takes the database's records, after copying its own state aside to `app-lb-pre-fleet-<time>/`. A host that already has a fleet snapshot but finds an unseeded database does not reseed it: it serves its snapshot read-only and says how to reseed on purpose.
- **Without the database:** a host with a snapshot serves it and refuses mutations; a host with neither refuses to start.
- **The feed** applies other hosts' changes to the files and reloads the owning store: namespaces, workflows, auth providers, secrets, tokens, guard rules and certificates. Deployments, plugin records, postgres ownership and the ACME account land in the files and take effect at the next start; with one writer per kind until phase 3 that is never exercised, and live apply of deployments arrives with phase 3, where the importer becomes their second writer.
- **Sealing.** Certificate private keys and the ACME account key are sealed with `APP_LB_SECRET_KEY` (AES-256-GCM, bound to kind and key) before they reach the database. Secrets are already sealed by their own store. **Fleet mode requires `APP_LB_SECRET_KEY`.**
- Host identity: `APP_LB_FLEET_HOST` (default: the hostname), suffixed with the process id, so a restarted app-lb is a new lease holder.

**The `StoredDeployment` split.** The fleet half is the spec plus `upstream_drains`, `discovery_version` and `route_handoff`; it goes to the database, with its snapshot in `app-lb-fleet.d/deployments/`. **Host fields stay in `app-lb-state.d/`, in the whole record a single server writes**, rather than a new `<state>-host.d/`: that file was already this host's, the format stays exact, and leaving fleet mode is a restart. Load merges the fleet half with this host's own state; a field added later is host state until it is listed in `FLEET_STATE_FIELDS`.

**Leases in use:** `acme` (issuance and renewal; certificate, key, account and backoff writes are fenced by it), `token-sweep` (the expiry sweep, hourly, replacing the sweep at each start), `tombstone-gc`. The placement controller's lease arrives with the controller.

**Admin API.** In fleet mode a mutation of fleet state answers **503** while the store cannot be written, before any handler runs. A write refused mid-request answers **409** (another writer changed the record; the record is re-read so a retry succeeds) or **503** (outage, or another host holds the lease), whatever the handler made of it. Sign-in, exec/shell, regional probes, disks and images are host-local and carry on. `/whoami` reports `fleet_store {available, snapshot_age_secs, cursor}`, and `heyctl whoami` prints it.

**pg-fc on us4** holds the fleet database (`fleet`) as its writer, listening on `127.0.0.1:6432` only, with the database in `PG_VM_POOL_KEEPALIVE_SCHEMAS`.

**Tests.** Against a real PostgreSQL when `APP_LB_FLEET_TEST_DATABASE_URL` is set, each in its own schema: CAS and conflicts, transactions, the feed's order and limit, seeding once, a lease's single holder and the fencing of a lapsed one, LISTEN, two hosts converging (including a forced conflict that succeeds after re-reading), offline start from a snapshot and the refusal without one, the reseed refusal, the fenced kind. Without a database: the registry split and merge, sealing, the admission rules, and the 503 with the store unreachable.

**Live gate on us4: passed 2026-10-14.** Scripts and raw evidence are in `us4:/root/phase2/`.
- **Backward compatibility.** The phase 2 binary in file mode (no fleet variables) left the state, ACME files, modes, deployments and certificates byte-identical, and wrote no fleet file.
- **Seeding.** Switching to fleet mode seeded the empty database with us4's 10 records. The files were unchanged apart from the new snapshot (`app-lb-fleet.d/`, `app-lb-fleet-snapshot.json`), and smoke-us4 kept serving over HTTP and HTTPS with no certificate reissued.
- **Store outage.** pg-fc's pooler was stopped for 10 minutes (18:18:28–18:28:35) under continuous load. 257,023 requests got **0 failures**: HTTPS and HTTP to a static deployment back to back, plus a VM deployment over HTTPS at 2/s. All 30 mutations during the outage answered **503**. `/whoami` reported the snapshot age rising from 20 s to 601 s. The store was writable again within 20 s of the restart, and every mutation afterwards answered 201.
- **Lease holder killed.** After `kill -9`, the next process took all three leases 15 s later (the TTL) at epoch 2. The dead process's `(holder, epoch)` no longer satisfies the fence.
- **CAS conflict.** A change was committed behind app-lb's back while app-lb's write of the same record waited on the write lock. App-lb's write answered **409**, and the retry answered 200 on top of the re-read record.
- **Fenced issuance.** A throwaway deployment on a `*.us4` name was issued a Let's Encrypt certificate in 5 s by the `acme` lease holder. Its key is sealed in the database, a `0600` PEM on disk, and served verified.

Caveat: the VM deployment's backend is a one-connection `busybox nc` loop. At full speed its health checks fail and app-lb rightly answers "no healthy backend", which voided a first outage run. That is why the VM path is paced.

Found along the way, and outside the fleet store: `pg-fc/Dockerfile.pg18` lacked `pg-fc-physical` (fixed in this phase). Deleting a namespace leaves the `heyo` auth provider the auth plugin auto-installed into it.

### Phase 3: shadow us5

us4 holds a one-way, read-only copy of us5's tenant state, and runs, routes and certifies nothing for it.

**`placement`** (the spec field from § 4)
- `{"mode": "pinned", "home": "<host>"}`. `spread` is refused until the placement controller exists (phase 6).
- Modelled in `heyctl/src/types.rs` (`heyctl describe` prints it), the checked-in schema, the MCP server's advertised schema, and a wire golden.
- A single server accepts it and ignores it. In fleet mode, a host's name is `APP_LB_FLEET_HOST`.

**A deployment placed on another host**
- It is kept in a separate *foreign* view in the registry, never in the map the autoscaler, adoption, proxy routing and ACME read. So a shadow host cannot boot, adopt, route or certify another host's deployment by construction, rather than by a check in each of those places.
- It is never this host's to delete, by persisting or by forgetting.
- The admin API refuses to register one placed elsewhere, or to reuse a foreign id (409): it is registered on its home host.
- Live apply: the feed now reloads deployments. Foreign ones are replaced as they arrive. A change to one of this host's *own* deployments made by another writer is logged and applied at the next start; applying it live needs the admin path's care with pools and rollouts, and only phase 5 has a second writer of local deployments.

**The session signing key is fleet state** (kind `auth-key`, sealed). A sign-in on one host is then a sign-in on all of them. The local key file is its snapshot, and a host offers a key it generated to a fleet that has none. This changes phase 1's "left as a host file".

**Credentials move as ciphertext, not through HeyoSecret.** us5 has no `APP_LB_SECRET_KEY` (its secrets are plaintext at rest), and anything relayed through an operator's session is recorded. So:
- The fleet key is us4's. us5 adopts it in phase 5.
- us5's values are carried *to* the fleet encrypted to a key only the fleet host holds. That is the importer below.

**`app-lb-fleet-import`**
- **`--export`** runs on us5.
  - It reads the state directory and writes one bundle, encrypted to us4's RSA public key (RSA-OAEP-SHA256 wrapping AES-256-GCM).
  - It needs no fleet credential, never writes us5's state, and cannot start a server.
  - An unreadable record stops the export rather than vanish from the bundle; otherwise apply would delete it.
- **`--apply`** runs on us4.
  - It decrypts the bundle with the private key, which never leaves us4.
  - It writes into the fleet store in **one transaction**, as `import:us5`. Secrets are sealed in the secret store's own format, and the signing key in the fleet's.
  - Records it wrote before that are gone at the source are deleted.
  - The source's values win for tenant identity. For deployments, a fleet host's own record under the same id is kept and reported: each host's `app-lb-admin` admin route, for example.
  - `--dry-run` reports counts only, and so does the real run. A repeat with nothing changed writes nothing.
- **What is carried:** namespaces, auth providers, deployments (fleet half, pinned to the source), secrets, tokens, guard rules, the signing key.
- **What is not carried:** plugin records, workflows, postgres ownership and ACME state. Carrying them would have us4 act on us5's behalf: run its CI, provision on its pg-fc, renew its certificates.
- Shadowing is a re-run of export then apply, not a long-running process on us5. Phase 5 makes us5 a fleet member that writes directly.

**Gate, on us4** (test hostnames via `--resolve`, no DNS change):
- a us5 app token answers on us4's admin API;
- us5's secrets are readable on us4, sealed in the store;
- the signing key is us5's, so a us5 session cookie verifies on us4;
- us4 creates no VM, route or certificate for any us5 deployment;
- us4 forwards one request for a us5 app to us5's ingress through a plain static upstream.

**Gate on us4: passed 2026-10-14.** us5 was read, never written: the importer and us4's public key went to `/root/fleet-import/`, and the bundle was deleted after use.
- **Export on us5.** 14 deployments, 15 namespaces, 17 auth providers, the secrets document (22 secrets, plaintext on us5), the tokens document (7) and the signing key. 0 unreadable. A 53 KB bundle, ciphertext wherever it travelled.
- **Apply on us4.** 48 writes in one transaction. us5's `app-lb-admin` was kept as us4's, as designed. us4's feed applied the rest live: 13 deployments into the foreign view, plus namespaces, auth providers, secrets and tokens.
- **Token.** us5's `prod` app token (admin, namespace `us5`) answers on us4's admin API as the same token id. It sees the same 4 secrets and 1 namespace as on us5, and `/whoami` on us4 reports the fleet store.
- **Secrets.** Sealed (`aes-256-gcm`) in the fleet store and in us4's `0600` file, while us5 still holds them in plaintext.
- **Signing key.** After the restart, us4's key file hashes the same as us5's. A us5 session cookie verifies on us4 *by construction* (same HMAC key, same gate code). No real browser session was presented: that part is configured, not executed.
- **Nothing for us5 on us4.** Over a minute of ticks after the apply: heyvm sandboxes unchanged (smoke-us4, pg-fleet), certificates unchanged, no ACME attempt for a us5 name, and us5 hostnames answer 404 on us4.
- **Forwarding.** A temporary static deployment on us4 routing `farm-rsvp.us5.heyo.work` to us5's IP answered 200 through us4, the same as direct. The deployment was then removed. Its one ACME attempt failed, as it must, on us4's own account.

Found along the way: adding the `auth-key` kind to an already seeded fleet deleted us4's signing key file, because the snapshot sync replaced it with the nothing the fleet held. Fixed: the fleet now records the kinds it has seeded, and a kind new to it is seeded from the starting host's own records.

### Phase 4: restarts that drop nothing

Both, in order: the proxy worker stays alive across a management restart, and the next manager then hands its listening sockets to a worker of its own build.

**Before.** The forwarding worker was spawned with a parent-death signal, in the manager's process group, and exited on any loss of request control. So every restart closed :80 and :443 and cut what was in flight. Worse, the manager itself sat through pingora's default 300 s grace on `SIGTERM`, and every `supervisorctl restart` ended in supervisor's `SIGKILL` after `stopwaitsecs` (35 s on us4).

**Now.**
- **The worker outlives its manager.** It runs in its own session, so stopping the manager's process group does not reach it, and it keeps its listeners.
  - A request that needs a decision while no manager answers waits for the next one, up to `APP_LB_WORKER_WAIT_SECS` (60). After that it gets a 503 with `Retry-After`; it is never dropped.
  - Requests already forwarding finish without a manager.
- **The control directory is fixed** (`app-lb-worker.d/` beside the state): `requests`, `bootstrap`, `upgrade` and `worker.json`. The next manager:
  - binds the sockets;
  - finds the worker still serving, and skips the startup port check it would otherwise fail;
  - starts a worker from its own binary, and waits until that worker is listening on `upgrade`;
  - then sends the old worker `SIGQUIT`. pingora hands the listening sockets across, the old worker keeps accepting for 5 s, then stops and drains for `APP_LB_DRAIN_SECS` (300) before exiting. A held stream survives a restart for that long. (pingora's runtime shutdown after the drain cancels tasks rather than waiting for them, so the drain is the whole of it.)
  - The proxy app defers pingora's shutdown cleanup by 3 s. On shutdown pingora stops accepting and, in the same instant, drops every connection still waiting for its request. That includes one the old worker accepted a moment earlier whose request is still in flight: a request lost to the restart. With the delay, those requests arrive and are served, and only connections idle for the whole delay are closed.
- **One manager at a time is unchanged.** The instance lock still keeps a second app-lb off the daemon. Only the worker, which never touches the daemon, outlives a manager.
- **A lost request-control link is told apart.** If the manager that began the request still answers, the link failed under it: the worker exits as before, which releases the admission state it held. If that manager is gone, it was a restart, and the worker carries on.
  - The handshake names the manager, in an optional field older peers ignore. Adjacent releases stay compatible across a takeover.
- **Admission state** whose link broke is released when the worker that held it exits. That worker is the connection's peer pid (`SO_PEERCRED`), since a taken-over worker is no manager's child.
- **A real stop:** a worker no manager returns to drains and exits after `APP_LB_WORKER_ORPHAN_SECS` (120). Setting it to `0` restores dying with the manager.
- **The manager exits at once on `SIGTERM`** (grace 0): it holds no listener to drain.
- **The worker logs to `app-lb-worker.d/worker.log`**, rotated at 50 MB. The manager's stdout is a supervisor pipe that closes when the manager exits.

The first restart onto this build still drops: the old binary takes its worker down with it. Every restart after that hands over.

A request whose manager is replaced between being begun and being forwarded is begun again with the next manager. That happens only when the link dropped and a different manager now answers; an answer from a live manager is unchanged.

**Gate on us4: passed 2026-10-14.** Five `supervisorctl restart app-lb`, 40 s apart, under continuous load. Scripts are in `us4:/root/phase4/`.
- **Requests:** 98,901 with **0 failures**. That is HTTPS and HTTP back to back to a static deployment with a Let's Encrypt certificate, plus a VM deployment over HTTPS at 2/s.
- **Latency:** a separate probe every 0.2 s over HTTPS made 1,406 requests, all 200, and its **slowest was 0.01 s**. The time with no manager is shorter than the probe interval.
- **Held streams:** two streams of 150 s, each one line a second, received **all 150 lines** across four of the restarts.
- **Restart time:** each restart took 5.1 s, which is supervisor's `startsecs`. Before this phase every restart took 35–40 s and ended in `SIGKILL`.
- **A real stop:** a request made after `supervisorctl stop` waited the 60 s budget and got a 503. A start inside the orphan window took the waiting worker over, and requests answered 200 again.

Getting there found two drops, both now fixed:
- **pingora's shutdown cleanup** cut a request the old worker had accepted at its last moment (1 failure in 82k). Fixed by deferring the cleanup 3 s.
- **A dead manager mid-request:** a request begun by a manager that exited before the request asked for its upstream failed with 500 (1 in 82k). Fixed by beginning it again with the next manager.

The first run's streams also showed that the drain, not the runtime shutdown timeout, bounds a held stream's life. The default drain is now 300 s.

### Phase 5: us5 joins

Done 2026-10-14. us5 and us4 are members of one fleet, and the fleet database's writer is on us5's pg-fc. Decisions, made with the user:
- **The writer lives on production (us5)**, so production writes never depend on the shadow host. us4 reaches it over TLS at `pg.us5.heyo.work:6432`.
- **The first deploy onto the phase 4 build was a fast kill:** `SIGKILL` the old manager, and supervisor restarts the new binary.
- **Plugins run only on a home host.**
- **Per-host deployments are renamed:** `app-lb-admin` became `app-lb-admin-us4` and `app-lb-admin-us5`.

**What joining needed** (a joining host's files are replaced by the fleet's):
- **Plugin home host.** Plugin records carry `home`. In fleet mode only that host starts the plugin and acts for its namespaces; the others keep the record. A plugin first configured or default-enabled on a host is homed there, and acting on it elsewhere answers 409 `plugin_elsewhere`. Without this, us5's CI, postgres and remote plugins would have run on us4 too.
- **Default placement.** In fleet mode a deployment registered or updated without a placement is pinned to the host that took it. us4's unpinned smoke VM would otherwise have started on us5.
- **Per-host ACME lease (`acme:<host>`).** A host issues only for the deployments it runs: the names DNS sends it, and the only HTTP-01 challenges it can answer from memory. A fleet-wide lease would have had us4 order certificates for us5's names and fail.
- **The join import.**
  - `--export --join` also carries plugins (homed on the source), the postgres ownership map, the ACME account and every certificate, with keys sealed on apply.
  - `--host-scoped ID` carries a per-host deployment as `ID-<host>`.
  - Bundles name the kinds they speak for, and apply deletes only within them.
  - `--apply --seed` makes a bundle the first records of an empty store.
- **TLS to the database.** This binary's openssl is built from source (`openssl-src`), so its default trust store is the empty `/usr/local/ssl`. The client now loads the system CA bundle, or `APP_LB_FLEET_CA_FILE`.
- **Adoption wakes held requests.** A request that reached a starting manager before adoption held for a cold start that adoption never ended. At us5's switch one request hung for 70 s. Adoption now notifies waiters, and the manager decides requests only once adoption is done (60 s at most), so requests held across a restart go straight to the adopted VMs. pingora starts a dependent service when its dependency *starts*, not when it is ready, so the old "proxy waits for adoption" ordering never really held.

**Rollout, in order**
1. **us4:** the new build, by handoff.
2. **us5:** the new build in file mode, by fast kill.
   - The drop was **about 2 s** (10 of 176 probes at 0.2 s).
   - Afterwards state, certificates, deployments, plugins and every production name were identical. The only change was `dassie-app`'s host state, a deployment whose VM has been failing to boot since 2026-10-10.
3. **Credentials moved as ciphertext only** (RSA-OAEP to the receiving host's key):
   - the fleet database's password to us4;
   - the fleet `APP_LB_SECRET_KEY` (us4's; us5 had none) to us5.
4. **The `fleet` database was created on us5's pg-fc.** pg-fc's config was not changed (that needs a restart that drops customer databases). The database is never idle, because every member holds a `LISTEN` connection.
5. **us4 seeded it with its own join bundle** (`--seed`, 47 records). Then us5's fresh join bundle was applied over it (93 writes): us5's values overwrote the stale shadow copies, and us4's `app-lb-admin-us4` and `smoke-us4` were kept.
6. **us4 moved onto it.** With its snapshot record removed it rejoined as a fresh member: it runs `app-lb-admin-us4` and `smoke-us4`, keeps us5's 14 deployments as foreign, and starts none of us5's 7 plugins.
7. **us5 switched.**
   - A final export and apply came first. The fleet key went into `/etc/app-lb/env`, and the supervisor command now sources `/etc/app-lb/fleet.env`.
   - The restart was a handoff. us5 copied its state aside (`app-lb-pre-fleet-*`, plaintext secrets included) and took the fleet's 139 records. It runs its 14 deployments, sees us4's 2 as foreign, and holds `acme:us5`.

**Gate**
- **Restart on production names.** After the adoption fix, a handoff restart under paced load (admin, hub and farm-rsvp, each every 0.2 s): **1,159 requests, 0 failures, max latency 0.06 s**. The switch restart itself, before that fix, lost the one request described above.
- **Nothing lost.** Against us5's pre-fleet baseline: the same 14 deployments, with the admin route renamed and still serving `admin.us5.heyo.work`. The same plugins, enabled and applied; the same answers on every production name; 22 secrets across the namespaces, now sealed at rest; 7 tokens; us5's 35 certificates, plus us4's 4.
- **One authority.** A namespace created on us5 was visible through us4's admin API about a second later, and its delete propagated.

**Rollback (us5).** Move `/etc/app-lb/fleet.env` aside and restart. The files are a complete snapshot, and the fleet key stays in `/etc/app-lb/env`, which the sealed secrets file needs. The pre-fleet state is in `/var/lib/app-lb/app-lb-pre-fleet-1792016345/`, and the previous binary is `app-lb.bak-pre-fleet-join`.

**Not done here**
- **A read replica.** pg-fc replicates logically and needs `PG_VM_POOL_REPLICATION` on both nodes, which means restarting us5's pg-fc and dropping customer database connections. It also needs the sequence step from the open questions before a replica could be promoted. Each host keeps serving from its own snapshot while the writer is down; writes answer 503.
- **us4's old fleet database** (on us4's pg-fc) is unused and can be removed.
### Phase 6: serve together

1. Enable the fleet hop (`APP_LB_FLEET_FORWARD=1`), us4 first.
2. Enable the placement controller and opt-in `spread`: the smoke app, then new stateless apps, then remote and artifacts.
3. Add fleet certificates and dual-A DNS on a test name, then on the fleet domain. `*.us5.heyo.work` keeps pointing at us5 only.
4. Run live acceptance (§ Gates). Only after it passes do new deployments default to `spread`.

#### 6a as built: the fleet hop (2026-10-14)

- **Membership.** Migration 2 adds `fleet.hosts`. Each host heartbeats its row every 5 s, with its `APP_LB_FLEET_ADDRESS` and boot id, and reads the table back. A member is live if its heartbeat is under 15 s old, measured by the database clock.
- **Token.** The peer token is a sealed fleet record (`peer-token`). The first host to start without one creates it. Hosts compare it in constant time. It is never logged or shown in `Debug`.
- **Ingress.** With `APP_LB_FLEET_FORWARD=1`, a request with no local route but a foreign one (from the fleet's view of other hosts' registries) runs every edge check, then goes once over HTTPS to the home host's address, with the original `Host` as SNI. The home host's `x-vm-id` passes through unchanged. A hop is never retried.
- **Receiver.** A hop header without the right token gets 403. A valid hop takes the client address from `X-Forwarded-For`. A valid hop for a deployment this host does not run gets 503 and is never forwarded again.
- **Live as of 2026-10-14:**
  - us4: `APP_LB_FLEET_FORWARD=1`, address 204.13.237.70.
  - us5: accepts hops but does not forward, address 216.158.232.126.

**Gate evidence (One hop, 2026-10-14, 3fc4cbb):**
- **Load through us4.** 60 s of paced requests through us4's ingress to farm-rsvp.us5, hub.us5 and admin.us5: 504 of 504 succeeded, with us5's VM ids passed through.
  - An earlier, faster run got 429s from hub's own rate limit. A burst sent directly to us5 hits the same 429 (from the same VM), so those 429s came from the app, not the hop.
- **Forged hops.** Sent to us5, a hop header with no token gets 403, and one with a wrong token gets 403.
- **Genuine hop for us4's deployment.** Sent to us5 with the real token and `Host: smoke.us4.heyo.work`, it gets 503: "runs on us4, not here; a fleet hop is never forwarded again". The same hop for farm-rsvp.us5 gets 200.
- **Not tested live:** a home host with the route but an empty pool. That case takes the ordinary local path (cold start or 503), never a forward.
- **Handoff.** us5's handoff to 3fc4cbb under load: 584 requests, 0 failed.
- **Bug found by this gate.** The first live hop closed the worker's control stream: the manager required a local backend for every peer. The worker exited and its supervisor replaced it. Fixed in 3fc4cbb.

#### 6b as built: shared ACME challenges (2026-10-15)

- **Challenges are fleet state.** Outstanding HTTP-01 responses are a fleet kind (`acme-challenges`), keyed by token. Each record names its issuer and is fenced by that host's `acme:<host>` lease.
  - The feed loads them into every member's challenge table, so any host answers any host's challenge.
  - The responses are not sealed: they are public by design, and they are retracted when the order ends.
- **Proof before ready.** Before marking a challenge ready, the issuing host fetches it, as the CA would, from each other live member whose address the name resolves to. It allows 20 s each.
  - If one cannot answer, the order is abandoned before the CA spends any of its validation budget. The failure then goes into the usual backoff.
  - Members outside the name's DNS are never asked, so host-scoped names (`*.us5.heyo.work`) behave as before.
- **Clean starts.** A host retracts any challenges an earlier process of its own left behind.
- **Cross-host nudge.** A deployment change arriving through the feed nudges this host's issuance, which closes the "issue-now is local" open question for deployments a host runs. (A fleet kind may now have several reload hooks.)
- **Not yet decided:** which host issues for a spread deployment. That is 6c's.

**Gate evidence (2026-10-15, f206556):**
- **Negative.** us4 ran 6b; us5 still ran 6a. us4 registered `fleet-acme-test.us5.heyo.work`, a name that resolves to us5 only. us4 abandoned the order without telling the CA the challenge was ready: "fleet host us5 (216.158.232.126:80) did not answer the challenge within 20s: answered 404".
- **Handoff.** us5 handed off to 6b under load: 584 requests, 0 failed.
- **Positive.** us4 registered the same name again and got a Let's Encrypt certificate (CN=YE2, SAN fleet-acme-test.us5.heyo.work) about 10 s later. The CA could only have validated at us5, which answered us4's challenge from the fleet store. The challenge record was then retracted: its tombstone was written by us4, and no live challenge records remain.
- **Not tested live:** the cross-host nudge.

#### 6c as built: spread placement and the controller (2026-10-15)

- **Spec.** `placement.mode: spread` is accepted for VM pools with no host-bound state. Refused: no VM pool, `vm.workspace`, `vm.mounts`, `vm.disk_size_gb`, `idle_action: retain`, `vm.build`, an artifact store given as a path, and regional discovery or gateways.
- **Tables (migration 3).**
  - `host_demand(host, deployment, in_flight, waiters, ready, booting, idle_secs)`: each host writes its rows once a second, only when they change, and clears them at start.
  - `placement_targets(deployment, host, desired, generation)`.
  - Every host reads both into a cached view once a second. The data plane reads the view, never the database. This replaces the `/fleet/v1/pool` poll the design proposed.
- **Controller** (`fleet_placement`, lease `placement`, every 2 s):
  - It sizes each deployment once for the fleet with the single-host formula (`deployment::desired_for`) applied to the summed demand. It splits the result across live, active hosts: demand first, then hosts already running replicas, then by name.
  - It writes in one transaction, fenced by the lease epoch.
  - **Make before break:** while any host is short of its share, no host's target drops below what it has ready.
- **Hosts.**
  - The autoscaler runs this host's target. Until the first read of the view, a host sizes itself, so a restart keeps the replicas it adopts.
  - A waiter on a host whose target is zero boots one replica there, and the controller absorbs it.
  - Another host's change to a spread deployment applies at once, by the admin API's rule: a new template (VM, upstreams or artifact) rebuilds the pool, and anything else keeps it. A pull filling in `vm.image` is not a new template. Removal tears down this host's replicas.
- **Routing.** A spread request with nothing ready locally goes once to the least-utilised peer that has ready replicas and still a target. Failing that, if this host has no target, it goes to the peer that does. Otherwise it waits locally. A spread deployment this host does not run is forwarded the same way.
- **Certificates.** The first live host by name among those running a spread deployment issues its certificate.
- **Forwarding is on for both hosts.** us5's `fleet.env` gained `APP_LB_FLEET_FORWARD=1`; its backup is `/root/phase5/fleet.env.bak-pre-forward`.

**Gate evidence (2026-10-15, 85dabcf):** the `spread-smoke` test app, routed through both ingresses (us4 locally, and us5 at its public address).
- **Spread.** With `min_replicas: 2`, each host runs exactly one VM (targets 1/1). Each ingress is served by its own host's VM: 20 of 20 through each.
- **Template change under load.** A new VM template registered on us4 rebuilt the pool on both hosts.
  - 729 requests through both ingresses, 0 failed.
  - During the gap, each ingress served from the other host's new VM.
  - One VM per host afterwards.
- **Scale down under load.** At `min_replicas: 1`, us5 drained to zero, and its ingress forwarded every request to us4's VM: 664 requests, 0 failed.
- **Scale from zero.** With every target at zero, a request through us5 booted a replica there on us5's own authority: 200 in 6.6 s.
- **Controller restart.** The lease holder (us4, epoch 6) was restarted while scaling to 4.
  - us5 took the lease at epoch 7, and the targets held at 2/2.
  - Each host ended with exactly 2 VMs: no duplicates.
  - 808 requests during it, 0 failed.
  - The stale-epoch fence is covered against Postgres (`write_targets` refuses a stale epoch).
- **Removal.** Deregistering on us4 tore down us5's replicas, and the targets were removed.
- **Restarts.** us5 adopted and kept its spread replica across its own restart. Every production handoff dropped nothing (582, 582, 592 and 596 requests, 0 failed).

**Found and fixed during the gate:**
- another host's change to a spread deployment waited for a restart;
- a restart drained adopted replicas against the empty view;
- a request was forwarded to a peer that was about to drain;
- a peer's template change kept this host's old pool.

**Not changed (pre-existing):** with `min_replicas: 0` and `warm_pool: 0`, the sizing formula returns 0 as soon as demand is 0, so `scale_to_zero_after_secs` never delays the drain. A single host behaves the same.

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
| [x] One hop (6a, 2026-10-14) | Requests to us4 for a us5-pinned app succeed. A forged `x-heyo-fleet-hop` without the token is refused. Forcing B's pool empty yields 503, never a bounce. |
| [ ] Drain us5 | Continuous requests through both ingresses during drain → upgrade → restore → bake: zero failures, no admissions to drained backends, and the surviving path does not use us5's ingress. |
| [ ] Drain us4 | Same, the other way. |
| [x] Controller restart (6c, 2026-10-15) | Kill the lease holder mid-scale: no duplicate replicas, targets converge, and the epoch fences the old holder. |
| [ ] Unhealthy candidate and rollback | A `spread` rollout whose candidate fails health stops on both hosts and rolls back, with serving capacity preserved. |
| [ ] app-lb restart | Restarting app-lb on one host (infrastructure maintenance, not app rollout) with traffic moved away first: zero failures. |
| [ ] Never cross-daemon | Audit both heyvm logs across all gates: no host created, adopted or killed a VM on the other host's daemon. |

## Open questions

- **Promoting a logical replica of the fleet database.** pg-fc replicates logically, which does not carry sequences: before a replica takes writes, `fleet.revision` must be set past `max(revision)`, or new revisions would repeat old ones and every feed would skip them. Phase 5 needs either that step in the promotion runbook or a physical replica.
- **ACME across hosts.** Answered by 6b: challenges are shared, and the nudge travels with the feed. Which host issues for a `spread` deployment is 6c's.
- **One token document.** Tokens are one fleet record, so two hosts minting at once conflict, and the loser's sign-in token is dropped from memory when its store reloads. Before two hosts serve sign-ins (phase 6), tokens should become one record each.

- **Customer database snapshots:**
  - the snapshot interval, which is the recovery point;
  - the method (`pg_basebackup`, or `fsfreeze` plus reflink);
  - how far back S3 retention goes.
- **The fleet tenant domain**, and whether existing `*.us5.heyo.work` customer routes are migrated or kept host-scoped.
- **Whether us2** joins this fleet, or stays a separate single host.
- **The staleness bound** after which a host should refuse authenticated requests rather than serve from an old snapshot (revocation versus availability).
