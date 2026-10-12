# Heyo Web Services

Heyo Web Services (HWS) is an open-source stack for running your own cloud on your own hardware: microVM workloads behind a load balancer and autoscaler, plus the secrets, observability, artifact, CI, database and queue services an application needs around them.

HWS is shaped like the platforms agents already know — deployments, replicas,
routes, secrets, namespaces, tokens — but every piece is a single binary you
run on hosts you control. Workloads are Firecracker or KVM microVMs (or Incus
containers) whose images you build from a Dockerfile, managed by
[heyvm](https://heyo.computer/docs/quickstart.html). HWS adds everything above
the VM.

## Components

| Component | What it does | Page |
| --- | --- | --- |
| **app-lb** | The edge and control plane. A Pingora-based HTTP/HTTPS proxy that routes by host and path to autoscaled microVM pools, fixed upstreams or static sites. Runs the admin API and dashboard for deployments, secrets, builds, artifact pulls, host updates, ACME certificates, disk reclamation and fleet views, and a built-in SIEM with block rules. | [app-lb](app-lb.md) |
| **Authentication** | app-lb protects its admin API (Basic auth, scoped `applb_…` app-tokens, federated Heyo bearers) and puts an optional sign-in gate in front of each deployment (Google, app-token or JWT/OIDC). | [Authentication](app-lb-auth.md) |
| **heyctl** | A kubectl-style CLI and Rust client library for the app-lb admin API, with named contexts for switching between fleets. | [heyctl](heyctl.md) |
| **Plugins** | Optional capabilities a host enables and each namespace installs: telemetry, git repositories, CI, Postgres databases, the artifact store, a secrets page, and Heyo or Google sign-in for deployments. | [Plugins](plugins.md) |
| **SDKs** | [`@heyocomputer/hws`](https://www.npmjs.com/package/@heyocomputer/hws) (TypeScript) and [`hws`](https://crates.io/crates/hws) (Rust): deployments, exec, secrets and every plugin from code. | [SDKs](sdk.md) |
| **Orchestrator** | The Postgres-backed record of what should run where. Provisions CI sandboxes, deploys services (blue/green or rolling), publishes the discovery sets app-lb routes from, and runs durable region-by-region rollouts. | [Orchestrator](orchestrator.md) |
| **app-obs** | Collects console and application logs from each VM, accepts pushed logs over HTTP and syslog, polls app-lb's metrics, stores it all as compacted Parquet with retention, and serves a query API, dashboard and webhook alerts. | [app-obs](app-obs.md) |
| **Artifacts (`art`)** | A content-addressed blob store tuned for ext4: VM images stored sparsely, site bundles, build inputs, workspace snapshots and release binaries, served by the `art` CLI and `art serve`. | [Artifacts](artifacts.md) |
| **HeyoSecret** | A single-tenant store of versioned, AES-256-GCM-encrypted secrets in Postgres, with a bearer-authenticated machine API and an optional dashboard. | [HeyoSecret](heyosecret.md) |
| **pg-fc** | Postgres with one Firecracker microVM per database behind a single wire-protocol pooler on `:6432`. Idle databases stop; cold ones move down storage tiers and come back on the next connect. | [pg-fc](pg-fc.md) |
| **Queue** | A read-only dashboard over a NATS JetStream server, plus recipes for running NATS itself as a managed microVM. | [Queue](queue.md) |
| **ci** | Plans GitHub-Actions-shaped workflow files into jobs, queues them on NATS JetStream with Postgres as the source of truth, and runs each job in a fresh microVM on your runner hosts. Code arrives through `git submit`. | [ci](ci.md) |
| **MCP server** | `heyo-mcp` gives coding agents tools for sandboxes, deployments, logs, metrics, CI runs and artifacts, over stdio or hosted behind app-lb. | [MCP server](mcp.md) |
| **Developer tools** | `printer` (a spec-driven code factory), `codegraph` (tree-sitter code index and patching) and `computer` (Linux desktop automation), with plugins and agent skills. | [Developer tools](developer-tools.md) |

## How the pieces fit

```
                        clients / browsers / agents
                                   │
                                   ▼
   heyctl ──admin API──▶  app-lb  (routing · TLS · sign-in gates · SIEM · autoscaler)
   heyo-mcp ───────────▶    │  ▲                 │
                            │  │ metrics         │ creates / stops VMs
                            │  └──── app-obs ◀───┤ console + app logs
                            ▼                    ▼
                  microVM pools, upstreams,    heyvmd on each host
                  static sites                 (Firecracker · KVM · Incus)
                            ▲
                            │ images, workspaces, site bundles
                           art  ◀── ci (builds, artifacts) ◀── git submit
                                     │
                                     └── NATS JetStream (queue) · Postgres
   heyosecret ── secrets for ci and orchestrator
   orchestrator ── discovery sets and regional rollouts consumed by app-lb
   pg-fc ── databases as microVMs, reached by apps on :6432
```

A request arrives at **app-lb**, which matches a route, checks the
deployment's sign-in gate and block rules, and forwards to the least-busy
replica. If the pool is scaled to zero, app-lb asks the host's heyvm daemon
to boot a VM and holds the request until it is healthy.

A deployment is a JSON spec registered with app-lb (with `heyctl apply`, the
admin API, or the MCP server). A `build` block builds its image from a
Dockerfile on the host; a `workspace` block restores and snapshots its data
through **art**; `env_from` injects secrets from app-lb's secret store.

**ci** turns a `git submit` into jobs, boots a microVM per job, and uploads
what the job produces to **art**. The release workflows in this repository
publish every HWS binary that way, and [installation](installation.md)
installs them back out.

**app-obs** follows every VM's logs and scrapes app-lb's metrics, so a
deployment's logs, latency and errors are queryable without any change to the
application.

## Where to start

- **[Installation](installation.md)** — stand up a host and register a first deployment.
- **[app-lb](app-lb.md)** — the deployment spec, scaling and the admin API.
- **[heyctl](heyctl.md)** — drive a fleet from the command line.
- **[SDKs](sdk.md)** — drive it from TypeScript ([npm](https://www.npmjs.com/package/@heyocomputer/hws)) or Rust ([crates.io](https://crates.io/crates/hws)).
- **[Plugins](plugins.md)** — give namespaces telemetry, git, databases and sign-in.
- **[MCP server](mcp.md)** — let an agent deploy and debug for you.
- **[Multi-region](multi-region.md)** — run one platform across regions.
- **[Contributing](contributing.md)** — build and test the repository.
