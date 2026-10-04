# HWS documentation

Heyo Web Services documentation. These pages are also published at
[heyo.computer/docs](https://heyo.computer/docs/hws-overview.html).

## Start here

- [Overview](overview.md) — what HWS is and how the components fit together
- [Installation](installation.md) — stand up a host and register a first deployment
- [Onboarding](onboarding.md) — a new user's path: namespace, MCP token, first deployment
- [Multi-region](multi-region.md) — one platform across several regions

## Routing and deployments

- [app-lb](app-lb.md) — load balancer, autoscaler, deployment spec and admin API
- [Authentication](app-lb-auth.md) — admin API credentials, app-tokens and sign-in gates
- [heyctl](heyctl.md) — the command-line client
- [Orchestrator](orchestrator.md) — service deployments, discovery and regional rollouts

## Platform services

- [app-obs](app-obs.md) — logs, metrics, retention and alerts
- [Artifacts](artifacts.md) — the `art` content-addressed store
- [HeyoSecret](heyosecret.md) — encrypted secrets
- [pg-fc](pg-fc.md) — Postgres on microVMs
- [Queue](queue.md) — NATS JetStream and its dashboard
- [ci](ci.md) — workflows, runners and releases
- [MCP server](mcp.md) — HWS tools for coding agents

## Development

- [Developer tools](developer-tools.md) — printer, codegraph, computer, plugins and skills
- [Contributing](contributing.md) — repository layout, building, testing and releasing

## Design records

Longer design documents and decision logs live in [`design/`](design/):
[orchestrator design](design/ORCHESTRATOR_DESIGN.md),
[orchestration service spec](design/HEYO_AI_ORCHESTRATION_SERVICE_SPEC.md) and
[multi-region design](design/MULTI_REGION_DESIGN.md). They record how the
system got here; the pages above describe how it works now.
