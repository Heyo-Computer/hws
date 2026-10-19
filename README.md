# hws — Heyo Web Services

Heyo Web Services is an open-source stack for running your own cloud on your
own metal. It boots Firecracker and KVM microVMs from images you build with a
Dockerfile, puts a Pingora load balancer, autoscaler and SIEM in front of
them, and adds the services an application needs around that: secrets,
observability, an artifact store, CI, Postgres, a queue, and an MCP server so
an agent can drive all of it.

Documentation: **[docs/](docs/README.md)** · [heyo.computer/docs](https://heyo.computer/docs/hws-overview.html)

## Components

| Path | What it is |
| --- | --- |
| [`app-lb/`](app-lb/) | Load balancer, autoscaler and control plane for microVM deployments; ships the `heyctl` CLI |
| [`app-obs/`](app-obs/) | Logs, metrics, retention and a query API for app-lb deployments |
| [`artifacts/`](artifacts/) | Content-addressed artifact store (`art`) for images, workspaces and release binaries |
| [`ci/`](ci/) | CI orchestrator that runs jobs in heyvm microVMs, queued on NATS JetStream |
| [`heyosecret/`](heyosecret/) | Encrypted secrets store with a machine API and dashboard |
| [`orchestrator/`](orchestrator/) | Control plane for sandboxes, service deployments and regional rollouts |
| [`pg-fc/`](pg-fc/) | Postgres in Firecracker, with a pooler that runs a VM per database |
| [`queue/`](queue/) | Dashboard for a NATS JetStream server |
| [`mcp/`](mcp/) | MCP server exposing deployments, logs, builds and artifacts to agents |
| [`ui/`](ui/) | Shared dashboard kit every service serves |
| [`skills/`](skills/) | Reusable agent skills |

## Install

HWS runs on hosts that already run [heyvm](https://heyo.computer/docs/quickstart.html).
Install the services from the public releases, with no credential:

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sh -s -- --list
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sh -s -- heyosecret art app-lb app-obs ci
```

See [Installation](docs/installation.md) for the full order, configuration and
a first deployment.

## Build from source

Each service is its own Cargo workspace:

```sh
cargo build --locked --manifest-path app-lb/Cargo.toml
cargo test  --locked --manifest-path app-lb/Cargo.toml
```

See [Contributing](docs/contributing.md) for the rest.

## License

[Apache License, Version 2.0](LICENSE).
