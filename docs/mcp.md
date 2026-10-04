# MCP server

`heyo-mcp` is a Model Context Protocol server that gives coding agents such as Claude Code tools for HWS sandboxes, app-lb deployments, app-obs logs and metrics, ci runs and the artifact store.

## What it is

The server lives in `mcp/` (TypeScript, Node 22). It exposes two kinds of tool:

- **Sandbox tools** use the Heyo cloud API to boot a microVM, run commands in it, and move files in and out.
- **Fleet tools** operate on [app-lb](app-lb.md), [app-obs](app-obs.md), [ci](ci.md) and the [artifact store](artifacts.md). Several diagnostic tools answer questions that span services. For example, `diagnose_empty_pool` combines app-lb's pool state, app-obs's logs and the metrics that explain why a pool won't fill.

It runs in two modes:

| Mode | When | How callers authenticate |
|---|---|---|
| stdio (default) | An agent launches it locally | Credentials come from the environment the agent host starts it in |
| HTTP | `HEYO_MCP_HTTP_PORT` is set. It runs as an app-lb deployment, shared by many callers. | app-lb's gate in front, plus the caller's own bearer token forwarded upstream |

Every service is optional. A service you don't configure still lists its tools, and calling one returns an error naming the variable to set. Sandbox tools are the exception: they are listed only when a usable cloud key is available.

## Install

```sh
cd mcp
npm install
npm run build        # compiles to mcp/dist/
npm test             # optional: node --test over dist/*.test.js
```

### Claude Code, hosted server

Heyo runs the server at `https://mcp.us2.heyo.work/mcp` (streamable HTTP). Point Claude Code at it with an app-lb token:

```sh
claude mcp add --transport http heyo https://mcp.us2.heyo.work/mcp \
  --header "Authorization: Bearer applb_…"
```

A namespace user mints that token from the app-lb dashboard's "Get started" card (or **App-tokens → New token**). It is an `admin`-tier token confined to their namespace and expires within 90 days; see [app-lb auth](app-lb-auth.md#namespace-admins-mint-their-own-tokens). The `applb_*` tools work with it. The app-obs and ci tools do not yet, because those gates live in the `default` namespace (see [Limits and known gaps](#limits-and-known-gaps)).

### Claude Code, local server

```sh
claude mcp add heyo \
  -e HEYO_API_KEY=heyo_api_… \
  -- node /path/to/hws/mcp/dist/index.js
```

Or in a project's `.mcp.json`:

```json
{
  "mcpServers": {
    "heyo": {
      "command": "node",
      "args": ["/path/to/hws/mcp/dist/index.js"],
      "env": {
        "HEYO_API_KEY": "heyo_api_…",
        "APPLB_URL": "http://127.0.0.1:9090",
        "APPLB_TOKEN": "applb_…"
      }
    }
  }
}
```

Other MCP hosts work the same way: run `node /path/to/hws/mcp/dist/index.js` over stdio with the variables below in its environment. The server writes logs to stderr only, because stdout carries the protocol. At startup it prints a ready line listing the configured services, plus a `CREDENTIAL FAULT` banner if a key has the wrong shape (for example an `applb_` token in `HEYO_API_KEY`).

After connecting, call `heyo_status` first. It reports which services the server can reach and what each says about itself.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `HEYO_API_KEY` | unset | Heyo cloud API key (`heyo_api_…`). Enables the sandbox tools, and is app-lb's default credential in managed mode. |
| `HEYO_BASE_URL` | `https://server.heyo.computer` | Cloud API base URL. |
| `APPLB_URL` | cloud base (managed mode) | app-lb base URL: its own admin listener (for example `http://127.0.0.1:9090`) or the cloud base. |
| `APPLB_NAMESPACE` | discovered from the key | Managed mode: the base becomes `${APPLB_URL}/namespaces/<ns>/lb`. |
| `APPLB_TOKEN` | falls back to `HEYO_API_KEY` in managed mode | Bearer token for app-lb: an `applb_…` app token (self-hosted) or a `heyo_api_…` key (managed). |
| `APPLB_BASIC` | unset | `user:pass`, or a complete `Basic …` header, for a password-gated app-lb. Sent byte for byte. |
| `APP_OBS_URL` | unset | app-obs base URL. |
| `APP_OBS_API_TOKEN` | unset | Bearer token for app-obs query routes. |
| `CI_URL` | unset | ci base URL. Use ci's own listener (see [ci behind a gate](#ci-behind-an-app-lb-gate)). |
| `CI_TOKEN` | unset | A repository submit token (`git config ci.token`), used by `ci_run_status` and `ci_run_logs`. |
| `ART_URL` | unset | Artifact store base URL. |
| `ART_API_KEY` | unset | The store's own key, sent as `x-api-key`. |
| `ART_GATE_TOKEN` | `APPLB_TOKEN` | App token for an app-lb gate in front of the store, sent as `Authorization`. |
| `HEYO_MCP_TIMEOUT_MS` | `30000` | Timeout per upstream request. |
| `HEYO_MCP_HTTP_PORT` | unset | Set this to serve HTTP instead of stdio. |
| `HEYO_MCP_HTTP_HOST` | `127.0.0.1` | HTTP bind address. |
| `HEYO_MCP_REQUIRE_IDENTITY` | on | HTTP mode: refuse requests without an app-lb forwarded identity. Set `0` to disable (see [Hosted mode](#hosted-mode)). |

### Minimal configurations

Managed app-lb through Heyo cloud. One key covers sandboxes and deployments, and the namespace is discovered from the key on first use:

```sh
HEYO_API_KEY=heyo_api_…
```

If the key can see several namespaces, discovery fails and lists them. Set `APPLB_NAMESPACE` to choose one.

Self-hosted HWS fleet, run on the app-lb host:

```sh
APPLB_URL=http://127.0.0.1:9090
APPLB_TOKEN=applb_…
APP_OBS_URL=http://127.0.0.1:9600
APP_OBS_API_TOKEN=…
CI_URL=http://127.0.0.1:9555
CI_TOKEN=…
ART_URL=http://127.0.0.1:8090
ART_API_KEY=…
```

## Credentials

Four kinds of credential are involved. They are not interchangeable.

| Credential | Looks like | Accepted by |
|---|---|---|
| Heyo cloud API key | `heyo_api_…` | Heyo cloud (sandboxes), and app-lb only through cloud's `/namespaces/{ns}/lb` path |
| app-lb app token | `applb_…` | app-lb's admin API, and app-lb auth gates in front of deployments. **Not** accepted by cloud. |
| Service tokens | anything | Only the service they belong to (`APP_OBS_API_TOKEN`, `CI_TOKEN`, `ART_API_KEY`) |
| JWT | `eyJ…` | app-lb `jwt` gates (see [app-lb auth](app-lb-auth.md)) |

### App token scopes

An app-lb app token has two independent scopes, checked in different places:

- **Admin tier** (`none`, `view`, `admin`) is checked by app-lb's admin API. `view` covers only `/metrics`, `/disks`, `/feeds`, `/security`, `/ingress` and `/storage`, which serve `applb_metrics`, `applb_disks`, `applb_security_events` and the feed tools. Everything else needs `admin`.
- **Deployment scope** (a `deployments` list and/or a `namespace`) is checked by each deployment's own gate.

There is no read-only tier for deployments. `GET /deployments` requires `admin`, because specs can hold secrets. So a token that can run `applb_get_deployment` can also run `applb_delete_deployment`. To narrow a token that needs deployment reads, restrict its `deployments` list or `namespace`.

When a call returns 401 or 403, run `heyo_whoami`. It reports the current credential's admin tier, namespace, deployment scope and expiry, which tells an authentication failure apart from a scope failure.

## Tools

65 tools in total. **Read-only** tools only issue `GET` requests, which is checked by a test. **Destructive** tools have descriptions starting with `DESTRUCTIVE`, and that prefix is what sets `destructiveHint`. The full generated list with descriptions is in [the component README](../mcp/README.md#tools) (`npm run catalogue` regenerates it).

### Diagnostics

| Tool | Notes |
|---|---|
| `heyo_status` | read-only. Which services are reachable and configured. Also resolves the managed namespace. |
| `heyo_whoami` | read-only. The current credential's scope and expiry. |
| `fleet_overview` | read-only. app-obs rows plus app-lb topology and ingest counters. |
| `diagnose_deployment` | read-only. Args `id`, `window`. app-lb record, pool, series, recent errors. |
| `deployment_logs` | read-only. Args `id`, `window` or `from`/`to`, `level`, `backend`, `q`, `before`. |
| `diagnose_empty_pool` | read-only. Why a VM pool is empty or won't fill. |
| `diagnose_ci_job` | read-only. Why a ci job isn't running. Needs ci's own listener. |

### Deploying

| Tool | Notes |
|---|---|
| `applb_deploy` | Entry point. Arg `spec`. Validates cross-field rules, creates or updates, starts the right job, waits, and reports TLS. |
| `applb_spec_schema` | read-only. Arg `block` (for example `VmSpec`, `AuthGate`, `JwtSpec`, `MountSpec`, `ScalingPolicy`, `BuildSpec`). Omit it for the index. |
| `applb_create_deployment` | `POST /deployments`: replaces the deployment and recycles its pool. |
| `applb_update_deployment` | `PUT`: keeps the pool when the `vm` block is unchanged. |
| `applb_delete_deployment` | destructive. |
| `applb_scale` | Args `id`, `scaling`. |
| `applb_build` | `vm` deployments with a `build` block. Arg `git_ref`. |
| `applb_pull` | `vm` or `site` deployments, from an artifact store. Arg `artifact_ref`. |
| `applb_pull_mounts` | Re-unpack a `vm` deployment's mounts. |
| `applb_host_update` | Static (`upstreams`) or `site` deployments only: runs their `update.commands`. |
| `applb_job`, `applb_deployment_jobs` | read-only. Job status. |

### Fleet and pools

| Tool | Notes |
|---|---|
| `applb_list_deployments`, `applb_get_deployment` | read-only (but need `admin` tier). |
| `applb_metrics`, `applb_disks`, `applb_certs`, `applb_security_events` | read-only. |
| `applb_feeds`, `applb_feed` | read-only. Per-namespace deployment event feed. |
| `applb_drain_upstream` | destructive. Take a static upstream out of rotation. |
| `applb_uncordon_upstream` | Put it back. |
| `applb_evict_vm` | destructive. Destroy one pool VM. |
| `applb_exec` | destructive. Run a command in a deployment's guest. Args `id`, `command`, `cwd`, `env`, `sandbox_id`. |
| `applb_purge_disk`, `applb_purge_orphan_disks`, `applb_sweep_disks` | destructive. "Orphaned" is app-lb's inference, so review before purging. |

### Sandboxes

Listed only when a usable `heyo_api_…` key is available, either configured or forwarded by the caller.

| Tool | Notes |
|---|---|
| `sandbox_create` | Args include `image`, `size_class`, `region`, `driver`, `name`, `archive_id`, `start_command`, `working_directory`, `env_vars`, `open_ports`, `setup_hooks`, `wait_seconds` (default 120), `retries` (503 retries, default 3). |
| `sandbox_list`, `sandbox_info` | List sandboxes, or show one. |
| `sandbox_exec` | Runs `sh -c` and returns stdout, stderr and exit code. |
| `sandbox_read_file`, `sandbox_write_file` | Writes are limited to 512 KiB. Use the archive route for larger files. |
| `sandbox_upload_url`, `sandbox_finalize_upload`, `sandbox_attach_archive` | Large uploads through a presigned URL. |
| `sandbox_set_ttl`, `sandbox_stop`, `sandbox_start`, `sandbox_restart` | Lifecycle. A stopped sandbox keeps its disk. |
| `sandbox_kill` | destructive. Deletes the sandbox and its disk. |
| `heyo_capacity` | read-only. Daemons registered to this key, and running sandboxes. |

### Artifact store

| Tool | Notes |
|---|---|
| `art_publish` | Args `tag`, `content_base64` or `path` (stdio only), `name`, `kind`, `annotations`. Uploads the blob, writes a manifest, and points the tag at the **manifest** digest. |
| `art_list_tags`, `art_get_tag`, `art_get_manifest`, `art_list_blobs`, `art_usage` | read-only. |

### ci

| Tool | Notes |
|---|---|
| `ci_run_status`, `ci_run_logs` | read-only. Use `CI_TOKEN`. Work through the public gated hostname. Check `run.finished`, not the status string. |
| `ci_cancel_run`, `ci_destroy_vm`, `ci_cleanup_failed_vms` | destructive. |

### Raw requests

`heyo_request` (sandboxes only), `applb_request`, `obs_request`, `ci_request` and `art_request` send arbitrary HTTP to each service. Prefer a named tool: a raw call's intent, including a `DELETE`, is hidden in its arguments.

### Resources and prompts

| URI | Contents |
|---|---|
| `heyo://applb/deployment-spec` | Full deployment spec schema, generated from app-lb's Rust types, plus cross-field rules |
| `heyo://applb/deploy-guide` | The deploy sequence end to end |
| `heyo://applb/tls` | Why exact `host` routes get certificates and `host_suffix` routes need a wildcard |
| `heyo://applb/examples/{name}` | Each spec in [app-lb/examples](../app-lb/examples), for example `heyo://applb/examples/git-build.json` |

The server has one prompt, `deploy_a_service(kind, id, host?)`, where `kind` is `vm`, `site` or `static`. It returns the ordered plan for that backend type.

## Deploying with an agent

A typical request is "deploy this service". The agent should do the following:

1. Call `applb_spec_schema` (or read `heyo://applb/deployment-spec`) and pick the closest example.
2. Call `applb_deploy` with the full spec. In managed or namespace-scoped use, include `"namespace": "<ns>"`: a spec without one means `default`.
3. Watch the job it returns with `applb_job`.

A minimal `vm` deployment that builds from a Dockerfile:

```json
{
  "id": "hello",
  "namespace": "team-a",
  "routes": [{ "host": "hello.example.com" }],
  "vm": {
    "driver": "firecracker",
    "image": "hello",
    "port": 8080,
    "size_class": "micro",
    "start_command": "setsid nohup /usr/local/bin/hello </dev/null >/var/log/hello.log 2>&1 &"
  },
  "build": {
    "repo": "https://github.com/example/hello.git",
    "ref": "main",
    "dockerfile": "Dockerfile"
  },
  "scaling": { "min_replicas": 1, "max_replicas": 3 },
  "health": { "path": "/health", "timeout_secs": 2 }
}
```

This follows `heyo://applb/examples/git-build.json`, which also shows private-repo auth and the remaining scaling fields. [app-lb](app-lb.md) documents the spec in full.

Which job applies depends on the backend:

| Backend | Update with |
|---|---|
| `vm` with a `build` block | `applb_build` |
| `vm` or `site` with bytes in an artifact store | `art_publish`, then `applb_pull` |
| static `upstreams` | `applb_host_update` (runs the spec's `update.commands` on the app-lb host) |

Choosing the wrong job is refused, not ignored. `applb_host_update` never updates a managed `vm` deployment.

TLS: an exact `host` route gets a certificate automatically within seconds. A `host_suffix` route needs a fleet wildcard certificate, and without one it is served a fallback certificate that won't validate.

### Publishing a build

`art_publish` performs three requests in order: `PUT /blobs/{sha256}`, `PUT /manifests`, then `PUT /tags/{tag}` with the manifest's digest. The store accepts a tag that points at a blob digest, but nothing can resolve it, so publish with this tool rather than with raw requests. Re-publishing identical bytes only moves the tag.

When the store is behind an app-lb gate, one request carries two credentials: `Authorization: Bearer applb_…` for the gate (`ART_GATE_TOKEN`) and `x-api-key` for the store (`ART_API_KEY`). On the store's own listener, `ART_API_KEY` alone is enough.

## Hosted mode

Set `HEYO_MCP_HTTP_PORT` to serve MCP over streamable HTTP at `/mcp`, with an open `GET /healthz` that reports the tool count, configured services and credential faults. The transport is stateless (a new server per request), so it works behind a load-balanced pool. Paths other than `/mcp` and `/healthz` return 404.

### Credential forwarding

A hosted instance can act as each caller rather than as itself:

| Caller's `Authorization` | What the server uses upstream |
|---|---|
| `Bearer applb_…` | **Always** the caller's token for app-lb, even when `APPLB_TOKEN` is configured. Also used for app-obs, ci and the store when their configured credential is empty or is itself an `applb_` token, which means an app-lb gate fronts them. Never used for cloud. |
| `Bearer heyo_api_…` | Used for cloud only when `HEYO_API_KEY` is unset. Used for app-lb only when no app-lb credential is configured. |
| anything else | The configured credentials |

This prevents a narrowly scoped app token from borrowing the server's broader credential. app-lb re-checks the caller's scope on every request.

For forwarding to app-lb, `APPLB_URL` must still be set (with no token), so the server knows where app-lb is.

### Behind an app-lb gate

`HEYO_MCP_REQUIRE_IDENTITY` (on by default) makes the server refuse any `/mcp` request that lacks `x-auth-request-user` or `x-auth-request-email`, the headers app-lb sets after a `google` or `jwt` gate admits a caller. Each call is logged to stderr with that identity. The server does not re-verify the JWT.

| Gate on the deployment | `HEYO_MCP_REQUIRE_IDENTITY` | Notes |
|---|---|---|
| `jwt` or `google` | leave on | The gate forwards an identity. |
| `app-token` | `0` | app-lb forwards no identity for token callers. The gate does the authentication. |
| `/mcp` in `public_paths` | `0` | Safe only if the instance holds **no** credentials, so every call carries the caller's own token. |
| none | never `0` | That leaves an unauthenticated process that can delete deployments. |

In HTTP mode, `art_publish` accepts only `content_base64`: a `path` would name a file on the server, not the caller's machine.

### Deploying it

The repository ships two shapes:

- **Host process**: `mcp/deploy/supervisor/heyo-mcp.conf` runs `node …/mcp/dist/index.js` bound to loopback, and `mcp/deploy/heyo-mcp.json` registers it with app-lb as a static deployment behind a `jwt` gate. Make the deployment's `upstreams` port match `HEYO_MCP_HTTP_PORT` (the conf uses `9650`).
- **MicroVM**: `mcp/deploy/image/Dockerfile` builds a rootfs (`heyvm mvm build --local-only -f deploy/image/Dockerfile -c . -n heyo-mcp` from `mcp/`). Its `init.sh` firewalls the listener to the host gateway, and app-lb starts node with the deployment's `start_command` and env. `mcp/deploy/vm.md` describes the zero-credential, app-token-gated posture this shape is designed for.

An instance with `HEYO_API_KEY` set gives **every** caller the gate admits the same cloud account. Leave it unset for a fleet-operations instance. An `app-token` gate cannot pass a cloud key through, so sandbox tools won't be listed.

## ci behind an app-lb gate

When ci is behind an app-lb gate, its `public_paths` are only `/healthz`, `/api/submit`, `/api/runs/`, `/api/stream/` and `/__ui/`. Its HTML pages (runs, jobs, runners, VMs, repos) admit browsers only. For that reason:

- `ci_run_status` and `ci_run_logs` work against the public hostname with `CI_TOKEN`. A token for another repository gets 404.
- `diagnose_ci_job` and the VM tools need ci's **own** listener. Run the server on the ci host, or tunnel to it:

```sh
ssh -N -L 8081:127.0.0.1:8081 ci-host    # then CI_URL=http://127.0.0.1:8081
```

Pointed at the gated host, those tools fail with this explanation rather than a bare 401.

## Limits and known gaps

| Limit | Details |
|---|---|
| Cloud request bodies are capped at 1 MB | `sandbox_write_file` refuses more than 512 KiB. For larger files, use `sandbox_upload_url`, then `PUT` the `.tar.gz` (`Content-Type: application/gzip`, **no** `Authorization`), then `sandbox_finalize_upload`, then `sandbox_create {archive_id}` or `sandbox_attach_archive`. |
| 503 from `sandbox_create` | Region capacity, not a fault. It is retried with backoff (3 attempts from 2 s). Try another `driver` or region. Cloud publishes no free-capacity figure, so `heyo_capacity` can't predict it. |
| Namespace tokens and default-namespace gates | app-obs and ci gates normally live in `default`, so a token confined to another namespace gets 403 from them while app-lb tools still work. |
| Managed mode route set | Through cloud's namespace path, fleet-wide operator tools (`applb_disks`, `applb_certs`, `applb_purge_disk`, `applb_purge_orphan_disks`, `applb_sweep_disks`) return `404 route not exposed through the namespace proxy`. |
| Guest `start_command` failures | Written to `/var/log/heyvm-start.log` in the guest, never to app-obs. Read the file with `applb_exec`. An empty log beside an empty pool points here. |
| Untyped fallbacks | The raw `*_request` tools bypass schema validation and read-only guarantees. |
| No JWT re-verification | In HTTP mode the server trusts app-lb's forwarded identity headers, so it must only be reachable through app-lb. |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `<service> is not configured — set <VAR>` | Set that variable. `heyo_status` shows everything that's missing. |
| No `sandbox_*` tools listed | No usable cloud key. `HEYO_API_KEY` is unset, or it holds an `applb_` token. |
| 401 or 403 from an `applb_*` tool | Run `heyo_whoami`. The admin tier is usually too low (`view` can't read deployments) or the namespace is wrong. |
| 401 from cloud with an `applb_` token | Wrong kind of credential. Cloud needs `heyo_api_…`. |
| Managed mode reports an ambiguous namespace | The key sees several namespaces. Set `APPLB_NAMESPACE`. |
| 401 from ci tools against the public hostname | The expected gate behaviour. Point `CI_URL` at ci's own listener. |
| Art writes return 401 while reads work | `ART_API_KEY` is missing. |
| HTTP mode returns 401 "did not arrive through app-lb's gate" | Either a direct request to the port, or an `app-token` or public gate with `HEYO_MCP_REQUIRE_IDENTITY` still on. |
| A tool call times out after 30 s | The upstream accepted the connection and never answered. Raise `HEYO_MCP_TIMEOUT_MS` only if the service is really that slow. |

## See also

- [app-lb](app-lb.md) and [app-lb auth](app-lb-auth.md): the deployment spec, gates and app tokens
- [heyctl](heyctl.md): the CLI for the same APIs
- [developer-tools](developer-tools.md)
- [Component README](../mcp/README.md)
