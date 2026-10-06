# heyctl

`heyctl` is a kubectl-style command-line client, and a Rust client library, for the app-lb admin API: deployments, VM pools, secrets, tokens, auth providers, builds, pulls, artifact stores, and the telemetry the `obs` plugin collects. The crate is published on crates.io as [`hws`](https://crates.io/crates/hws), the Heyo Web Services SDK; the binary it installs is `heyctl`.

## What it is

[app-lb](app-lb.md) is the HWS load balancer and autoscaler. Everything it does is driven through its admin API (default `http://127.0.0.1:9090`), and `heyctl` is the CLI for that API. Its verbs follow kubectl's: you `apply` declarative specs, use imperative helpers (`create`, `scale`, `set`) that write those specs for you, and read them back with `get`, `describe` and `top`.

It is a separate crate from app-lb (`app-lb/heyctl`), so installing it does not pull in pingora, openssl or the ACME stack. It shares only the wire format with the server. The same crate is also a library: build it with `default-features = false` to get the typed client without clap or a terminal.

A deployment is one of three kinds, and many commands only apply to one of them:

| | managed (`vm`) | static (`upstreams`) | site (`site`) |
| --- | --- | --- | --- |
| Backends | an autoscaled pool of microVMs | fixed `host:port` addresses | none: files served from disk by app-lb |
| `scale`, `restart`, `delete vm` | yes | rejected | rejected |
| `cordon` / `drain` / `uncordon` | rejected | yes | rejected |
| `exec` / `shell` | yes | rejected | rejected |
| `set image` / `set env` | yes | rejected | rejected |
| `set build` / `build`, `set artifact` / `pull` | yes (one or the other, not both) | rejected | rejected |
| `set update` / `update` | rejected | yes | yes |
| `set upstreams` | rejected | yes | rejected |
| `set auth` | yes | yes | yes |

When the server rejects a command for a deployment kind, heyctl passes the server's reason through.

## Install

### Installer

```sh
curl -fsSL https://heyo.computer/install.sh | sh
```

The script is [`app-lb/heyctl/install.sh`](../app-lb/heyctl/install.sh). It reads a version manifest (`<site>/heyctl/versions.json`), downloads the matching blob anonymously from the artifact store, verifies it against its sha256 digest and against the `SHA256SUMS` inside the tarball, and installs `heyctl` into `~/.local/bin`.

Pass flags through the pipe with `sh -s --`. Without the `-s --`, `sh` reads the flags as its own:

```sh
curl -fsSL https://heyo.computer/install.sh | sh -s -- --prefix /usr/local
curl -fsSL https://heyo.computer/install.sh | sh -s -- --list
curl -fsSL https://heyo.computer/install.sh | HEYCTL_VERSION=0.1.7 sh
```

| Flag | Meaning |
| --- | --- |
| `--prefix PATH` | Install into `PATH/bin` (default `~/.local`) |
| `--version VER` | Install this version (default: the manifest's `latest`) |
| `--digest SHA256` | Install this exact blob and skip the manifest |
| `--list` | Show the versions the manifest offers; install nothing |

| Env var | Default | Meaning |
| --- | --- | --- |
| `HEYCTL_BASE_URL` | `https://heyo.computer` | Site serving `heyctl/versions.json` |
| `HEYCTL_MANIFEST_URL` | unset | Full manifest URL; overrides `HEYCTL_BASE_URL` |
| `HEYCTL_STORE_URL` | the manifest's `store` | Artifact store base URL |
| `HEYCTL_VERSION` | the manifest's `latest` | Version to install |
| `HEYCTL_DIGEST` | unset | Install this blob directly (rollback, or a link you were given) |
| `HEYCTL_PREFIX` | `$HOME/.local` | Install prefix |
| `HEYCTL_NO_VERIFY` | unset | Non-empty skips the `SHA256SUMS` cross-check. The blob digest is always verified |

The installer never sends an `Authorization` header. The artifact store serves public blobs only to anonymous requests, so an `ART_API_KEY` in your environment is ignored on purpose. Redirects may not downgrade from HTTPS to HTTP.

It detects `linux`/`darwin` and `x86_64`/`aarch64`, and tells you which platforms the manifest actually offers if yours is missing.

### From source

heyctl is the `hws` package in the app-lb Cargo workspace:

```sh
cargo install hws                    # from crates.io
# or, from this repository:
cd app-lb
cargo build --release -p hws
install -m 0755 target/release/heyctl ~/.local/bin/
```

As a library (the Heyo Web Services SDK):

```toml
[dependencies]
hws = { version = "0.2", default-features = false }
```

The library is async. The `blocking` feature adds `hws::blocking::Client`, which is what the CLI uses. The [crate README](../app-lb/heyctl/README.md#as-a-library) has a quick start that creates a workload, reads its telemetry and rolls it out with a namespace token; [`examples/namespace_workload.rs`](../app-lb/heyctl/examples/namespace_workload.rs) is the same program. `cargo doc -p hws --no-default-features --open` builds the API docs; the [changelog](../app-lb/heyctl/CHANGELOG.md) lists what changed between releases.

## Connecting

With no config file and no flags, heyctl talks to `http://127.0.0.1:9090`, app-lb's default admin listener. A local app-lb needs no setup.

The admin listener is plaintext HTTP on loopback by default. To reach a remote one, either tunnel it:

```sh
ssh -L 9090:127.0.0.1:9090 lb-host
heyctl --server 127.0.0.1:9090 get deployments
```

or front the admin listener with an app-lb TLS deployment (see [`examples/app-lb-admin.json`](../app-lb/examples/app-lb-admin.json)) and log in to its HTTPS name. `--insecure-skip-tls-verify` accepts a self-signed certificate on an endpoint you control.

Do not point a context at a hostname behind a Google sign-in gate. heyctl cannot complete an OAuth flow, so every command fails with a 401 whatever credentials you store. Tunnel to the admin listener instead, or see [Putting the dashboard behind Google](app-lb-auth.md#putting-the-admin-dashboard-behind-google).

## Credentials, contexts and the config file

### The config file

Contexts (server plus credentials) and artifact-store registries live in one JSON file:

| Location | When |
| --- | --- |
| `--config PATH` / `HEYCTL_CONFIG` | if set |
| `$XDG_CONFIG_HOME/heyctl/config.json` (usually `~/.config/heyctl/config.json`) | default on Linux |
| the platform config dir (`dirs::config_dir()`) + `heyctl/config.json` | default elsewhere |
| `~/.heyctl/config.json` | fallback when there is no config directory |

The file is written mode `0600` and its directory `0700`. **It holds passwords, tokens and API keys in plaintext.** Don't print it, paste it, or commit it. `heyctl config view` redacts secrets unless you pass `--show-secrets`; `heyctl config path` prints the location. An empty file is treated as no file.

To keep credentials out of the file, store a command instead of the value (`--password-command`, `--token-command`, `--api-key-command`), or verify without storing (`--no-store-password`, `--no-store-key`) and supply the value through the environment.

### How app-lb authenticates heyctl

app-lb accepts three credentials on its admin API. See [app-lb auth](app-lb-auth.md#the-admin-api) for the server side.

| Credential | How heyctl sends it | Reach |
| --- | --- | --- |
| HTTP Basic (`APP_LB_DASHBOARD_USER` / `APP_LB_DASHBOARD_PASSWORD`) | `--user` / `--password` | the whole fleet |
| App-token `applb_…` | `--token` | whatever it was minted with |
| Heyo API key `heyo_api_…` or Heyo JWT | `--token` | the namespaces the Heyo auth service grants |

A namespace-scoped Heyo API key is used against Cloud's namespace door, `https://<cloud>/namespaces/<ns>/lb`, and reaches only that namespace at the tier it was minted with (`view` or `admin`).

### Heyo account login and regional visibility

For a platform administrator account, use `--email`, not `--user` (gateway Basic auth):

```sh
heyctl login --server https://admin.heyo.work --email sam@heyo.computer
heyctl get deployments --fleet
heyctl get deployments --fleet --namespace default -o json
```

Login prompts for the account password and uses the same HTTPS `/login` exchange
as the dashboard. It saves only the expiring session token in the existing
permission-restricted config. Run login again when it expires; no password is
retained for unattended refresh. Redirects and insecure TLS are not allowed.

`--fleet` reads the gateway's configured fleet, showing each deployment's gateway,
region, health and unavailable-region errors. JSON/YAML preserves the server's
full response, including truncation and error fields. It does not discover servers
from DNS, change write targets, or fail over the selected admin endpoint.
Without `--fleet`, existing reads and all deployment writes remain regional.
Use an explicit regional context for host maintenance; fleet observation does not
turn `apply` or `restart` into a coordinated release.

For a reusable app-token across servers, mint it at the configured token authority:

```sh
heyctl token mint fleet-reader --admin view --all-deployments --all-servers
heyctl login --server https://admin.us3.heyo.work --token-stdin
heyctl get deployments --fleet
```

The mint command displays the secret once; supply it to `--token-stdin` without
putting it on the command line. Each other server must have `token_authority`
configured and a successful `token_sync` in `/control-plane/config`. Mirroring
normally takes up to ten seconds. Failed synchronization retains the previous
mirror, so revocations reach disconnected servers only after synchronization
recovers; expiry is still enforced locally.

Caller-auth fleet gateways accept forwarded, authenticated all-server tokens as
well as Heyo identities. Ordinary local tokens and Basic passwords are never
forwarded. `--all-servers` changes where a token works, not what it may do:
namespace-scoped tokens still require `get deployments --fleet --namespace <name>`
and cannot read other namespaces. Account login remains a separate option; it
does not mint an all-server app-token. Neither option provides DNS/TLS failover.

### Precedence

For each of the password, token and artifact API key, heyctl uses the first of:

1. the flag or env var (`--password`/`HEYCTL_PASSWORD`, `--token`/`HEYCTL_TOKEN`, `--api-key`/`HEYCTL_ART_API_KEY`)
2. the context's stored `*_command`, run through `sh -c` on each request
3. the context's stored value

A token outranks a user/password on the same context. The username defaults to `admin`; `login` never prompts for it, so pass `--user` if the server sets `APP_LB_DASHBOARD_USER` to something else. A wrong username gives the same 401 as a wrong password.

### Global options

These work on every command, before or after the subcommand.

| Flag | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `-o, --output FORMAT` | | `table` | `table`, `wide`, `json`, `yaml`, `name` |
| `--config PATH` | `HEYCTL_CONFIG` | see above | Config file |
| `--context NAME` | `HEYCTL_CONTEXT` | current context | Which stored context to use |
| `--server URL` | `HEYCTL_SERVER` | context, else `http://127.0.0.1:9090` | Admin API URL. `host:port` means http |
| `--user NAME` | `HEYCTL_USER` | context, else `admin` | Basic-auth user |
| `--password PASSWORD` | `HEYCTL_PASSWORD` | | Basic-auth password. Visible in `ps`; prefer the env var |
| `--token TOKEN` | `HEYCTL_TOKEN` | | Bearer token (`applb_…` or `heyo_api_…`). Visible in `ps`; prefer the env var |
| `--insecure-skip-tls-verify` | | off | Accept any TLS certificate |
| `--request-timeout SECS` | | `30` | Per-request timeout |

`-o json` and `-o yaml` print the server's payload unmodified, so they round-trip into `apply`. `-o name` prints `deployment/<id>` lines for `xargs`.

Scripts and CI can skip the config file entirely:

```sh
HEYCTL_SERVER=https://cloud.example.com/namespaces/team-a/lb \
HEYCTL_TOKEN="$HEYO_KEY" heyctl get deployments
```

### `login`, `logout`, `whoami`

```sh
heyctl login --server 127.0.0.1:9090                       # prompts for a password if the server wants one
heyctl login --server https://lb-admin.example.com --user admin
heyctl login --server lb.example.com:9090 --password-command 'pass show app-lb/admin'
heyctl login --server lb.example.com:9090 --no-store-password   # then export HEYCTL_PASSWORD
heyctl login --server https://cloud.example.com/namespaces/team-a/lb --token-stdin <<< "$HEYO_KEY"
heyctl whoami
heyctl logout --keep-context                               # drop the stored password only
```

`login` probes the server, verifies the credentials against whatever is actually gated, and saves a context (named after the server's host unless you pass `--name`). A token login verifies with `GET /deployments`, since Cloud's namespace door has no `/healthz` to probe.

| `login` flag | Meaning |
| --- | --- |
| `--server URL` | Admin API to log in to |
| `--user NAME` | Basic-auth user (default `admin`) |
| `--password`, `--password-stdin`, `--password-command CMD` | Password source; the command form stores the command, not the password |
| `--token`, `--token-stdin`, `--token-command CMD` | Log in with a bearer token instead |
| `--no-store-password` | Verify, but don't write the password or token to disk |
| `--name NAME` | Context name |
| `--no-switch` | Save without making it current |
| `--insecure-skip-tls-verify` | Accept any certificate |

`whoami` prints the config file, context, server, user, where the password comes from, whether the server is reachable, which routes require auth, and whether the deployment API and `/metrics` are allowed for this identity. It is the first thing to run when you get a 401. It also reports the current artifact registry.

### `config`

| Command | Does |
| --- | --- |
| `config view [--show-secrets]` | Print the config file, secrets redacted |
| `config get-contexts` | List contexts |
| `config current-context` | Print the current context |
| `config use-context NAME` | Switch contexts |
| `config set-context NAME [--server] [--user] [--password] [--password-command] [--insecure-skip-tls-verify] [--current]` | Create or update a context |
| `config delete-context NAME` | Remove a context |
| `config path` | Print the config file path |

`--context NAME` on any command uses a context once without switching.

## Command reference

Resource names take kubectl's forms: `deployments`, `deployment web`, `deployment/web`, `deploy web`, or a bare `web` where the kind is unambiguous. Kinds and aliases:

| Kind | Aliases |
| --- | --- |
| `deployment` | `deploy`, `dep`, `d`, `app` |
| `vm` | `instance`, `backend`, `replica` |
| `cert` | `certificate` |
| `secret` | `sec` |
| `workflow` | `wf`, `flow`, `ci` |
| `job` | `build`, `pull`, `update`, `run` |
| `disk` | `pv`, `volume`, `vol`, `storage` |
| `namespace` | `ns` |
| `auth-provider` | `provider`, `idp` |
| `all` | |

### Reading

| Command | Main flags | Does |
| --- | --- | --- |
| `get RESOURCE...` (alias `list`) | `-d/--deployment`, `-n/--namespace`, `-w/--watch`, `--interval SECS` (2) | List any kind above |
| `describe RESOURCE` | `-n/--namespace` (auth providers) | Spec, pool, backends, traffic, gate, mounts; or an auth provider |
| `top [deployments\|vms\|host]` | `-w/--watch`, `--interval` | CPU, memory, latency and 5xx ranking |
| `status` (alias `cluster-info`) | | Uptime, host, fleet and traffic totals |
| `feed [NAMESPACE]` | `--xml`, `-n/--limit N` | A namespace's event feed; with no argument, the namespaces that have events |

```sh
heyctl get deployments -o wide          # adds MIN MAX WARM TARGET BACKEND SOURCE AUTH
heyctl get deployment/web -o yaml
heyctl get vms -d web
heyctl get secrets -n team-a            # ids and key names, never values
heyctl get jobs -d web                  # builds, pulls, updates and mount pulls, newest first
heyctl get job job-3f2a1c8e             # one job, with its log
heyctl get disks -d sb-7f3a9c
heyctl get auth-providers -n team-a
heyctl describe deployment web
heyctl top vms -w
```

### Creating and applying

| Command | Main flags | Does |
| --- | --- | --- |
| `create deployment NAME` (`deploy`, `dep`) | see below | Register a deployment |
| `create secret NAME [KEY=VALUE]...` (`sec`) | `-n`, `--from-file KEY=PATH`, `--from-env KEY[=VAR]`, `--from-stdin KEY`, `--description`, `--dry-run` | Store write-only secret values |
| `create namespace NAME` (`ns`) | `--description`, `--dry-run` | Declare a namespace (fleet admin only) |
| `create auth-provider NAME` (`provider`, `idp`) | `-n`, `--preset`, `--issuer`, `--client-id`, key and claim flags | Declare a namespace auth provider; see [app-lb auth](app-lb-auth.md#auth-providers) |
| `create workflow ID` (`wf`, `flow`) | `--repo` (required), `--network` (required), `--ref` (`main`), `--path` (`.ci/workflows/*.yml`), `--secrets-prefix`, `--disabled` | Register a [CI](ci.md) workflow |
| `apply -f FILE` | `-f/--filename` (repeatable, `-` for stdin), `--dry-run` | Create or replace from JSON or YAML: one spec, a JSON array, or a multi-document YAML stream. Objects with `kind: auth-provider` are upserted as providers |
| `edit RESOURCE` | | Open the server's JSON in `$VISUAL`/`$EDITOR` and `PUT` it back. A rejected edit is kept on disk |

`create deployment` flags, by group:

| Group | Flags |
| --- | --- |
| General | `-n/--namespace` (default `default`), `--dry-run` |
| Routing | `--host`, `--host-suffix`, `--path-prefix` (together one rule), `--route RULE` (repeatable: `host=a.example.com,path=/api`, `*.example.com`, `/api`), `--no-route` |
| VM pool | `--image`, `--port` (required for managed), `--driver` (`firecracker`; `libvirt` is rejected), `--start-command`, `--size` (`micro`..`xlarge`), `--disk-gb`, `--workdir`, `-e/--env KEY=VALUE`, `--setup-hook`, `--open-port`, `--ttl` |
| Static site | `--site-root DIR`, `--site-index`, `--site-404`, `--site-spa`, `--site-cache-control` |
| Static upstreams | `--upstream ADDR` (repeatable), `--discovery-service SERVICE` |
| Build source | `--repo` or `--build-store`, `--ref`, `--dockerfile`, `--build-context`, `--image-name`, `--size-mb`, `--secret NAME[/KEY]` |
| Scaling | `--min`, `--max`, `--warm`, `--target-concurrency`, `--scale-to-zero-after`, `--cold-start-timeout`, `--drain-timeout`, `--boot-timeout`, `--idle-action destroy\|retain` |
| Health | `--health-path` (default `/`), `--health-tcp`, `--health-port`, `--health-timeout` |

`--path-prefix` is forwarded unchanged; app-lb does not strip it. `--disk-gb` is the only guest storage that survives a VM stop, because the root filesystem is recopied from the image on every boot.

Secret values passed as `KEY=VALUE` arguments are visible in `ps` and shell history. Prefer `--from-file`, `--from-env` or `--from-stdin`.

### Editing in place

Every `set` command is a read-modify-write of the whole spec (`PUT /deployments/:id`). heyctl edits the server's JSON rather than its own struct, so fields it does not know about survive. All `set` commands take `--dry-run`.

| Command | Main flags | Does |
| --- | --- | --- |
| `set image RESOURCE IMAGE` | | Change a managed deployment's image; recycles the pool |
| `set env RESOURCE KEY=VALUE... / KEY-` | | Set or remove guest env vars; recycles the pool |
| `set upstreams RESOURCE ADDR...` | | Replace a static deployment's upstream list |
| `set route RESOURCE` (`routes`) | `--host`, `--host-suffix`, `--path-prefix`, `--route`, `--add`, `--none` | Replace or extend route rules; `--none` withdraws a managed deployment from the proxy |
| `set build RESOURCE` | `--repo` or `--store`, `--ref`, `--dockerfile`, `--build-context`, `--image-name`, `--size-mb`, `--secret NAME[/KEY]` (default key `token`), `--username`, `--no-auth`, `--clear` | Record where `build` gets its Dockerfile |
| `set artifact RESOURCE` (`art`) | `--store URL\|PATH`, `--ref`, `--image-name`, `--grow-gb`, `--secret`, `--no-auth`, `--clear` | Record where `pull` gets a rootfs |
| `set update RESOURCE` | `--workdir` (absolute, on the app-lb host), `-c/--command` (repeatable), `-e/--env`, `--secret-env [ENV=]NAME/KEY`, `--secret`, `--no-auth`, `--command-timeout`, `--verify-timeout`, `--clear` | Record how `update` redeploys a static deployment or site |
| `set auth RESOURCE` | `--provider-ref` or `--client-id`/`--secret`/`--allow-domain`/`--allow-email`; `--public-path`, `--base-path`, `--session-ttl`, `--cookie-name`, `--no-forward-identity`, `--clear` | Put a deployment behind a sign-in gate; see [app-lb auth](app-lb-auth.md#google) |
| `set secret RESOURCE [KEY=VALUE\|KEY-]...` (`sec`) | `-n`, `--from-file`, `--from-env`, `--from-stdin`, `--description` | Rotate keys; unmentioned keys keep their values |

Passing any `--command`, `--env`, `--secret-env`, `--allow-domain`, `--allow-email` or `--public-path` replaces that whole list. Use `heyctl edit` for incremental changes.

`set auth --public-path` writes a bare-string entry, which app-lb reads as scope `admin`: the path skips Google sign-in but requires an admin-tier app-token. To make a path fully open (a health check, a webhook), write `{"path": "/healthz", "scope": "public"}` with `heyctl edit` or `apply`. See [public paths](app-lb-auth.md#public-paths-and-scopes).

`set build` and `set artifact` are mutually exclusive on one deployment, because both rewrite `vm.image`.

### Jobs: build, pull, update, mounts

These start an asynchronous job on the app-lb host. Without `--wait` they return the job id straight away; follow it with `heyctl get job <id>`. One job runs per deployment at a time; a second is refused, not queued. A failed job makes heyctl exit non-zero after printing the tail of the log.

| Command | Main flags | Does |
| --- | --- | --- |
| `build RESOURCE` | `--ref` (one-off), `-w/--wait`, `--logs` (implies `--wait`), `--timeout` (1800) | Build the image with `heyvm mvm build` and roll the pool |
| `pull RESOURCE` | `--ref` (one-off), `--force`, `-w/--wait`, `--logs`, `--timeout` (1800) | Pull a rootfs from an artifact store and roll the pool |
| `mounts pull RESOURCE` | `--force`, `-w/--wait`, `--logs`, `--timeout` (1800) | Unpack `vm.mounts` tarballs; the pool rolls only if a digest changed |
| `update RESOURCE` | `-w/--wait`, `--logs`, `--timeout` (1800) | Run a static deployment's update commands, then re-probe its upstreams |

`pull --ref <digest>` pins exact bytes without changing the stored spec, which is how you roll back. A tag follows wherever it is moved. `apply` and `edit` start a mount pull automatically when a mount has no tree on the host.

An update whose commands succeed but whose upstreams never come back is reported as a failure. The commands run as app-lb's user.

### Scaling and lifecycle

| Command | Main flags | Does |
| --- | --- | --- |
| `scale RESOURCE` (`autoscale`) | `-r/--replicas N`, `--min`, `--max`, `--warm`, `--target-concurrency`, `--scale-to-zero-after`, `--cold-start-timeout`, `--drain-timeout`, `--boot-timeout`, `--idle-action` | Partial `PATCH` of the scaling policy; unset fields keep their values |
| `restart RESOURCE` | `--force`, `--wait`, `--timeout` (300) | Drain every VM; the autoscaler boots replacements |
| `rollout status RESOURCE` | `--timeout` (300), `--no-wait` | Wait until desired equals ready and nothing is draining |
| `rollout restart RESOURCE` | as `restart` | Same as `restart` |
| `cordon RESOURCE UPSTREAM` | `--force`, `--reason` | Stop new requests to one static upstream |
| `drain RESOURCE UPSTREAM` | `--force`, `--reason`, `--timeout` (300) | Cordon, then wait for in-flight requests to finish |
| `uncordon RESOURCE UPSTREAM` | | Return a cordoned upstream to traffic once healthy |
| `delete RESOURCE...` (`rm`) | `-d/--deployment`, `-n/--namespace`, `--all`, `--force`, `-y/--yes` | Delete deployments, VMs, secrets, workflows, namespaces or auth providers |

`--replicas N` pins `min = max = N`. Give `--min`/`--max` again to hand control back to the autoscaler.

`--idle-action retain` stops an idle VM instead of destroying it, and a later request or `exec` resumes it. Only the `/workspace` data disk (`--disk-gb`) persists across that stop.

Cordon state is durable across app-lb restarts. A drain is refused when no other healthy upstream would remain, unless you pass `--force`. On timeout the upstream stays cordoned.

`delete vm` recycles a VM: the autoscaler replaces it if the policy still wants the capacity. Use `scale` to shrink. `delete secret` is refused while a deployment references the secret; `--force` deletes it anyway. Certificates, jobs and disks cannot be deleted with `delete`.

### Getting inside a VM

| Command | Main flags | Does |
| --- | --- | --- |
| `exec RESOURCE -- CMD...` | `--cwd`, `-e/--env`, `--timeout` (60), `--no-wake` | Run one command through `sh -c` in the guest. stdout, stderr and the exit code pass through |
| `shell RESOURCE` (`ssh`) | `--cwd`, `--no-wake`, `--vm SANDBOX_ID` | Interactive PTY |

Both go through app-lb, not the heyvm daemon, so they work wherever the admin API does. Both start a VM if the deployment has none running (up to its `cold_start_timeout_secs`), unless you pass `--no-wake`. An open shell counts as in-flight work, so the pool will not scale to zero under it. These are the only way into a deployment created with `--no-route`.

### Tokens

App-tokens are app-lb's own scoped, revocable bearer credentials. See [app-lb auth](app-lb-auth.md#app-tokens) for the scope model.

| Command | Main flags | Does |
| --- | --- | --- |
| `token mint NAME` | `--admin none\|view\|admin` (default `none`), `-d/--deployment ID` (repeatable), `--all-deployments`, `--namespace NS`, `--expires-in HOURS`, `-q/--quiet` | Mint a token. The secret is printed once |
| `token list` | | List live tokens; never shows secrets |
| `token describe ID` | | Show one token |
| `token set ID` | `--name`, `--admin`, `-d/--deployment`, `--all-deployments`, `--never-expires` | Re-scope without changing the secret |
| `token revoke ID` | `-y/--yes` | Revoke; takes effect on the next request |

`mint` writes the secret to stdout and everything else to stderr, so capturing it is safe:

```sh
APP_LB_TOKEN=$(heyctl token mint ci --admin admin --all-deployments -q)
```

A token scoped to specific deployments cannot mint tokens, so it cannot widen itself.

### Plugins

| Command | Does |
| --- | --- |
| `plugins list` (alias `plugin`) | List plugins and whether each is enabled |
| `plugins describe ID` | Configuration and live status |
| `plugins enable ID` / `plugins disable ID` | Toggle; configuration is kept |
| `plugins set ID -f FILE [--enable]` | Replace a plugin's configuration from JSON (`-` for stdin) |
| `plugins list -n NS` | Plugins a namespace can install, and whether it has |
| `plugins install ID [-n NS] [-f FILE]` | Install a per-namespace plugin into a namespace (needs `admin` there) |
| `plugins uninstall ID [-n NS]` | Uninstall it |
| `plugins installs ID` | Every namespace a plugin is installed in (fleet scope) |

`enable`/`disable` are the operator's fleet-wide switch. Per-namespace plugins (`obs`) also have to be installed in a namespace before they do anything there. Where `-n` is optional, it defaults to the namespace the token is confined to.

### Telemetry

| Command | Does |
| --- | --- |
| `logs DEPLOYMENT [-n NS]` | A deployment's logs, oldest first: `--since 1h`, `--level error`, `--grep TEXT`, `--backend SANDBOX`, `--limit N` |
| `top -n NS [--window 1h] [-w]` | Every deployment in a namespace with request/error rates, latency, CPU, memory and log counts over the window |

Both read app-obs through app-lb's `obs` plugin, so they need it installed in the namespace (`heyctl plugins install obs -n NS`) and nothing beyond a namespace token. `top` without `-n` still shows the LB's live counters.

### Artifact stores

An [artifact store](artifacts.md) (`art serve`) is a separate service from app-lb, so `heyctl artifact` (aliases `art`, `registry`) keeps its own saved **registries** in the same config file. `--context` never retargets an artifact command.

| Registry option | Env var | Meaning |
| --- | --- | --- |
| `--registry NAME` | `HEYCTL_REGISTRY` | Which saved registry |
| `--registry-url URL` | `HEYCTL_ART_URL` | Store URL override (`host:port` means http) |
| `--api-key KEY` | `HEYCTL_ART_API_KEY` | Store API key override |

| Command | Main flags | Does |
| --- | --- | --- |
| `artifact login URL` | `--api-key`, `--api-key-stdin`, `--api-key-command`, `--no-store-key`, `--name`, `--no-switch`, `--insecure-skip-tls-verify` | Verify a store key and save a registry |
| `artifact logout [NAME]` | `--key-only` | Forget a registry, or just its key |
| `artifact registries` (`contexts`) | | List saved registries |
| `artifact use NAME` (`use-registry`) | | Switch registry |
| `artifact push [FILE]` | `--image NAME`, `--tag`, `--no-tag`, `--force` | Upload an ext4 rootfs and tag it |
| `artifact push-dockerfile FILE` (`push-df`) | `--build-context PATH`, `--tag`, `--no-tag`, `--image-name`, `--size-mb`, `--source`, `--force` | Upload a Dockerfile and context as a `heyvm.dockerfile.v1` manifest |
| `artifact ls` (`tags`) | | List tags |
| `artifact describe REF` | | What a tag or digest resolves to |
| `artifact usage` | | Logical size, physical size, free space |
| `artifact untag NAME` (`rm-tag`) | | Remove a tag; the blob stays until `art gc` |

`push --image NAME` resolves `~/.heyo/images/firecracker/<name>.ext4` (or under `$MVM_DATA_DIR`), where `heyvm mvm build` writes images. The tag defaults to the file name without `.ext4`. `push-dockerfile`'s tag defaults to the Dockerfile's directory name. The build context is packed as-is, with no `.dockerignore` handling, so point it at a clean directory.

### Shell completion

```sh
heyctl completion bash > /etc/bash_completion.d/heyctl
heyctl completion zsh  > ~/.zfunc/_heyctl
```

`fish`, `elvish` and `powershell` are also supported.

## Common workflows

### Deploy a spec

```yaml
# web.yaml
id: web
routes: [{ host: web.example.com }]
vm:
  driver: firecracker
  image: nginx-fc
  port: 80
  size_class: mini
scaling: { min_replicas: 1, max_replicas: 4 }
health: { path: /healthz }
```

```sh
heyctl apply -f web.yaml --dry-run   # print what would be sent
heyctl apply -f web.yaml
heyctl rollout status web
heyctl describe deployment web
```

For field names, generate a spec with `heyctl create deployment ... --dry-run` or read an existing one with `heyctl get deployment web -o yaml`. Copying between load balancers is a pipe:

```sh
heyctl get deployment web -o json | heyctl --context staging apply -f -
```

The imperative equivalent:

```sh
heyctl create deployment web --host web.example.com --image nginx-fc --port 80 \
  --size mini --min 1 --max 4 --health-path /healthz
```

### Build from a Dockerfile

```sh
heyctl create secret github --from-stdin token < ~/.github-pat
heyctl set build web --repo https://github.com/acme/web.git --ref main --secret github
heyctl build web --logs
```

Each build produces an image named `<deployment>-<short sha>`, so `describe` and `get -o wide` show which commit is running.

### Push and pull an image

Build the image once, push it to a store, and let each app-lb host pull it:

```sh
heyctl artifact login https://art.us2.heyo.work --api-key-stdin < ~/.art-key
heyctl artifact push --image web-v2

heyctl create secret art --from-stdin api_key < ~/.art-key
heyctl set artifact web --store https://art.us2.heyo.work --ref web-v2 --secret art/api_key
heyctl pull web --wait
heyctl get jobs -d web
```

A store root on the app-lb host (`--store /srv/artifacts`) is much cheaper than a URL: the image is materialised locally and sparse regions are skipped. Re-pulling unchanged bytes skips the transfer but still rolls the pool.

### Follow logs

Application logs come from the `obs` plugin, once it is installed in the namespace:

```sh
heyctl plugins install obs -n team-a
heyctl logs web -n team-a --since 15m --level error
heyctl top -n team-a
```

Job output comes with the job:

```sh
heyctl build web --logs        # stream build output, then wait
heyctl pull web --logs
heyctl update app-obs --logs
heyctl get job job-3f2a1c8e    # status plus log tail of any job
```

Without the plugin, run a command in the guest (`heyctl exec web -- tail -n 100 /var/log/heyvm-start.log`). Guest start-command errors live in that file, not in app-obs.

### Scale

```sh
heyctl scale web --min 1 --max 8 --warm 2 --target-concurrency 20
heyctl scale web --replicas 3                  # pin
heyctl scale web --scale-to-zero-after 600
heyctl restart web --wait                      # rolling recycle
heyctl top
```

### Agent sandbox

```sh
heyctl create deployment sb-7f3a9c --no-route --port 8080 --size medium --disk-gb 8
heyctl scale sb-7f3a9c --idle-action retain
heyctl exec sb-7f3a9c --cwd /workspace -- git status
heyctl shell sb-7f3a9c
heyctl set route sb-7f3a9c --host sb-7f3a9c.example.com   # expose it later
heyctl set route sb-7f3a9c --none                         # withdraw it again
```

### Static upstream maintenance

```sh
heyctl drain stage us1.internal:8080 --reason 'kernel upgrade' --timeout 300
# ... maintenance ...
heyctl uncordon stage us1.internal:8080
heyctl get vms -d stage     # shows Draining separately from health
```

### Work in a namespace

```sh
heyctl create namespace team-a --description "Acme"            # fleet admin
heyctl create deployment api -n team-a --host api.example.com --port 8080
heyctl create secret db -n team-a --from-env url=DATABASE_URL
heyctl token mint team-a-ci --admin admin --namespace team-a -q
heyctl get deployments -n team-a
heyctl plugins install obs -n team-a                             # telemetry for every app in it
```

A token minted with `--namespace` and no `--deployment` reaches every deployment in that namespace and nothing outside it. Secrets and auth providers are resolved per namespace: `get secrets -n team-a` is the only way to name one when ids collide across namespaces.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success (for `exec`, the guest command's exit code is passed through instead) |
| `1` | The command failed; the reason is on stderr as `error: …` |
| `2` | Usage error from the argument parser |

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `connection refused` to `127.0.0.1:9090` | No app-lb on this machine, or no tunnel. Run `ssh -L 9090:127.0.0.1:9090 host`, or `heyctl login --server` the right endpoint |
| Every command 401s, `whoami` shows deployment API and metrics `denied` | Wrong credential, or the server is behind a Google gate that heyctl cannot pass. Tunnel to the admin listener instead |
| 401 with the right password | Wrong username. `login` defaults to `admin`; pass `--user` to match `APP_LB_DASHBOARD_USER` |
| `get` works but writes 401 | The server has `APP_LB_ADMIN_AUTH=1` and you have no credential, or your token is `view` tier |
| 403 `insufficient_scope` | Your token is valid but its deployment or namespace scope does not cover the target. A higher admin tier will not help; re-scope with `token set` |
| A scoped token cannot `create deployment` or `token mint` | Fleet-wide routes are refused to deployment-scoped tokens by design |
| `heyo_api_…` key refused against app-lb directly | A namespace key belongs at Cloud's `https://<cloud>/namespaces/<ns>/lb` door, or app-lb needs `APP_LB_AUTH_URL` set to resolve it |
| Artifact push 401 while everything else works | Artifact commands use the registry key, not the context. Check `heyctl whoami` and `heyctl artifact registries` |
| `build`/`pull` refused with a conflict | A job is already running for that deployment. Wait for it (`get jobs -d NAME`) |
| `set artifact` refused | The deployment has a `build` source. Clear it with `set build NAME --clear` first (and vice versa) |
| `scale`, `exec` or `restart` refused | The command does not apply to this deployment kind; see the table at the top |
| Deployment shows `0` ready after `apply` | A mount has not been pulled, or boot is failing. Check `heyctl describe` and `heyctl get jobs -d NAME` |
| A `--public-path` still asks for a token | Bare public paths mean scope `admin`. Write `{"path": ..., "scope": "public"}` with `heyctl edit` |
| `exec` hangs, then times out | The guest command outlived `--timeout` (60s default), or the VM is cold-starting; raise `--timeout` |

For the full spec format see [app-lb](app-lb.md) and the [app-lb README](../app-lb/README.md). The heyctl source README, [`app-lb/heyctl/README.md`](../app-lb/heyctl/README.md), has longer notes on each command.
