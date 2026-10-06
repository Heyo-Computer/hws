# hws — the Heyo Web Services SDK (and `heyctl`)

A Rust SDK **and** a kubectl-shaped CLI for creating and managing workloads on
Heyo: deployments and their microVM pools, images, secrets, tokens — and the
metrics and logs the `obs` plugin collects for them. Everything goes through the
[app-lb](../README.md) admin API, and everything works with a namespace-scoped
token.

Published on crates.io as [`hws`](https://crates.io/crates/hws) (formerly
`serverctl`). See the [changelog](CHANGELOG.md).

One crate, two products. `cargo install hws` gets the `heyctl` CLI;
`hws = { version = "0.2", default-features = false }` gets the library
with none of clap, rpassword or a terminal linked in. The CLI is the library's
own first consumer, which is the point: a field the client stops understanding
becomes a compile error rather than a silently blank column at somebody's
terminal.

There is a [TypeScript client](../sdk/typescript), `@heyocomputer/hws` on npm,
with the same version, the same surface and the same wire contract.

The verbs are kubectl's because the mental model is the same: declarative specs you `apply`,
imperative helpers (`create`, `scale`, `set`) that write those specs for you, and read commands
(`get`, `describe`, `top`) that render them back. What it drives is app-lb's admin API —
deployments, their microVM pools, and the certificates app-lb issues for their hostnames.

## Install

```sh
curl -fsSL https://heyo.computer/install.sh | sh
```

That is [`install.sh`](install.sh), served from the marketing site. It puts
`heyctl` in `~/.local/bin`; `sh -s -- --prefix /usr/local` puts it somewhere
else, and `--list` shows what is published. Note the `-s --`: without it `sh`
reads the script from stdin and takes the flags for its own.

Or build it:

```sh
cargo build --release -p hws
install -m 0755 target/release/heyctl ~/.local/bin/
```

It is a separate crate from the load balancer, so installing it doesn't drag in pingora, openssl
or the ACME stack — it shares nothing with app-lb but the wire format.

### What the installer needs from a release

The binaries live in the artifact store, but the store's anonymous carve-out is
exactly one route — `GET /blobs/{digest}` for a blob marked public — so tags,
which is how [`.ci/install.sh`](../../.ci/install.sh) finds the newest build,
are not readable without `ART_API_KEY`. A public installer therefore cannot ask
the store what "latest" means.

It asks the site instead, through a small manifest at
`<site>/heyctl/versions.json`. [`publish-versions.sh`](publish-versions.sh)
writes it:

```sh
ART_API_KEY=… sh app-lb/heyctl/publish-versions.sh \
    --from-url https://heyo.computer/heyctl/versions.json \
    --out versions.json
```

Then upload `versions.json` to that path. That is the whole release.

The division of labour is the point: `publish-versions.sh` holds the credential
and runs once per release; `install.sh` holds nothing and runs on strangers'
machines. Given `--from-url`, the live manifest *is* the state, so nobody has
to keep a copy in a working tree.

What it does, in order: finds the newest `ci-app-lb-<run>-release-app-lb` tag
and resolves it to a blob digest; downloads that blob and checks it hashes to
the digest it was fetched by; unpacks it, confirms there is a `heyctl` inside,
and reads the version out of `BUILD-INFO` — which the workflow wrote as
`heyctl --version`, so the manifest says what the binary says; makes sure the
blob is marked public; and merges the entry in, keeping the versions already
there so a pinned `--version 0.1.6` goes on working after 0.1.7 ships.

```sh
sh publish-versions.sh --dry-run                    # resolve and verify, write nothing
sh publish-versions.sh --ref ci-app-lb-019fca… --no-latest   # backfill, or stage a build
sh publish-versions.sh --keep 5                     # cap how far the manifest grows
sh publish-versions.sh --platform darwin-aarch64    # once CI builds one
```

The file it writes:

```json
{
  "latest": "0.1.7",
  "store": "https://art.us2.heyo.work",
  "artifacts": [
    { "version": "0.1.7",
      "platform": "linux-x86_64",
      "digest": "<sha256 of the tarball>",
      "bin": "heyctl" }
  ]
}
```

`artifacts` is a flat array rather than nested objects because the installer
parses it in POSIX `sh` with no `jq`, and flat records split unambiguously.
Adding macOS is a CI target plus one more entry — the installer already asks
for `${OS}-${ARCH}` and reports what the manifest actually offers.

Marking the blob public is normally a no-op: `.ci/workflows/app-lb.yml` uploads
with `public: true` and prints the resulting `{store}/blobs/{digest}` link. The
generator checks anyway and marks it if needed, because a manifest published
over a private blob is an install that 401s for every stranger and works for
whoever tests it with a key in their environment. By hand that step is
`art public <digest>`.

The installer verifies the download against the digest it was fetched by (a
blob's name *is* the sha256 of its bytes) and then against the `SHA256SUMS`
inside the tarball. That makes `versions.json` the trust root, so it has to be
served over HTTPS from a host you control.

## As a library

```toml
[dependencies]
hws = { version = "0.2", default-features = false }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
serde_json = "1"
```

### Quick start: a workload in your namespace

A namespace token (`heyctl token mint … --namespace team-a`, or the one your
Heyo account hands you) is all this needs. The server narrows every call to the
token's namespace, and fills in `namespace` when a spec leaves it out.

```rust,no_run
use hws::{Client, LogQuery};
use serde_json::json;
use std::time::Duration;

#[tokio::main]
async fn main() -> hws::Result<()> {
    let lb = Client::builder(
        std::env::var("HEYCTL_SERVER").unwrap_or_else(|_| "http://127.0.0.1:9090".into()),
    )
    .token(std::env::var("HEYCTL_TOKEN").expect("set HEYCTL_TOKEN"))
    .build()?;

    // Who am I, and where can I deploy?
    let me = lb.whoami().await?;
    let ns = me.sole_namespace().unwrap_or("default").to_string();

    // Create a workload: a managed microVM pool behind a hostname.
    lb.create_deployment(&json!({
        "id": "web",
        "namespace": ns,
        "routes": [{"host": "web.example.com"}],
        "vm": {"image": "nginx-fc", "port": 80},
        "scaling": {"min_replicas": 1, "max_replicas": 4},
    }))
    .await?;
    lb.wait_for_ready("web")
        .timeout(Duration::from_secs(300))
        .await?;

    // Collect its telemetry — once per namespace — and read it back.
    lb.install_plugin(&ns, "obs", None).await?;
    let obs = lb.obs(&ns);
    for d in obs.fleet(Some("1h")).await?.deployments {
        println!(
            "{}: {} log lines, {} errors",
            d.id, d.log_lines, d.error_logs
        );
    }
    for line in obs
        .logs("web", &LogQuery::new().level("error").limit(20))
        .await?
        .rows
    {
        println!("{} {}", line.ts, line.message);
    }

    // Change it: whole-spec replace, or a rollout that verifies the new pool
    // before draining the old one.
    let current = lb.deployment("web").await?;
    let mut spec = lb.raw().spec("web").await?;
    spec["vm"]["image"] = json!("nginx-fc:1.27");
    let op = lb
        .start_rollout("web", "web-1-27", &current.rollout_revision, &spec)
        .await?;
    println!("rollout {} is {}", op.operation_id, op.status);

    lb.delete_deployment("web").await?;
    Ok(())
}
```

The same in a terminal:

```sh
heyctl create deployment web --host web.example.com --image nginx-fc --port 80 --min 1 --max 4
heyctl rollout status web
heyctl plugins install obs          # namespace taken from the token
heyctl top -n team-a
heyctl logs web --level error --since 1h
```

This is [`examples/namespace_workload.rs`](examples/namespace_workload.rs):
`HEYCTL_SERVER=… HEYCTL_TOKEN=… cargo run --example namespace_workload`.

### The rest of the surface

```rust
use hws::{Client, ExecRequest};

let lb = Client::builder("127.0.0.1:9090")
    .token(std::env::var("APP_LB_TOKEN")?)
    .build()?;

let out = lb.exec("sb-7f3a9c", &ExecRequest::new("uname -a")).await?;
println!("{}", out.stdout);
```

Async by default. Under the `blocking` feature, `hws::blocking::Client` is
the same surface with the `await`s taken out — it is what the CLI uses, and it
returns a clear error rather than tokio's panic if you call it from inside a
runtime.

**Typed reads, `Value` writes.** Reads come back as structs; writes take
`serde_json::Value`. That asymmetry is load-bearing: `PUT /deployments/:id`
replaces a *whole* spec, so a client that parsed one into a struct it only half
understood and wrote it back would silently delete every field this build has
never heard of. Round-tripping the `Value` cannot lose anything. `client.raw()`
gives the same reads unparsed, for printing a response or for the read half of a
read-modify-write.

**Shells own their framing.** `client.shell()` returns a session whose `write`
and `resize` speak plain bytes — app-lb's wire protocol prefixes stdin with
`0x01` and silently drops a frame that does not, which is the easiest way to
write a shell client that connects perfectly and types nothing.

**`ShellExit::is_clean()`, not `code == 0`.** app-lb reports an *unknown* exit
code as `0`, so a VM dying under a live session and a clean logout are the same
number. `is_clean()` is false when an error preceded the exit.

**Waiting is provided.** `wait_for_job` reports new log lines as they arrive;
`wait_for_ready` waits on *healthy* backends rather than `ready`, which counts
VMs that are in the pool and failing their health check.

```rust
let job = lb.start_build("api", None).await?;
lb.wait_for_job(&job.id)
    .on_log(|line| println!("{line}"))
    .await?;
```

Full API documentation: `cargo doc -p hws --no-default-features --open`.

## App-tokens

```sh
heyctl token mint agent-runner --admin admin -d sb-7f3a9c --expires-in 24
heyctl token list
heyctl token set <id> --all-deployments      # re-scope, same secret
heyctl token revoke <id>
```

The secret is printed once and cannot be recovered — app-lb stores only its
hash. `mint` writes it to stdout and everything else to stderr, so capturing it
works with or without `-q`:

```sh
APP_LB_TOKEN=$(heyctl token mint ci --admin admin --all-deployments -q)
```

A token scoped to specific deployments is refused the fleet-wide routes,
*including minting* — so it cannot widen itself. See the
[app-tokens section](../README.md#app-tokens) of app-lb's README.

## Quick start

```sh
heyctl login --server 127.0.0.1:9090        # prompts for the password, if the server wants one
heyctl get deployments
heyctl create deployment web --host web.local --image nginx-fc --port 80 --min 1 --max 4
heyctl rollout status web
heyctl top
```

With no config file at all, commands go to `http://127.0.0.1:9090` — app-lb's default admin
listener — so a local LB needs no setup.

## Connecting

app-lb's admin listener is **plaintext HTTP on loopback** by default. To reach a remote one,
either tunnel it:

```sh
ssh -L 9090:127.0.0.1:9090 lb-host
heyctl --server 127.0.0.1:9090 get deployments
```

…or front it with app-lb's own TLS listener (see [`examples/app-lb-admin.json`](../examples/README.md))
and point heyctl at the HTTPS name:

```sh
heyctl login --server https://lb-admin.example.com --user admin
```

`--insecure-skip-tls-verify` exists for a self-signed admin endpoint you control.

**Do not point a context at a hostname behind a Google sign-in gate.** heyctl
cannot complete an OAuth flow, and the gate knows it: a browser gets a `302` to
Google, everything else gets a `401` carrying a `login_url` only a browser can
use. Every command then fails with *"the server rejected these credentials"* —
which is what it received, but the credentials were never the problem, and
`whoami` will report the deployment API and `/metrics` both `denied` no matter
what you store.

Two ways out, in the order worth trying:

```sh
# 1. Tunnel to the admin listener and bypass the gate entirely.
ssh -L 9090:127.0.0.1:9090 lb-host
heyctl login --server 127.0.0.1:9090 --user "$APP_LB_DASHBOARD_USER"

# 2. Or let the API paths past the gate, server-side, and gate them with Basic
#    auth instead — see the app-lb README, "Putting the dashboard behind Google".
```

While you are there: `login` prompts for a password but never for a *username*,
and defaults to `admin`. If the server sets `APP_LB_DASHBOARD_USER` to anything
else, pass `--user` — a wrong username produces a `401` indistinguishable from a
wrong password.

## Authentication

app-lb authenticates with HTTP Basic and has **two independent gates**:

| Server setting | Gates |
| --- | --- |
| `APP_LB_DASHBOARD_PASSWORD` | the dashboard and `/metrics` (so: `top`, `status`) |
| `APP_LB_ADMIN_AUTH=1` | additionally the deployment API (so: `get`, `create`, `scale`, …) |

`heyctl login` probes both, tells you which it found, verifies the credentials against
whichever is actually gated, and saves a **context**. `heyctl whoami` reports what the current
identity is allowed to do — the answer to "why am I getting a 401":

```
$ heyctl whoami
Client:
  Config file:             ~/.config/heyctl/config.json
  Context:                 local
  Server:                  http://127.0.0.1:9090
  User:                    admin
  Password:                stored in the config file
Server:
  Reachable:               yes (GET /healthz)
  Auth required for:       dashboard, /metrics and the deployment API
  Deployment API:          allowed
  Metrics:                 allowed
```

### Where the password comes from

In precedence order:

1. `--password` / `HEYCTL_PASSWORD`
2. the context's `password_command` — a shell command whose stdout is the password
3. the context's stored `password`

The config file is written `0600` (and its directory `0700`), but a stored password is stored in
the clear — there is no token endpoint to trade it for something shorter-lived. To keep it out of
the file entirely:

```sh
heyctl login --server lb.example.com:9090 --password-command 'pass show app-lb/admin'
heyctl login --server lb.example.com:9090 --no-store-password   # then export HEYCTL_PASSWORD
```

### Tokens

The other way in is a bearer token — an app-lb app-token (`applb_…`, see the app-lb README), or a
**namespace-scoped Heyo API key** (`heyo_api_…`, minted on a namespace's page in the Heyo dashboard)
used against Cloud's namespace door. That door speaks only bearer, has no `/healthz` and no gate to
probe, so a token login verifies with `GET /deployments` and stores the token in the context:

```sh
heyctl login --server https://server.heyo.computer/namespaces/team-a/lb --token-stdin <<< "$HEYO_KEY"
heyctl get deployments
heyctl shell web
```

A token outranks a stored user/password on the same context. The same ladder as passwords applies —
`--token` / `HEYCTL_TOKEN`, then the context's `token_command`, then its stored `token` — and
`--no-store-password` keeps it out of the file. A namespace-scoped key reaches exactly that namespace,
at the tier it was minted with (`view` lists and watches; `admin` also creates, edits and shells), and
nothing else on the cloud; `whoami` says which credential the next request will send.

### Contexts

Several load balancers, kubeconfig-style:

```sh
heyctl config get-contexts
heyctl config use-context prod
heyctl config set-context staging --server https://lb.staging.example.com --user admin
heyctl --context staging get deployments      # one-off, without switching
heyctl logout --keep-context                  # forget just the password
```

`HEYCTL_CONFIG`, `HEYCTL_CONTEXT`, `HEYCTL_SERVER`, `HEYCTL_USER`, `HEYCTL_PASSWORD` and
`HEYCTL_TOKEN` override the file for scripts and CI:

```sh
HEYCTL_SERVER=https://server.heyo.computer/namespaces/team-a/lb HEYCTL_TOKEN=heyo_api_… heyctl get deployments
```

## Commands

Resource names take kubectl's forms: `deployments`, `deployment web`, `deployment/web`, `deploy web`,
or a bare `web` where the kind is unambiguous.

### Reading

```sh
heyctl get deployments                 # NAME KIND ROUTES DESIRED READY PENDING IN-FLIGHT
heyctl get deployments -o wide         # + MIN MAX WARM TARGET BACKEND SOURCE AUTH
heyctl get deployment/web -o yaml      # the server's JSON, as YAML
heyctl get vms -d web                  # backends of one deployment
heyctl get certs                       # issued TLS certificates and expiry
heyctl get secrets                     # ids and key *names* — never values
heyctl get jobs -d web                 # builds, pulls and updates, newest first
heyctl get job job-3f2a1c8e            # one job in full, with its log
heyctl get deployments -w              # re-render every 2s

heyctl describe deployment web         # spec, pool, backends and traffic in one page
heyctl status                          # uptime, host, fleet and traffic totals
heyctl top                             # per-deployment CPU, memory, latency, 5xx
heyctl top vms
heyctl top host
```

`-o json|yaml` prints the server's own payload untouched, so it round-trips:

```sh
heyctl get deployment web -o json | heyctl --context staging apply -f -
```

### Creating and editing

```sh
# A managed VM pool.
heyctl create deployment web \
  --host web.local --image nginx-fc --port 80 --size mini \
  --min 1 --max 4 --warm 1 --target-concurrency 10 \
  --health-path /healthz -e RUST_LOG=info

# A static (proxy_pass) deployment.
heyctl create deployment legacy --path-prefix /legacy --upstream 10.0.0.9:8080 --health-tcp

# A managed VM with no ingress — an agent sandbox, reached by exec/shell only.
heyctl create deployment sb-7f3a9c --no-route --port 8080 --size medium

# A static site: no backend at all, files served off disk by app-lb itself.
heyctl create deployment docs --host docs.example.com --site-root /srv/docs/dist

# From a file — JSON or YAML, one spec, a JSON array, or a multi-doc YAML stream.
heyctl apply -f deploy.yaml
heyctl apply -f examples/heyosecret.json --dry-run

# In place.
heyctl edit deployment web             # $EDITOR round-trip; a rejected edit is kept on disk
heyctl set image web nginx-fc-v2
heyctl set env web RUST_LOG=debug FEATURE_X-        # `KEY=VALUE` sets, `KEY-` removes
heyctl set upstreams legacy 10.0.0.9:8080 10.0.0.10:8080
heyctl set route web --host web.example.com --path-prefix /api
heyctl set route web --route '*.apps.example.com' --add
heyctl set route sb-7f3a9c --none                  # withdraw from the proxy

# Static upstream maintenance: durable and independent from probe health.
heyctl cordon stage us1.internal:8080 --reason 'regional maintenance'
heyctl drain stage us1.internal:8080 --timeout 300
heyctl uncordon stage us1.internal:8080
```

Routing flags: `--host`, `--host-suffix` and `--path-prefix` describe **one** rule together, so
`--host web.local --path-prefix /api` means "that host under that path". `--route` adds further
rules and is repeatable — `--route host=a.example.com,path=/api`, or the shorthands `--route /api`,
`--route '*.apps.example.com'`.

`--no-route` (on `create`) and `--none` (on `set route`) are the two halves of
leaving a managed deployment off the proxy entirely. Exposing a sandbox is then
one `set route`, and withdrawing it is one more — neither disturbs the running
VM or its shell sessions. Both are refused for a static (`proxy_pass`)
deployment, which has no other door and would become unreachable.

Every `set` command and `edit` is a read-modify-write against `PUT /deployments/:id`, which
replaces the whole spec. heyctl edits the server's JSON rather than a struct of its own, so
fields it has never heard of survive the round trip.

### Building an image from a Dockerfile

A managed deployment can carry a *build source* — where its Dockerfile comes from — instead of
only an image name. `heyctl build` gets that Dockerfile onto the app-lb host, builds the image
with `heyvm mvm build`, and rolls the pool onto the result. The recipe comes from a git checkout
(`--repo`) or from a Dockerfile manifest in an artifact store (`--store`); exactly one of the two.

```sh
# Store the credential first, if the repo is private. The value is never readable back.
heyctl create secret github --from-stdin token < ~/.github-pat
heyctl create secret github --from-env token=GITHUB_TOKEN --description 'CI PAT for acme/*'

# Record where the image comes from. This builds nothing on its own.
heyctl set build web --repo https://github.com/acme/web.git --ref main --secret github
heyctl set build web --dockerfile deploy/Dockerfile --size-mb 768

# Or say it at creation time.
heyctl create deployment web --host web.example.com --port 8080 \
  --repo https://github.com/acme/web.git --ref main --secret github

# Build and roll out.
heyctl build web --wait                 # blocks until it succeeds or fails
heyctl build web --ref v2.1.0 --logs    # a one-off ref; streams the build output
heyctl build web                        # fire and forget; poll with `get job <id>`

heyctl set build web --clear             # stop tracking a source; keep the current image
```

The recipe can live in the artifact store instead of a repo, which is what
[`artifact push-dockerfile`](#pushing-a-dockerfile-to-an-artifact-store) puts there:

```sh
heyctl set build web --store http://10.0.0.4:8080 --ref web-rootfs
heyctl create deployment web --host web.example.com --port 8080 \
  --build-store http://10.0.0.4:8080 --ref web-rootfs
heyctl build web --wait
```

`--repo` and `--store` are alternatives, and switching drops the other along with the flags that
only meant something to it (`--dockerfile`, `--build-context`). `--ref` is read by whichever
source is set — a branch or commit for a repo, a manifest tag or digest for a store, where it is
required because a store has no default branch to fall back on.

A build is asynchronous server-side, so plain `heyctl build` returns as soon as it is
scheduled and prints the id to follow. `--wait` polls to completion, `--logs` also streams the
output as it arrives; either way a failed build exits non-zero after printing the tail of the
log. One job runs per deployment at a time — a second is refused, not queued.

Each build produces an image named `<deployment>-<short sha>`, so `heyctl describe` and
`get -o wide` say which commit is actually running. Rotating a token is
`heyctl set secret github token=ghp_new…`; keys you don't mention keep their values, which
matters because there is no way to read them back and resend them.

### Pulling an image from an artifact store

The other way a managed deployment gets its image: instead of building one, pull one somebody
already built. `heyctl set artifact` records where from, and `heyctl pull` fetches it,
materializes it as an `.ext4` the daemon can boot, and rolls the pool onto it.

```sh
# Store the API key first, if the store is gated. As with a build's, it stays write-only.
heyctl create secret art api_key=…
heyctl create secret art --from-stdin api_key < ~/.art-key

# Record where the image comes from. This pulls nothing on its own.
heyctl set artifact web --store http://10.0.0.4:8080 --ref web-v2 --secret art/api_key
heyctl set artifact web --grow-gb 8         # extend the rootfs (sparsely) on materialize

# A store root on the app-lb host instead of a URL — much cheaper, see below.
heyctl set artifact web --store /srv/artifacts --ref web-v2

# Pull and roll out.
heyctl pull web --wait                      # blocks until it succeeds or fails
heyctl pull web --ref <digest> --logs       # a one-off ref; the spec's is left alone
heyctl pull web --force                     # re-fetch even if the image is already here

heyctl set artifact web --clear             # stop tracking a source; keep the current image
```

A pull is the same kind of job as a build — asynchronous, `--wait`/`--logs`, one per deployment
at a time, listed by `heyctl get jobs` — and its record answers the question a pull exists to
answer: which *bytes* are running.

```
JOB                DEPLOYMENT   KIND            STATUS      TARGET   RESULT             TOOK
job-c628fbe1ef07   web          artifact-pull   succeeded   web-v2   web-1b9b737b73e2   1s
```

Three things worth knowing:

- **A tag resolves at pull time; a digest does not.** `--ref web-v2` follows wherever that tag is
  moved, so pushing over it is a deploy. `--ref <digest>` pins the bytes, which is what a
  rollback should do — and as a one-off flag it does not touch the stored spec.
- **A re-pull of unchanged bytes is free.** Images are named `<deployment>-<12 hex of digest>`,
  so the file already being there proves the content is right and the transfer is skipped. The
  pool still rolls, because the running VMs booted from whatever rootfs *they* were given.
- **A local store is dramatically cheaper than a URL.** `--store /path` runs `art heyvm
  materialize`, which skips the blob's holes — 48 KiB written for a 48 MiB image against 48 MiB
  transferred over HTTP. Use a URL when the store is on another host; use a path when it is not.

`build` and `artifact` are mutually exclusive on one deployment: both rewrite `vm.image`, so
`set artifact` on a deployment that already builds is refused, and vice versa. To do both, build
on one host and push the result for the others to pull.

### Mounting a directory into a deployment's VMs

An image decides what the guests *run*; `vm.mounts` decides what they *hold*. Each entry names a
tarball in an artifact store and a path inside the guest, and every replica boots with that path
already populated — a corpus, a model, a seed database, a bundle of assets.

There is no `heyctl set mounts`: the list is part of the VM template, so it is edited the way the
rest of the template is, with `heyctl apply` or `heyctl edit`.

```yaml
# search.yaml
id: search
routes: [{ host: search.example.com }]
vm:
  driver: firecracker
  image: search-1b9b737b73e2
  port: 8080
  mounts:
    - path: /data/corpus
      store: http://10.0.0.4:8080
      ref: corpus-2026-08
      strip_components: 1        # drop the wrapper dir, as tar does
```

```sh
tar czf corpus.tgz -C corpus .
art put corpus.tgz --tag corpus-2026-08     # a bundle, like a site's — `heyctl artifact push`
                                            # is for rootfs images, not tarballs

heyctl apply -f search.yaml     # a mount pull starts on its own
heyctl get jobs                 # watch it land
heyctl describe deployment/search
```

```
Mounts
  /data/corpus   /data/corpus <- 10.0.0.4:8080/corpus-2026-08 (ro) — digest 0f1e2d3c4b5a
```

`heyctl apply` and `heyctl edit` start the pull themselves whenever a mount has no tree on the
app-lb host, so the usual path needs no second command. `heyctl mounts pull` is for the two cases
that leaves — a tag that has moved, and a tree to re-fetch:

```sh
heyctl mounts pull search --wait
heyctl mounts pull search --force --logs
```

Its job record carries a row per mount rather than a single digest, because one job covers them
all:

```
JOB                DEPLOYMENT   KIND         STATUS      TARGET                     RESULT        TOOK
job-91af0c2d55e3   search       mount-pull   succeeded   /data/corpus,/opt/models   1/2 updated   47s
```

Four things worth knowing:

- **A deployment whose mounts have not been pulled has no pool.** app-lb refuses to create a VM
  that would boot without the data its spec claims, so `heyctl get deployments` shows `0` ready
  and the reason is on the job and in `heyctl describe`. It is a loud failure on purpose — the
  alternative is a replica that passes its health check and then fails on the first request that
  reads the mount.
- **The pool recycles only when a digest actually changes.** Unlike a build or an image pull,
  which roll unconditionally, a mount tree is content-addressed and a running VM's copy came from
  the same digest. Re-running a pull that finds nothing new leaves the fleet alone.
- **Mounts are read-only by default**, and a writable one is refused on the `kvm` driver, whose
  backend syncs the guest's writes back into the tree every other replica boots from. For
  writable space, `vm.disk_size_gb` is a per-VM data disk.
- **Editing the list recycles the pool**, because a mount is attached at boot. It is a template
  change like `image` or `size_class`, not a scaling knob.

## Artifact stores

An artifact store (`art serve`) is a separate service from app-lb, so `heyctl artifact` keeps
its own saved *registries* rather than using the `--server` context. A store is authenticated by
a shared key, not a username and password, and `--context` never retargets a push.

```sh
heyctl artifact login http://10.0.0.4:8080          # prompts for the key
heyctl artifact login http://10.0.0.4:8080 --api-key-stdin < ~/.art-key
heyctl artifact login … --api-key-command 'pass show art/prod'   # keep it in a keychain
heyctl artifact login … --no-store-key              # verify only; supply HEYCTL_ART_API_KEY

heyctl artifact registries                          # CURRENT NAME URL KEY
heyctl artifact use prod-store
heyctl artifact logout --key-only                   # drop the key, keep the url
```

Registries live in the same `0600` config file as the contexts, under their own key, and
`heyctl whoami` reports both identities — which is the answer to "why did my push get a 401
when everything else works".

### Pushing an image to an artifact store

```sh
heyctl artifact push --image web-v2                 # a heyvm image, by name
heyctl artifact push ./rootfs.ext4 --tag web-v2     # or a path
heyctl artifact push ./rootfs.ext4 --no-tag         # upload only; name the manifest digest
heyctl artifact push ./rootfs.ext4 --force          # upload even if the store has the bytes
```

`--image NAME` resolves `~/.heyo/images/firecracker/<name>.ext4` (or `$MVM_DATA_DIR/…`), which is
where `heyvm mvm build` puts one — so building locally and pushing is two commands. The tag
defaults to the filename without `.ext4`.

A push hashes the file, asks the store whether it already holds those bytes, uploads only if not,
then writes a manifest and moves the tag onto it. The manifest matters: it is what makes a pushed
image indistinguishable from one `art heyvm import` put in, and therefore pullable. Re-pushing
unchanged bytes is two round trips and reports `uploaded: false`.

### Pushing a Dockerfile to an artifact store

The counterpart of `push`, one step earlier: `push` ships an image somebody already built,
`push-dockerfile` ships the recipe and lets app-lb build it on the host that will run it.

```sh
heyctl artifact push-dockerfile ./Dockerfile --build-context . --tag web-rootfs
heyctl artifact push-dockerfile ./Dockerfile --image-name web --size-mb 4096
heyctl artifact push-dockerfile ./Dockerfile --no-tag       # name the manifest digest instead
```

The context may be a directory (packed here, deterministically, so an unchanged tree re-pushes as
one `HEAD`) or an archive you rolled yourself. Nothing is excluded — no `.dockerignore` handling —
because a packer that silently dropped files produces a build that fails on somebody else's host
with an error pointing at the Dockerfile. Point `--build-context` at a clean directory.

It is spelled `--build-context` rather than `--context` because `--context` is a global flag that
selects the saved app-lb context. The tag defaults to the Dockerfile's *directory* name, not its
filename — every project's recipe is called `Dockerfile`, so a filename default would have every
push in a shared store fighting over one tag.

The manifest is `heyvm.dockerfile.v1`: entries `Dockerfile` and `context.tar.gz`, annotated with
the image name and size defaults. Its digest covers all of that together, so
`heyctl set build web --store … --ref <digest>` pins a build to exact inputs.

```sh
heyctl artifact ls                                  # the store's tags
heyctl artifact describe web-v2                     # what a tag or digest resolves to
heyctl artifact usage                               # blobs, logical vs stored, free space
heyctl artifact untag web-v2                        # the blob stays until the store's `art gc`
```

### Updating a static deployment

A static deployment has no image to build — its backend is a process on the app-lb host. Its
update path is a working directory and the commands to run in it: what you would otherwise ssh
in and do.

```sh
heyctl set update app-obs \
  --workdir /srv/app-obs \
  -c 'git pull --ff-only' \
  -c 'cargo build --release' \
  -c 'supervisorctl restart app-obs'

heyctl update app-obs --wait --logs     # run them, then check the upstreams answer
heyctl update app-obs                   # fire and forget; poll with `get job <id>`

# Optional extras.
heyctl set update app-obs --secret github            # credential for a private `git pull`
heyctl set update app-obs --secret-env APP_OBS_INGEST_TOKEN=obs/ingest_token
heyctl set update app-obs --verify-timeout 0         # skip the post-update health check
heyctl set update app-obs --clear                    # stop tracking how it updates
```

Each `--command` is a shell line run in `--workdir`, in order, and the first failure stops the
job — `heyctl get jobs` shows how far it got (`1/3 commands`). Afterwards the deployment's
upstreams are re-probed with its own health check: **a job whose commands exited 0 but whose
service never came back is a failure**, and says so rather than reporting success.

Passing `--command` replaces the whole list (as do `--env` and `--secret-env`), so send the
steps you want, not a delta. Everything else you don't pass is kept.

The commands run as app-lb's user. Restarting a service usually needs a grant for exactly that
verb — access to supervisord's socket, or a `sudo -n` entry for one `systemctl restart` — and
nothing broader; the admin API is what triggers this.

### Putting a deployment behind Google sign-in

Any deployment — managed or static — can be gated. The gate runs in app-lb's proxy, so the
application behind it is unchanged and unaware.

```sh
# The client secret is a stored secret, never a spec field.
heyctl create secret google --from-stdin client_secret < ~/.google-oauth-secret

heyctl set auth web \
  --client-id 1234-abc.apps.googleusercontent.com \
  --secret google/client_secret \
  --allow-domain example.com \
  --allow-email contractor@gmail.com \
  --public-path /healthz

heyctl describe deployment web     # prints the redirect URI to register with Google
heyctl get deployments -o wide     # AUTH column: which deployments are gated
heyctl set auth web --clear        # remove the gate
```

`--public-path` writes a bare-string entry, which app-lb reads as scope `admin`:
the path skips Google but still needs an admin-tier app-token. For a path open to
everyone, write `{"path": "/healthz", "scope": "public"}` with `heyctl edit`.

Both allow flags are repeatable and take any number of entries, and the two lists are **OR'd** —
one match admits the caller:

```sh
heyctl set auth web \
  --allow-domain sarocu.com --allow-domain heyo.computer \
  --allow-email contractor@gmail.com --allow-email auditor@example.org
```

`--allow-domain` matches Google's `hd` claim — the Workspace that *governs* the account, not the
text after `@` — so a personal account with a lookalike address is refused. That also means a
personal account can only be admitted by `--allow-email`, since it carries no `hd` at all; if
`dig +short MX <domain>` shows something other than Google's servers, every account there is a
personal one as far as this claim goes. A Workspace with several domains needs each domain that
appears in `hd`.

`--allow-domain '*'` admits any Google account, and is the only way to say that: an empty
allow-list is rejected.

**Passing any `--allow-domain`/`--allow-email`/`--public-path` replaces that whole list**, so
growing one means resending all of it. There is no "add one" flag; `heyctl edit deployment web`
is the incremental route — it opens the spec in `$EDITOR` and touches only what you change.

Adding or removing an entry signs every current user out once — they bounce through Google and
straight back in — which is what makes *removing* someone take effect immediately rather than
when their cookie expires. Reordering or re-casing a list is free: the policy fingerprint sorts
and lowercases before hashing, so only a real change to who may enter invalidates a session.

### Putting a deployment behind a JWT

The other kind of gate: instead of app-lb signing people in, it verifies a token **somebody
else** issued. For an application whose users already sign in elsewhere.

There is no `heyctl set jwt`. The block has a dozen fields and is written once, so it goes in
with the rest of the spec — `heyctl apply -f`, or `heyctl edit deployment <id>`:

```yaml
# search.yaml
id: search
routes: [{ host: search.example.com }]
upstreams: ["127.0.0.1:8080"]
auth:
  provider: jwt
  jwt:
    secret:        { secret: heyo-auth, key: jwt_secret }
    algorithms:    ["HS256"]
    issuer:        auth-service
    audience:      heyo-app
    subject_claim: userId              # the Heyo auth API's subject is not `sub`
    require:       { role: [user, admin] }
```

```sh
heyctl create secret heyo-auth --from-stdin jwt_secret < ~/.heyo-jwt-secret
heyctl apply -f search.yaml
heyctl describe deployment search
```

```
Sign-in gate
  Provider              jwt
  JWT issuer            auth-service
  JWT audience          heyo-app
  JWT key               shared secret heyo-auth/jwt_secret
  JWT algorithms        HS256
  JWT admits            role=user|admin
  JWT subject claim     userId -> x-auth-request-user
```

The same block with `jwks_url`, `RS256` and the default `sub` fronts an Auth0, Okta, Cognito or
Keycloak deployment — nothing about the gate is specific to one issuer.

Four things worth knowing, all of them enforced when the spec is registered rather than
discovered at runtime:

- **`algorithms` is required and has no default.** A token names its own algorithm in a header
  the caller controls, so the spec decides and never the token — otherwise an unsigned token
  (`alg: none`) or one signed with the gate's *public* key as an HMAC secret would verify. A
  block naming an algorithm its key could not verify is refused.
- **`require` is the allow-list, not `--allow-domain`/`--allow-email`.** Those match a Google
  identity and are *refused* on a gate with no `google` provider, rather than looking like they
  restrict something. `require` takes any claim, against a value or a set of them.
- **A token with no `exp` is refused.** app-lb did not issue it and cannot revoke it, so the
  expiry is the only thing that ever stops it.
- **Mixing works.** `provider: [google, jwt]` is the common shape for a product UI: a person
  signs in with Google, and the UI's own API calls carry the token the auth service gave it.

### Declaring an auth provider, and inheriting it

The block above is one deployment's copy of an identity. An **auth provider** is
that identity on its own — named, owned by a namespace, and inherited by any
deployment in it. Editing the provider reaches every one of them at once, and
rotating the key is a secret write and nothing else.

```sh
# The Heyo auth API, verified against its published key set. No secret exists
# to store, which is what makes it safe in a namespace somebody else runs.
heyctl create auth-provider heyo -n team-a \
  --preset heyo-jwks \
  --require accountId=acct_7f3c            # the preset alone admits every Heyo user

# The same service's HS256 access tokens, for a fleet and a namespace that are
# both yours. That key mints as well as verifies.
heyctl create secret heyo-auth -n team-a --from-stdin jwt_secret < ~/.heyo-jwt-secret
heyctl create auth-provider heyo-hs -n team-a \
  --preset heyo --secret heyo-auth/jwt_secret

# Any other issuer: Auth0, Okta, Cognito, Keycloak, your own service.
heyctl create auth-provider okta -n team-a \
  --issuer https://example.okta.com \
  --jwks-url https://example.okta.com/oauth2/v1/keys \
  --alg RS256 --require groups=engineering,ops

# Google, with one session shared across the namespace's deployments.
heyctl create auth-provider corp-google -n team-a \
  --client-id 1234.apps.googleusercontent.com --secret google/client_secret \
  --allow-domain example.com --cookie-domain .example.com

heyctl set auth reports --provider-ref heyo --public-path /healthz
heyctl get auth-providers -n team-a
heyctl describe auth-provider heyo -n team-a
heyctl delete auth-provider okta -n team-a
```

A spec file works too, and `apply` upserts it:

```yaml
kind: auth-provider
name: heyo
namespace: team-a
preset: heyo
secret: { secret: heyo-auth, key: jwt_secret }
```

Four things worth knowing:

- **A gate either inherits an identity or writes one.** `--provider-ref` and
  `--client-id`/`--secret`/`--allow-*` are refused together, because app-lb refuses
  a gate carrying both. Setting one clears the other; everything route-scoped
  (`--public-path`, `--base-path`, `--cookie-name`, `--session-ttl`) stays where it is.
- **The key is named exactly once.** `--secret` for `HS*`, `--jwks-url` for a rotating
  key set, `--public-key-file` for a static public key — and `--alg` defaults by which
  one you chose, because the token never gets to pick. A key set rotates with no change
  here at all: app-lb refetches when it meets a `kid` it has not seen.
- **Prefer a key set to a shared secret.** An `HS*` key verifies *and* mints, so whoever
  can read it can issue any identity that issuer can — and a namespace admin can read
  any secret behind their own wall (`vm.env_from` puts it in a guest they control).
- **`--require` is the allow-list.** `--require role=user,admin` is "either of these";
  several `--require` flags must all hold. With none, any unexpired token that issuer
  signed for the audience gets in.
- **For people in browsers, add `--cookie` and `--login-url`.** A navigation cannot carry
  an `Authorization` header, so app-lb redirects a token-less browser to your issuer's
  sign-in page and reads the cookie it sets on the way back. See
  [AUTH_PROVIDERS.md](../AUTH_PROVIDERS.md) for that contract.

### Scaling and rollouts

```sh
heyctl scale web --replicas 3          # pin: min = max = 3
heyctl scale web --min 1 --max 8 --warm 2 --target-concurrency 20
heyctl scale web --scale-to-zero-after 600
heyctl scale sb-7f3a9c --idle-action retain   # stop idle VMs instead of killing them

heyctl restart web                     # drain every VM; the autoscaler boots replacements
heyctl restart web --force --wait      # kill now, then block until the pool is healthy
heyctl rollout status web              # poll until desired == ready and nothing is draining
```

`scale` uses the API's partial `PATCH .../scaling`, so fields you don't pass keep their values.
`--replicas` is a pin, not a one-off: it sets both ends of the band, which is what stops the
autoscaler moving off the number. Give it a `--min`/`--max` band again to hand control back.

`--idle-action retain` stops an idle VM instead of killing it, so a later request
or `exec` resumes that VM rather than booting a fresh one. It keeps the sandbox's
`/workspace` data disk and nothing else — **not** the root filesystem, which the
daemon recopies from the base image on every boot. Pair it with
`--disk-gb` at create time and keep the sandbox's state under `/workspace`,
or it only saves boot time; `heyctl describe` reports which mode a deployment
is in under "When idle".

### Cordoning and draining static upstreams

`cordon` stops assigning new requests to one address in a static (`upstreams`)
deployment and returns immediately. `drain` performs the same state change and
then polls until that address has no requests in flight. Neither removes the
address from the spec, kills a process, nor changes probe health.

```sh
heyctl cordon stage us1.internal:8080 --reason 'kernel upgrade'
heyctl drain stage us1.internal:8080 --timeout 300
heyctl uncordon stage us1.internal:8080
```

The state persists across app-lb restarts and deployment replay. A drain is
refused while there is no other healthy, accepting upstream; `--force` opts into
taking the deployment fully offline. If waiting times out, the upstream remains
cordoned and the error names the `uncordon` command that restores it. `get vms
-d stage` shows `Draining` separately from health throughout the operation.

### Static sites

```sh
heyctl create deployment docs --host docs.example.com --site-root /srv/docs/dist
heyctl create deployment app  --host app.example.com  --site-root /srv/app/dist --site-spa
heyctl update docs             # run the build commands, then re-check the site
```

A site has no backend at all: app-lb serves the files itself, out of a directory
on its own host. `--site-root` is what makes a deployment one; `--site-index`,
`--site-404`, `--site-spa` and `--site-cache-control` configure it, and each is
refused without a root rather than silently ignored.

`--site-spa` serves the index for any unmatched path so a client-side router
owns the URL space — for single-page apps only, since it turns every typo into a
200.

Pair it with `set update` for a git-backed deploy: `heyctl update` runs the
build commands in a directory on the app-lb host and then checks that the index
is actually in the root, so a build that writes its output elsewhere fails
loudly instead of leaving a site that 404s everything. `heyctl describe`
shows the root, index, 404 page and cache policy under "Site".

### Getting inside a VM

```sh
heyctl exec sb-7f3a9c -- ls -la /workspace     # one command; its exit code becomes ours
heyctl exec sb-7f3a9c --cwd /workspace -e RUST_LOG=debug -- cargo test
heyctl shell sb-7f3a9c                          # an interactive PTY
```

`exec` is a pass-through: the guest's stdout goes to stdout, its stderr to
stderr, and its exit code becomes heyctl's — so it composes in a pipeline,
not only at a prompt. `-o json` returns the whole record instead, including
which `sandbox_id` ran it.

Both commands **start a VM** for a deployment that has none running, waiting up
to the deployment's `cold_start_timeout_secs`; `--no-wake` asks for an error
instead. Both go through app-lb rather than the heyvm daemon, so they work from
anywhere the admin API does, use the credentials already in your context, and
can wake a sandbox that was suspended by `--idle-action retain`.

Together they are the only way into a deployment created with `--no-route`,
which takes no HTTP traffic at all. An open `shell` holds the VM: it counts as
in-flight work, so a sandbox will not be scaled to zero underneath a live
session.

### Deleting

```sh
heyctl delete deployment web           # deregister, then drain and reap every VM
heyctl delete deployments --all
heyctl delete vm sb-abc123 -d web      # drain one VM
heyctl delete vm sb-abc123 -d web --force   # kill it, dropping in-flight requests
heyctl delete secret github            # refused while a deployment's build refers to it
heyctl delete secret github --force    # delete anyway; those builds stop authenticating
```

Evicting a VM is *recycle*, not *shrink* — the autoscaler boots a replacement on its next tick if
the policy still wants the capacity. Use `scale` to shrink.

### Shell completion

```sh
heyctl completion bash > /etc/bash_completion.d/heyctl
heyctl completion zsh  > ~/.zfunc/_heyctl
```

## The three kinds of deployment

The distinction runs through every command, because app-lb enforces it:

| | managed (`vm`) | static (`upstreams`) | site (`site`) |
| --- | --- | --- | --- |
| backends | an autoscaled pool of microVMs | fixed `host:port` addresses | none — files off disk |
| `scale` | yes | rejected — the policy is inert | rejected — nothing to scale |
| `restart` / `delete vm` | yes | rejected — nothing to evict | rejected — nothing to evict |
| `cordon` / `drain` / `uncordon` | rejected — use VM eviction | yes | rejected — no upstream |
| `exec` / `shell` | yes | rejected — upstreams are addresses | rejected — a site is files |
| `set image` / `set env` | yes | rejected — no VM template | rejected — no VM template |
| `set build` / `build` | yes | rejected — no guest image to build | rejected — no guest image |
| `set artifact` / `pull` | yes — but not alongside `build` | rejected — no guest image to pull into | rejected — no guest image |
| `set update` / `update` | rejected — its backends are VMs | yes | yes — how a site is deployed |
| `set auth` | yes | yes | yes — the gate is in the proxy, ahead of all three |
| `set upstreams` | rejected | yes | rejected |
| `DESIRED` column | the autoscaler's target | `—` |

Where the API rejects one of these, heyctl passes the server's reason through and, where it
knows the answer up front, says which command to use instead.

## Exit codes

`0` success, `1` a failed command (the reason goes to stderr as `error: …`), `2` a usage error
from the argument parser.
