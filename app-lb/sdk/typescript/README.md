# @heyocomputer/hws

The TypeScript twin of [`hws`](https://crates.io/crates/hws), the app-lb SDK:
register deployments, scale pools, run commands inside a microVM, attach an
interactive shell, roll out new specs, and — through a namespace's installed
plugins — read its telemetry.

Same wire contract and the same version as the [Rust crate](../../heyctl)
(source in this repo, published as `hws` on crates.io), which also ships the
`heyctl` CLI. Both are checked against the golden fixtures app-lb's own tests
write.

```sh
npm install @heyocomputer/hws
```

```ts
import { Hws } from "@heyocomputer/hws";

const lb = new Hws({
  server: "127.0.0.1:9090",
  token: process.env.APP_LB_TOKEN,
});

const { stdout, exit_code } = await lb.exec("sb-7f3a9c", "uname -a");
```

Node 18+, Bun, Deno and browsers. Everything uses `fetch`; shells use
[`ws`](https://www.npmjs.com/package/ws) on the server and the native
`WebSocket` in a browser.

## Authenticating

Prefer an **app-token**: scoped to particular deployments, revocable without
restarting app-lb, optionally expiring. Basic auth also works and is unscoped —
it is the operator credential, and the one that mints tokens.

```ts
const admin = new Hws({ server, user: "admin", password: process.env.PW! });

const minted = await admin.mintToken({
  name: "agent-runner",
  admin: "admin",
  deployments: ["sb-7f3a9c"],
  expiresInSecs: 86_400,
});

// The secret is in the reply and nowhere else, ever — app-lb stores only its
// hash and no endpoint reads it back.
console.log(minted.token);
```

A token scoped to specific deployments is refused the fleet-wide routes —
listing every deployment, the secret store, and minting — so it cannot widen
itself. `/metrics` is the exception: rather than refusing a scoped token it
narrows the answer to what that token can see.

## Sandboxes

```ts
await lb.createDeployment({
  id: "sb-7f3a9c",
  routes: [],                       // unrouted: reached by exec and shell only
  vm: { driver: "firecracker", port: 8080, disk_size_gb: 20 },
  scaling: { min_replicas: 0, max_replicas: 1, idle_action: "retain" },
});

await lb.waitForReady("sb-7f3a9c", {
  onProgress: (p) => console.log(`${p.healthy}/${p.desired} healthy, ${p.pending} booting`),
});
```

`waitForReady` counts **healthy** backends, not `ready` — `ready` is the size of
the pool, including a VM that is failing its health check, so waiting on it
reports success for a deployment that cannot serve a request.

## Shells

```ts
const shell = await lb.shell("sb-7f3a9c", { cols: 120, rows: 40 });
shell.onData((bytes) => process.stdout.write(bytes));

process.stdin.on("data", (d) => shell.write(d));
process.stdout.on("resize", () =>
  shell.resize(process.stdout.columns, process.stdout.rows));

const { code, clean, error } = await shell.exit;
```

**Check `clean`, not `code === 0`.** app-lb reports an *unknown* exit code as
`0`, which is what a VM dying under a live session looks like — so a crash and a
logout are the same number. `clean` is false when an error preceded the exit.

**There is no resume.** If the socket drops the session is gone; reconnecting
gives a *new* shell. This package will not silently retry, because a retry that
quietly discards a session is worse than an error.

### In a browser

A browser's `WebSocket` constructor cannot set headers, so a browser shell needs
an **app-token**, which travels in the query string. app-lb accepts
`?app_token=` on the shell route and nowhere else, for exactly that reason.

A credential in a URL lands in access logs, proxy logs and browser history, so
mint a short-lived one:

```ts
const ticket = await admin.mintToken({
  name: `terminal ${user}`,
  admin: "admin",
  deployments: [sandboxId],
  expiresInSecs: 120,
});
// hand `ticket.token` to the page, which opens the shell with it
```

Basic credentials cannot be used for a browser shell at all, and this package
throws rather than silently failing the upgrade.

## Errors

Every failure is a subclass of `HeyctlError` carrying `status`, `retryable`
and `isAuth`:

| | |
|---|---|
| `UnauthorizedError` | 401 — missing, wrong, revoked or expired. app-lb does not distinguish those, so token ids cannot be enumerated. |
| `ForbiddenError` | 403 — the credential was good, the scope was not. Re-presenting it will not help. |
| `NotFoundError` | 404, carrying `kind` and the name |
| `NoRunningVmError` | 409 from `exec`/`shell` with `wake: false` |
| `ConflictError` | 409 — a job is already running, a secret is still referenced, a rollout's revision moved. `code` carries app-lb's reason when it gives one, e.g. `plugin_not_installed` / `plugin_disabled` |
| `ColdStartTimeoutError` | 503 — no VM appeared in time. `retryable`. |
| `UpstreamError` | 502 — the daemon failed. `retryable`. |
| `MalformedResponseError` | a response that could not be interpreted |

```ts
try {
  await lb.exec("sb-1", "make test", { wake: false });
} catch (e) {
  if (e instanceof NoRunningVmError) {
    await lb.exec("sb-1", "make test");   // wake it after all
  } else if (e.retryable) {
    // ColdStartTimeout, Upstream, Transport
  } else throw e;
}
```

Note app-lb answers a failed request in **two** shapes: `{"error": "…"}` from
its own handlers, and plain text for the 401 and every framework-level rejection
(415 for a missing content-type, 422 for well-formed JSON of the wrong shape).
This package parses both, so a caller never sees a JSON syntax error where an
HTTP status was the actual answer.

## Three things this package does not smooth over

**A non-zero exit resolves.** `exec` rejects only when the command could not be
*run*. Check `exit_code`.

**`exec`'s timeout does not kill anything.** `timeoutSecs` bounds app-lb's call
to the daemon; when it expires you get an `UpstreamError` and **the command
keeps running in the guest**. The daemon offers no streaming and no
cancellation, so output is buffered until it exits. The client-side deadline is
sized to outlast the server's worst case — the command timeout plus a possible
cold start — because abandoning a request app-lb is still serving turns a
well-defined answer into an unexplained transport error.

**Registering a deployment does not mean it has a certificate.** ACME issuance
is asynchronous; poll `certs()`.

## Rollouts

`replaceDeployment` recycles the pool in place. To roll a new spec beside the
old pool, verify it, and only then drain the old one:

```ts
const { rollout_revision, spec } = await lb.deployment("api");
spec.vm!.image = "api-v2";
const op = await lb.startRollout("api", {
  operationId: crypto.randomUUID(),     // retry a lost reply with the same id
  expectedRevision: rollout_revision!,  // 409 if anything changed it since
  spec,
});
let now = op;
while (now.status === "running") now = await lb.rollout("api", op.operation_id);
```

## Namespace plugins and telemetry

Some plugins install per namespace. The operator enables one for the fleet; a
namespace administrator installs it. Installing `obs` makes app-obs collect
every deployment in the namespace, readable with the namespace's own token:

```ts
await lb.installPlugin("team-a", "obs");
const obs = lb.obs("team-a");
const fleet = await obs.fleet({ window: "1h" });
let page = await obs.logs("web", { level: "error", limit: 100 });
while (page.next_before_ms !== null) {
  page = await obs.logs("web", { level: "error", limit: 100, before: page.next_before_ms });
}
```

Before it is installed every `obs` call rejects with a `ConflictError` whose
`code` is `plugin_not_installed` (or `plugin_disabled` while the operator has it
off).

`whoami()` says what the server makes of the credential: its tier, whether it is
confined, and to which namespace.

## Building deployments

Writes take the spec as an object and send it verbatim. Read with
`deployment()`, edit `status.spec`, and pass that back — `PUT` replaces the
*whole* spec, so anything dropped in between is genuinely dropped.

```ts
const { spec } = await lb.deployment("api");
spec.vm!.image = "api-v2";
await lb.replaceDeployment("api", spec);
```

## Development

```sh
npm install
npm test          # builds, then unit tests + the wire-contract check
```

The wire-contract test reads `testdata/wire/*.json` — fixtures written by
app-lb's own response types — and asserts every key in them is declared in
`src/types.ts`. To a JS client an unknown field and an absent one look
identical, which is exactly how five fields once went missing from the Rust
client without a test failing. A field app-lb starts sending now fails this test
instead of going silently unread.

`examples/e2e.mjs` runs the whole surface against a live app-lb.

`Heyctl` is still exported as an alias of `Hws`, so code written against the
pre-0.2 package name keeps compiling after changing its import.
