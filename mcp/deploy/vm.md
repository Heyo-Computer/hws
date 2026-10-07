# Deploying heyo-mcp as a VM

The alternative to `deploy/heyo-mcp.json` + `deploy/supervisor/heyo-mcp.conf`,
which run this as a host process behind app-lb. Both shapes are supported; this
one exists because of what the host-process shape *lets the server do*.

## Why

Inbound traffic was never the problem. A `proxy_pass` deployment is fully under
app-lb: TLS, the app-token gate, and a health probe of the upstream every
autoscaler tick, which drops it from `select` and raises a feed event when it
stops answering (`app-lb/src/autoscale.rs:626-670`).

The **outbound** half was. As a host process this server reaches
`127.0.0.1:9090`, `:9600` and `:9555` directly — app-lb's admin listener,
app-obs and ci, each *behind* a gate it never passes through. Being a host
process is what grants that. A VM cannot do it, so every call goes in the front
door as a scoped principal app-lb verifies.

Nothing is exposed to make this work. app-lb's :443 is already public, guests
already have egress (`mvm-ctrl/src/driver/tap_networking.rs:470-500`), and
`heyo-cloud.json` already reaches a host service by public hostname. The admin
listener stays on 127.0.0.1:9090, untouched.

## The credential posture, which is the point

**This deployment holds no credentials.** No `APPLB_TOKEN`, no `HEYO_API_KEY`,
no service tokens for app-obs or ci — `env_vars` is three URLs and four
switches, and there is no `env_from` at all. Every call it makes runs as the
caller who asked for it.

`withForwardedAuth` (`src/config.ts`) hands each app-lb, app-obs and ci call the
caller's own `applb_…` token, and app-lb scope-checks it *twice* on the app-lb
path:

1. the gate on the admin deployment (`auth.rs:315-330`, `token.admits(...)`), and
2. the admin listener itself, which accepts `Authorization: Bearer applb_…`
   against the same `TokenStore` and applies `satisfies_in`
   (`app-lb/src/admin.rs:616-646`).

One credential, two enforcement points, no conflict — the proxy forwards
`Authorization` unchanged, stripping only `IDENTITY_HEADERS`
(`app-lb/src/proxy.rs:700-702`). For app-obs and ci there is one enforcement
point, their own gate, and it is the same token being checked.

The rule that makes this safe to ship without breaking the loopback deployment
is that app-obs and ci yield to a caller's token only when what is configured
for them is *nothing*, or *another app-lb token* — either of which says app-lb
is the authenticator. A service's own token (`APP_OBS_API_TOKEN` against a
loopback listener) is left alone, because an `applb_…` bearer means nothing to
app-obs's own auth and forwarding one would 401 every tool on a deployment that
was working.

This is also what makes the VM's `0.0.0.0` bind acceptable. See below.

## No artifact-store credential

This server used to hold the store's key (`ART_API_KEY`) and decide, per
request, whom it acted for. It no longer does. app-lb fronts the single global
artifact store and serves each namespace's corner of it at
`/namespaces/{ns}/artifacts/…` on its admin API, holding the store key itself.
The `art_*` tools call that route with the **caller's own app-lb credential**,
so app-lb is the one place that decides access: reads need the view tier in the
namespace, writes the admin tier over the whole namespace, and tags must start
with `<ns>/`. There is no `/art` gateway on this server any more, and no
`artifacts` secret to deliver with `env_from` — remove one left over from an
older manifest.

A deployment that runs a published artifact names only `artifact: {ref:
"<ns>/name:tag"}`; app-lb pulls it from its own store and authenticates the
pull itself.

## Preconditions (not in this manifest — apply separately)

1. **Add `app-token` to the admin deployment's gate.** Confirm the id first
   (`applb_list_deployments`; it fronts `127.0.0.1:9090` on `admin.us2`), then
   add `"provider": ["google", "app-token"]` to its `auth`. Do **not** add
   `public_paths` there — `app-lb/src/main.rs:496-540` explains why a
   prefix-matched public path on that deployment is unauthenticated RCE.

2. **Add `app-token` to `obs.json`'s gate**, the same way. `ci.json` already
   has it.

3. **Unset `APP_OBS_API_TOKEN` on the app-obs process.** There is one
   `Authorization` header and, through a gate, two things that want it. Resolve
   it the way ci already does: let the gate be the authenticator. app-obs's
   listener stays on `127.0.0.1:9600`, so this is not an exposure.

4. **Nothing else.** There is no `mcp` secret and no fourth step: this spec
   carries no credentials at all. See below.

## Minting caller tokens

A caller's reach is their token's scope. **This deployment's own gate does not
check it**: `/mcp` is a `public` path (next section), so the token passes through
untouched and is judged by the gates of the services it is used against, each
of which checks `admits()` against the deployment *it* belongs to. With no
credentials of its own, this server can clear no gate the caller cannot.

- **app-lb tools** go through `app-lb-admin`, whose upstream is the admin
  listener. That gate admits any verified app-token and leaves the scope check
  to the listener (`fronts_admin_api`, `app-lb/src/auth.rs`), so a namespace
  token works and sees and creates only within its namespace. The spec must say
  `"namespace": "<ns>"`: registering does not fill it in, and a spec without one
  means `default`, which such a token cannot reach.
- **app-obs and ci tools** go through gates that still apply the namespace wall.
  Both live in `default`, so a token confined to any other namespace gets a 403
  from them and working app-lb tools everywhere else — the intended shape.
- A token that lists deployments instead of confining by namespace —
  `deployments: ["app-lb-admin", "app-obs", "ci", "fastcar"]` — clears those
  gates but cannot use a fleet-wide route: it can operate `fastcar`, and it
  cannot create a deployment.

This section used to recommend confining by namespace as "the simpler answer"
without noticing that every gate on the path lives in `default`, which made it
true only for `default` itself.

The `admin` axis is unchanged and still coarser than it sounds: `view` reaches
only `/metrics`, `/disks`, `/feeds`, `/security`, `/ingress`, `/storage`. There
is no read-only tier for deployment routes — `GET /deployments/:id` is CRUD-tier
because a spec's env vars can hold secrets — so a token that can *read* a
deployment can also delete it. `env_from` above is why this spec has nothing
worth reading.

## Why `/mcp` is public at this deployment's gate

The gate is `app-token` with two public paths:

```json
"auth": {
  "provider": "app-token",
  "public_paths": [
    { "path": "/healthz", "scope": "public" },
    { "path": "/mcp", "scope": "public" }
  ]
}
```

Until 2026-09-11 only `/healthz` was public, and every token confined to a
namespace other than `default` was refused with a 403. The gate checks
`admits("heyo-mcp", "default")` before the request reaches anything, and this
deployment's upstream is a VM rather than the admin listener, so the
`fronts_admin_api` exemption never applies. The hosted server was unusable by
exactly the tenant-scoped callers it exists for.

Opening `/mcp` is safe for the reason the rest of this document is about: **the
server holds nothing.** An unauthenticated request reaches a server with no
credential to act with, and every upstream call carries the caller's own bearer.
app-lb forwards `Authorization` untouched on a public path — it replaces the
header only when a gate minted a session, which a public path never does
(`app-lb/src/proxy.rs`) — so the services behind this one judge that bearer as
if it had been sent to them directly.

Three things follow:

- **`HEYO_MCP_REQUIRE_IDENTITY=0` is required.** No identity header arrives on a
  public path.
- **`art_publish` takes no `path` over HTTP.** Over stdio a path names the
  caller's own file; over HTTP it would name this server's disk for whoever
  asked. It is left out of the schema in HTTP mode and refused if it arrives.
- **Public paths are prefixes**, so this opens `/mcp…` as well. The server
  answers nothing there but `/mcp` itself.

An anonymous caller gets the tool list, the deployment schema and examples, and
`heyo_status`'s view of which services answer — documentation, not capability.

## This deployment has no sandbox tools, on purpose

An app-token gate admits `applb_…` and nothing else, and cloud has never heard
of that credential. So there is no cloud key here and no way for a caller to
supply one — which makes the fourteen `sandbox_*` tools plus `heyo_capacity`
unreachable by construction, not by misconfiguration.

`buildTools` (`src/server.ts`) therefore omits them when no cloud credential is
present, and `withForwardedAuth` refuses to substitute an app-lb token for one:
borrowing it would have produced a tool list that is complete, advertised, and
401s on every call. `heyo_status` still probes cloud and reports it as not
configured, so the absence stays an answerable question.

The gate is on the *credential*, not on a deployment-wide switch, so the same
build still serves the multi-tenant shape: an instance carrying no key of its
own gives the sandbox tools to a caller who presents a `heyo_api_*` key, per
request. That is a different deployment — no app-lb gate, since the gate would
reject a cloud key at the door — and it is the natural home for customer
sandbox access if it is ever wanted.

What is left here is the fleet: app-lb, app-obs, ci, and the feed.

## The 0.0.0.0 bind, and the rule that replaces the loopback one

app-lb reaches the guest over the tap, so the server must bind `0.0.0.0`. That
matters more than it looks: heyvmd installs a blanket
`-s 172.16.0.0/12 -d 172.16.0.0/12 -j ACCEPT` in the host's FORWARD chain
(`mvm-ctrl/src/driver/tap_networking.rs:509-534`), so **every other VM on the
host, customer sandboxes included, can route to this guest**. A naive port of
this deployment would relocate the exact hole the loopback bind existed to
close.

Two things close it, in this order:

1. **Nothing to steal.** The VM holds no credentials, so a peer reaching :9650
   directly gets a server that acts as whoever called — with no credential of
   its own to act with, for any of the four services. An unauthenticated request
   reaches an unauthenticated server.
2. **`init.sh` firewalls INPUT** to the host end of the /30 (tcp/9650 and
   tcp/22). Best-effort and logged if unavailable, because a boot that cannot
   firewall itself is not worth wedging — it is the second layer, not the first.

`HEYO_MCP_REQUIRE_IDENTITY=0` is still required, and still only by the
app-token gate, which forwards no identity by design ("a token is not a
person"). Under this shape the old justification — "and the listener is
loopback" — no longer holds, and the two items above are what stands in for it.

## Building

`heyvm mvm build` runs docker build → docker create → docker export → mke2fs,
so only the filesystem survives; the kernel boots `init=/init.sh` and app-lb
starts node afterwards via `start_command`, the only channel carrying the env
vars above.

    # locally, from mcp/
    heyvm mvm build --local-only -f deploy/image/Dockerfile -c . -n heyo-mcp

    # on the fleet
    applb_build_deployment heyo-mcp     # POST /deployments/heyo-mcp/build

The `build` block pairs `"dockerfile": "mcp/deploy/image/Dockerfile"` with
`"context": "mcp"`, keeping the context to this subtree. There is no `update`
block: a VM deployment ships a new image, it does not `git pull` in place.

## Rollback

The host-process shape is still supported and unchanged: `deploy/heyo-mcp.json`
plus `deploy/supervisor/heyo-mcp.conf`, reaching all three services on loopback
with their own tokens. Nothing in this change altered how that behaves — the
`applb_`-prefix test on the configured credential is what keeps the two shapes
apart, and `config.test.ts` guards it directly.
