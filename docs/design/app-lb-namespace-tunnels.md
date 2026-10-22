# App-lb namespace tunnels

Status: proposal, 2026-10-21. Follows PR #113 (the Heyo Cloud `tunnel` plugin),
which is held until this is decided.

## Goal

An app-lb the internet cannot reach (a desktop, a home server, a machine behind
NAT) gets a public hostname by **authenticating to a namespace on a public
app-lb** and registering a deployment there that bridges public traffic to it.

The public app-lb owns everything visitors see: the hostname, its certificate,
its routing, its sign-in gate and its access log. The local app-lb serves the
requests the way it serves any other.

Compare #113, where the bridge is a row in Heyo Cloud and the cloud edge does
the public half. That design depends on the cloud's wildcard TLS. It cannot
work where an app-lb, not the cloud, is the front door, which is us2-demo
today. It also authorizes with the operator's Heyo account through heyvmd,
rather than with anything the public app-lb's namespaces control.

## What a user does

On the public app-lb, a namespace admin (or the operator) mints a token for the
local machine:

```sh
heyctl --context us2 token create --namespace sam --tunnel desktop
# applb_… (shown once)
```

On the local app-lb, they store it and point the plugin at the public one:

```sh
heyctl create secret tunnel-us2 --from-stdin token <<< 'applb_…'
heyctl plugins set tunnel --enable -f - <<'EOF'
{"provider": "app-lb",
 "remote": "https://admin.us2.heyo.work",
 "namespace": "sam",
 "token": {"secret": "tunnel-us2", "key": "token"},
 "tunnels": [{"name": "desktop", "hostnames": ["desktop--sam.us2.heyo.work"]}]}
EOF
```

`heyctl --context us2 get deployments -n sam` then shows a deployment
`desktop` of kind `tunnel`. `https://desktop--sam.us2.heyo.work` reaches the
local app-lb, and the local app-lb routes it to whichever of its own
deployments has that host.

## Shape

```text
visitor ──TLS──▶ public app-lb (worker) ──loopback──▶ public app-lb (manager)
                  routes, ACME, auth gate,             tunnel dialer: iroh,
                  guard, access log                    ALPN heyo/applb-ingress/1
                                                              │ QUIC bi-stream
                                                              ▼  (NAT-traversed)
                                       local app-lb (manager): tunnel plugin
                                       accepts only the public app-lb's ids,
                                       serves through its own LbProxy
```

### Local side: the `tunnel` plugin, provider `app-lb`

Most of #113 is unchanged and is reused as-is:

| From #113 | Reused for |
|---|---|
| persisted iroh key (`app-lb-tunnel.key`, 0600) and endpoint, ALPN `heyo/applb-ingress/1` | same endpoint; the node id is stable across restarts |
| stream → duplex → pingora bridge in the manager (`serve_stream`, `LbProxy::for_tunnel_ingress`) | same |
| allow-list of dialer endpoint ids, refused before a byte is served | now filled from the public app-lb's registration answer |
| `X-Heyo-Client-IP` trusted on tunnel ingress only, stripped on every ingress | same header, set by the public app-lb |
| register-then-accept ordering, refresh every minute | same loop, a different registration target |

The new parts:

- The config grows a `provider`: `cloud` (today's heyvmd path) or `app-lb`.
  Both providers share the endpoint, and one plugin instance may use both.
- The `app-lb` provider registers with `remote` directly. heyvmd is not
  involved, and the local app-lb holds the token, as an app-lb secret.
- **Host check (also needed in #113).** A tunnel request whose `Host` is not
  one of the hostnames this app-lb registered is answered 421 before routing.
  See [Security](#security).

### Public side: a `tunnel` deployment kind

This adds a fourth backend kind, beside `vm`, `upstreams` and `site`, and
mutually exclusive with them:

```json
{"id": "desktop", "namespace": "sam",
 "routes": [{"host": "desktop--sam.us2.heyo.work"}],
 "tunnel": {"node_id": "24200cf8…", "relay_url": "https://…", "lease_secs": 300},
 "auth": {"provider_ref": "heyo", "require": {"emails": ["sam@…"]}}}
```

- **No address is given, only a node id.** A namespace caller therefore cannot
  aim this deployment at the public host's loopback or private network, which a
  static `upstreams` list can. That is the reason for a new kind rather than
  reusing `upstreams`.
- **Everything else is the ordinary deployment machinery:** routes, ACME,
  `auth` gates (private tunnels are a sign-in gate, which replaces the cloud's
  `is_public`), maintenance, guard rules, metrics, the access log and the
  feed.
- **Health and leases.** A tunnel is healthy while its lease is live and its
  QUIC connection answers a health probe (see below). An expired or unhealthy
  tunnel answers 503 "tunnel offline", but stays registered, as a static
  deployment with no healthy upstream does.

#### Data plane: a loopback bridge in the manager

The forwarding worker's upstreams are TCP peers, so the manager gives each live
tunnel a loopback listener (`127.0.0.1:0`). It accepts on it, opens a
bi-stream on its QUIC connection to the tunnel's node, and copies bytes both
ways. Request control returns that listener as the peer.

This reuses pingora's upstream handling (keep-alive, retries, `fail_to_connect`)
and the autoscaler's health probes as they are.

- One QUIC connection per tunnel, redialed on loss. iroh does the NAT
  traversal, through a relay when a direct path fails.
- For tunnel peers, request control sets `X-Heyo-Client-IP` to the client
  address it already uses for `X-Forwarded-For`. Any client-sent copy has
  already been stripped.
- **Health probe:** the local app-lb answers `GET /.well-known/heyo-tunnel/health`
  itself, on tunnel ingress only, before routing. A probe that reached the
  local router would 404 on an unknown host and mark the tunnel unhealthy.
- **Restarts:** the bridge lives in the manager, so a public-side manager
  restart drops tunnel streams in flight, the same gap #113 has (see
  [Lifecycle](#lifecycle-and-failure)). Phase 3 moves the dialer into the
  worker, which already survives manager restarts.

#### Registration API

```text
PUT    /namespaces/:ns/tunnels/:name    register or refresh
GET    /namespaces/:ns/tunnels          list (view tier)
DELETE /namespaces/:ns/tunnels/:name    release
```

`PUT` body:

```json
{"node_id": "…", "relay_url": "…", "hostnames": ["desktop--sam.us2.heyo.work"],
 "proof": {"ts": 1792609000, "sig": "<ed25519 over ns|name|node_id|ts|remote ids>"}}
```

It answers:

```json
{"urls": ["https://desktop--sam.us2.heyo.work"],
 "dialer_ids": ["<host A endpoint id>", "<host B endpoint id>"],
 "lease_secs": 300}
```

- **Upsert.** `PUT` creates the `tunnel` deployment or updates its node,
  relay and lease, and is idempotent. The local plugin repeats it every
  minute. That brings in a changed relay or a new fleet member's dialer id,
  and keeps the lease alive.
- **Why its own route, rather than `POST /deployments`:** a tunnel token can
  then be narrower than a namespace admin token. It may register tunnels only:
  never VMs, static upstreams, builds or secrets.
- **Authentication** uses the gate the admin API already has:
  - a namespace app-token with the new `tunnel` scope, limited to the names
    it was minted for;
  - or a federated Heyo bearer with `namespace:<ns>:admin`;
  - or the operator.
- **`proof`** is a signature by the node's own iroh key. It shows that the
  caller holds the node it names. Without it, a namespace could point its
  hostname at someone else's app-lb (see [Security](#security)).
- **`dialer_ids` lists every fleet host's endpoint id**, so any host that
  takes the request can dial. Each host persists its own key in the fleet
  store. No placement is needed, because there are no VMs.

#### Hostnames: a prerequisite that is not specific to tunnels

Apart from discovery deployments, app-lb does not stop one namespace's
deployment from routing a host another namespace already routes. The admin API
checks deployment *ids* across namespaces, not *hosts*. Tunnels make this
sharper: an internet-facing hostname would become self-service through a
narrow token.

Before the registration API ships:

1. **A namespace hostname policy** on the declared namespace object, set by the
   operator: the hosts and suffixes the namespace may route. The default is
   `*--<ns>.<fleet wildcard>`, for example `*--sam.us2.heyo.work`, which needs
   no DNS work under an existing wildcard. Custom domains are added by the
   operator; DNS-verified self-service can come later.
2. **Fleet-wide host uniqueness:** refuse a route host that another namespace
   already routes, with the same opaque 403 that id conflicts get.

Both apply to every deployment kind, not only tunnels.

TLS needs no change on the public side: an exact-host route gets an HTTP-01
certificate as today, and a covering wildcard (`APP_LB_ACME_WILDCARD`) avoids a
certificate order per tunnel.

## Security

| Threat | Control |
|---|---|
| Someone other than the public app-lb opens streams into the local one | local allow-list of `dialer_ids`, enforced before a byte is read (from #113) |
| A namespace registers a victim's node id under its own hostname, so its traffic lands in the victim's app-lb | `proof` (node-key signature) at registration, and the local **Host check**: the local side serves only hostnames it registered. This hole exists in #113 too: the cloud edge's id is in every app-lb's allow-list, so the Host check should land there first. |
| A namespace takes another's hostname | hostname policy and fleet-wide host uniqueness (prerequisite) |
| A namespace aims a deployment at the public host's internals (SSRF) | the `tunnel` kind has no address field, only a node id |
| A visitor forges their client IP | the public side strips `X-Heyo-Client-IP` and sets it from the socket peer; the local side trusts it on tunnel ingress only |
| Leaked token | tunnel scope (registration only), named tunnels only, revocable. A revoke fails the next refresh and the lease lapses within `lease_secs`; `DELETE` is immediate |
| Abuse of a public hostname | per-namespace tunnel count and bandwidth limits, the guard, and the deployment's `auth` gate. The owning account is stamped on the deployment, as for VMs |

## Lifecycle and failure

| Event | Behaviour |
|---|---|
| Local app-lb restarts | same key, same node id, a new epoch. It registers at once; the epoch tells the public side to drop its connections to the old process and dial the new one. Streams in flight at the moment of the restart are dropped (the ingress is in the local manager). Measured: one request in flight failed; everything else succeeded. |
| Local plugin reconfigured | in place: the endpoint and its connections stay, only registrations change. Measured: 68/68, no gap. |
| Local plugin disabled | stops taking connections, lets requests in progress finish (≤10s), winds idle keep-alive streams down, then closes. |
| Public manager restarts | nothing is cut: the forwarding worker dials the node itself, and each worker generation uses the other of two keys. Measured: an 8s request across the restart completed; 112/112. |
| A node vanishes without a word | the dialers' QUIC idle timeout (10s, keep-alives every 5s) notices it. |
| A fleet host is added | its id appears in `dialer_ids` on the next refresh; until then the local side refuses it, and its health probe keeps it from serving the tunnel |
| Token revoked | refresh gets 401; the plugin card says so; the lease lapses and the tunnel answers 503 |
| Network partition | probe fails, so the tunnel answers 503; the lease is independent of the dial |

## Plan

0. **Prerequisites.**
   - Host check on tunnel ingress; land it in #113.
   - Namespace hostname policy and fleet-wide host uniqueness.
1. **Public side.**
   - The `tunnel` deployment kind, with validation and lease.
   - Registration routes and the `tunnel` token scope.
   - The manager-side dialer and loopback bridge.
   - Request control setting `X-Heyo-Client-IP`.
   - Tests: lease expiry, refused proof, scope confinement, host conflict.
2. **Local side.**
   - The `app-lb` provider in the `tunnel` plugin: config, proof signing,
     registration loop, `dialer_ids` allow-list, health path.
   - The Plugins page and `heyctl` show both providers.
3. **Hardening** (done, except where noted).
   - Drain on plugin stop; reconfigure in place; a node epoch so a restarted node is dialed at once.
   - Dialer in the worker, with two alternating keys, so a public manager restart drops nothing.
   - Per-namespace tunnel count limit. *Not done:* bandwidth limits.
   - *Not done:* the local ingress still lives in the local manager, so a local manager restart drops the streams in flight at that instant.
4. **Acceptance (live).** With a disposable app behind a local app-lb,
   registered with us2's app-lb:
   - continuous requests through the public hostname;
   - restart the local app-lb, then the public manager, then the public worker;
   - revoke the token;
   - register an unhealthy tunnel;
   - confirm visitor IP handling and that forged headers are dropped;
   - confirm that a second namespace can neither take the hostname nor point
     it at this node.

   Record evidence in the acceptance checklist.

## What happens to #113

Merge it once the Host check is added, as the `cloud` provider. Everything it
built is the local half of this design. Alternatively, hold it and land both
providers together; the code is the same either way.

## Open questions

- **Hostname shape.** `name--ns.<wildcard>` fits under existing wildcard DNS
  and TLS. `name.ns.<wildcard>` reads better, but needs a wildcard per
  namespace.
- **Who dials in a fleet.** Every host dials (proposed), or a tunnel is
  placed on one host and others fleet-hop to it. Every host dialing costs one
  QUIC connection per tunnel per host, and avoids a hop.
- **Federated callers.** Should a Heyo bearer registering a tunnel also need
  a tunnel-specific scope from the auth service, or is `namespace:<ns>:admin`
  enough?
- **Bandwidth.** Through a relay, a busy tunnel costs relay bandwidth.
  Should the public side run its own relay (`HEYO_IROH_RELAY_URL`) rather
  than n0's?
