# Identity and health

These endpoints answer whether app-lb is reachable, which gates it has switched on, and what it makes of the credential you presented.

Back to the [API reference](overview.md).

## Health

`GET /healthz`

**Tier:** open. Never gated. **Crate:** `Client::healthz() -> Result<()>`

Answers `200` with the body `ok` and an `x-heyo-revision` header carrying the build's git SHA. Because it needs no credential, a success proves reachability and nothing else.

```sh
curl -si $LB/healthz
```

## Who am I

`GET /whoami`

**Tier:** any credential the gate recognises, at any admin scope, including `none`. **Crate:** `Client::whoami() -> WhoAmI`

Describes the credential on the request. It never echoes a secret. It is the one admin route a token minted with `admin: none` can call, so call it first when other requests are refused.

```sh
curl -s -H "Authorization: Bearer $TOKEN" $LB/whoami
```

```json
{
  "caller": "app-token",
  "may": {"read_view_routes": true, "use_admin_routes": true},
  "fleet": false,
  "confined": true,
  "admin_scope": "admin",
  "token": {"id": "b2c3d4e5f6a1", "name": "team-a operator"},
  "namespace": "team-a",
  "deployments": [],
  "expires_at": 1730176000,
  "expires_in_secs": 7775000,
  "note": "A deployment's own gate checks whether this credential admits that deployment; ..."
}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `caller` | string | `ungated`, `operator`, `app-token` or `federated`. |
| `admin_scope` | string | `none`, `view` or `admin`, or `unchecked` on an ungated listener. For a federated caller, the strongest tier it holds in any namespace. |
| `fleet` | bool | May use fleet-wide routes. |
| `confined` | bool | Behind a namespace wall. |
| `may.read_view_routes` | bool | Passes the View tier. |
| `may.use_admin_routes` | bool | Passes the CRUD tier. |
| `token` | `{id, name}` | App-tokens only. |
| `namespace` | string | An app-token's namespace, when confined. |
| `deployments` | string[] | An app-token's deployment list as minted. `["*"]` is every deployment; empty on a namespace token is everything in the namespace. |
| `expires_at`, `expires_in_secs` | integer | An app-token's expiry, when it has one. |
| `subject` | `{user_id, email, account_id}` | Federated callers only. |
| `namespaces` | `{"<ns>": "admin" \| "view"}` | Federated callers only. |
| `detail` | string | For `ungated` and `operator`, why this credential is unscoped. |
| `note` | string | A reminder that a deployment's own gate is checked separately. |

`WhoAmI::sole_namespace()` returns the namespace a confined caller can leave implicit: the token's namespace, or the only key of a federated caller's `namespaces`.

Errors: `401` when no recognised credential was sent and the listener is gated.

## Gates

**Crate:** `Client::gates(server, insecure) -> Gates`, `Client::probe(path) -> u16`, `Client::probe_detail(path) -> (u16, Option<String>)`

app-lb has two independent gates, and which are on is not visible from outside except by asking. `Client::gates` is an associated function that builds its own anonymous client and makes two requests:

| Request | `Gates` field | True when |
| --- | --- | --- |
| `GET /metrics` | `view` | The anonymous request answered `401`. |
| `GET /deployments` | `crud` | The anonymous request answered `401`. |

`Gates::any()` is false when nothing is gated, which means there is no credential to log in with.

`probe` and `probe_detail` send a `GET` with this client's credential and return the status instead of raising on `4xx`. `probe_detail` also returns the server's explanation, joining the `error` and `detail` fields of a gate refusal (`{"error": "authentication required", "scope": "admin", "detail": "…"}`). Use it to tell a caller why a credential was refused before a write fails.
