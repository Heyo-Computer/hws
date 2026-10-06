# App-tokens

App-tokens are app-lb's own bearer credentials (`applb_…`), scoped to an admin tier and to particular deployments or one namespace, and these endpoints mint, list, re-scope and revoke them.

Back to the [API reference](overview.md). How tokens are used against deployment gates is in [app-lb-auth](../app-lb-auth.md).

All routes are CRUD tier. app-lb stores only `sha256(secret)`. **The secret appears once, in the mint response**, and no endpoint reads it back.

## Scope

A token carries two independent limits:

- **`admin`** is its tier on this API: `none`, `view` or `admin`. A `none` token can pass a deployment's [app-token gate](../app-lb-auth.md#app-token-gate) but can only call [`/whoami`](identity.md#who-am-i) here.
- **Reach**: `deployments: ["*"]` with no namespace covers the whole fleet. A list of ids covers only those. `namespace: "<ns>"` confines the token to one namespace, where an empty `deployments` list means every deployment in it, now and in future.

A token scoped to specific deployments is refused the fleet-wide routes, including minting, so it cannot widen itself.

## Mint a token

`POST /tokens`

**Crate:** `Client::mint_token(&NewToken) -> MintedToken` · `Raw::mint_token(&NewToken)`

| Field | Default | `NewToken` | Meaning |
| --- | --- | --- | --- |
| `name` | required | `NewToken::new(name)` | What it is for. The crate refuses a blank name before sending. |
| `admin` | `none` | `.admin(AdminScope::Admin)` | `none`, `view` or `admin`. |
| `deployments` | `[]` | `.for_deployments(ids)`, `.fleet_wide()` | Ids, or `["*"]`. |
| `namespace` | unset | `.in_namespace(ns)` | Confine to one namespace. |
| `expires_in_secs` | never | `.expires_in(duration)` | Lifetime. |
| `fleet` | `false` | `.on_all_servers()` | Control plane only: a token mirrored to every gateway. `409` on an app-lb with no gateways. |

The crate's defaults are the safe ones: a `NewToken` with nothing set can do nothing.

```rust
use hws::{AdminScope, NewToken};
use std::time::Duration;

let minted = lb.mint_token(&NewToken::new("ci")
    .admin(AdminScope::Admin)
    .in_namespace("team-a")
    .expires_in(Duration::from_secs(86400))).await?;
store_somewhere(&minted.token);   // the only time you will see it
```

Answers `201`:

```json
{"id": "7f3a9c2b1e4d", "name": "ci", "admin": "admin", "namespace": "team-a", "deployments": [],
 "created_at": 1722400000, "expires_at": 1722486400, "minted_by": "token:b2c3d4e5f6a1",
 "token": "applb_7f3a9c2b1e4d_…"}
```

`MintedToken` is the summary below plus `token`.

## The token summary

`TokenSummary`, returned by list, get and patch. The mint response without `token`.

| Field | Meaning |
| --- | --- |
| `id`, `name` | |
| `admin` | `none`, `view` or `admin`. |
| `namespace`, `deployments` | Reach, as above. |
| `created_at`, `expires_at` | Unix seconds. `expires_at` absent means never. |
| `minted_by` | Who minted it, for tokens minted by a confined caller. |
| `last_used_at` | Flushed opportunistically, not per request, so a busy token can still read as unused. |
| `fleet`, `mirrored_from` | A fleet token, and the control plane it is mirrored from. A mirrored token cannot be changed here: `PATCH` and `DELETE` answer `409` naming the authority that owns it. |

## List, get, re-scope and revoke

| Method and path | Crate | Does |
| --- | --- | --- |
| `GET /tokens` | `Client::tokens() -> Vec<TokenSummary>` · `Raw::tokens()` | Every token the caller can see. Expired tokens are swept first. |
| `GET /tokens/:id` | `Client::token(id)` · `Raw::token(id)` | One summary. |
| `PATCH /tokens/:id` | `Client::patch_token(id, &patch)` · `Raw::patch_token` | Re-scope, rename or change expiry **without changing the secret**, so narrowing a credential does not mean redistributing it. |
| `DELETE /tokens/:id` | `Client::revoke_token(id) -> ()` | Revoke. Answers `204` and takes effect on the next request: verification is a store lookup, not a signature check. |

Every `PATCH` field is optional: `name`, `admin`, `namespace` (`null` lifts the wall), `deployments`, and `expires_at` (absolute Unix seconds, `null` for never).

## Confined callers

A confined caller may use these routes only if it administers a whole namespace: a namespace token with `admin` scope and no `deployments` list, or a federated `namespace:<ns>:admin` grant. app-lb then enforces:

- **Mint:** `namespace` is required and must be one you administer (`403` otherwise). `expires_in_secs` defaults to, and may not exceed, `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` (90 days by default; `400` past it).
- **List, get, revoke:** only tokens confined to your namespaces. Any other id is `404 no token "<id>"`, the same as one that does not exist.
- **Patch:** cannot move a token to another namespace, lift its wall or clear its expiry (`403`), or push its expiry past the cap (`400`).

A deployment-scoped token or a `view` caller cannot mint.

## Errors

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Invalid body, or an expiry past the tenant cap. |
| `403` | `Forbidden` | Out of scope, per the rules above. |
| `404` | `NotFound` | No such token, or one you cannot see. |
| `409` | `Conflict` | A mirrored fleet token, or `fleet: true` on an app-lb with no gateways. |
| `500` | `Api` | The token file could not be written. |
