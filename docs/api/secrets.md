# Secrets

Secrets hold credentials that deployments reference by name (a git token, a store key, an OAuth client secret), and these endpoints store, list, change and delete them.

Back to the [API reference](overview.md). How deployments reference them is under [secret references](../app-lb.md#secret-references).

Secrets are write-only: values go in and no endpoint returns one. All routes are CRUD tier and walled by namespace. A deployment in `team-a` resolves `team-a`'s secrets and cannot name another namespace's, so a secret stored in the wrong namespace is invisible to it, not misfiled. The item routes take `?namespace=`, which defaults to `default`; a confined caller must name one of its own namespaces. A view-only federated namespace may read summaries but gets `403` on writes.

## The secret summary

`SecretSummary`, from [`secret-summary.json`](../../app-lb/testdata/wire/secret-summary.json):

```json
{"id": "github", "namespace": "default", "description": "PAT for private repos",
 "keys": ["token", "username"], "updated_at": 1722400000, "encrypted_at_rest": true}
```

`keys` names the keys only. `encrypted_at_rest` reports whether app-lb's secret file is encrypted.

## Store a secret

`POST /secrets`

**Crate:** `Client::put_secret(&spec) -> SecretSummary` · `Raw::put_secret(&spec)`

```json
{"id": "github", "namespace": "team-a", "description": "PAT for private repos",
 "data": {"token": "ghp_…", "username": "ci-bot"}}
```

`namespace` and `description` are optional. Answers `201` when new and `200` when it replaced an existing secret; a replace swaps every key.

## List secrets

`GET /secrets[?namespace=]`

**Crate:** `Client::secrets()`, `Client::secrets_in(namespace) -> Vec<SecretSummary>` · `Raw::secrets()`, `Raw::secrets_in(namespace)`

Summaries of every secret the caller can reach, or of one namespace.

## Get a secret

`GET /secrets/:id[?namespace=]`

**Crate:** `Client::secret(id)`, `Client::secret_in(namespace, id) -> SecretSummary`, `Client::secret_exists_in(namespace, id) -> bool` · `Raw::secret_in(namespace, id)`

The summary of one secret. `secret_exists_in` turns a `404` into `false`.

## Change keys

`PATCH /secrets/:id[?namespace=]`

**Crate:** `Client::patch_secret(id, &patch)`, `Client::patch_secret_in(namespace, id, &patch) -> SecretSummary` · `Raw::patch_secret_in`

```json
{"data": {"token": "ghp_new…", "old_key": null}, "description": "rotated 2026-10-06"}
```

A key with a value is set, a key with `null` is removed, and keys not mentioned are left alone. `description` is optional.

## Delete a secret

`DELETE /secrets/:id[?namespace=][&force=true]`

**Crate:** `Client::delete_secret(id, force)`, `Client::delete_secret_in(namespace, id, force) -> ()`

Answers `204`. Refused with `409` while a deployment in the namespace references it, unless `force=true`. The crate always sends `force` explicitly.

## Errors

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Invalid id, namespace or body. |
| `403` | `Forbidden` | The namespace is out of reach, or the caller may only view it. |
| `404` | `NotFound` | No such secret in that namespace. |
| `409` | `Conflict` | Still referenced, on delete without `force`. |
| `500` | `Api` | The secret file could not be written. The message says what was not saved. |

app-lb also serves `PUT /secrets/:id` (a whole replace, where the path id and `?namespace=` win over the body's). The crate uses `POST` instead.
