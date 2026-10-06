# Auth providers

An auth provider is the identity half of a deployment's sign-in gate (who may enter and how they are verified), declared once per namespace and inherited by deployments with `auth.provider_ref`. These endpoints declare, read and remove providers.

Back to the [API reference](overview.md). Field meanings, presets and worked examples are in [app-lb-auth: Auth providers](../app-lb-auth.md#auth-providers).

A provider is identified by `(namespace, name)`; names are unique within a namespace, not across the fleet. app-lb resolves the provider on every gated request, so editing one reaches every deployment that names it.

## The provider

`AuthProviderView`, from [`auth-provider-google.json`](../../app-lb/testdata/wire/auth-provider-google.json):

```json
{"name": "corp-google", "namespace": "team-a", "description": "Workspace sign-in for team-a's apps",
 "created_at": 1722400000, "provider": "google",
 "client_id": "1234.apps.googleusercontent.com",
 "client_secret": {"secret": "google-oauth", "key": "client_secret"},
 "allowed_domains": ["example.com"], "cookie_domain": ".example.com"}
```

| Field | Meaning |
| --- | --- |
| `name`, `namespace`, `description`, `created_at` | Identity. `description` is up to 400 characters. |
| `provider` | One provider as a string (`"google"`), or several as an array (`["google", "app-token"]`). The crate keeps it as JSON; `AuthProviderView::providers()` returns a list either way, and an empty value means `google`. |
| `client_id`, `client_secret` | Google OAuth. The secret is a reference, never a value. |
| `allowed_domains`, `allowed_emails` | Google allow-list. `"*"` in `allowed_domains` admits any Google account. |
| `jwt` | JWT verification: exactly one of `secret`, `public_key`, `jwks_url`, plus `algorithms`, `issuer`, `audience`, `require`, the claim names, `leeway_secs`, `cookie`, `login_url`, `login_redirect_param`, `authorize_url`, `token_url`. |
| `cookie_domain` | Share one sign-in across every deployment under a parent domain. |

`AuthProviderView::admits()` renders who gets in as one line.

## List providers

`GET /auth-providers[?namespace=]`

**Tier:** View. Narrows itself. **Crate:** `Client::auth_providers(namespace) -> Vec<AuthProviderView>` · `Raw::auth_providers(namespace)`

Without `namespace`, a confined caller gets its own namespaces' providers rather than a refusal, so this is the call for "what identity is declared anywhere I can reach".

## Declare a provider

`POST /auth-providers`

**Tier:** CRUD, admin of the provider's namespace. **Crate:** `Client::create_auth_provider(&spec) -> AuthProviderView`

An upsert: `201` when new, `200` when it replaced one, keeping the original `created_at`. Applying the same object twice is not an error.

The body is the provider's fields, plus request-only conveniences that app-lb expands and never stores: `preset` (`heyo-jwks` or `heyo`), `secret` (for `heyo`), `jwks_url` (for `heyo-jwks` without `APP_LB_AUTH_URL`), and `require`, `cookie`, `login_url`, `login_redirect_param`, which are laid over the preset's expansion.

```json
{"name": "heyo-users", "namespace": "team-a", "preset": "heyo-jwks",
 "require": {"accountId": "acct_7f3c"}}
```

Because of those fields there is no stored type that could round-trip the body, which is why the crate takes a `Value`.

## Get a provider

`GET /auth-providers/:namespace/:name`

**Tier:** CRUD. **Crate:** `Client::auth_provider(namespace, name) -> AuthProviderView`, `Client::auth_provider_exists(namespace, name) -> bool` · `Raw::auth_provider(namespace, name)`

Both halves of the identity are required. Use `hws::DEFAULT_NAMESPACE` (`"default"`) when the provider has none.

## Delete a provider

`DELETE /auth-providers/:namespace/:name`

**Tier:** CRUD. **Crate:** `Client::delete_auth_provider(namespace, name) -> ()`

Answers `204`. Refused with `409` while any deployment's gate inherits the provider: resolution fails closed, so removing it would take those gates offline.

## Errors

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Invalid provider: bad preset, missing or conflicting identity fields, more than one JWT key source. |
| `403` | `Forbidden` | Not an admin of the namespace. |
| `404` | `NotFound` | No such provider in that namespace. |
| `409` | `Conflict` | Still inherited by a deployment, on delete. |

Through the managed door, the item routes are reachable only for the door's own namespace.
