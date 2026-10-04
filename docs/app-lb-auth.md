# app-lb authentication

app-lb authenticates two different audiences: operators and programs calling its admin API, and end users reaching a deployment through a per-deployment sign-in gate (Google, app-tokens, or JWTs from any issuer).

## Overview

| Plane | Protects | Configured by | Credentials |
| --- | --- | --- | --- |
| Admin API | the admin listener (default `127.0.0.1:9090`): dashboard, `/metrics`, deployment CRUD, secrets, tokens | environment variables at startup | HTTP Basic, app-tokens (`applb_…`), federated Heyo bearers |
| Deployment gate | one deployment's traffic on the proxy listener | the deployment's `auth` block, or a namespace auth provider | Google sign-in, app-tokens, JWTs |

The two are independent. A deployment gate never consults the admin API's Basic credentials, and the admin gate never reads a deployment's `auth` block. A gate runs in the proxy before a backend is chosen, so it works the same for managed VM pools, static upstreams and static sites, and the application behind it needs no auth code.

For the CLI side (`heyctl login`, contexts, tokens) see [heyctl](heyctl.md). For the rest of app-lb see [app-lb](app-lb.md).

## The admin API

### Environment variables

| Env var | Default | Meaning |
| --- | --- | --- |
| `APP_LB_DASHBOARD_USER` | `admin` | Basic-auth username |
| `APP_LB_DASHBOARD_PASSWORD` | unset | Basic-auth password. Unset means the dashboard is open |
| `APP_LB_DASHBOARD_AUTH` | on | `0`/`false`/`no`/`off` leaves the view tier (`/`, `/dashboard`, `/metrics`, `/security`, …) open while the password still gates CRUD and token minting |
| `APP_LB_ADMIN_AUTH` | off | `1`/`true`/`yes`/`on` extends the gate to deployment CRUD and to reads that expose a spec. Requires a password |
| `APP_LB_AUTH_URL` | unset | Base URL of the Heyo auth service. Enables federated bearers. Requires `APP_LB_ADMIN_AUTH=1` |
| `APP_LB_AUTH_CACHE_SECS` | `60` | How long a federated bearer's scopes are cached (never past the token's own expiry) |
| `APP_LB_AUTH_TIMEOUT_SECS` | `5` | Timeout for calls to the auth service |
| `APP_LB_HOME_URL` | unset | Absolute http(s) URL of the front end a namespace user is sent back to when a handed-off session expires |
| `APP_LB_TOKENS_PATH` | `app-lb-tokens.json` | App-token store (hashes only, mode `0600`) |
| `APP_LB_AUTH_KEY` | `app-lb-auth-key` | HMAC key that signs gate sessions. Generated (32 random bytes, `0600`) on first start |
| `APP_LB_SIEM` | on | `0` disables security monitoring, including the record of refused sign-ins |

Relative paths resolve against app-lb's working directory. Keep `APP_LB_AUTH_KEY` stable: deleting it signs out every gated session, and anyone who holds it can forge a session for any gated deployment.

### Startup checks

app-lb refuses to start with a configuration that looks protected but is not:

| Configuration | Result |
| --- | --- |
| `APP_LB_ADMIN_AUTH=1` without `APP_LB_DASHBOARD_PASSWORD` | Startup fails |
| `APP_LB_AUTH_URL` set without `APP_LB_ADMIN_AUTH=1` | Startup fails |
| Password set, `APP_LB_DASHBOARD_AUTH=0`, admin auth off | Warning: the password gates nothing |
| A gated deployment fronts the admin listener, has `public`-scoped paths other than `/healthz`, and admin auth is off | Error logged naming the exposed paths |
| No `APP_LB_ADMIN_AUTH` | Warning: the deployment, secret and job API is unauthenticated |

### Which routes each setting gates

| Settings | View tier (`/dashboard`, `/metrics`, `/security`) | CRUD, secrets, jobs | `/healthz` |
| --- | --- | --- | --- |
| no password | open | open | open |
| password | Basic | open | open |
| password + `APP_LB_ADMIN_AUTH=1` | Basic | Basic | open |
| password + `APP_LB_ADMIN_AUTH=1` + `APP_LB_DASHBOARD_AUTH=0` | open | Basic | open |

The admin listener is plaintext HTTP. If it leaves localhost, reach it over an SSH tunnel or front it with a TLS deployment. A production setup is:

```sh
APP_LB_DASHBOARD_PASSWORD="$(cat /etc/app-lb/admin-password)" \
APP_LB_ADMIN_AUTH=1 \
app-lb
```

### Credentials the admin API accepts

With `APP_LB_ADMIN_AUTH=1` the gate checks, in order:

| Presented as | Resolved by | Reach |
| --- | --- | --- |
| `Authorization: Basic …` | the startup user and password (compared in constant time) | the whole fleet |
| `Authorization: Bearer applb_…` | the local token store | whatever the token was minted with |
| `Authorization: Bearer <anything else>` | `GET {APP_LB_AUTH_URL}/api/auth/scopes` | the namespaces the auth service lists |
| `__Host-heyo-admin` cookie | same as a federated bearer | as above; set by the browser sign-in below |

A local token is never sent to the auth service. An explicit `Authorization` header always wins over the browser cookie.

`GET /whoami` answers what the presented credential is and what it may do. `heyctl whoami` uses it.

## App-tokens

An app-token is a credential app-lb mints itself: scoped, revocable and optionally expiring. The admin API accepts it, and so does any deployment gate that lists the `app-token` provider. Only `sha256(secret)` is stored, so the secret is shown once at mint and cannot be recovered.

```sh
curl -u admin:"$PW" -XPOST localhost:9090/tokens -H 'content-type: application/json' \
  -d '{"name":"agent-runner","admin":"admin","deployments":["sb-7f3a9c"],"expires_in_secs":86400}'
# or
heyctl token mint agent-runner --admin admin -d sb-7f3a9c --expires-in 24
```

| Mint field | Default | Meaning |
| --- | --- | --- |
| `name` | required | What the token is for |
| `admin` | `none` | Tier on the admin API: `none`, `view`, `admin` |
| `deployments` | `[]` | Deployment ids, or `["*"]` for all, present and future |
| `namespace` | unset | Confine the token to one namespace. With no `deployments` it reaches every deployment in that namespace |
| `expires_in_secs` | never | Lifetime |

| `admin` tier | Admin API reach |
| --- | --- |
| `none` | nothing: a credential for deployment gates only |
| `view` | `/metrics`, `/dashboard` and other view routes |
| `admin` | everything, within its deployment scope |

A token scoped to specific deployments is refused fleet-wide routes (create deployment, list all, secrets, minting), so it cannot mint itself a wider one. `/metrics` narrows its answer to what the token can see instead of refusing.

### Namespace admins mint their own tokens

A caller that administers a whole namespace may use the token routes for that namespace. That means a namespace token with `admin` tier and no `deployments` list, or a federated `namespace:<ns>:admin` grant. This is how a namespace user gets a token for the hosted MCP server: the dashboard's "Get started" card mints one.

- Mint (`POST /tokens`): `namespace` is required and must be one the caller administers. `expires_in_secs` is capped by `APP_LB_TENANT_TOKEN_MAX_TTL_SECS` (default 90 days); when it is omitted, the cap is used, so a tenant token always expires. The token records `minted_by` (`token:<id>` or `user:<userId>`).
- List and read: only tokens confined to namespaces the caller administers. Any other id answers `404 no token "<id>"`, the same as one that does not exist.
- Re-scope (`PATCH`): the token cannot be moved out of the caller's namespaces, have its wall lifted (`"namespace": null`), lose its expiry, or get an expiry past the cap.
- Revoke: as for reading.

A namespace token narrowed to particular deployments, and a `view`-tier caller, cannot mint: a token they minted would reach past their own scope.

| Route | Does |
| --- | --- |
| `POST /tokens` | Mint |
| `GET /tokens` | List (never shows a secret) |
| `PATCH /tokens/:id` | Re-scope, rename or change expiry without changing the secret |
| `GET /tokens/:id` | One token's summary |
| `DELETE /tokens/:id` | Revoke; takes effect on the next request |

Present a token as `Authorization: Bearer applb_…`. The shell WebSocket, and only that route, also accepts `?app_token=…`, because a browser's `WebSocket` cannot set headers. Tokens in URLs end up in logs, so mint short-lived ones for that.

## Federated Heyo auth (managed mode)

On a fleet whose deployments belong to customers, set `APP_LB_AUTH_URL` (plus `APP_LB_ADMIN_AUTH=1` and a password). The admin API then accepts any bearer the Heyo auth service issued, a JWT or a `heyo_api_…` key, and asks `GET /api/auth/scopes` what it may reach.

| Scope string | Meaning |
| --- | --- |
| `namespace:<name>:admin` | Admin tier on every deployment in `<name>` |
| `namespace:<name>:view` | View tier in `<name>`: directory, `/metrics`, `/security`, list and get |
| `fleet:admin` | Unconfined, like the Basic operator |

Unknown scope strings are ignored. The tier is checked against the namespace of the deployment a route names. A federated caller is confined like a namespace token: listings narrow to its namespaces, it cannot register into or move deployments out of other namespaces, fleet routes (workflows, `/jobs`, disks, block rules) are closed, and secrets and tokens are walled per namespace in their handlers. No grant ever contains the `default` namespace.

Answers are cached by the SHA-256 of the bearer for `APP_LB_AUTH_CACHE_SECS`; refusals are cached for 5 seconds. A scope withdrawn upstream therefore lingers for up to the cache TTL. If the auth service is unreachable, the request is refused.

A namespace-scoped `heyo_api_…` key (minted per namespace in the Heyo dashboard with scope `admin` or `view`) resolves to that one namespace. It is the credential to hand CI or a teammate's heyctl.

### Browser sign-in to the dashboard

With federation and the admin gate on, a browser navigating to the dashboard without credentials is sent to `/login`:

| Route | Does |
| --- | --- |
| `GET /login` | Email/password form |
| `POST /login` | Posts credentials to the auth service. The account must hold `fleet:admin`. Sets a `__Host-heyo-admin` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`) |
| `POST /login/handoff` | Form post of `token` and `namespace` from the Heyo front end: a namespace token becomes the session cookie and the browser lands on `/dashboard?namespace=<ns>` |
| `POST /logout` | Clears the cookie |

Serve the dashboard over HTTPS and preserve its `Host` header. Cookie-authenticated writes and WebSocket upgrades require a same-origin HTTPS `Origin`. Basic credentials remain valid as emergency operator access.

## Deployment gates

Add an `auth` block to any deployment spec, or use `heyctl set auth`. Turning a gate on or off is proxy configuration: it never restarts the pool.

### How a request is decided

For each request to a gated deployment, app-lb checks in this order:

1. `<base_path>/callback`, `<base_path>/logout` and `<base_path>/login` are answered by app-lb itself.
2. A path matching `public_paths` gets that entry's scope instead of the gate (see [public paths](#public-paths-and-scopes)).
3. An app-token, if the gate lists `app-token` and the token's scope admits this deployment.
4. A JWT, if the gate lists `jwt` and one is presented in the `Authorization` header or the configured cookie.
5. A valid session cookie (Google, or the JWT password form).
6. Otherwise: a recognised app-token that does not cover this deployment gets `403 insufficient_scope`; a browser (`Accept` includes `text/html`) is redirected to sign in; anything else gets `401` with a JSON body.

Providers are alternatives. Any one listed provider admits the request.

### `auth` block fields

| Field | Default | Meaning |
| --- | --- | --- |
| `provider` | `"google"` | `google`, `app-token`, `jwt`, or a list of them |
| `client_id` | | Google OAuth client id. Required for `google`; rejected without it |
| `client_secret` | | Secret reference `{"secret": NAME, "key": KEY}` holding the Google client secret. Required for `google` |
| `allowed_domains` | `[]` | Google Workspace domains, matched on the `hd` claim. `["*"]` admits any Google account |
| `allowed_emails` | `[]` | Individual addresses, case-insensitive |
| `jwt` | | JWT verification policy; required when `provider` includes `jwt`. See [JWT](#jwt-and-oidc) |
| `public_paths` | `[]` | Path prefixes that bypass sign-in, each with a scope. See [public paths](#public-paths-and-scopes) |
| `session_scope` | unset | `none`, `view` or `admin`: mint a fleet-wide app-token at sign-in and present it upstream as `Authorization: Bearer` for the session's life |
| `base_path` | `/__applb/auth` | Where app-lb's `callback`, `login` and `logout` endpoints live under the deployment's hostname |
| `session_ttl_secs` | `43200` (12h) | Session lifetime. Must be greater than 0 |
| `cookie_name` | `applb_session` | Session cookie name |
| `cookie_domain` | host-only | Parent domain to share one session across gates. See [cookie domain](#sessions-and-cookie-domain) |
| `redirect_url` | `https://<host><base_path>/callback` | OAuth redirect URI, when something in front rewrites the host or terminates TLS |
| `forward_identity` | `true` | Send `x-auth-request-user`, `-email` and `-name` upstream |
| `provider_ref` | | Inherit the identity half from a namespace [auth provider](#auth-providers) |

Registration rejects: an empty Google allow-list, `client_id` or `client_secret` on a gate without `google`, allow-lists on a `jwt` gate without `google`, a `jwt` block without the `jwt` provider (or the reverse), a `public_paths` entry not starting with `/`, an invalid cookie name or domain, and a path-routed deployment whose `base_path` is not under its route prefix (the callback would 404).

### Google

Google sign-in is the OAuth 2.0 authorization code flow with PKCE. The in-flight state rides in an `applb_auth_flow` cookie valid for 10 minutes. The resulting session cookie is self-describing and HMAC-signed with `APP_LB_AUTH_KEY`, so there is no session store and a restart signs nobody out.

Setup:

1. In the Google Cloud console, create an OAuth 2.0 Client ID of type Web application. Register the redirect URI `https://<hostname><base_path>/callback`, for example `https://web.example.com/__applb/auth/callback`. `heyctl describe deployment web` prints the exact string.
2. Store the client secret:

   ```sh
   heyctl create secret google --from-stdin client_secret < ~/.google-oauth-secret
   ```

3. Add the gate:

   ```sh
   heyctl set auth web \
     --client-id 1234-abc.apps.googleusercontent.com \
     --secret google/client_secret \
     --allow-domain example.com \
     --allow-email contractor@gmail.com
   ```

The equivalent spec:

```json
{
  "id": "web",
  "routes": [{"host": "web.example.com"}],
  "upstreams": ["127.0.0.1:8080"],
  "auth": {
    "provider": "google",
    "client_id": "1234-abc.apps.googleusercontent.com",
    "client_secret": {"secret": "google", "key": "client_secret"},
    "allowed_domains": ["example.com"],
    "allowed_emails": ["contractor@gmail.com"],
    "public_paths": [{"path": "/healthz", "scope": "public"}]
  }
}
```

| Request | Response |
| --- | --- |
| No session, browser navigation | `302` to Google, then back to the original URL |
| No session, anything else (curl, heyctl, a page's own `fetch()`) | `401` with `{"error": "authentication required", "login_url": …}` |
| Valid session, on the allow-list | Proxied, with identity headers |
| Signed in, not on the allow-list | `403` naming the account, with a link to switch account |

Things to know:

- **Domains match the `hd` claim, not the email suffix.** A personal Google account has no `hd`, so admit it with `allowed_emails`. If a domain you own does not use Google Workspace (`dig +short MX <domain>`), every account there is personal.
- **The two lists are OR'd.** One match admits.
- **Changing who may enter signs everyone out once.** Each session carries a fingerprint of the policy (provider, client id, allow-lists, cookie domain). Reordering or re-casing entries does not change it.
- **Sessions cannot be revoked individually.** Remove the person from the allow-list.
- **The `Secure` cookie attribute follows the connection.** Over plaintext HTTP the cookie is not `Secure`; use the TLS listener for anything real.
- `<base_path>/login` starts a fresh sign-in (useful for switching accounts); `<base_path>/logout` clears app-lb's cookie but does not sign out of Google.

### App-token gate

For a deployment only programs reach:

```json
{
  "id": "api",
  "routes": [{"host": "api.example.com"}],
  "upstreams": ["127.0.0.1:8080"],
  "auth": {"provider": "app-token"}
}
```

```sh
TOKEN=$(heyctl token mint api-client -d api -q)     # admin tier none: gate access only
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/things
```

A token gets in when its deployment or namespace scope covers the deployment; the admin tier is not checked at the gate. No identity headers are forwarded for a token, because a token is not a person. A browser reaching such a gate gets a `401`, not a redirect. Adding `app-token` to a Google gate (`"provider": ["google", "app-token"]`) is the usual shape for a UI that an agent also drives.

### JWT and OIDC

The `jwt` provider verifies a token another issuer signed and keeps no state. It fits the Heyo auth API, Auth0, Okta, Cognito, Keycloak or your own service.

| `jwt` field | Default | Meaning |
| --- | --- | --- |
| `secret` | | Secret reference holding an HMAC key, for `HS256/384/512` |
| `public_key` | | Inline PEM public key or certificate, for `RS*`, `PS*`, `ES*` |
| `jwks_url` | | Issuer key set. Cached 10 minutes and refetched on an unknown `kid`. Must be `https://` unless loopback |
| `algorithms` | required | Accepted algorithms. Never taken from the token |
| `issuer` | required | Exact `iss` |
| `audience` | unchecked | Required `aud` (string, or member of an array) |
| `require` | `{}` | Claim constraints: a value or list per claim; OR within a claim, AND across claims; a list-valued claim matches if it contains a wanted value |
| `subject_claim` | `sub` | Claim forwarded as `x-auth-request-user`. A token without it is refused |
| `email_claim` | `email` | Claim forwarded as `x-auth-request-email` |
| `name_claim` | `name` | Claim forwarded as `x-auth-request-name` |
| `leeway_secs` | none | Clock skew on `exp`/`nbf`, max `300` |
| `cookie` | | Cookie to read the token from when there is no `Authorization` header |
| `login_url` | | Issuer's hosted sign-in page for token-less browsers. Requires `cookie`; must be `https://` or loopback |
| `login_redirect_param` | `redirect_uri` | Query parameter that page reads the return URL from (`return_to`, `next`, `rd` are common) |
| `login_endpoint` | | Heyo Auth `/api/auth/login` URL: app-lb serves its own email/password form. Requires `cookie`; HTTPS (or loopback HTTP), no credentials, query or fragment |

Exactly one of `secret`, `public_key` and `jwks_url`. Every token must have a valid signature with a listed algorithm, an unexpired `exp` (a token with no `exp` is refused), a matching `iss`, a matching `aud` when set, and then satisfy `require`. `allowed_domains` and `allowed_emails` are rejected on a gate that does not also list `google`; use `require` instead. Refusals get a bare `401` and are logged, with the reason, to security monitoring as `gate-jwt`.

Heyo auth API access tokens (`HS256`, shared secret):

```json
"auth": {
  "provider": "jwt",
  "jwt": {
    "secret": {"secret": "heyo-auth", "key": "jwt_secret"},
    "algorithms": ["HS256"],
    "issuer": "auth-service",
    "audience": "heyo-app",
    "subject_claim": "userId",
    "require": {"role": ["user", "admin"]}
  }
}
```

An OIDC issuer with a key set:

```json
"auth": {
  "provider": "jwt",
  "jwt": {
    "jwks_url": "https://example.auth0.com/.well-known/jwks.json",
    "algorithms": ["RS256"],
    "issuer": "https://example.auth0.com/",
    "audience": "https://api.example.com",
    "require": {"permissions": "deploy:write"}
  }
}
```

Browsers cannot put an `Authorization` header on a navigation, so a JWT gate for people needs one of two browser paths:

- **Hosted sign-in (`cookie` + `login_url`).** A token-less browser is redirected to `login_url?redirect_uri=<the URL it wanted>`. That page must sign the person in, set a JWT from the same issuer in the named cookie on a domain the gated host also receives (for example `Domain=.example.com`), and redirect back only to the URL it was given. app-lb keeps no flow state; the cookie is the session.
- **Password form (`cookie` + `login_endpoint`).** app-lb shows an email/password form, posts it to Heyo Auth's `/api/auth/login`, verifies the returned token against this policy, and sets a host-only `Secure`, `HttpOnly` cookie. This returns an `HS256` access token with `aud: heyo-app`, so it pairs with the shared-secret policy above, not with `heyo-jwks`. Passwords and refresh tokens are never stored; auth services that require CAPTCHA or other interactive challenges cannot use it.

Mixing works as elsewhere: `"provider": ["google", "jwt"]` lets a person sign in with Google while the UI's API calls carry the issuer's token.

## Public paths and scopes

`public_paths` lists path prefixes the sign-in gate does not sit in front of. Each entry names what app-lb requires instead:

| Scope | What is required |
| --- | --- |
| `public` | Nothing. The only scope that admits a request with no credential |
| `none` | An app-token that admits this deployment (any tier), or a valid JWT when the gate lists `jwt` |
| `view` | An app-token of tier `view` or `admin` that admits this deployment |
| `admin` | An app-token of tier `admin` that admits this deployment |

```json
"public_paths": [
  {"path": "/healthz", "scope": "public"},
  {"path": "/api/", "scope": "view"},
  {"path": "/api/admin/", "scope": "admin"},
  "/deployments"
]
```

Rules:

- **A bare string means `admin`**, the most closed scope. Specs written before scopes existed became stricter on upgrade. `heyctl set auth --public-path` writes bare strings, so use `heyctl edit` or `apply` to write `public`.
- **Longest prefix wins**, so a narrow entry can tighten a broad one regardless of order.
- **Matching is by prefix.** `/deployments` also covers `/deployments/web/build`.
- **A listed path does not accept the Google session.** Only the credentials in the table above pass it. Don't list paths a signed-in browser needs to call.
- When the gate fronts app-lb's own admin listener, only the token's tier is checked here; the admin API then checks deployment and namespace scope itself.

Use `public` for a path whose upstream does its own authorization (an artifact store checking its API key) or has nothing to protect.

## Identity forwarding

When `forward_identity` is true (the default) and a person is admitted, app-lb sets:

| Header | Google | JWT |
| --- | --- | --- |
| `x-auth-request-user` | Google subject id | `subject_claim` |
| `x-auth-request-email` | email | `email_claim` |
| `x-auth-request-name` | display name | `name_claim` |

These three headers are stripped from every incoming request to a gated deployment, whatever `forward_identity` says, so clients cannot forge them. App-token requests forward no identity. A JWT is still in the original `Authorization` header if the application wants more claims.

With `session_scope` set, the gate also replaces `Authorization` with `Bearer <session app-token>` on each admitted request. The token is fleet-wide (`deployments: ["*"]`) at the named tier and expires with the session. Set it only on a gate whose upstream authenticates app-tokens, in practice app-lb's own admin listener. Never set it on an ordinary application.

## Sessions and cookie domain

| Property | Value |
| --- | --- |
| Session cookie | `cookie_name`, default `applb_session`, `HttpOnly` |
| Lifetime | `session_ttl_secs`, default 12 hours |
| Signing key | `APP_LB_AUTH_KEY` file, HMAC-SHA256 |
| Bound to | the deployment and the policy fingerprint |

By default the cookie is host-only, so signing in at `docs.example.com` does not sign you in at `api.example.com`. Set `cookie_domain` to the same parent (for example `example.com`) on both gates, or on the shared auth provider, and one sign-in covers both. A session is still refused unless the presenting gate has an identical policy fingerprint, so a gate with a narrower allow-list starts its own sign-in.

The value must have at least two labels and be the request host or a parent of it; a leading dot is accepted and ignored. It is not checked against the public suffix list. A wider cookie is sent to every host under that domain, including ones app-lb does not serve, so only use it when every host under the domain is trusted. Sessions cannot be shared across different registrable domains.

## Auth providers

An auth provider is the identity half of a gate, declared once per namespace and inherited by deployments with `provider_ref`. app-lb resolves it on every gated request, so editing the provider updates every deployment that names it, and changes to who may enter re-sign existing sessions.

- A provider is identified by `(namespace, name)`. A deployment may only inherit one from its own namespace.
- A gate with `provider_ref` carries only route-scoped fields (`public_paths`, `session_scope`, `base_path`, `cookie_name`, `redirect_url`, `forward_identity`, `session_ttl_secs`). Setting an identity field too is rejected.
- A reference to an undeclared provider is rejected at registration. If a provider disappears later, the gate fails closed with `500`.
- Secret references resolve in the provider's own namespace.

| Provider field | Meaning |
| --- | --- |
| `name` | Unique within the namespace |
| `namespace` | Owning namespace (default `default`) |
| `description` | Free text, up to 400 characters |
| `provider`, `client_id`, `client_secret`, `allowed_domains`, `allowed_emails`, `jwt`, `cookie_domain` | As in the `auth` block |

`POST /auth-providers` also takes request-only fields that are never stored: `preset`, `secret` (for the `heyo` preset), `jwks_url` (for `heyo-jwks`), and `require`, `cookie`, `login_url`, `login_redirect_param`, which are laid over the preset's expansion.

| Preset | Expands to | Needs |
| --- | --- | --- |
| `heyo-jwks` | `RS256` via key set, issuer `auth-service`, audience `heyo-gate`, subject `userId`, `role` in `{user, admin}` | nothing; the key set URL is derived as `{APP_LB_AUTH_URL}/.well-known/jwks.json`. Without `APP_LB_AUTH_URL`, pass `jwks_url` |
| `heyo` | `HS256`, issuer `auth-service`, audience `heyo-app`, subject `userId`, `role` in `{user, admin}` | `secret` holding the auth service's signing key |

Prefer `heyo-jwks`: it holds nothing secret. An `HS*` key both verifies and mints, and any namespace admin can read secrets in their namespace. Both presets admit every signed-in Heyo user, so narrow them with `require`, for example `accountId`, or `namespace=<ns>` (present only on tokens exchanged from a namespace-scoped key).

| Route | Tier | Notes |
| --- | --- | --- |
| `GET /auth-providers[?namespace=]` | view | Narrowed to namespaces the caller reaches |
| `POST /auth-providers` | `namespace:<ns>:admin` | Upsert; keeps the original `created_at` |
| `GET /auth-providers/{namespace}/{name}` | admin | Secrets appear as references |
| `DELETE /auth-providers/{namespace}/{name}` | admin | `409` while any deployment inherits it |

### Worked examples

Heyo gate tokens, nothing secret, with browser sign-in through the hosted page:

```sh
heyctl create auth-provider heyo -n team-a \
  --preset heyo-jwks \
  --require accountId=acct_7f3c \
  --cookie heyo_token --login-url https://auth.example.com/login
heyctl set auth reports --provider-ref heyo
```

Heyo access tokens with the signing key (only where you run both the fleet and the namespace):

```sh
heyctl create secret heyo-auth -n team-a --from-stdin jwt_secret < ~/.heyo-jwt-secret
heyctl create auth-provider heyo-hs -n team-a --preset heyo --secret heyo-auth/jwt_secret
```

Any OIDC issuer:

```sh
heyctl create auth-provider okta -n team-a \
  --issuer https://example.okta.com \
  --jwks-url https://example.okta.com/oauth2/v1/keys \
  --alg RS256 --audience api://default \
  --require groups=engineering,ops
```

Google, one session across the namespace:

```sh
heyctl create secret google -n team-a --from-stdin client_secret < ~/.google-oauth
heyctl create auth-provider corp-google -n team-a \
  --client-id 1234.apps.googleusercontent.com --secret google/client_secret \
  --allow-domain example.com --cookie-domain example.com --app-token
```

`--alg` defaults to `HS256` with `--secret` and `RS256` with `--jwks-url` or `--public-key-file`. `--app-token` adds the `app-token` provider. As a spec file for `heyctl apply`:

```yaml
kind: auth-provider
name: heyo
namespace: team-a
preset: heyo-jwks
require: { accountId: [acct_7f3c] }
```

Rotation: a key-set provider rotates with no change in app-lb (the issuer publishes the new key; app-lb refetches on an unknown `kid`). A shared-secret provider rotates with `heyctl set secret heyo-auth -n team-a --from-stdin jwt_secret`, which is a hard cutover: the issuer and the secret must change together.

Through Cloud's namespace door (`https://<cloud>/namespaces/<ns>/lb`), a namespace-scoped key can list, create, get and delete providers in that namespace only.

## Putting the admin dashboard behind Google

You can front the admin listener with a gated static deployment (upstream `127.0.0.1:9090`, see [`examples/app-lb-admin.json`](../app-lb/examples/app-lb-admin.json)). The gate lets people sign in; then something must authenticate them to the admin API.

The recommended shape uses `session_scope` so the signed-in person's requests reach the admin API with an app-token:

```json
"auth": {
  "provider": ["google", "app-token"],
  "client_id": "1234-abc.apps.googleusercontent.com",
  "client_secret": {"secret": "google", "key": "client_secret"},
  "allowed_emails": ["ops@example.com"],
  "session_scope": "admin",
  "public_paths": [{"path": "/healthz", "scope": "public"}]
}
```

Run app-lb with `APP_LB_DASHBOARD_PASSWORD` and `APP_LB_ADMIN_AUTH=1`. The dashboard and its `/metrics` polls work through the Google session. Programs such as heyctl present an app-token (`heyctl login --server https://lb-admin.example.com --token-stdin`), which the `app-token` provider admits. Basic credentials do not pass the gate; use an SSH tunnel for Basic access.

Order matters: set `APP_LB_ADMIN_AUTH=1` and restart before exposing any admin path, or the CRUD API (including `/secrets` and build endpoints, which run commands on the host) is reachable with nothing in front of it. Only set `APP_LB_DASHBOARD_AUTH=0` when a sign-in gate is already live in front of the listener, because it opens the view tier to anything that reaches it.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| app-lb exits at startup mentioning `APP_LB_ADMIN_AUTH` | Admin auth needs `APP_LB_DASHBOARD_PASSWORD`; federation needs admin auth |
| Google says `redirect_uri_mismatch` | Register exactly `https://<host><base_path>/callback`, or set `redirect_url` if a proxy rewrites the host |
| Sign-in loops forever | `cookie_domain` does not cover the host, the connection is not HTTPS, or a `login_url` page sets its cookie on a domain the gated host never receives |
| Dashboard behind Google loads but shows no data | The admin API behind the gate still wants its own credential for `/metrics`. Set `session_scope` so the session carries an app-token upstream, and don't list `/metrics` in `public_paths` (listed paths ignore the Google session) |
| heyctl gets 401 against a gated hostname | heyctl cannot do OAuth. Add `app-token` to the gate and log in with a token, or tunnel to the admin listener |
| A "public" path asks for a token | Bare-string entries mean scope `admin`. Write `{"path": …, "scope": "public"}` |
| `403 insufficient_scope` at a gate | The app-token is valid but its deployment or namespace scope does not cover this deployment. A higher tier will not help |
| Personal Gmail account refused with a domain allow-list | Personal accounts have no `hd`. Add the address to `allowed_emails` |
| Everyone was signed out after an edit | Expected when the allow-list, client id, provider or cookie domain changes |
| JWT refused with a bare `401` | Check app-lb's log or the security page for the reason (expired, wrong issuer, bad signature, missing `exp` or subject claim) |
| Gate returns `500` | Its `provider_ref` no longer resolves; the gate fails closed. Recreate the provider |
| Deleting an auth provider returns `409` | Deployments still inherit it; the response names them |
| Federated caller loses access late | Scopes are cached for `APP_LB_AUTH_CACHE_SECS` |

The long-form design notes are in [`app-lb/AUTH_PROVIDERS.md`](../app-lb/AUTH_PROVIDERS.md) and the [app-lb README](../app-lb/README.md).
