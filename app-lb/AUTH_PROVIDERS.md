# Auth providers

An **auth provider** is the identity half of a sign-in gate on its own: who may
enter and how they are verified, given a name and an owning namespace. A
deployment inherits one with `auth.provider_ref` and keeps only its own
route-scoped settings.

```jsonc
// The object, declared once per namespace.
{ "name": "heyo", "namespace": "team-a", "provider": "jwt", "jwt": { "…": "…" } }

// Every deployment that wants it.
{ "id": "reports", "auth": { "provider_ref": "heyo", "public_paths": ["/healthz"] } }
```

Why it exists: written inline, an identity was copied into every spec that
needed it, so rotating a client secret or tightening an allow-list meant editing
each one and being out of step until the last was done. Resolution here is
**live** — app-lb reads the provider on every gated request — so an edit reaches
every deployment that names it at once, and because the resolved gate's policy
fingerprint changes, sessions issued under the old policy are re-signed rather
than left standing.

Three properties are worth knowing before anything else:

- **A provider is `(namespace, name)`.** Two namespaces may each declare `heyo`;
  a deployment may only inherit one from its *own* namespace.
- **It fails closed.** A gate whose `provider_ref` no longer resolves refuses
  the request (500) rather than serving the deployment ungated.
- **Its secret references are bound to its namespace.** Whatever a body writes,
  a provider in `team-a` resolves `team-a`'s secrets. Naming another namespace's
  is not an error to report; it is a thing the object cannot express.

## Declaring one

`POST /auth-providers`, or `heyctl create auth-provider`. The write tier is
`namespace:<ns>:admin`; the listing is view tier and narrows itself to the
namespaces a credential reaches.

### The Heyo auth API — `heyo-jwks`, and nothing secret

`--preset heyo-jwks` expands, **on the server**, into the policy for that
service's *gate tokens*: `RS256` verified against its published key set, issuer
`auth-service`, audience `heyo-gate`, subject claim `userId`, `role` in
`{user, admin}`.

```sh
heyctl create auth-provider heyo -n team-a --preset heyo-jwks
```

That is the whole command. app-lb derives the key set URL from the auth service
it already federates to (`APP_LB_AUTH_URL`); pass `--jwks-url` when it has none.
No secret is created, stored or referenced, which is what makes this safe to
declare in a namespace somebody else administers — **a secret in a namespace is
readable by whoever administers it**, because a deployment's `vm.env_from` puts
its value in a guest they control.

The preset admits **every signed-in Heyo user** — `role` is `user` or `admin`
for everyone — so narrow it to the population you actually mean, in the same
command:

```sh
heyctl create auth-provider heyo -n team-a \
  --preset heyo-jwks --require accountId=acct_7f3c
```

Over the API the same thing is one `POST /auth-providers`: next to `preset`,
the request-only fields `require` (merged claim by claim over the preset's, so
its `role` check stays), `cookie`, `login_url` and `login_redirect_param` are laid
over the expanded policy:

```json
{"name": "heyo", "namespace": "team-a", "preset": "heyo-jwks",
 "require": {"accountId": ["acct_7f3c"]},
 "cookie": "heyo_token", "login_url": "https://auth.example.com/login"}
```

This is what Heyo sends when a namespace is created from its UI.

`--require namespace=team-a` is the other useful one: that claim is only present
on a token exchanged from a namespace-scoped API key, so it admits exactly the
credentials minted for this namespace.

Where the gate tokens come from: `GET /login` on the auth service puts one in the
cookie for a browser, and `POST /api/auth/gate-token` hands one to a program that
already holds a Heyo token. They carry their own audience precisely so that a
platform access token cannot be replayed at a gate, and a gate token cannot be
replayed at the API.

### The same service's access tokens — `heyo`, which needs the signing key

```sh
heyctl create secret heyo-auth -n team-a --from-stdin jwt_secret < ~/.heyo-jwt-secret
heyctl create auth-provider heyo -n team-a \
  --preset heyo --secret heyo-auth/jwt_secret --require accountId=acct_7f3c
```

`HS256`, audience `heyo-app`. Use it only where the fleet and the namespace are
both yours: that key verifies *and* mints, so anything that can read it can issue
any identity the auth service can — and a namespace admin can read any secret
behind their own wall. Prefer `heyo-jwks`.

### Any other issuer

Nothing about a gate is specific to one issuer — `--issuer` plus a key is the
whole of it. Auth0, Okta, Cognito, Keycloak and a service you wrote yesterday
all look like this:

```sh
heyctl create auth-provider okta -n team-a \
  --issuer https://example.okta.com \
  --jwks-url https://example.okta.com/oauth2/v1/keys \
  --alg RS256 \
  --require groups=engineering,ops
```

Key material is `--jwks-url` (a rotating key set, refetched when a token names a
`kid` app-lb has not seen), `--public-key-file` (one static public key, sent
inline because it is public), or `--secret` (an `HS*` shared secret from the
secret store). Exactly one — two would leave "which key verified this?"
answerable only by reading the code.

`--alg` defaults to `HS256` for a shared secret and `RS256` for a public key,
and is never taken from the token: the algorithm is named in a header the caller
controls, so a verifier that dispatches on it accepts both `alg: none` and a
public key used as an HMAC secret.

### Google

```sh
heyctl create secret google --from-stdin client_secret < ~/.google-oauth
heyctl create auth-provider corp-google -n team-a \
  --client-id 1234.apps.googleusercontent.com --secret google/client_secret \
  --allow-domain example.com --cookie-domain .example.com
```

`--cookie-domain` belongs on the provider rather than each gate: one provider is
one sign-in realm, so the deployments that inherit it share a session.

## Inheriting one

```sh
heyctl set auth reports --provider-ref heyo --public-path /healthz
```

A gate carries either a reference or an inline identity, never both — app-lb
refuses the pair rather than silently overriding one, so `set auth
--provider-ref` clears any identity already written there. What stays the
deployment's own: `public_paths`, `base_path`, `cookie_name`,
`session_ttl_secs`, `redirect_url`, `forward_identity`, `session_scope`. Note that
`--public-path` writes a bare-string entry, which means scope `admin`, not
open; write `{"path": "/healthz", "scope": "public"}` for an unauthenticated
path.

A reference to a provider that is not declared in the deployment's namespace is
refused at registration, with the provider named — not discovered on the first
gated request.

Reading it back:

```sh
heyctl get auth-providers -n team-a
heyctl describe auth-provider heyo -n team-a
heyctl describe deployment reports      # says which provider it inherits
```

## Rotating and removing

A provider built on a key set rotates **without touching app-lb at all**: the
issuer publishes the new key beside the old, signs with it, and app-lb refetches
the set the first time it meets a `kid` it does not know. Tokens signed before
the rotation keep working for as long as the old public key stays published.

A shared-secret provider rotates with a secret write, and nothing else — the key
is resolved per request, so the next request uses the new value:

```sh
heyctl set secret heyo-auth -n team-a --from-stdin jwt_secret < ~/.heyo-jwt-secret.new
```

That one is a hard cutover: a gate verifies with exactly one key, so the issuer
and every copy of the secret change at the same moment or requests 401 in
between. The asymmetric form has no such moment, which is the other reason to
prefer it.

`DELETE /auth-providers/{namespace}/{name}` is refused with `409` while any
deployment still inherits it, naming them: resolution fails closed, so removing
one out from under a live gate would take those deployments offline.

## Browsers: scoped sign-in (preferred)

The redirect-and-cookie contract further down has one weakness on a shared
fleet. The issuer's cookie has to sit on a domain the gated host also sees, so
every host under that domain receives it, other tenants' deployments included.
Scoped sign-in avoids that. app-lb asks the issuer for access to one namespace,
and the token comes back to app-lb, not to the browser:

```sh
curl -X POST …/auth-providers -d '{
  "name": "heyo", "namespace": "team-a", "preset": "heyo-jwks",
  "authorize_url": "https://auth.example.com/oauth/authorize",
  "token_url": "https://auth.example.com/oauth/token"
}'
```

A token-less **browser** is sent through an OAuth 2.0 authorization-code flow
with PKCE (`S256`) and `state`:

1. app-lb redirects it to `authorize_url` with `scope=namespace:<the
   deployment's namespace>` and `redirect_uri=https://<host><base_path>/callback`.
2. The issuer signs the person in and decides whether they may reach that
   namespace. The Heyo auth API checks membership of the owning account and asks
   "Continue to `<host>`?" once per host. It then returns a single-use code.
3. app-lb redeems the code at `token_url` server to server, verifies the token
   against this provider's policy, and requires `gateHost` to equal the request
   host and `namespace` to equal the deployment's namespace.
4. app-lb keeps its own host-only session (`applb_session`), which ends when the
   token would have.

Any JWT carrying `gateHost` or `namespace` is held to those claims on every
path, the `Authorization` header included. A token issued for one host is
refused on every other host.

Two rules are enforced at registration. Both endpoints are required, and must
be `https://` (loopback `http://` aside). Scoped sign-in also can't be combined
with a `cookie_domain` realm, because a session issued for one namespace's host
must not be honoured by a sibling gate in another namespace.

## Browsers, and the sign-in page contract

A `jwt` provider is stateless: it verifies a credential the request already
carries. That is right for a program and a dead end for a person, because a
browser cannot put an `Authorization` header on a navigation — so a token-less
browser would get a `401` it has no way to act on.

Two fields close that gap:

```sh
heyctl create auth-provider heyo -n team-a \
  --preset heyo-jwks \
  --cookie heyo_token \
  --login-url https://auth.example.com/login
```

With them, app-lb redirects a token-less **browser** (a request whose `Accept`
includes HTML) to:

```
https://auth.example.com/login?redirect_uri=https://reports.example.com/the/path
```

and reads the token out of the `heyo_token` cookie when it comes back. A program
still gets the `401`. app-lb mints nothing and keeps no flow state: the cookie
the issuer set *is* the session.

So the page at `login_url` has two jobs and no others:

1. sign the person in, and leave a JWT **its own issuer signed** in the cookie
   named by `--cookie`, on a domain the gated host also sees (a cookie set on
   `auth.example.com` is not sent to `reports.example.com` — it wants
   `Domain=.example.com`);
2. redirect back to the URL it was handed, and to nowhere else.

That is the entire contract. The Heyo auth service implements it at `GET /login`
(see `auth/src/routes/login.routes.ts`, configured by `LOGIN_COOKIE_NAME`,
`LOGIN_COOKIE_DOMAIN` and `LOGIN_ALLOWED_REDIRECT_HOSTS` — the return URL
app-lb sends is absolute, so the gated hostname must be on that allow-list). An
operator who would rather not depend on it implements the same two behaviours
against their own issuer and points `--login-url` there; app-lb prefers neither.
`--login-redirect-param` matches whatever that page reads the return URL from —
`redirect_uri` unless set, and `return_to`, `next` and `rd` are the other
spellings in the wild.

### The other browser path: `login_endpoint`

app-lb can also serve the password form itself: `jwt.login_endpoint` points at
Heyo Auth's `/api/auth/login`, the gate posts the credentials there, checks the
returned token against this very policy, and sets its own host-only cookie (see
"Browser sign-in with existing Heyo Auth" in the README).

That one pairs with the **`heyo`** shape, not `heyo-jwks`: `/api/auth/login`
returns an `HS256` access token with `aud: heyo-app`, which a `heyo-jwks` policy
is built to refuse. So the two browser paths line up with the two presets — the
hosted page (`--login-url`) for a gate that verifies gate tokens and holds no
secret, `login_endpoint` for a gate that already holds the signing key.

`--login-url` requires `--cookie`. Without the cookie the browser is redirected
to sign in, comes back carrying nothing the gate can read, and is redirected
again — a loop that is impossible to diagnose from outside. It must be `https://`
(or loopback `http://`), for the reason a JWKS URL must.

## Giving a customer a namespace

The provisioning sequence, with nothing secret crossing the wall:

```sh
heyctl create namespace team-a --description "Acme"          # fleet admin
heyctl create auth-provider heyo -n team-a \
  --preset heyo-jwks \
  --require accountId=<their heyo account> \
  --cookie heyo_token --login-url https://auth.example.com/login
```

They then gate their own deployments with
`heyctl set auth <deployment> --provider-ref heyo`, drive everything else through
cloud with a namespace-scoped API key, and never hold a credential of ours.

One thing this does **not** yet enforce: the provider lives in their namespace,
so a namespace admin can replace it — dropping the `--require` and admitting any
signed-in Heyo user to their own deployment. It is their app either way, but if
that rule should be ours rather than theirs, providers need an operator-owned
flag that a confined caller may read and inherit but not overwrite. Not built.

## Not relying on the Heyo auth API at all

The `heyo` preset is a convenience, not a coupling. An operator running their
own app-lb who wants nothing to do with our issuer has a complete path:

| What | Theirs |
| --- | --- |
| Tokens | Their issuer's, verified by `--issuer` + `--jwks-url` / `--public-key-file` / `--secret` |
| Who gets in | `--require <claim>=<values>` against their claims |
| Browser sign-in | Their page at `--login-url`, setting `--cookie` |
| Identity upstream | `--subject-claim` / `--email-claim` / `--name-claim` → `x-auth-request-*` |

The one thing worth thinking about before choosing `HS*`: a shared secret both
*verifies* and *mints*, so the app-lb host holding it can issue identities for
that issuer. On a fleet somebody else runs, an asymmetric key (`--jwks-url`,
`RS256`) hands them only the ability to check signatures — which is all a gate
ever needs. That is the same reason the Heyo auth API publishes a key set of its
own, and why `heyo-jwks` is the preset to reach for.

## Through the managed service

Cloud proxies the provider routes for a namespace, so a namespace-scoped
credential drives them the same way it drives deployments:

```sh
heyctl login --server https://cloud.example.com/namespaces/team-a/lb --token heyo_api_…
heyctl get auth-providers
```

The door pins the namespace: the listing is narrowed to `team-a`, a create is
stamped with it, and an item route naming another namespace in its path is a
404. `GET`, `POST` and the item `GET`/`DELETE` are exposed; nothing else is.

## Wire reference

| Route | Tier | Notes |
| --- | --- | --- |
| `GET /auth-providers[?namespace=]` | view | Narrows itself to what the caller reaches |
| `POST /auth-providers` | admin | Upsert; keeps the original `created_at` |
| `GET /auth-providers/{namespace}/{name}` | admin | Secrets appear as references, never values |
| `DELETE /auth-providers/{namespace}/{name}` | admin | `409` while a gate still inherits it |

`POST` accepts three request-only fields that are never stored: `preset`, the
`secret` reference the `heyo` preset needs, and the `jwks_url` that `heyo-jwks`
takes when app-lb cannot derive one. `require`, `cookie`, `login_url`,
`login_redirect_param`, `authorize_url` and `token_url` may also be sent at the
top level. They're laid over the resulting `jwt` policy, which is how a preset
is tuned in the same request. Everything else is the object itself —
`name`, `namespace`, `description`, `provider`, `client_id`, `client_secret`,
`allowed_domains`, `allowed_emails`, `jwt`, `cookie_domain`.

The golden fixtures in `testdata/wire/auth-provider-*.json` are written from the
server's own types; `heyctl`'s `tests/wire_contract.rs` asserts it still
understands every field in them.
