# Plugins

Plugins are app-lb's optional capabilities: telemetry, git, CI, Postgres databases, the artifact store, secrets pages and sign-in providers, switched on at runtime and used by namespaces through the admin API, the dashboard, `heyctl` and the SDKs.

Every plugin is compiled into app-lb; none are loaded dynamically. Whether each one runs, and with what configuration, is a record on disk that the dashboard's **Plugins** page, `heyctl plugins` and the [SDKs](sdk.md) edit. The HTTP routes are in the [API reference](api/namespaces.md#namespace-plugins).

## Enable, then install

A plugin is switched on in two halves:

1. **The operator enables it** for the whole host, with a configuration that points it at the service behind it (app-obs, ci, the git remote, pg-fc, an artifact store). Credentials never go in the configuration: they live in app-lb's secret store, and the configuration references them as `{"secret": "…", "key": "…"}`.
2. **Each namespace installs it.** An *auto-installing* plugin installs itself into every namespace (existing ones when it is switched on, new ones as they appear) unless the operator sets `"auto_install": false`. The others are opt-in: a namespace administrator installs them. A namespace that uninstalls an auto-installing plugin stays uninstalled.

A plugin does nothing for a namespace unless both are true. Calls to one that is not installed answer `409` with `"code": "plugin_not_installed"` and the install command in the message; while the operator has it off, `"code": "plugin_disabled"`.

```sh
# Operator, on the app-lb host
heyctl create secret app-obs --from-env api_token=APP_OBS_API_TOKEN
echo '{"url": "http://127.0.0.1:9600", "api_token": {"secret": "app-obs", "key": "api_token"}}' \
  | heyctl plugins set obs -f -
heyctl plugins enable obs
heyctl plugins describe obs          # configuration, live status, last error

# A namespace administrator
heyctl plugins list -n team-a        # what team-a can install, and what it has
heyctl plugins install postgres -n team-a
heyctl plugins install auth-google -n team-a -f google.json   # with per-namespace configuration
heyctl plugins uninstall postgres -n team-a
```

The same from code, with [`@heyocomputer/hws`](https://www.npmjs.com/package/@heyocomputer/hws) or [`hws`](https://crates.io/crates/hws):

```ts
await lb.setPlugin("obs", true, { url: "http://127.0.0.1:9600", api_token: { secret: "app-obs", key: "api_token" } });
await lb.installPlugin("team-a", "postgres");
const installed = await lb.namespacePlugins("team-a");
```

Installing needs `admin` over the whole namespace: the operator, a fleet admin token, a namespace token with no `deployments` list, or a federated `namespace:<ns>:admin` grant. Enabling and configuring is the operator's.

## The plugins

| Plugin | Name | Installs | What a namespace gets | SDK |
| --- | --- | --- | --- | --- |
| `obs` | Observability | automatically | Logs, metrics and error alerts for every VM, collected by [app-obs](app-obs.md), and a dashboard | `lb.obs(ns)` |
| `remote` | Git | automatically | Git repositories on the region's git remote, repo tokens, and a repository browser | install only |
| `secrets` | Secrets | automatically | A page for the namespace's own secrets: key names, never values | `lb.secrets(ns)` and friends |
| `artifacts` | Artifacts | automatically | Its `<ns>/` corner of the global [artifact store](artifacts.md): tags, manifests, repository visibility | `lb.artifacts(ns)` |
| `auth-heyo` | Heyo sign-in | automatically, **enabled by default** | The auth provider `heyo`, so a deployment requires Heyo sign-in with one call | `lb.setAuth(id, { provider: "heyo" })` (since 0.4.0) |
| `postgres` | Postgres | opt-in | Dedicated databases on [pg-fc](pg-fc.md), each with its own role, credentials written to the secret `pg-<name>` | `lb.postgres(ns)` |
| `auth-google` | Google sign-in | opt-in | The auth provider `google`, with the namespace's own OAuth client | `lb.setAuth(id, { provider: "google" })` (since 0.4.0) |
| `ci` | CI | opt-in | Repositories, runs and submit tokens on the region's [ci](ci.md) | install only |
| `pgfc` | pg-fc databases | fleet only | An operator console for pg-fc pools | — |
| `vapi` | vapi inference | fleet only | An operator console for vapi inference gateways | — |

`obs`, `remote`, `secrets`, `postgres` and `ci` also have a dashboard, framed by app-lb at `/namespaces/<ns>/plugin-console/<id>`. The namespace dashboard's **Plugins** button lists them.

### obs

Operator configuration: `url` (app-obs's API listener, required), `api_token` (a reference to `APP_OBS_API_TOKEN`), `poll_secs`, `auto_install` (default `true`). No per-namespace configuration.

Installing starts collection for every deployment in the namespace; uninstalling stops it, and what was collected ages out with app-obs's retention. Reads go through app-lb with the namespace's own token: fleet overview, per-deployment metrics, paged logs and error alerts. See the [obs API](api/obs.md).

```ts
const obs = lb.obs("team-a");
const fleet = await obs.fleet({ window: "1h" });
const errors = await obs.logs("web", { level: "error", limit: 50 });
await obs.createAlert({ deployment: "web", threshold: 5, webhook_url: "https://hooks.example.com/x" });
```

### remote

Operator configuration: `url` (the git remote, e.g. `https://git.us5.heyo.work`, required), `api_token` (a reference to the remote's `REMOTE_PLUGIN_API_TOKEN`, required), `poll_secs`, `auto_install` (default `true`).

The namespace's repositories, created, browsed and tokened in the git remote's own pages, framed in app-lb. The git remote also accepts the namespace's app-lb token directly at `POST /api/repos/<ns>` and `POST /api/tokens`, which is how a program creates a repository and a scoped push token.

### secrets

Operator configuration: `auto_install` (default `true`) only; the store is app-lb's own.

A page where a namespace administrator creates, rotates and deletes the namespace's secrets, which deployments read with `env_from` and builds with `auth`. It lists key names and never shows a value. The SDKs manage the same secrets with `putSecret` / `patchSecret` / `deleteSecret`.

### artifacts

Operator configuration: `url` and `api_key` (a reference to the store's `ART_API_KEY`), both optional and defaulting to `APP_LB_ARTIFACT_STORE` and `APP_LB_ARTIFACT_STORE_API_KEY`, so on a host already configured that way `{}` adopts that store and its key. `auto_install` defaults to `true`.

While it is enabled its store is the global store: where a deployment's storeless `artifact` block pulls from. Disabling it falls back to the environment. A namespace reaches only its own `<ns>/` tags and repositories (and blobs and manifests by digest); publishing needs `admin` over the whole namespace. See [namespace artifacts](app-lb.md#namespace-artifacts).

```ts
const store = lb.artifacts("team-a");
const v2 = await store.tag("team-a/web:v2");
await store.setTag("team-a/web:latest", v2.digest);   // promote
await store.setRepo("team-a/web", { public: true });  // publish on the hub
```

Pushing an image itself is `heyctl artifact push`.

### postgres

Operator configuration: `url` (pg-fc's dashboard listener, required), `user`, `password` (a reference to its dashboard password), `pg_host` (the pooler's public name, for connection strings), `pg_port` (default `6432`), `sslmode` (default `require`), `max_per_namespace` (default `10`), `poll_secs`. Opt-in per namespace, with no per-namespace configuration.

Each database is a dedicated pg-fc database named `ns_<namespace>_<name>` with its own role. The password comes back once, and is also written to the namespace secret `pg-<name>` (`url`, `host`, `port`, `database`, `user`, `password`) unless asked not to. Deleting revokes the credential; the data stays on pg-fc until an operator purges it, and the secret is left for the namespace to delete.

```ts
const pg = lb.postgres("team-a");
const db = await pg.createDatabase({ name: "app" });   // db.url, once; also in secret pg-app
await pg.databases();
await pg.deleteDatabase("app");
```

### auth-heyo and auth-google

Installing either declares an [auth provider](app-lb-auth.md#auth-providers) in the namespace, and uninstalling removes it. A deployment then requires sign-in by inheriting it, with `auth.provider_ref`, `heyctl set auth <id> --provider-ref heyo`, or `setAuth` / `set_auth` from the SDKs.

- **`auth-heyo`** declares `heyo`: Heyo gate tokens verified against the auth service's published key set, holding nothing secret. It is enabled by default on any host with `APP_LB_AUTH_URL`, and installs itself everywhere. Operator configuration, all optional: `jwks_url`, `login_url`, `cookie`, `auto_install`. Per namespace, `name` and `require`, for example `{"require": {"accountId": ["acct_7f3c"]}}` to admit one account only.
- **`auth-google`** declares `google`, with the namespace's own OAuth client. Opt-in. Per namespace: `client_id`, `client_secret` (a reference to a secret in the namespace), `allowed_domains` and/or `allowed_emails`, and optionally `name`, `cookie_domain` and `app_token: true` to admit app-tokens as well.

```ts
await lb.installPlugin("team-a", "auth-google", {
  client_id: "1234.apps.googleusercontent.com",
  client_secret: { secret: "google", key: "client_secret" },
  allowed_domains: ["example.com"],
});
await lb.setAuth("intranet", { provider: "google", publicPaths: [{ path: "/healthz" }] });
```

The plugins never replace or remove a provider somebody declared by hand: installing over one of the same name answers `409` (install with `{"name": "…"}` instead), and the automatic install skips that namespace. Uninstalling while a deployment still inherits the provider answers `409` and names the deployments.

### ci

Operator configuration: `url` (ci's listener, required), `api_token` (a reference to ci's plugin token, required), `tenant_network` (the heyvm network tenant jobs run on, required), `poll_secs`, `auto_install` (default `false`).

A namespace that installs it registers repositories, mints submit tokens and follows its runs on the region's ci. Tenant jobs read the namespace's secrets `ci`, `ci.<repo>` and `ci.<repo>.<env>`.

### pgfc and vapi

Operator consoles, not installed by namespaces: `pgfc` monitors and configures pg-fc pools (configuration `nodes`), and `vapi` watches and drives vapi inference gateways (configuration `gateways`).

## Through Heyo Cloud

A namespace managed by Heyo Cloud reaches app-lb through cloud's door, `https://<cloud>/namespaces/<ns>/lb`, with a Heyo API key. The door forwards only what it names. For plugins, that is the namespace's plugin list, installing and uninstalling `obs`, `postgres`, `artifacts`, `auth-heyo` and `auth-google`, the `obs` and `postgres` APIs, and the `artifacts` API without blob uploads. The cloud SDKs' `Namespace.workloads()` returns an [`@heyocomputer/hws`](https://www.npmjs.com/package/@heyocomputer/hws) / [`hws`](https://crates.io/crates/hws) client pointed at that door. See [SDKs](sdk.md#through-heyo-cloud).
