# SDKs

Two SDKs drive app-lb from code — deployments, scaling, exec and shells, builds and pulls, secrets, tokens, and every namespace plugin — one for TypeScript and one for Rust, released together and checked against the same wire contract.

| Language | Package | Install |
| --- | --- | --- |
| TypeScript / JavaScript | [`@heyocomputer/hws`](https://www.npmjs.com/package/@heyocomputer/hws) on npm | `npm install @heyocomputer/hws` |
| Rust | [`hws`](https://crates.io/crates/hws) on crates.io ([docs.rs](https://docs.rs/hws)) | `cargo add hws --no-default-features` |

The Rust crate is also the `heyctl` CLI (`cargo install hws` installs the binary); `--no-default-features` leaves out the CLI and gives you only the library. Both are versioned together (currently 0.4.0) and tested against the response fixtures app-lb's own tests write, so a field app-lb sends that an SDK does not model fails a test rather than going missing. Their changelogs: [TypeScript](../app-lb/sdk/typescript/CHANGELOG.md), [Rust](../app-lb/heyctl/CHANGELOG.md).

For the routes underneath, see the [HTTP API](http-api.md) and the [API reference](api/overview.md).

## Connecting

Point a client at an app-lb's admin API with a credential: an app-token (`applb_…`), a federated Heyo bearer, or the operator's Basic auth. A token minted for one namespace (`heyctl token mint … --namespace team-a`) reaches that namespace and nothing else, which is the right credential for an application or an agent.

```ts
import { Hws } from "@heyocomputer/hws";

const lb = new Hws({ server: "https://admin.example.com", token: process.env.APP_LB_TOKEN });
console.log(await lb.whoami());   // tier, confinement, namespace
```

```rust
let lb = hws::Client::builder("https://admin.example.com")
    .token(std::env::var("APP_LB_TOKEN")?)
    .build()?;
println!("{:?}", lb.whoami().await?);
```

The Rust crate also has a blocking client, `hws::blocking::Client`, with the same methods.

## Deployments

```ts
await lb.createDeployment({
  id: "web", namespace: "team-a",
  routes: [{ host: "web.example.com" }],
  vm: { image: "nginx-fc", port: 80 },
  scaling: { min_replicas: 0, max_replicas: 4 },
});
await lb.waitForReady("web");
const out = await lb.exec("web", "uname -a");
```

Everything a deployment does is here: `deployment`/`deployments`, `replaceDeployment`, `patchScaling`, `startBuild`/`startPull` and `waitForJob`, rollouts, `exec` and an interactive `shell`, `deleteDeployment`. Writes take the spec as a plain object and send it as is.

## Plugins

Each namespace [plugin](plugins.md) with an API has a client, and every call carries the namespace's wall: a `409` with `code: "plugin_not_installed"` until the namespace installs it.

| Plugin | TypeScript | Rust | Calls |
| --- | --- | --- | --- |
| any | `namespacePlugins`, `installPlugin`, `uninstallPlugin` | `namespace_plugins`, `install_plugin`, `uninstall_plugin` | What a namespace can install, and installing it with its configuration |
| any (operator) | `plugins`, `plugin`, `setPlugin`, `pluginInstalls` | `plugins`, `plugin`, `set_plugin`, `plugin_installs` | Enable and configure a plugin for the host |
| `obs` | `lb.obs(ns)` | `lb.obs(ns)` | `fleet`, `deployment`, `logs` (paged), `alerts`, `createAlert`, `deleteAlert` |
| `postgres` | `lb.postgres(ns)` | `lb.postgres(ns)` | `databases`, `createDatabase`, `deleteDatabase` |
| `artifacts` | `lb.artifacts(ns)` | `lb.artifacts(ns)` | `info`, `tags`, `tag`, `setTag`, `deleteTag`, `manifest`, `repo`, `setRepo` |
| `auth-heyo`, `auth-google` | `lb.setAuth(id, gate)`, `lb.clearAuth(id)` | `lb.set_auth(id, &Gate)`, `lb.clear_auth(id)` | Put a deployment behind the provider the plugin declared, or take it out (since 0.4.0) |

```ts
// A database for the app, its URL handed to the deployment as a secret.
await lb.installPlugin("team-a", "postgres");
await lb.postgres("team-a").createDatabase({ name: "app" });   // writes secret pg-app

// Heyo sign-in in front of the app, its health check left open.
await lb.setAuth("web", { provider: "heyo", publicPaths: [{ path: "/healthz" }] });

// Its errors from the last hour.
const page = await lb.obs("team-a").logs("web", { level: "error", window: "1h" });
```

```rust
use hws::{Gate, NewDatabase};

lb.install_plugin("team-a", "postgres", None).await?;
lb.postgres("team-a").create_database(&NewDatabase::new("app")).await?;
lb.set_auth("web", &Gate::provider("heyo").public("/healthz")).await?;
```

## Errors

Failures are typed: `NotFoundError` / `Error::NotFound`, `ForbiddenError` / `Error::Forbidden`, `ConflictError` / `Error::Conflict` (with app-lb's `code`, such as `plugin_not_installed`), `UnauthorizedError`, invalid requests, and transport errors. Each carries app-lb's message, which says what to do next.

## Through Heyo Cloud

A namespace on Heyo Cloud is reached through cloud's door, `https://<cloud>/namespaces/<ns>/lb`, with a Heyo API key instead of an app-token. The cloud SDKs hand you an `hws` client already pointed there:

| Language | Package | Accessor |
| --- | --- | --- |
| TypeScript | [`@heyocomputer/sdk`](https://www.npmjs.com/package/@heyocomputer/sdk) | `Namespace.connect("team-a").workloads()` returns an `Hws` |
| Rust | [`heyo-sdk`](https://crates.io/crates/heyo-sdk) | `Namespace::connect("team-a", opts)?.workloads()?` returns an `hws::Client` |

`workloads()` arrives in `@heyocomputer/sdk` 0.2.0 and `heyo-sdk` 0.2.0, both built on hws 0.4.0. The door exposes deployments, secrets, auth providers, and the `obs`, `postgres`, `artifacts`, `auth-heyo` and `auth-google` plugins; see [Through Heyo Cloud](plugins.md#through-heyo-cloud).
