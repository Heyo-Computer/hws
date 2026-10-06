# Namespaces and plugins

A namespace is the wall a tenant's deployments, secrets, tokens and auth providers sit behind. These endpoints list and declare namespaces, install per-namespace plugins such as `obs`, switch plugins on for the fleet, and read each namespace's event feed.

Back to the [API reference](overview.md).

## Namespaces

| Method and path | Tier | Crate |
| --- | --- | --- |
| `GET /namespaces` | View, narrows itself | `Client::namespaces() -> Vec<NamespaceEntry>` · `Raw::namespaces()` |
| `POST /namespaces` | CRUD, operator | `Client::create_namespace(&spec) -> Value` |
| `DELETE /namespaces/:name` | CRUD, operator | `Client::delete_namespace(name) -> ()` |

`GET /namespaces` lists the namespaces the caller can see, with the number of their deployments the caller may view. A credential confined to one namespace gets that namespace back even when it is empty.

```json
[{"namespace": "team-a", "deployments": 4, "declared": true,
  "description": "Payments team", "created_at": 1760000000},
 {"namespace": "scratch", "deployments": 1, "declared": false}]
```

| Field | Meaning |
| --- | --- |
| `deployments` | Deployments in it that this credential may see. |
| `declared` | A namespace object exists, as opposed to the name being one a deployment mentions. Both scope the same way; only a declared one can be described or deleted. |
| `description`, `created_at` | Declared namespaces only. |

`POST /namespaces` declares one: `{"name": "team-a", "description": "…"}`. It answers `201` with `{name, description, created_at}` when new and `200` when it existed; re-declaring updates the description and keeps `created_at`. Declaring a namespace also installs every enabled plugin that installs automatically (see [obs](obs.md)). A confined credential gets `403`, and an invalid name `400`.

`DELETE /namespaces/:name` undeclares one and answers `204`. It is refused with `409` while deployments are still in it.

On Heyo's managed fleet, namespaces are created in Heyo cloud, not on app-lb.

## Namespace plugins

Some plugins install per namespace. Two switches decide whether one does anything for a namespace: the operator **enables** it for the fleet ([below](#fleet-plugins)), and a namespace administrator **installs** it into the namespace. Both must be on.

| Method and path | Tier | Crate |
| --- | --- | --- |
| `GET /namespaces/:ns/plugins` | View, namespace wall | `Client::namespace_plugins(ns) -> Vec<NamespacePlugin>` · `Raw::namespace_plugins(ns)` |
| `GET /namespaces/:ns/plugins/:id` | View, namespace wall | not in the crate |
| `PUT /namespaces/:ns/plugins/:id` | CRUD, admin of the whole namespace | `Client::install_plugin(ns, id, config) -> NamespacePlugin` |
| `DELETE /namespaces/:ns/plugins/:id` | CRUD, admin of the whole namespace | `Client::uninstall_plugin(ns, id) -> NamespacePlugin` |

From [`namespace-plugins.json`](../../app-lb/testdata/wire/namespace-plugins.json):

```json
[
  {"id": "obs", "name": "Observability",
   "description": "Logs, metrics and alerts for every app in a namespace.",
   "enabled": true, "installed": true, "installed_at": 1760000000,
   "installed_by": "token:0123456789ab", "config": {}}
]
```

| Field | Meaning |
| --- | --- |
| `enabled` | The fleet-wide switch, which the operator controls. |
| `installed`, `installed_at`, `installed_by` | This namespace's install. `installed_by` is `token:<id>`, `user:<id>` or `auto`, and absent for the operator. |
| `config` | The per-namespace configuration. `obs` takes none: send `{}`. |

`PUT` installs the plugin or replaces its per-namespace config, and is idempotent. The body is `{"config": {…}}`, optional; the crate sends `{}` when `config` is `None`. `DELETE` uninstalls; it is allowed while the plugin is disabled. Both return the plugin as the namespace now sees it.

"Admin of the whole namespace" is the operator, a fleet admin token, a namespace token with `admin` scope and no `deployments` list (or `["*"]`), or a federated `namespace:<ns>:admin` grant. A namespace token narrowed to particular deployments gets `403`.

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Invalid namespace name, or config the plugin rejects. |
| `403` | `Forbidden` | Not an administrator of the whole namespace. |
| `404` | `NotFound` | No such plugin, or one that does not install per namespace. |
| `409` | `Conflict` | The operator has the plugin switched off (`"code": "plugin_disabled"`). |

## Fleet plugins

Plugins are compiled into app-lb and switched on per host. These routes are fleet-wide: a confined caller gets `403`.

| Method and path | Tier | Crate |
| --- | --- | --- |
| `GET /api/plugins` | View, operator | `Client::plugins() -> Vec<PluginView>` · `Raw::plugins()` |
| `GET /api/plugins/:id` | View, operator | `Client::plugin(id) -> PluginView` |
| `PUT /api/plugins/:id` | CRUD, operator | `Client::set_plugin(id, enabled, config) -> PluginView` |
| `GET /api/plugins/:id/installs` | View, operator | `Client::plugin_installs(id) -> PluginInstalls` · `Raw::plugin_installs(id)` |
| `POST /api/plugins/:id/enable`, `/disable` | CRUD, operator | not in the crate; `set_plugin` with `config: None` does the same |

A plugin, from [`plugins.json`](../../app-lb/testdata/wire/plugins.json):

```json
{"id": "example", "name": "Example", "description": "A plugin that is switched on and failing.",
 "config_schema": {"type": "object", "properties": {"url": {"type": "string"}}},
 "per_namespace": true, "installed_in": ["team-a"],
 "enabled": true, "config": {"url": "http://127.0.0.1:34199"},
 "updated_at": 1760000000, "last_error": "connection refused", "status": {"state": "retrying"}}
```

| Field | Meaning |
| --- | --- |
| `config_schema` | JSON Schema for `config`. Advisory; app-lb validates on write. |
| `per_namespace`, `installed_in` | Whether namespaces install it themselves, and which have. |
| `enabled`, `config` | The stored record. `config` is kept while disabled. |
| `last_error` | Why the last apply failed. A plugin can be enabled and failing at once. |
| `status` | Whatever the plugin reports about itself. |

`PUT /api/plugins/:id` takes `{"enabled": true, "config": {…}}`. With `config` omitted, the stored config is kept. It answers `200` once the record is saved, **even if applying it failed**: check `last_error` on the result. Invalid config is a `400`.

`GET /api/plugins/:id/installs` lists every namespace the plugin is installed in. app-obs polls it to learn what to collect. From [`plugin-installs.json`](../../app-lb/testdata/wire/plugin-installs.json):

```json
{"plugin": "obs", "enabled": true, "namespaces": ["team-a", "team-b"],
 "installs": {"team-a": {"installed_at": 1760000000, "installed_by": "user:u_123", "config": {}},
              "team-b": {"installed_at": 1760000000, "installed_by": null, "config": {}}}}
```

## Feeds

Each namespace has a feed of lifecycle events and issues: deployments added, changed and removed, and problems such as cold-start timeouts.

| Method and path | Tier | Crate |
| --- | --- | --- |
| `GET /feeds` | View, operator | `Client::feeds() -> Vec<FeedIndexEntry>` · `Raw::feeds()` |
| `GET /feeds/:namespace?format=json` | View, namespace wall | `Client::feed_events(ns) -> Vec<FeedEvent>` · `Raw::feed_events(ns)` |
| `GET /feeds/:namespace` (or `:namespace.xml`) | View, namespace wall | `Client::feed_rss(ns) -> String` |

`GET /feeds` lists namespaces with events: `[{"namespace": "team-a", "events": 12}]`. A namespace's feed is RSS by default, for feed readers; `?format=json` returns the events, newest first:

```json
{"id": 7, "ts": 1722400000, "last_ts": 1722400120, "count": 3, "namespace": "team-a",
 "deployment": "web", "kind": "issue", "title": "web: cold start timed out",
 "detail": "a request waited 120s and no VM became available"}
```

| Field | Meaning |
| --- | --- |
| `id` | The RSS `<guid>`. |
| `ts`, `last_ts`, `count` | Repeats of the same issue fold into one event: first seen, last seen, and how many times. |
| `kind` | `deployed`, `updated`, `removed` or `issue`. |
