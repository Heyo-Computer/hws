# Changelog

Versioned with the [`hws`](https://crates.io/crates/hws) crate; the two
releases share a wire contract and are checked against the same app-lb fixtures.

## 0.2.0

First published release.

### Renamed

- The package is **`@heyocomputer/hws`**, the TypeScript twin of the `hws`
  crate. It was `heyctl` in-tree and never published under that name.
- `Hws` is the client class. `Heyctl` remains exported as the same class, and
  `HwsOptions` as an alias of `HeyctlOptions`, so only the import changes.
- Licensed Apache-2.0, like the rest of the repository.

### Added — parity with hws 0.2.0

- `whoami()` — the credential's tier, confinement and namespace.
- `startRollout(id, { operationId, expectedRevision, spec })` and
  `rollout(id, operationId)` — replace a spec by rolling a verified pool beside
  the old one.
- `discoveryStatus(id, { staged })`.
- `cordonUpstream` / `uncordonUpstream` for static upstreams.
- Namespace plugins: `namespacePlugins(ns)`, `installPlugin(ns, id, config?)`,
  `uninstallPlugin(ns, id)`, `pluginInstalls(id)`.
- Telemetry through the `obs` plugin: `obs(ns)` returns an `ObsClient` with
  `fleet`, `deployment`, `logs` (with the `before` page cursor), `alerts`,
  `createAlert` and `deleteAlert`.
- Namespaces: `namespaces()`, `createNamespace`, `deleteNamespace`.
- Workflows: `workflows`, `workflow`, `createWorkflow`, `replaceWorkflow`,
  `deleteWorkflow`.
- Auth providers: `authProviders(ns?)`, `authProvider`, `authProviderExists`,
  `createAuthProvider`, `deleteAuthProvider`.
- `startMountPull(id, force)`, `disks()`, `feedRss(ns)`, `probe(path)`.
- Errors carry app-lb's machine-readable `code` when it sends one, e.g.
  `plugin_not_installed` / `plugin_disabled` on a `ConflictError`.
- Types: `WhoAmI`, `RolloutOperation`, `DiscoveryStatus`, `NamespaceEntry`,
  `AuthProviderView`, `NamespacePlugin`, `PluginInstalls`, `NamespaceInstall`,
  `ObsFleet`, `ObsFleetRow`, `ObsDeployment`, `ObsLogs`, `ObsLogRow`,
  `ObsAlert`, `ObsMetricBucket`, `ObsLogBucket`, `ObsFreshness`, `LogQuery`,
  `NewAlert`; `PluginView` gains `per_namespace` and `installed_in`.

### Fixed

- The wire-contract test now covers every fixture app-lb writes, including the
  auth-provider and inherited-gate fixtures, a status's `site`, a gate's
  `provider_ref` and the JWT login fields — declarations the types already had
  but the test did not check.

## 0.1.0

The in-tree client: deployments, scaling, exec and shells, secrets, tokens,
feeds, jobs, metrics, certificates and fleet plugins.
