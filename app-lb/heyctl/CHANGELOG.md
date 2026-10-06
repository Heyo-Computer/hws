# Changelog

All notable changes to the `hws` crate (the Heyo Web Services SDK and the
`heyctl` CLI). The crate follows [semantic versioning](https://semver.org/);
while it is `0.x`, a minor bump may break the API.

## Unreleased

### Added

- **Tokens for every server.** `NewToken::on_all_servers()` (and
  `heyctl token mint … --all-servers`) mints at a control-plane app-lb a token
  that every server mirroring it accepts. `TokenSummary` gains `fleet` and
  `mirrored_from`; `heyctl token list` has a SERVERS column and `heyctl token
  describe` says where a token works and where to revoke it.

### Changed

- `NewToken` and `TokenSummary` have new public fields, which breaks code that
  builds either one with a struct literal. Use `NewToken::new(…)` and its builder
  methods instead.

## 0.2.0 — unreleased

The crate is now the SDK for creating and managing workloads on Heyo, including
reading their telemetry, with a namespace-scoped token.

### Added

- **Telemetry.** `Client::obs(namespace)` returns an `ObsClient` that reads the
  metrics and logs the `obs` plugin collects for a namespace: `fleet`,
  `deployment`, `logs` (with `LogQuery` filters and `before` paging) and alert
  rules (`alerts`, `create_alert`, `delete_alert`). Reads go through app-lb's
  `/namespaces/:ns/plugins/obs/…` routes, so a namespace token is enough and
  app-obs's address and credential are never needed.
- **Namespace plugins.** `namespace_plugins`, `install_plugin`,
  `uninstall_plugin` and (fleet scope) `plugin_installs`. `PluginView` gains
  `per_namespace` and `installed_in`.
- **Workload API gaps.** `whoami` (with `WhoAmI::sole_namespace`),
  `start_rollout` / `rollout` for replace-by-rollout with an idempotency key and
  revision check, and `discovery_status`.
- Unparsed variants of the new reads on `client.raw()`, and every new call on
  `blocking::Client`.
- CLI: `heyctl plugins install|uninstall ID [-n NS]`, `heyctl plugins list -n
  NS`, `heyctl plugins installs ID`, `heyctl logs DEPLOYMENT [-n NS] [--since
  --level --grep --backend --limit]`, and `heyctl top -n NS [--window]`. When
  `-n` is omitted, the namespace comes from the token (via `/whoami`) when the
  token is confined to exactly one.
- `examples/namespace_workload.rs`: create, observe, roll out and delete a
  workload with a namespace token.

### Changed

- Repository metadata points at `Heyo-Computer/hws`; docs.rs builds the library
  features.

## 0.1.1 — 2026-10-01

First release on crates.io under the name `hws`. Same code as `heyctl` 0.1.x
(formerly `serverctl`): the async and blocking app-lb clients, the artifact
store client, and the `heyctl` binary, which keeps its name. Library users
change `heyctl::` / `serverctl::` paths to `hws::`.
