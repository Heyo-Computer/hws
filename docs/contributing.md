# Contributing

How the hws repository is laid out, how to build and test each component, how the shared dashboard UI works, and how changes are validated and released through the repository's own CI.

## Repository layout

Every service and CLI is its own Cargo project with its own `Cargo.lock`.
There is no root workspace, so you build and test each one with
`--manifest-path`.

### Services

| Directory | What it is | Docs |
| --- | --- | --- |
| `app-lb/` | Pingora load balancer, autoscaler, and control plane for heyvm microVMs. A Cargo workspace whose member `heyctl/` is the CLI. `sdk/typescript/` is the TypeScript client (`@heyocomputer/hws`); `examples/` holds deployment specs; `deploy/` holds the supervisor unit | [app-lb](app-lb.md), [heyctl](heyctl.md) |
| `app-obs/` | Logs, metrics, retention, alerts, and query API fed by app-lb. Builds `app-obs` and `app-obs-dump` | [app-obs](app-obs.md) |
| `artifacts/` | Content-addressed artifact store. Library plus the `art` CLI and `art serve` daemon | [artifacts](artifacts.md) |
| `ci/` | heyvm-backed CI orchestrator with NATS JetStream as the job queue. `bin/git-submit` is the submit client; `migrations/` are compiled into the binary | [ci](ci.md) |
| `heyosecret/` | Encrypted secrets store with a machine API and dashboard | [heyosecret](heyosecret.md) |
| `heyosecret-client/` | Rust client library the orchestrator uses to resolve secret references | [heyosecret](heyosecret.md) |
| `orchestrator/` | Control plane for sandboxes, service deployments, and regional rollouts. `docs/` holds operational notes | [orchestrator](orchestrator.md), [multi-region](multi-region.md) |
| `pg-fc/` | Postgres in Firecracker microVMs and the `pg-vm-pool` pooler. A workspace with member `api/`; `deploy/` holds rollout tooling | [pg-fc](pg-fc.md) |
| `queue/` | Dashboard and API for a NATS server | [queue](queue.md) |
| `mcp/` | MCP server (Node.js/TypeScript) exposing app-lb, app-obs, ci, and art to agents | [mcp](mcp.md) |
| `ui/` | Shared dashboard stylesheet, theme script, fonts, and Rust helpers | [below](#shared-dashboard-ui) |

### Developer tools

| Directory | What it is | Docs |
| --- | --- | --- |
| `printer/` | Spec-driven agent driver CLI | [developer tools](developer-tools.md#printer) |
| `codegraph/` | Tree-sitter code index and patch CLI | [developer tools](developer-tools.md#codegraph) |
| `computer/` | Desktop automation CLI | [developer tools](developer-tools.md#computer) |
| `plugins/` | printer plugins and integrations for Claude Code, OpenCode, and pi | [developer tools](developer-tools.md#printer-plugins) |
| `skills/` | Agent skills: `heyvm`, `git-submit` | [developer tools](developer-tools.md#skills) |

### Everything else

| Path | What it is |
| --- | --- |
| `docs/` | These pages. `docs/design/` holds design documents |
| `examples/` | Example projects built with the developer tools |
| `specs/` | printer specs used to develop printer itself |
| `.ci/` | This repository's CI: `workflows/`, build images in `image/`, installers, and `README.md` |
| `.heyo/` | Workflows and deployment metadata for the external Heyo CI/CD service: `workflows/`, `services/`, `regions/`, `fleet/`, `deployment-environments.json` |
| `.github/workflows/` | GitHub Actions build of the printer/codegraph/computer release tarballs |
| `.opencode/`, `opencode.json` | OpenCode codegraph agent and `/cg-*` commands for working in this repository |
| `.poolside/`, `.printer/` | Local agent-tool state checked into the repository |
| `AGENTS.md` | Instructions for coding agents working in the repository |
| `INTEGRATION.md` | How a desktop app embeds printer, codegraph, and computer |
| `Makefile`, `install.sh` | Build/install and binary installer for the three developer CLIs |
| `LICENSE` | Apache License 2.0 |

## Building and testing

You need a stable Rust toolchain. Service builds need some system packages; see
[installation](installation.md#build-from-source).

### Services

```sh
cargo build --locked --manifest-path <path>/Cargo.toml
cargo check --locked --manifest-path <path>/Cargo.toml
cargo test  --locked --manifest-path <path>/Cargo.toml
cargo fmt   --manifest-path <path>/Cargo.toml -- --check
```

`<path>` is one of `heyosecret`, `heyosecret-client`, `orchestrator`,
`app-lb`, `app-obs`, `artifacts`, `ci`, `queue`, `pg-fc`. Always pass
`--locked`: CI fingerprints its build caches on the lockfile.

Per-crate notes:

| Crate | Notes |
| --- | --- |
| app-lb | Test the load balancer and the CLI separately: `cargo test --locked --manifest-path app-lb/Cargo.toml -p app-lb` and `cargo test --locked --manifest-path app-lb/heyctl/Cargo.toml`. Build both binaries with `--workspace`. The SDK: `cd app-lb/sdk/typescript && npm ci && npm test` |
| app-obs | The heaviest build (DataFusion and Arrow). Lower `CARGO_BUILD_JOBS` if rustc is OOM-killed |
| ci | Links the system OpenSSL; install `libssl-dev` and `pkg-config` |
| orchestrator | Some Postgres-backed tests are `#[ignore]`d and need `ORCHESTRATOR_TEST_DATABASE_URL`; run them with `-- --ignored` (see `.ci/workflows/orchestrator.yml`) |
| pg-fc | A reclaim niceness test can fail under heavy CPU load; re-run it before treating it as a regression |
| mcp | `cd mcp && npm ci && npm run build && npm test` (tests run from `dist/`) |

Operational scripts have Python `unittest` tests beside them, for example
`.heyo/test_*.py`, `ci/deploy/test_start_artifact.py`, and
`pg-fc/deploy/test_*.py`. Run one with `python3 <file>`.

### Developer tools

```sh
cargo build --manifest-path printer/Cargo.toml
cargo test  --manifest-path printer/Cargo.toml
cargo clippy --manifest-path printer/Cargo.toml -- -D warnings
cargo fmt   --manifest-path printer/Cargo.toml
```

The same commands work for `codegraph/` and `computer/`. `make check` and
`make test` run all three; `make install` builds and installs them into
`~/.local/bin`.

### Formatting and lint

Run `cargo fmt` and `cargo clippy` for any crate you touch. Printer's CI runs
`cargo fmt --check` and `cargo clippy -- -D warnings`, so warnings fail its
build.

## Shared dashboard UI

app-lb, app-obs, ci, heyosecret, artifacts, and queue serve web dashboards that
share one look, one sign-in, and one theme. The shared pieces live in `ui/`:

| File | What it is |
| --- | --- |
| `heyo.css` | Tokens, base type, and shared primitives |
| `theme.js` | Theme toggle; writes a cookie. No framework, no build step |
| `ui.rs` | Rust helpers: asset serving, the theme cookie, forwarded identity, the top bar |
| `fonts/` | Silkscreen and IBM Plex Mono, latin subsets, self-hosted (OFL) |

Apps include `ui.rs` by path rather than depending on it, so it needs no
`Cargo.toml` entry and does not change any lockfile:

```rust
#[path = "../../ui/ui.rs"]
mod heyo_ui;
```

An app then serves `/__ui/*` from `ui.rs`, stamps `data-theme` on `<html>` from
the request's cookie before rendering, and renders `heyo_ui::topbar_html`.
`ui.rs` names no framework types, because the apps use different axum versions
and Rust editions.

Rules, enforced by tests in `ui.rs` and the apps:

- Anything a second app would want goes in `heyo.css`. An app's own stylesheet
  keeps only its own components.
- An app stylesheet declares no palette: no `:root` tokens, no
  `prefers-color-scheme`, no hard-coded `#rrggbb`. Every colour is a
  `var(--token)`.
- Both themes define the same token set. `--series-1..3`, `--grid`, and
  `--axis` are chart colours chosen for colour-vision separation; do not
  retint them.
- Font names in `heyo.css` and `ui.rs` must match.

Theme cookie configuration (`HEYO_UI_COOKIE_DOMAIN`, `HEYO_UI_COOKIE_NAME`,
and per-app `*_UI_COOKIE_DOMAIN` overrides) and the identity-forwarding opt-ins
are described in [`ui/README.md`](../ui/README.md) and
[app-lb auth](app-lb-auth.md).

A change under `ui/` changes every binary that includes it, even though no
lockfile moves. Of the CI workflows, `art.yml`, `queue.yml`, and
`heyosecret.yml` list `ui/**` in their `paths:`; `app-lb.yml`, `app-obs.yml`,
and `ci.yml` do not, so a UI-only change does not rebuild those three. Build
them locally when you change `ui/`.

## CI for this repository

Two sets of workflows exist, run by different systems.

### `.ci/workflows/` — HWS ci

These run on HWS's own [ci](ci.md) service, in heyvm microVMs. Each file is one
workflow with one job, gated by a `paths:` filter.

| Workflow | Trigger | Builds / does |
| --- | --- | --- |
| `app-lb.yml` | submit | `app-lb` and `heyctl`, with `app-lb.conf` |
| `app-obs.yml` | submit | `app-obs` and `app-obs-dump`, with `app-obs.conf` |
| `art.yml` | submit | `art` |
| `ci.yml` | submit | `ci` and its migrations, with `ci.conf` |
| `codegraph.yml` | submit | `codegraph` |
| `heyosecret.yml` | submit | `heyosecret`, migrations, `heyosecret.conf` |
| `orchestrator.yml` | submit | Tests (including Postgres-backed ones) and packages `orchestrator` |
| `pg-fc.yml` | submit | `pg-vm-pool` |
| `queue.yml` | submit | `queue`, `queue.conf`, and an app-lb deployment template |
| `regional-drain-validation.yml` | submit | Validation only: regional drain contract for app-lb and orchestrator |
| `regional-release.yml` | release | After validation passes: `merge` (`ci/merge-release`), then regional deployment jobs in order, then the controller update |

Each release artifact contains the binaries plus `SHA256SUMS` and
`BUILD-INFO`, and is tagged `ci-<workflow>-<run>-<job>-<name>` in the artifact
store. The installers in [installation](installation.md) consume these.

Build images live in `.ci/image/` (`apps/`, `ci/`, `codegraph/`). An image is
named by the hash of its Dockerfile, context, and `size_mb`, so any edit builds
a new one automatically.

When you add a workflow, copy an existing one and adjust:

1. `paths:` — the crate, **every path dependency** of it, and its own workflow
   and image files.
2. `cache_key_files:` — the lockfile, every `Cargo.toml` that can change what
   is compiled (workspace members, path deps), and `rust-toolchain.toml` even if
   it does not exist.
3. `working-directory:` — an absolute path such as `/workspace/<crate>`.
4. `cargo build --locked --bins`, plus `--workspace` if the crate has members.
5. The image — add system packages only when the dependency graph needs them
   (for example, `libssl-dev` only when nothing vendors OpenSSL).
6. `size_class` by memory need, and `ttl_seconds` for jobs longer than 60
   minutes. Steps without `timeout-minutes` get 30 minutes.

`CARGO_TARGET_DIR` points outside `/workspace`, which is wiped on every
checkout, so copy binaries back into the workspace before uploading them.
[`.ci/README.md`](../.ci/README.md) explains each of these in detail.

### `.heyo/workflows/` — external Heyo CI/CD

These use GitHub Actions syntax and run on push to `main` in the external Heyo
CI/CD service:

| Workflow | Does |
| --- | --- |
| `app-lb.yml` | Tests app-lb, heyctl, and the TypeScript SDK |
| `app-obs.yml` | Tests app-obs |
| `artifacts.yml` | Tests artifacts |
| `printer.yml` | `fmt --check`, `clippy -D warnings`, and tests for printer |
| `deploy-heyo-services.yml` | Deploys heyosecret, orchestrator, and app-obs through the orchestrator API, using `.heyo/services/*.json` and `.heyo/deployment-environments.json` |

`.github/workflows/build.yml` separately builds the printer, codegraph, and
computer release tarballs for Linux and macOS on GitHub Actions.

## Submitting changes with `git submit`

`git submit` sends a change to the ci orchestrator for validation. It uploads
the exact patch against a base revision that the runner can fetch from your
`origin`, so push the base first. There is no full-repository upload.

Install the client from this repository and point it at your ci:

```sh
ci/install-git-submit.sh                      # installs ~/.local/bin/git-submit
git config ci.endpoint https://ci.example.com
git config ci.token <token>                   # from the ci dashboard's /repos page
```

Then, from the repository root:

```sh
git fetch origin main
git submit                          # validate HEAD against trunk
git submit --only app-obs           # run one workflow (validation only)
git submit --dirty                  # include uncommitted tracked changes
git submit pr123                    # submit a GitHub pull request's head
git submit --dry-run                # show what would be sent
```

| Option | Meaning |
| --- | --- |
| `pr<number>` | Submit that pull request's exact head |
| `--ref <rev>` | Submit another commit (default `HEAD`) |
| `--dirty` | Include uncommitted tracked changes |
| `--only <workflow>` | Run only this workflow. Repeatable. Validation only; never merges or deploys |
| `--workflow <id>` | Name the workflow object the run belongs to |
| `--submit-empty` | Submit even when the tree equals the default branch |
| `--dry-run` | Inspect the submission without sending it |
| `--upgrade`, `--version` | Update or show the client |

Configuration comes from the environment first, then git config:
`CI_ENDPOINT`/`ci.endpoint`, `CI_TOKEN`/`ci.token`,
`CI_WEBHOOK_SECRET`/`ci.secret`. Use `git submit -h`; `--help` may open Git's
man page lookup instead.

A full submission runs the validation workflows its changed paths select. If
they all pass, the `on: release` workflow merges the exact validated commit and
runs the deployment jobs. Passing validation runs alone do not mean deployment
finished; follow the submission link `git submit` prints.

Before you submit a pull request branch:

- Commit everything; the worktree should be clean.
- Rebase or merge the latest `main`, and make sure the diff applies cleanly to
  it.
- Push, and check that the remote branch and the pull request head both match
  your local `HEAD`.

The [`git-submit` skill](../skills/git-submit/SKILL.md) covers run inspection
and cleanup.

## Design documents

Longer-form design material lives in `docs/design/`:

| Document | Covers |
| --- | --- |
| [`ORCHESTRATOR_DESIGN.md`](design/ORCHESTRATOR_DESIGN.md) | Orchestrator architecture |
| [`HEYO_AI_ORCHESTRATION_SERVICE_SPEC.md`](design/HEYO_AI_ORCHESTRATION_SERVICE_SPEC.md) | Orchestration service specification |
| [`MULTI_REGION_DESIGN.md`](design/MULTI_REGION_DESIGN.md) | Two-region platform design and acceptance evidence |

Component-specific notes live beside the code, for example `orchestrator/docs/`,
`pg-fc/docs/`, and each component's `README.md`. The user-facing summary of the
multi-region work is [multi-region](multi-region.md).

## Guidelines

- Keep each change within one component where you can; CI path filters then
  build only what you touched.
- Never commit credentials. Supervisor files and examples use `change-me` or
  `REPLACE-ME` placeholders; keep it that way.
- Configuration is by environment variable. When you add one, document it in
  the component's README and the matching page under `docs/`, with its default.
- When you change a CLI flag, route, or config field, update the docs in the
  same change.
