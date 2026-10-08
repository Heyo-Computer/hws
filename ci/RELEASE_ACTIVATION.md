# Release promotion: verification and activation

The five stacked changes are opt-in. Installing their binaries alone does not
change submission behavior or enable daily builds or environment promotion.
This document is an activation procedure, not a record of a live deployment.

## Service-scoped upgrade

New release builds select one service, and promotion state is keyed by
environment and service. See [service release policies](README.md#environment-promotion-of-retained-releases)
for the current API and `services` policy shape. The environment-wide example
and procedure below describe the legacy installation, not a new activation.

Migration 052 preserves the legacy tables and adds service-scoped tables.
Upgrade every CI executor sharing the queue before setting
`CI_RELEASE_SERVICE_ENVIRONMENTS_ENABLED=true`. Until then, leave it false and
retain the legacy policy so admitted legacy work can finish. Install the same
service-scoped policy on every executor before activation. Do not copy legacy
environment pointers into service history or roll back to an executor that
cannot recognize service-scoped promotions after activation.

Configure a build component and an independent regional promotion workflow for
each service to expose it in the panel. Stage may automatically promote each
service's newest retained candidate; production may require manual promotion.
Manual promotion holds only that service's automation. Unchanged declared build
inputs reuse a retained candidate, so unrelated services need no rebuild or
redeployment. Existing managed rollout actions still own regional sequencing.

### Consolidating repository-named environments

Install support for service-level repositories on every CI executor before
changing policies. Put each service under `stage` with its existing repository,
workflow scope and rollout targets. Do not merely rename `heyo-stage` and
`hws-stage`: persisted state is keyed by environment and service.

Before retiring either name, let its active promotions finish and preserve its
service current/previous pointers, automation holds and promotion history under
the new name in one database transaction. Reject destination conflicts rather
than overwriting them. Preserve historical request identities and run references;
do not relabel legacy environment-wide history as a service deployment. Keep
automation held during this transition, then install the identical consolidated
policy on both executors and verify the panel before restoring intended modes.
Retained candidates remain repository/service scoped and need no rebuild.
Production must remain unconfigured until its targets and policy are supplied.

## State and ownership

- Existing CI PostgreSQL stores build membership, immutable bundle manifests,
  environment pointers, holds and normal persisted promotion jobs. No separate
  platform database or global CI execution lock is introduced.
- The HTTP artifact service retains release content by dedicated `release-*`
  tags. Those tags must not be removed by ordinary short-lived build cleanup.
- Use Sam's global art store through `CI_ARTIFACT_SINK=artifacts`, with a stable
  authenticated endpoint reachable from every CI region. Art owns S3 credentials;
  S3 is authoritative and regional art disks are caches. CI's raw `s3` sink does
  not provide the manifest/tag retention contract and is not interchangeable.
- Before replacing an existing standalone art instance with a disposable cache,
  verify its backfill using `artifacts/docs/runbook-global-store-migration.md`.
  A verified global cache does not require a new disk-preserving VM update path.
- CI executes existing managed rollout actions. app-lb's control panel reads and
  changes CI state through authenticated ingress; it is not a rollout authority.
- An environment is a deployment destination such as stage or production, not
  a repository or a hardcoded region. Each configured service resolves its own
  repository and rollout workflow; mode and prerequisites inherit environment
  defaults unless overridden. Its workflow determines regional order. Stage may
  be automatic; production may be manual. Both permit selection and rollback.
- A manual promotion holds automation. Resume is explicit. Existing jobs are not
  migrated or killed by an automation hold.
- Optional `requires: [environment-name]` policies require the exact bundle to
  have a settled successful promotion in each named environment. This applies to
  both manual and automatic deployment, including undoing a successful release.
  Unknown environments, mismatched repositories for the same service and cycles
  are rejected.
- After a failed partial deployment, **Recover failed deployment** restores the
  last completely successful release, not the previous release. For A → B → C,
  where C fails, recovery restores B; after a successful B, **Roll back** selects A.
  Recovery waits for the active rollout to settle and keeps automation held.
  It bypasses new prerequisites only for that exact known-good recovery target.
  Without a recorded successful release, there is no inferred recovery target.
  This is a new managed deployment, not Uber's in-progress rollback signal.

## Checked example, not live configuration

`deploy/releases.example.yml` contains three independently installed values:
`CI_RELEASE_POLICIES`, `CI_RELEASE_BUILDS`, and `CI_RELEASE_ENVIRONMENTS`.
Its syntax, artifact references, sequential jobs, target shape and different
environment modes are checked by a Rust test. Its `.invalid` targets deliberately
cannot address real infrastructure. Replace them and the scope/network values;
provision the referenced secrets using existing operator configuration.

The example releases **orchestrator only**. A bundle covers exactly its declared
components; it is not automatically a complete platform release. Before adopting
this for every service, map each component to a supported managed rollout action.
Do not silently omit components while describing a release as platform-wide.
S3/disk artifact sinks do not implement this release-retention contract.

The supported actions have different lifecycle contracts:

| Target | Action | Required operator configuration |
| --- | --- | --- |
| Stateless managed service | `ci/rollout-service` | `service_targets`: existing release mount, start command and revision marker |
| Persistent singleton service | `ci/rollout-stateful-service` | `stateful_targets`: existing Firecracker workspace, singleton scaling, release mount and revision-identifying health URL |
| Static site | `ci/rollout-site` | `site_targets`: existing site deployment and configuration fingerprint |
| PostgreSQL pooler | `ci/rollout-pooler` | `pooler_targets`: executable, process manager, config/state paths and SQL credential references |
| Host app-lb | `ci/rollout-host-app-lb` | Existing trusted host mapping, frozen at admission |
| Host heyvm/heyvmd | `ci/host-heyvm-maintenance` / `ci/rollout-host-heyvmd` | Existing trusted host mappings and a coordinator on the other host |
| CI application | `ci/deploy-controller` | Existing application membership, lifecycle authority and regional deployment configuration |

The singleton action preserves the existing workspace and changes only the
release mount and revision marker. It is stop–replace–start, not a zero-downtime
handoff; the other region must serve traffic. It verifies the new revision and
attempts to restore the prior release if replacement fails. It does not migrate
a standalone artifact store into the global store or create missing workspaces.

The pooler action embeds the existing replacement recipe; promotion workflows
cannot supply arbitrary shell commands. CI application promotion uses the same
regional update protocol as ordinary CI updates, but its provenance comes from
the retained bundle rather than a new Git merge. Running build jobs are not
replaced with the CI application.

## Local and disposable verification

Run the default CI and app-lb suites on Linux, then the targeted database tests
against a **disposable** PostgreSQL instance:

```sh
cargo test --locked --manifest-path ci/Cargo.toml --bin ci
cargo test --locked --manifest-path app-lb/Cargo.toml --bin app-lb
CI_TEST_DATABASE_URL=postgres://.../disposable \
  cargo test --locked --manifest-path ci/Cargo.toml --bin ci release_build -- --include-ignored
CI_TEST_DATABASE_URL=postgres://.../disposable \
  cargo test --locked --manifest-path ci/Cargo.toml --bin ci release_environment -- --include-ignored
```

Build tests exercise atomic duplicate admission, incomplete/failed producers and
artifact retention failure/retry. Promotion tests exercise retained provenance,
manifest tampering, distinct revisions, duplicate requests, independent
environments, unresolved rollout receipts, failure/hold/resume, and preservation
of the previous version. These are real database checks, not VM rollouts.

The Linux artifact integration test uses real art HTTP servers with independent
caches and one filesystem-backed remote:

```sh
cargo test --locked --manifest-path ci/Cargo.toml --bin ci \
  artifacts::tests::global_store_release_survives_region_cache_loss_and_build_cleanup
```

It checks cross-cache retention, build-tag deletion and remote garbage collection,
retrieval after deleting both caches, and refusal to acknowledge a new release
pin when the authoritative remote is unavailable. It does not test live S3,
deployed credentials, or the backfill status of existing regional stores.

The control-panel HTTP test starts a real app-lb, with fixture auth and HTTPS CI
ingress. Enable native CA roots **for this fixture build** so it can trust its
ephemeral test CA; this does not disable certificate verification:

```sh
cargo build --locked --manifest-path app-lb/Cargo.toml --bin app-lb \
  --features reqwest/rustls-tls-native-roots
node app-lb/testdata/release_transport.cjs
PLAYWRIGHT_MODULE=<installed-playwright> SCREENSHOT_DIR=<existing-directory> \
  node app-lb/testdata/releases.cjs
```

The HTTP test checks identity forwarding, mutation payload/status, catalog
pagination, credential isolation and cross-origin refusal. Browser checks cover
real HTML with API fixtures. Neither proves live ingress configuration or a
complete source-build-to-regional-rollout cycle.

## Activation after approval

1. Merge the stack bottom-up and deploy the compatible CI and app-lb binaries
   through the existing deployment mechanism. Keep release policies unchanged
   until every participating instance runs the compatible code.
2. Install the build policy, initially without a daily cutoff. Build one merged
   revision manually and confirm all selected artifacts are retained. Install
   environment policies in manual mode and provision their existing target and
   credential mappings. Use the same policy on all CI instances.
3. Configure each control panel's `APP_LB_RELEASE_CI_URL` with the authenticated
   CI ingress. Confirm the signed-in operator can read the catalog and is a CI
   admin. Do not use an ungated backend address or copy passwords into the panel.
4. Finish outstanding legacy deployments to these targets, then switch the
   repository to `merge_only`. Verify that a submission validates and merges but
   does not deploy. Other CI work continues normally; no global execution gate.
5. Manually deploy a retained release in stage through the panel. Exercise both
   regional stages, current/previous reporting, rollback, and restart recovery.
   Keep one region unchanged and healthy until the other has completed its
   update or recovery. Record continuous traffic and actual service revisions.
6. After those live checks pass, enable the daily build cutoff and stage's
   automatic policy, then explicitly resume automation. Keep production manual.
   Exercise a manual older-version selection in automatic stage: it must remain
   held until resumed, without rebuilding the selected artifacts.

Do not infer live readiness from the local checks. Live source builds, ingress
identity forwarding, region drain, rollback and service health remain activation
acceptance requirements. A failed partial rollout leaves the last-complete
pointer unchanged; its individual service records may show mixed revisions.
