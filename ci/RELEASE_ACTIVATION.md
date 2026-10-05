# Release promotion: verification and activation

The five stacked changes are opt-in. Installing their binaries alone does not
change submission behavior or enable daily builds or environment promotion.
This document is an activation procedure, not a record of a live deployment.

## State and ownership

- Existing CI PostgreSQL stores build membership, immutable bundle manifests,
  environment pointers, holds and normal persisted promotion jobs. No separate
  platform database or global CI execution lock is introduced.
- The HTTP artifact service retains release content by dedicated `release-*`
  tags. Those tags must not be removed by ordinary short-lived build cleanup.
- CI executes existing managed rollout actions. app-lb's control panel reads and
  changes CI state through authenticated ingress; it is not a rollout authority.
- An environment is a named repository-specific policy, not a hardcoded region.
  Its sequential workflow determines regional order. Stage may be automatic;
  production may be manual. Both permit manual selection and rollback.
- A manual promotion holds automation. Resume is explicit. Existing jobs are not
  migrated or killed by an automation hold.
- Optional `requires: [environment-name]` policies require the exact bundle to
  have a settled successful promotion in each named environment. This applies to
  both manual and automatic deployment, including undoing a successful release.
  Unknown environments, cross-repository dependencies and cycles are rejected.
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
Legacy arbitrary shell deployments (including the pooler shell workflow) are not
accepted as promotion actions by this implementation. Do not silently omit them
while describing a release as platform-wide. S3/disk artifact sinks likewise do
not implement this release-retention contract.

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
