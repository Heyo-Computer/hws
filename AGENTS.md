# hws — Heyo Web Services

## Two Regions, One Heyo System

- Make the Heyo platform work across us3 and eu1 before expanding CI deployment work. CI is an application that consumes the platform, not a substitute for proving it.
- Use one canonical HeyoSecret credential per operator/service role across regions. Do not create divergent regional identities for the same role or collapse unrelated roles into one universal credential. Check credential metadata, including the username, before reporting an access blocker. Never commit credential values.
- Complete backend enrollment, authentication, and placement through managed platform configuration/APIs. Verify that both regional orchestrators use the same authoritative rollout state; matching database names or replicated copies alone do not prove shared coordination.
- Prove the platform with a disposable application first: the same immutable revision in both regions, region/revision-identifying responses, both app-lbs consuming the same discovery authority, and requests through both regional ingresses and the normal application entry point.
- Acceptance requires continuous requests during withdrawal, confirmed in-flight drain, upgrade, health verification, traffic restoration, and bake, first for us3 and then eu1. Require no failed test requests and no new admissions to withdrawn backends. The surviving serving path must not depend on the drained region's ingress.
- Exercise an unhealthy candidate, controller restart mid-rollout, and rollback. Verify durable plan progress, preserved serving capacity, and no duplicate candidates after restart. Do not infer these properties from unit tests alone.
- Test regional infrastructure maintenance separately. A successful application rollout does not prove that restarting app-lb or another regional dependency is safe. Move traffic away before maintenance, verify recovery, and only then restore traffic.
- Only after these gates pass should CI move onto the verified platform, with shared application state and coordinated job ownership.
- Keep one acceptance checklist with evidence and unresolved blockers. Two healthy endpoints, sequential regional deployments, or a green release run do not establish that the two-region system works. Distinguish deployed capability from configured capability and executed live tests.

## Continue Through Authorized Work

- When the user approves a plan, execute its implementation, verification, and authorized operational follow-through without stopping after each milestone to ask whether to continue.
- Treat status questions and interruptions as steering, not cancellation. Answer briefly and continue outstanding work unless the user explicitly pauses or replaces it.
- Persist unfinished work and its evidence so the next session resumes execution rather than repeating planning or investigation.
- Stop only on completion, an explicit user pause, or a concrete blocker that cannot be resolved within existing authority and access. Before stopping, finish independent work and identify the exact missing action or access, not a generic request to proceed.
- This continuity rule does not authorize unrelated releases, destructive cleanup, or other shared-state changes outside the approved scope. Never disable safeguards or manufacture test success to avoid reporting a blocker.

## Pull Request Completion

- When the user asks to create or update a PR, completion requires both an open PR and **`git submit` readiness**, not GitHub Actions or PR-check status.
- After every authorized branch push, create or update the open PR targeting the intended trunk and report its URL. A merged or closed PR from an earlier use of the branch does not count.
- Before reporting a PR change ready, ensure the intended changes are committed, the worktree is clean, the branch contains the latest trunk, its net diff applies cleanly to that trunk exactly as `git submit` requires, `HEAD` matches the remote branch, and the PR's head SHA matches `HEAD`.
- Do not tell the user to wait for GitHub PR CI and do not use GitHub-hosted checks as the readiness signal unless the user explicitly asks for them.
- Do not run `git submit` unless the user explicitly asks; report that it is ready for the user to submit.

## Platform services
- paths: `heyosecret/`, `heyosecret-client/`, `orchestrator/`, `app-lb/`, `app-obs/`, `artifacts/`, `ci/`, `queue/`, `pg-fc/`, `remote/`
- build: `cargo build --locked --manifest-path <path>/Cargo.toml`
- check: `cargo check --locked --manifest-path <path>/Cargo.toml`
- test: `cargo test --locked --manifest-path <path>/Cargo.toml`
- format check: `cargo fmt --manifest-path <path>/Cargo.toml -- --check`
