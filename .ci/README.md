# CI for this monorepo

Workflows for [`ci`](https://ci.us2.heyo.work), the heyvm-backed orchestrator.
Each file under `.ci/workflows/` is an independent run and an independent answer
to "did this commit pass"; every file here holds one job. See
[One file or two?](#one-file-or-two) below for why.

| Workflow | Job | Builds | Artifact |
| --- | --- | --- | --- |
| `codegraph.yml` | `release` | `codegraph` | `codegraph` — binary, `SHA256SUMS`, `BUILD-INFO` |
| `app-lb.yml` | `release` | `app-lb`, `heyctl` | `app-lb` — both binaries, `app-lb.conf`, `SHA256SUMS`, `BUILD-INFO` |
| `app-obs.yml` | `release` | `app-obs`, `app-obs-dump` | `app-obs` — both binaries, `app-obs.conf`, `SHA256SUMS`, `BUILD-INFO` |
| `ci.yml` | `release` | `ci` | `ci` — binary, `ci.conf`, `migrations/`, `SHA256SUMS`, `BUILD-INFO` |
| `art.yml` | `release` | `art` | `art` — binary, `SHA256SUMS`, `BUILD-INFO` |
| `queue.yml` | `release` | `queue` | `queue` — binary, `queue.conf`, an app-lb deployment template, `SHA256SUMS`, `BUILD-INFO` |
| `pg-fc.yml` | `release` | `pg-vm-pool` | `pg-fc` — tested host binary, `SHA256SUMS`, `BUILD-INFO` |
| `heyosecret.yml` | `release` | `heyosecret` | `heyosecret` — binary, `migrations/`, `heyosecret.conf`, `SHA256SUMS`, `BUILD-INFO` |

The other crates here (`computer`, `heyosecret-client`, `printer`) have no
release workflow yet. `orchestrator.yml` tests and packages the orchestrator,
and `regional-*.yml` validate and sequence regional releases. Adding one
is the recipe at the bottom.

Six crates pull `ui/ui.rs` in with `#[path]` and embed the stylesheet, the theme
script and six fonts through `include_bytes!`, so a change under `ui/` is a
change to each of their binaries even though the lockfile cannot see it. Only
`art.yml`, `queue.yml` and `heyosecret.yml` list `ui/**` in their `paths:`. `app-lb.yml`,
`app-obs.yml` and `ci.yml` do not, so a stylesheet change does not rebuild them
— worth closing next time one of those files is touched.

[`install.sh`](install.sh) is the other end of that table: it pulls the newest
of each back out of the store and installs it. See
[Installing what these build](#installing-what-these-build).

`ci.yml` builds the orchestrator that reads these files. It only builds — the
artifact is deployed by hand or by `ci/deploy/ci.json`'s `update` block, never by
the run itself — and a restart mid-run is redelivered off the JetStream work
queue, so the self-reference costs less than it looks like it should.

## Shared Rust compiler cache pilot

`ci.yml` measures dependency-fetch and Cargo phase time and can use
[`rust-cache.sh`](rust-cache.sh) with pinned sccache 0.18.0. The first pilot is
the CI crate, not all Rust workflows. Job VMs and disks remain disposable.
The script downloads a checksum-verified Linux binary into the job's data disk;
it does not rebuild the base image or change the Rust toolchain.

Caching defaults to **off**. Configure these operator variables in the existing
`ci/heyo-public/default/` HeyoSecret scope (tag variables `public`):

| Variable | Meaning |
| --- | --- |
| `CI_RUST_CACHE_MODE` | `off`, `read-only`, or `read-write` |
| `CI_RUST_CACHE_BUCKET` | Dedicated compiler-cache bucket |
| `CI_RUST_CACHE_ENDPOINT` | HTTPS S3-compatible endpoint, not the artifact HTTP API |
| `CI_RUST_CACHE_REGION` | Storage provider's signing region |
| `CI_RUST_CACHE_PREFIX` | Shared project/trust namespace, identical across regions |

Inject `CI_RUST_CACHE_ACCESS_KEY_ID` and `CI_RUST_CACHE_SECRET_ACCESS_KEY` as
secrets. Provision credentials restricted to that cache namespace, not the
release-artifact bucket or deployment credentials. A prefix is not an access
control: enforce permissions at the storage service. Only trusted submissions
may write a cache consumed by trusted releases. Use separate credentials and
namespaces for untrusted workloads. Configure bounded storage/expiration before
enabling writes. Do not modify or expire release artifacts to reclaim cache.

The cache daemon receives dedicated credentials; Cargo does not need them.
Download/startup outages fall back to compilation, while invalid configuration
and checksum mismatches fail explicitly. Logs report whether caching was active,
setup time, command time, compiler hits/misses and non-cacheable reasons. The
command's failure status is preserved. Linking, test execution, dependency
downloads and build-script work are not all cacheable; a compiler cache is not
a promise to eliminate the entire build.

### Measure before enabling

Use the same source revision, lockfile, base image/toolchain, Cargo flags,
CPU/RAM class and host for paired comparisons. Each run must use a fresh VM and
empty `target` directory; rebuilding in the same VM measures Cargo freshness,
not shared-cache reuse. Record queue wait, image preparation, VM startup,
checkout, dependency fetch, compilation, tests, packaging and upload separately.
Cargo's `Finished ... in ...` and `test result ... finished in ...` lines
separate compilation from actual test execution inside the test phase.

1. Run with mode `off` to establish the unchanged baseline.
2. Run `read-write` with a new dedicated prefix: cold-cache population.
3. Run the same revision in another fresh VM with that prefix: warm-cache read.
4. Repeat paired measurements at least three times and report medians and range.
5. Repeat the warm read in the other region; report it separately because CPU
   capacity and network latency differ.
6. Change a source input and verify affected work misses; change compiler/flags
   to verify invalidation. Check an unavailable cache still compiles and a
   failing command stays failed.

Keep source identity and sccache statistics with the run links. A fallback run
with `active=false` is not a successful cache measurement. No speedup is claimed
until the real cold/warm comparisons complete. Stage deployment policy remains
independent: these validation jobs do not deploy a service by themselves.

## One file or two?

One buildable thing per file, and one job per file. `app-lb.yml` and
`app-obs.yml` used to be two jobs of one `apps.yml`, on the theory that the load
balancer and the observability service it feeds are one deployed thing and "did
the platform build" deserves one run page. It was the wrong trade, and the
reasons are worth knowing before you put two jobs in one file here:

- **A shared run page is a shared log.** app-obs is the slowest and most
  fault-prone build in the repository, and every one of its failures sat on a
  page under a 75-minute app-lb build. Debugging one thing meant scrolling past
  another.
- **Ordering became a tax.** The two jobs were pinned to one host, so the file
  ran app-obs `needs: [app-lb]` to keep two big builds off the same cores at
  once. Every attempt to reproduce an app-obs fault therefore waited for app-lb
  first. A `needs` cannot cross files, so the split gives that ordering up —
  a commit touching both now runs both side by side, and each is slower for
  it — in exchange for `git submit --only app-obs` running one build alone.
- **Two-level gating is a footgun.** A multi-job file gates on `paths:` and
  again on each job's `if: changed(...)`, and the second list has to repeat the
  shared image and the workflow file or editing the Dockerfile starts the
  workflow and skips every job in it. One job per file needs only `paths:`.

What the two files still share is `.ci/image/apps/`, because their system
requirements are the same set, and a second Dockerfile would mean a second
10-to-20-minute image build on every runner for byte-identical contents. Every
field under `vm.build` — Dockerfile, context, `size_mb` — must stay equal in
both files, because those are what the image is named by. They get separate
warm VM pools regardless: the pool fingerprint includes `size_class`,
`disk_size_gb` and `cache_key_files`, and those differ. The workflow and job
names are *not* in the fingerprint, so the rename did not retire anybody's
warm VM.

Put jobs in one file only when they genuinely answer one question *and* one
would never be run without the other — a build and the test of that build,
say. Independent binaries get independent files.

## Public releases (no key)

[`install-apps.sh`](install-apps.sh) installs any of app-lb, app-obs, ci, queue,
art, heyosecret — and, from the private monorepo's workflows in the same store,
cloud, auth, retail and heyvm — with **no credential**:

```sh
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sh -s -- app-lb heyvm
curl -fsSL https://get.us2.heyo.work/install-apps.sh | sh -s -- --list
```

It reads `<app>.json` manifests that [`publish-releases.sh`](publish-releases.sh)
writes at release time (the key holder resolves each app's newest `ci-…` tag to
a public blob digest once), then downloads `{store}/blobs/{digest}` anonymously
and checks the digest and the build's `SHA256SUMS`. Publishing:

```sh
ART_API_KEY=… sh .ci/publish-releases.sh --all --from-url https://get.us2.heyo.work --push-tag releases-live
heyctl pull releases
```

`--push-tag` uploads the manifests and the installer to the store as one public
bundle; the `releases` site deployment on us2
([`app-lb/examples/releases-site.json`](../app-lb/examples/releases-site.json))
follows that tag. Anonymous downloads also need the store's gate to leave
`/blobs/` public (`app-lb/examples/artifacts-gated.json`); the store itself still
refuses anything but GET/HEAD of a blob marked public.

## Installing what these build

```sh
ART_URL=https://art.us2.heyo.work ART_API_KEY=… sh .ci/install.sh
```

That installs `app-lb`, `app-obs`, `ci` and `art` — binaries into
`/usr/local/bin`, supervisor programs into `/etc/supervisor/conf.d`, and `ci`'s
migrations into `/var/lib/ci/migrations`. `ci` compiles its migrations in and
the shipped `ci.conf` leaves `CI_MIGRATIONS_DIR` unset; the copied files are
only used if you set it. Nothing is restarted unless you pass `--restart`.

`art` is there because app-lb needs it beside itself: a deployment whose
`vm.workspace.store` is a local path is restored and captured by app-lb running
`art` as a subprocess, found through `APP_LB_ART_BIN` — set that to
`/usr/local/bin/art` in `app-lb.conf`. Without it the deployment's pool holds
at zero replicas with "workspace restore pending: could not run art".

Every upload above is `public: true`, so the tarball itself — not the tag — is
fetchable by link with no key: the step log ends with `[ci] public link:
https://art.us2.heyo.work/blobs/<digest>`, and the run page lists it. That is the
URL to hand a host that should not hold `ART_API_KEY`. `install.sh` still needs
the key, because it resolves tags to find the newest build and tags stay
private; a public blob is a download, not a listing.

`queue` is deliberately not in that default set: it is a dashboard for a NATS
server, so it belongs on the host running one and nowhere else. Ask for it by
name — `sh .ci/install.sh queue` — on the box that has `nats-server` on it.

`pg-fc` is also opt-in: `sh .ci/install.sh pg-fc` installs only the
`pg-vm-pool` binary. It does not configure or restart a pooler, replace heyvm,
create databases, or change registries, disks, networking, or TLS. Keep the
host's service configuration and state paths when upgrading; point its service
command at the installed binary and restart that service explicitly. For a new
peer, follow `pg-fc/README.md`'s cross-host replication configuration and use a
distinct state directory and the intended host-local heyvm endpoint. The pg-fc
artifact is private by default; use authenticated artifact-store access.

### Managed pooler replacement

`regional-release.yml` now includes a `poolers` job before the final CI update.
It downloads `pg-fc` only from the current submission's successful validation,
checks its `BUILD-INFO` against the merged checkout, and passes a pinned artifact
digest to app-lb's existing managed host-update API. No SSH, database VM rollout,
guest image update, replica promotion, or database-state restore is involved.
The existing release-workflow-change triggers still select app-lb, Orchestrator,
and CI when the release YAML itself changes; a subsequent pg-fc-only change
selects only the pooler replacement steps.

This is **stop–replace–start**, not connection-preserving handoff. Existing
connections disconnect; clients must reconnect and may need to retry aborted
transactions. An unchanged peer does not make a primary's database interruption
disappear. The installer preserves the existing systemd/Supervisor definition,
executable ownership/mode, configuration files, and schema-to-VM bindings.
It does not call any VM lifecycle API. Normal pooler background activity resumes
when the service starts; this workflow does not disable or rewrite that policy.

Before enabling this workflow, provision repository-scoped HeyoSecret
`PG_FC_ROLLOUT_TARGETS` with an ordered JSON target list. The list, not Python
code, selects region names, count, endpoints, paths and order. For the current
installation use US3 first, EU1 second. The workflow already delivers the existing
`APP_LB_US3_TOKEN` and maps `POOLER_APP_LB_EU1_TOKEN` into `APP_LB_EU1_TOKEN`
for this job. The latter is a delivery alias of the existing namespace-scoped
host deployment credential, since the ordinary EU release token is restricted
to named deployments and cannot register maintenance launchers. Additional targets need their credential
environment reference in the operator release workflow. Never embed tokens or
database passwords in target JSON or the repository.

Example shape (operator values must replace every example path):

```json
{
  "artifact_store": "https://art.example.com",
  "targets": [{
    "name": "first-region",
    "url": "https://admin.first.example.com",
    "token_env": "APP_LB_US3_TOKEN",
    "namespace": "default",
    "env_from": [{
      "namespace": "default", "secret": "artifact-reader",
      "key": "token", "as": "ART_API_KEY"
    }, {
      "namespace": "default", "secret": "ci-regional",
      "key": "CI_DATABASE_URL", "as": "CI_DATABASE_URL"
    }],
    "pooler": {
      "manager": "systemd",
      "service": "pg-fc@first.service",
      "executable": "/usr/local/bin/pg-vm-pool",
      "registry": "/var/lib/pg-fc-first/registry.tsv",
      "update_state": "/var/lib/pg-fc-updates",
      "port": 6432,
      "config_files": [
        "/etc/systemd/system/pg-fc@.service",
        "/etc/pg-fc/first.env",
        "/etc/pg-fc/first.secrets.env"
      ],
      "sql_url_envs": ["CI_DATABASE_URL"]
    }
  }]
}
```

Host prerequisites: Python 3, `psql`, permission to stop/start the exact mapped
service and replace its executable. Use `manager: supervisor` and its exact
program name for Supervisor. Existing PostgreSQL URLs are delivered through
app-lb `env_from` references, never through argv or new host credential files.
The probe forces `hostaddr=127.0.0.1` and the mapped pooler port, retains the URL's
TLS options, and runs only `SELECT 1` with read-only transactions. Set optional
`pooler.tls_server_name` to the local pooler's certificate hostname when shared
database URLs name another region; otherwise the URL hostname is retained. It
disables psql startup files and password prompts. Supported URL options are
`sslmode`, `sslrootcert`, `sslcert`, and `sslkey`; unsupported options fail before
replacement. Include a probe for every database whose connectivity must gate
the next target. Include all effective unit/drop-in and environment configuration
files in `config_files`.
Use a dedicated update state directory consistently for this pooler; it contains
only executable backups and operation receipts, never database storage.

All targets must pass download, artifact, running-process, registry and SQL
preflight before the first replacement. Each replacement waits for the old PID
to disappear, atomically installs the executable, starts only that service, then
checks the running executable hash, configuration hashes, retained bindings and
SQL probes. Failed startup/readiness restores the previous executable and
verifies it, but still fails the release and prevents updating later targets.
Rollback is binary-only and requires backward-compatible persistent state.
Do not use this workflow for incompatible registry formats or guest migrations.

The per-pooler filesystem lock prevents overlapping installers; it is not a
global CI execution lock. Do not run concurrent fleet pooler releases: regional
ordering is within one job, not a fleet-wide transaction. CI/job cancellation or
host failure can interrupt the helper; `receipt.json` records its last durable
phase. An uncertain stop/install is never blindly replayed. Inspect the protected
receipt and actual process before recovery. A successful repeated operation
revalidates without restarting. A failed operation requires explicit recovery
and a new submission; it does not silently reopen a failed CI run.

Launchers are maintenance-only `.invalid` routes with no serving traffic. They
are retained with their operation identity for reconciliation. app-lb HTTP health
verification is disabled only for these launchers because the helper performs
pooler-specific SQL/process checks instead. SQL child output is not logged.
Provision and verify the operator mapping and secret references before merge; the
workflow and fixture tests alone are not evidence of a live pooler deployment.

```sh
sh .ci/install.sh --list            # what the store has, and what each thing is
sh .ci/install.sh --dry-run         # fetch and verify, install nothing
sh .ci/install.sh app-lb            # just one
sh .ci/install.sh --ref ci-app-lb-019fca…-release-app-lb app-lb   # roll back
PREFIX=~/.local SUPERVISOR_DIR= sh .ci/install.sh   # unprivileged, no units
```

**How it finds anything.** `ci` flattens an artifact's coordinates into one tag,
because the store's tag charset has no `/`:

```
ci-<workflow>-<run>-<job>-<name>
```

which for the table above is `ci-app-lb-<run>-release-app-lb`,
`ci-app-obs-<run>-release-app-obs`, `ci-ci-<run>-release-ci`,
`ci-codegraph-<run>-release-codegraph`, `ci-art-<run>-release-art` and
`ci-queue-<run>-release-queue`. The workflow name being in the tag
means renaming a workflow starts a new series: app-lb and app-obs were built
by `apps.yml` until 2026-08-27, and their older builds are tagged
`ci-apps-<run>-app-lb-app-lb` and `ci-apps-<run>-app-obs-app-obs`. The script
falls back to those only while nothing has been published under the new
name, and `--ref` takes either. The run id is `%012x-%08x` — epoch
milliseconds in hex, then a sequence — so it is fixed-width and zero-padded, and
**sorting the tags lexicographically sorts them chronologically**. That is the
one load-bearing coincidence in the whole script, so it matches the exact hex
widths rather than a wildcard: a tag that does not have them is not considered
at all, instead of sorting somewhere arbitrary.

**What it checks.** A blob's name *is* the sha256 of its bytes, so verifying the
download against the digest it was fetched by is free, and it covers the
transfer and the store in one comparison. Then `sha256sum -c SHA256SUMS` runs
inside the unpacked tree — the build's own statement about what it produced. A
mismatch on either refuses that app and names both hashes.

**What it will not do.** It never overwrites a supervisor config. Those hold
edited secrets — the shipped `app-lb.conf` carries
`APP_LB_DASHBOARD_PASSWORD="change-me"` and every real deployment has changed it
— so an existing file is kept and the new one written beside it as
`<name>.conf.new`, with a warning that a new setting will not apply until you
merge it.

The `description:` each workflow sets on its upload is what `--list` prints, and
it is stored as an artifact *label* rather than a manifest annotation — a
manifest is addressed by its own hash, so wording inside one would fork the
manifest for byte-identical builds the first time somebody edited it.

## Submitting

From the **repository root**, not from a subdirectory:

```bash
git submit
```

The client sends a pinned base revision plus the exact patch to build; no
repository, bundle or history is uploaded, and `--archive` has been removed. The
runner fetches the base from `origin` and applies the patch, so the base commit
must be pushed first. Two things follow:

- **`.git` exists in the guest.** `git describe`, `git log` and `git rev-parse`
  work in a step (a `--dirty` submission may have a synthetic `HEAD`).
  `codegraph.yml` uses that for its version stamp.
- **Path filters actually filter.** The client computes the changed paths across
  the full trunk-to-feature diff, and `ci` matches `paths:` against them. A
  commit touching only `app-lb/` starts no `codegraph` run at all.

## Adding a workflow

Copy `codegraph.yml`, or `app-obs.yml` if the build is big enough to need a
log file and an in-guest timeout. Then change these:

1. **`paths:`** — the crate's subtree, **plus every path dependency of it**.
   Cargo does not record a path dep's contents in the lockfile, so a sibling
   crate's source is a change to your build even though nothing in your own
   directory moved. `codegraph` has none, which is why its list is short; most
   of the others here do.
2. **`cache_key_files:`** — the lockfile, plus every `Cargo.toml` that can change
   what gets compiled without moving the lockfile: sibling path deps, and
   **workspace members**. `heyctl` is a member of the `app-lb` workspace, so
   cargo records its version in `Cargo.lock` but not its feature list; the root
   manifest carries `[workspace.dependencies]` for the same reason. These are
   hashed to fingerprint the warm VM — get them wrong and a run reuses a cache
   resolved against different dependencies. List `rust-toolchain.toml` even when
   there is none: a missing file hashes to an explicit marker, so adding one
   later busts the pool at the moment it most needs busting.
3. **`working-directory:` on the build step — absolute.** Unlike GitHub, `ci`
   renders `cd <value> && …` verbatim rather than joining it onto the workspace,
   so a bare `codegraph` resolves against the login shell's home directory and
   the step dies on `cd: no such file`. Write `/workspace/codegraph`.
4. **`cargo build` flags.** `--locked`, always, because the VM's fingerprint is
   a claim about the lockfile. `--bins` to skip test and example targets. And
   `--workspace` **if the crate has members** — without it cargo builds only the
   root package, so a member like `heyctl` silently never gets built and the
   artifact is quietly missing a binary.
5. **The image**, if the toolchain differs. There are three here and none was
   guessed — each package was read off `cargo tree`:
   - `image/codegraph/`: `build-essential` and `git` only. Nothing in that graph
     links a system library.
   - `image/apps/`: adds `cmake`, `perl` and `pkg-config`, because both app
     graphs reach `aws-lc-sys` (cmake) and app-lb also builds OpenSSL and
     zlib-ng from source (perl, cmake).
   - `image/ci/`: adds `pkg-config` and **`libssl-dev`** — the counterexample
     to the trap below. Nothing in that graph vendors OpenSSL, so it links
     the distribution's copy. It has no `cmake` or `perl`, because the only
     build-adjacent crates it reaches are `cc` and `pkg-config`.

   The trap worth knowing: **two images here link OpenSSL and only one installs
   `libssl-dev`.** app-lb does not need the distribution's copy, because
   `pingora-openssl` turns on `openssl/vendored` and `openssl-src` compiles
   OpenSSL into the binary — which is also the only reason `perl` is there.
   `ci` does need it: nothing in its graph vendors OpenSSL, and there is no
   `openssl-src` entry in `ci/Cargo.lock` to prove it. So neither "it uses
   OpenSSL, add libssl-dev" nor its opposite is the reflex — read the lockfile
   for `openssl-src` and let that decide. An unnecessary package costs image
   build time on every runner and hides what the build actually depends on; a
   missing one fails the link at the very end of a cold build.
6. **The `.ci/` entries in `paths:`** — name your own workflow and image
   directory rather than `.ci/**`, so adding a workflow for another crate does
   not rebuild yours. If you added a job to an existing file, add them to that
   job's `if:` too.
7. **`size_class`, and `ttl_seconds` if the build is long.** The classes are
   micro/mini/small (1 CPU) through medium (2 CPU, 4 GB), large (4/8) and
   xlarge (8/16). Pick on **memory**, not crate count: `app-obs` has fewer
   crates than `app-lb` and needs a class more, because datafusion and arrow
   generate code that makes individual rustc invocations enormous. There is no
   swap in a microVM, so a build that wants more is OOM-killed rather than slow
   — `CARGO_BUILD_JOBS` in the job's `env` is the knob that trades wall-clock
   for headroom.

   Set `ttl_seconds` on anything whose `timeout-minutes` exceeds 60. The default
   VM TTL is `CI_VM_TTL_SECONDS` (3600), and whether the orchestrator's renewal
   loop can extend it depends on the runner's heyvmd being new enough — older
   builds computed it as `started_at + ttl`, an uptime cap that renewal could
   not move, and a build past it was reaped mid-compile. A create-time TTL is
   honoured either way.

   Also worth remembering: a step with no `timeout-minutes` gets 30 minutes,
   which a cold build will blow through long before the job timeout matters.

`ci` builds the image itself, on whichever runner the job lands on, from the
hash of the Dockerfile plus its context plus `size_mb`. An unchanged image is
reused and any edit builds a new one, so there is nothing to bump and nothing to
run by hand on a runner.

Both the `path` in `ci/upload-artifact` and everything in `cache_key_files` are
relative to the **repository root**, not to the step's working directory.
`CARGO_TARGET_DIR` points outside the workspace entirely (`/var/cache/ci/target`,
on the data disk) because `ci` wipes `/workspace` on every checkout — so a
binary has to be copied back in before it can be uploaded.
