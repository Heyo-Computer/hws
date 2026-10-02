# Parallel us3 installation

These resources add a new installation. Do not deregister a staging backend,
replace staging services, move staging runners, or copy staging deployment history.
The existing Auth service and S3 object store can be shared without moving them.

## CI

`ci.json` builds `ci/Dockerfile.firecracker` through app-lb from a pinned public
commit. It starts inert, with no route and zero replicas. The image runs CI only;
Postgres and NATS are independent services. Replace `CI_NATS_URL` with the
authenticated broker's private endpoint before starting CI. NATS needs its own
persistent JetStream storage and lifecycle, not CI's writable workspace. For an
existing bundled installation, follow the backup/restore and cutover requirements
in `ci/README.md`; existing messages and consumer state are not disposable.

Populate app-lb's `ci-us3` delivery secret from HeyoSecret: the existing
`ci-us3-trial/{database-url,cloud-api-key,webhook-secret,native-runner-secret,nats-token}`
values plus `cloud/internal-api-key` as `daemon-api-key`. The latter authenticates
the direct us3 host daemon connection through the VM's private default gateway;
it does not move the host's staging registration. No credential is rotated.

Deliver `ci-us3/heyosecret-token` as `heyosecret-token` for server-side workflow
secret resolution. CI uses the regional artifact store's separate `api-key`.
Repository registration selects the workflow file; this does not require giving
the CI process fleet-admin access to app-lb's workflow-object API. Deployment
actions receive their own target-scoped app-lb credential through workflow secrets.

Copy the existing CI app-lb authentication policy and configured admin emails
before assigning a public route. Build the pinned revision, start a replica,
grant that VM's IP/tap pair access to regional Postgres through the existing
host firewall policy, then verify CI health and runner connectivity before
moving `ci.us3.heyo.work` to it. Keep release/tag publication disabled during
installation. The public client accepts `git submit pr59`; register the public
repository with `ci/system.yml` as its workflow path.

## Artifact store

`artifacts.json` builds the public `artifacts/Dockerfile` as a **regional cache
of the global store**: the S3 bucket named by `ART_S3_BUCKET` is the system of
record for every region, so us3 sees the same tags as us2 and eu1 and its disk
only needs to hold what us3 pulls (`ART_CACHE_MAX_BYTES`, 30 GiB here). See
[the global store](../../../docs/artifacts.md#global-store).

Credentials are the canonical ones, shared with every other region — one store,
one key:

- `artifacts/api-key` — the store's API key (`ART_API_KEY`), also CI's
  `CI_ARTIFACT_TOKEN`;
- `artifacts-s3/access-key-id` and `artifacts-s3/secret-access-key` — the
  bucket credentials.

Deliver both through app-lb secrets of the same names. Build at zero replicas,
then start one and verify `/healthz`, the startup log line `global store: this
daemon is a regional cache`, and authenticated blob/manifest access before
assigning `artifacts.us3.heyo.work`. Anonymous API calls must be rejected except
for public repositories. The cache disk is service state; never recycle it as
CI job scratch space.

Configure CI's HTTP artifacts sink with that URL and credential. app-lb pulls
the same immutable manifests using an artifact credential reference. The CI
actions `ci/publish-rootfs` and `ci/deploy-app-lb` join publication to app-lb's
existing VM deployment; they do not introduce another scheduler or namespace.

## Cloud

`cloud.json` is an inert app-lb template, with no routes and zero replicas.
Cloud and Orchestrator use the new `orchestrator_us3` database together: the
current Orchestrator reads Cloud's deployment-status table directly. Never point
this instance at the existing `cloud/database-url` or `orchestrator/database-url`.

Use the existing verified us3 Ubuntu Firecracker runtime image (the image of
`orchestrator-us3`) for `vm.image`. Its Orchestrator binary is not started in this
Cloud VM. The Cloud executable and migrations come from an independently
SHA-256-verified release archive, not from that runtime image.

Render `start-cloud.sh` into the deployment's start command: write its base64
contents to `/tmp/start-cloud.sh`, then daemonize `bash /tmp/start-cloud.sh` with
stdin from `/dev/null` and output redirected to `/tmp/cloud.log`. app-lb injects
the referenced secrets; never embed their values in the launcher or this repo.
The script signs its S3 download at boot, so it does not depend on a staging
service or an expiring presigned URL. Verify the archive's recorded deployment
digest before recording its permanent URL/digest in HeyoSecret under
`cloud-us3/source-archive-url` and `cloud-us3/source-archive-sha256`.

The `cloud-us3` app-lb delivery secret holds those release references and the
existing `cloud/s3-*` values. Existing keys are not rotated. Archive cleanup in
the verified Cloud release selects records from its own database; it does not
enumerate and purge unrelated objects in the shared bucket.

Start one replica, establish the existing narrow Postgres IP/tap grant for that
candidate, and verify migrations and health before publishing
`cloud.us3.heyo.work`. Cloud's own bearer authentication protects its APIs;
verify anonymous rejection and authenticated internal requests through HTTPS.
The template leaves NATS off until a regional broker is configured. API health
alone is not complete CI/CD verification.

Backend registration must be additional and confined to the new Cloud database.
Do not change the existing daemon's staging registration or callback destination.
Inspect registration/reconciliation effects before connecting it to a backend
that also hosts existing platform VMs.
