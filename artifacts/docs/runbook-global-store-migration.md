# Runbook: evolve an existing art store into the global store

Turn a running `art serve` deployment into the first regional cache of the S3
global store, without losing anything it holds. Written against
`art.us2.heyo.work` (app-lb deployment `artifacts` on host `us2`), but nothing
here is us2-specific except the names.

The rule that shapes every step: **the store's data lives on a per-sandbox
disk, and replacing the sandbox can lose it.** A rebuild, `restart`, spec edit
or app-lb orphan sweep creates a new sandbox. With no `vm.workspace` the new
disk is blank (2026-08-28); with one, it is restored from the last *capture*,
which only happens when a replica retires and can be weeks old (2026-09-29
rolled art.us2 back to Aug 30). So the store goes into the bucket **from a
copy taken off the running VM, before anything replaces it.**

Once this is done, the bucket is the system of record and that hazard is gone:
a replaced store VM refills from the bucket.

## 0. Prerequisites

- [ ] A build of this branch's `art` for the host (`cargo build --release
      --locked --manifest-path artifacts/Cargo.toml`), copied to the host as
      `/root/art-mig/art`. The host already runs `art` for workspace restores
      (`APP_LB_ART_BIN`), but that binary predates `art s3`.
- [ ] The bucket, in the region the stores mostly run near:
  - [ ] **versioning enabled** (tag history and undelete);
  - [ ] lifecycle rule: **abort incomplete multipart uploads after 1 day**;
  - [ ] an IAM user (or R2 token) limited to that bucket: `GetObject`,
        `PutObject`, `DeleteObject`, `ListBucket`, `AbortMultipartUpload`.
- [ ] HeyoSecrets, one canonical set for every region (AGENTS.md):
  - [ ] `artifacts-s3/access-key-id`, `artifacts-s3/secret-access-key`;
  - [ ] `artifacts/api-key` — **the key the store already uses**, not a new
        one. Check the secret's metadata against the live deployment's
        `ART_API_KEY` before going on. Rotating it now would break heyctl and
        serverctl registries, fastcar's `art` secret and CI's sink in the
        middle of the migration; rotate afterwards, once.
- [ ] Delivered to the us2 app-lb as secrets `artifacts` and `artifacts-s3`.

Set these in the shell on the host for every `art` command below (never in a
file that outlives the session):

```sh
export ART_S3_BUCKET=<bucket> ART_S3_REGION=<region> ART_S3_PREFIX=art/
export ART_S3_ACCESS_KEY_ID=... ART_S3_SECRET_ACCESS_KEY=...
export ART_MIN_FREE_BYTES=0
```

Check the credentials and the bucket before anything else. `art s3 probe` is
the same check `art serve` makes before it starts — reachable, credentials
accepted, conditional writes honoured:

```sh
/root/art-mig/art --root /root/art-mig/empty s3 probe
```

## 1. Copy the live store off the running VM

Do not restart, rebuild or `apply` the deployment during this step.

```sh
SB=sb-XXXXXXXX       # the live replica's sandbox: `heyctl describe artifacts`
mkdir -p /root/art-mig && cd /root/art-mig
cp --sparse=always /var/lib/heyvm/run/$SB/data.ext4 data.ext4      # the copy is what we touch
cp --sparse=always data.ext4 work.ext4 && e2fsck -fy work.ext4     # the journal was live
mkdir tree && debugfs -R "rdump /store $PWD/tree" work.ext4         # ART_ROOT=/workspace/store
```

If the extracted blobs come out dense, the backfill uploads their zeros too:
larger, never wrong — the digest covers the logical bytes either way.

Check the copy is a whole store and agrees with the live one:

```sh
/root/art-mig/art --root /root/art-mig/tree/store verify --all
/root/art-mig/art --root /root/art-mig/tree/store ls --tags > tags-copy.txt
curl -s -H "x-api-key: $KEY" https://art.us2.heyo.work/tags > tags-live.json
```

Every tag in `tags-live.json` should be in `tags-copy.txt` with the same
digest. A tag written in the seconds since the copy is fine — step 4 picks it
up.

Keep `data.ext4` until step 6 is signed off. It is the rollback.

## 2. Backfill the copy into the bucket

```sh
cd /root/art-mig
./art --root tree/store s3 backfill --dry-run     # blobs, bytes, tags; any conflicts
nohup ./art --root tree/store s3 backfill > backfill.log 2>&1 &
```

Safe to interrupt and re-run: it skips what the bucket already holds and
uploads tags last, so the bucket never holds a tag naming something missing.
Read the end of `backfill.log`:

- `skipped … is in neither store` — a manifest whose blob this store had
  already lost. The bucket refuses to hold a pointer to nothing; nothing to do
  but re-push that artifact from its source.
- `conflict …` — only possible if something else already wrote to this prefix.
  Stop and look before `--overwrite-tags`.

Then prove the bucket is whole:

```sh
./art --root /root/art-mig/empty s3 verify --deep
```

## 3. Cut over

Edit the deployment spec — the image, and only these `vm` fields:

```jsonc
"env_vars": {
  // existing ART_ROOT, ART_LISTEN, dashboard settings stay
  "ART_S3_BUCKET": "<bucket>",
  "ART_S3_REGION": "<region>",
  "ART_S3_PREFIX": "art/",
  "ART_CACHE_MAX_BYTES": "<~80% of disk_size_gb in bytes>"
},
"env_from": [
  { "secret": "artifacts", "key": "api-key", "as": "ART_API_KEY" },
  { "secret": "artifacts-s3", "key": "access-key-id", "as": "ART_S3_ACCESS_KEY_ID" },
  { "secret": "artifacts-s3", "key": "secret-access-key", "as": "ART_S3_SECRET_ACCESS_KEY" }
]
```

Remove `ART_API_KEY` from `env_vars` when it moves to `env_from`. Leave
`vm.workspace` as it is for now (step 6). Then build and roll as usual
(`heyctl set build artifacts --build-context .`, `heyctl build artifacts`).

What the new replica does on its first start, in order:

1. probes the bucket — **it refuses to start** if the credentials are wrong or
   the bucket ignores conditional writes, so a bad secret shows up as a replica
   that never goes Ready, with the reason in `/var/log/art.log`, not as a store
   that silently writes nowhere;
2. mirrors the bucket's tags, labels and repositories into its cache;
3. serves. Whatever the old replica's capture left on disk is a cache; blobs
   it lacks are fetched from the bucket on first request.

Writes are safe from the first request. A push whose blob the cache already
holds, or a tag naming a manifest only this cache has, publishes that content
to the bucket before succeeding.

## 4. Catch the tail

Anything written to the old replica after the step 1 copy is now either in the
new replica's cache (if the retirement capture got it) or nowhere. Look:

```sh
heyctl exec artifacts -- grep -c "exist only in this region" /var/log/art.log
```

That line counts tags the cache holds that the bucket does not. If it appears,
publish them from the retirement capture, exactly as in steps 1–2 but from
the workspace store instead of the run directory:

```sh
cd /root/art-mig && mkdir tail
art --root /var/lib/app-lb/workspace-store cat artifacts-workspace | tar -xz -C tail
./art --root tail/store s3 backfill
```

Then compare against the list from step 1 — every tag in `tags-live.json`
must resolve:

```sh
for t in $(jq -r '.[].tag' tags-live.json); do
  curl -s -o /dev/null -w "%{http_code} $t\n" -H "x-api-key: $KEY" \
    "https://art.us2.heyo.work/tags/$t"
done | grep -v '^200'          # prints nothing when all are there
```

## 5. Verify with the real clients

- [ ] `heyctl artifact ls` and `heyctl artifact describe <tag>` — same tags,
      same digests as `tags-live.json`.
- [ ] A push: `heyctl artifact push <file> --tag migration-check`, then
      `./art --root /root/art-mig/empty s3 verify` shows it in the bucket.
- [ ] Every deployment that pulls from the store (`artifact.ref`,
      `build.store`, `vm.workspace.store`: on us2 that is bdr-agent, docs,
      the marketing sites, fastcar's workspace, CI's artifact sink) —
      `heyctl pull <deployment> --wait` succeeds for one of each kind.
- [ ] `/healthz` and the dashboard.
- [ ] `art s3 gc --dry-run --min-age 24h` reports what it would remove, and
      none of it is a tag in `tags-live.json`.

## 6. Make the store VM disposable

With the bucket as the system of record, the `vm.workspace` capture is now
the thing that can hurt: restoring a stale capture only warms the cache, but
the capture/restore cycle is what has stalled art.us2 twice. Remove
`vm.workspace` from the spec, so a replaced VM simply starts with an empty
cache and refills from the bucket — no capture to go stale, no restore to
block on. Delete `/root/art-mig` (it holds
store contents and, in shell history, credentials) once this is signed off.

## Rollback

Until step 6 every step is additive: the bucket only gained objects, and the
old store's data is in `/root/art-mig/data.ext4` and the workspace capture.

- **Before step 3:** nothing to undo. Optionally delete the `art/` prefix.
- **After step 3:** re-apply the previous spec (no `ART_S3_*`). The cache the
  replica restored from its capture serves as before. Anything pushed while
  the global store was on is in the bucket; publish it back with `art s3 pull
  <ref>` against the restored store, or re-push it.

## Adding the next region

After us2: `.heyo/regions/us3/artifacts.json` is already a global-store cache
with the canonical secrets. There is nothing to backfill — a new region starts
empty and fills from the bucket. Verify `/healthz`, the startup line `global
store: this daemon is a regional cache`, and that a tag pushed in us2 resolves
in us3 within `ART_TAG_TTL`.
