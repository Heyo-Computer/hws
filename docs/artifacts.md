# Artifacts

The artifacts store (`art`) is a content-addressed blob store built for ext4: it holds VM images, site bundles, Dockerfile build inputs, and workspace snapshots, and serves them to app-lb and heyvm over the CLI or HTTP.

## What it is

A blob's only name is the sha256 of its bytes. Tags, manifests, and labels all point at digests. The project ships as:

- a Rust library (`artifacts`),
- the `art` CLI, which owns every destructive operation (`rm`, `untag`, `gc`, `heyvm sparsify`),
- the `art serve` HTTP daemon, which exposes content (upload, download, tags, manifests, labels) but never lifecycle.

How it fits into HWS:

- **heyvm base images.** `art heyvm import` takes heyvm's Firecracker images into the store, and `art heyvm materialize` produces a writable rootfs from one while copying only live data.
- **app-lb deployments.** A deployment's `artifact` block pulls a rootfs or site bundle from a store; its `build.store` points at a Dockerfile manifest to build; its `vm.workspace` block snapshots a workspace into a store. See [app-lb](app-lb.md).
- **heyctl.** `heyctl artifact` (alias `heyctl art`) logs in to a store and pushes images and Dockerfiles. See [heyctl](heyctl.md).
- **CI.** The CI service stores build artifacts in a store. See [ci](ci.md).

The store is Linux-only. It depends on `O_TMPFILE`, `FALLOC_FL_PUNCH_HOLE`, `copy_file_range`, and `statx`, and fails to build elsewhere.

## How it uses ext4

- **Hardlinks are references.** A read-only materialization is a hardlink, so it costs no bytes or time. The blob's `st_nlink` is the reference count, maintained by the kernel; the store keeps no counter and needs no crash recovery.
- **Sparse storage.** ext4 has no reflink, and heyvm images are fully allocated on disk but mostly zeros inside. `--squash` scans for zero runs and punches holes, so a 20 GiB image with ~600 MiB of real data takes ~600 MiB on disk. The digest still covers the full logical content, so it matches `sha256sum` of the original file.
- **Atomic, deduplicating inserts.** Bytes are written to an unnamed `O_TMPFILE`, synced, and linked into place under their digest. If the name already exists, that is a deduplication hit.
- **Free-space guard.** Writes that would leave less than `ART_MIN_FREE_BYTES` free on the filesystem are refused (exit code `3`, HTTP `507`).
- **Immutable blobs.** Blobs are mode `0444`. A writable materialization is always a private copy.

The store must be **owned by the user who reads it**. With `fs.protected_hardlinks=1` (the Linux default), only the owner can hardlink a `0444` file; a shared store silently falls back to copying for everyone else.

## Concepts

| Thing | What it is |
| --- | --- |
| Blob | Immutable bytes, named by their sha256 (64 lowercase hex characters) |
| Manifest | Canonical JSON listing named entries (`name`, `digest`, `size`) plus string `annotations`. Addressed by the sha256 of its own JSON. Has no timestamp, so re-importing an unchanged image dedupes |
| Tag | A mutable name pointing at a blob or manifest digest. Either **flat** (`debian-hermes`: `[A-Za-z0-9_.-]`, at most 64 characters) or **namespaced** (`heyo/postgres:16`: a repository, `:`, and a flat tag; a bare `heyo/postgres` means `:latest`). A 64-hex string is always a digest, never a tag |
| Repository | The part of a namespaced tag before the `:` — 1 to 4 `/`-separated lowercase segments (`[a-z0-9._-]`, each starting with a letter or digit). Has metadata: `public` and a `description`. A public repository is listed on the hub and pullable without a key |
| Label | A human `name` (max 80 characters) and `description` (max 2000) attached to a digest. Metadata only; it does not change the digest |
| Public flag | Marks one blob as downloadable without a credential. Repositories are the usual way to publish; this is for handing out one file |

A **ref** is a tag or a digest. When you ask for a blob by a tag that names a manifest, the store steps through it: a manifest with one entry resolves to that entry; a manifest with several is an error that lists them (except `art heyvm materialize`, which picks the `rootfs.ext4` entry).

Manifest kinds used today:

| Kind | Contents |
| --- | --- |
| `heyvm.rootfs.v1` | One `rootfs.ext4` entry, annotated with `heyvm.image`, `heyvm.primitive`, and `heyvm.nominal_size` |
| `heyvm.bundle.v1` | A heyvm sync bundle |
| `heyvm.dockerfile.v1` | A build input: `Dockerfile` and optional `context.tar.gz`, annotated with `heyvm.image`, `heyvm.size_mb`, `dockerfile.source` |
| `generic` | A plain collection of files |

Garbage collection marks every blob reachable from a tag (directly or through a manifest), then deletes blobs that are unreachable, have `st_nlink == 1` (no outstanding materializations), and are older than the minimum age. An untagged manifest does not keep its blobs alive. Labels and public markers for deleted content are removed in the same pass.

## Install

```sh
cargo build --release --locked --manifest-path artifacts/Cargo.toml
sudo install -m0755 artifacts/target/release/art /usr/local/bin/art
art init                    # creates the store under $ART_ROOT or ~/.artifacts
```

The HTTP daemon is behind the default-on `daemon` cargo feature and the S3 client behind the default-on `s3` feature. Build with `--no-default-features` for the library alone, or `--no-default-features --features daemon` for a daemon with no TLS stack (the remote tier then works only against `ART_REMOTE_DIR`).

## Configuration

Every value resolves flag, then environment variable, then default.

### Store (all commands)

| Env | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `ART_ROOT` | `--root` | `~/.artifacts` | Store root. Must be absolute |
| `ART_MIN_FREE_BYTES` | `--min-free-bytes` | `2147483648` (2 GiB) | Refuse writes that would leave less free space than this |
| `ART_GC_MIN_AGE_SECS` | `gc --min-age` | `3600` | Never sweep a blob younger than this |
| `ART_HEYVM_IMAGES_DIR` | none | `$MVM_DATA_DIR/images/firecracker`, else `~/.heyo/images/firecracker` | Where `art heyvm import` and `sparsify` find images |
| `RUST_LOG` | none | `art=info,artifacts=info` | Log filter (logs go to stderr) |

### Daemon (`art serve`)

| Env | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `ART_LISTEN` | `--listen` | `127.0.0.1:8080` | Listen address. Use `0.0.0.0:8080` inside a VM |
| `ART_API_KEY` | `--api-key` | unset | Shared secret for every API route except `/healthz`. **Unset means the API is open** |
| `ART_READ_ONLY` | `--read-only` | `false` | Reject every mutating route with `403` (pull-only mirror) |
| `ART_ADMIN_PASSWORD` | `--admin-password` | unset | Serve the dashboard behind a login with this password |
| `ART_ADMIN_USER` | `--admin-user` | `admin` | Dashboard login username |
| `ART_DASHBOARD_OPEN` | `--dashboard-open` | `false` | Serve the dashboard with no login. Accepts `1`/`true`/`yes`/`on` |
| `ART_DASHBOARD_GATE` | `--dashboard-gate` | `false` | Serve the dashboard behind an upstream app-lb auth gate and trust its forwarded identity |
| `ART_UI_COOKIE_DOMAIN` | none | `HEYO_UI_COOKIE_DOMAIN` | Parent domain for the shared theme cookie |

`ART_ADMIN_PASSWORD`, `ART_DASHBOARD_OPEN`, and `ART_DASHBOARD_GATE` are mutually exclusive; setting two of them is a startup error. With none set, the dashboard is not mounted at all.

| Env | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `ART_HUB` | `--hub` | `false` | Serve the public hub at `/hub` |
| `ART_HUB_HOST` | `--hub-host` | unset | The hub's host name; `/` on that host opens the hub instead of the dashboard |

### Global store (daemon and `art s3`, `art repo`)

Set `ART_S3_BUCKET` and the daemon becomes a regional cache in front of the bucket. See [Global store](#global-store).

| Env | Default | Meaning |
| --- | --- | --- |
| `ART_S3_BUCKET` | unset | The bucket. Unset means a local-only store, exactly as before |
| `ART_S3_PREFIX` | `art/` | Key prefix inside the bucket |
| `ART_S3_REGION` | `us-east-1` | Bucket region. A wrong value is corrected from S3's redirect and logged |
| `ART_S3_ENDPOINT` | unset | S3-compatible endpoint (R2, MinIO), addressed path-style |
| `ART_S3_ACCESS_KEY_ID`, `ART_S3_SECRET_ACCESS_KEY` | required with a bucket | Credentials. Deliver them from one `artifacts-s3` HeyoSecret shared by every region |
| `ART_S3_PART_SIZE` | `33554432` (32 MiB) | Multipart part size. Raised automatically past S3's 10,000-part limit |
| `ART_S3_CONCURRENCY` | `4` | Parts uploaded at once. Memory is part size × concurrency |
| `ART_REMOTE_DIR` | unset | A directory standing in for a bucket (tests, a shared mount). Exclusive with `ART_S3_BUCKET` |
| `ART_TAG_TTL` | `30s` | How long a tag read is trusted before it is revalidated against the bucket |
| `ART_SYNC_INTERVAL` | `30s` | How often the mirror, the public index and cache eviction run |
| `ART_CACHE_MAX_BYTES` | unset | Evict cached blobs once they occupy more than this |
| `ART_CACHE_MIN_FREE_BYTES` | 2 × `ART_MIN_FREE_BYTES` | Evict cached blobs once the filesystem has less free than this |

## CLI reference

Global flags: `--root`, `--min-free-bytes`, `--json` (machine-readable output on every command).

Exit codes: `0` success, `1` failure, `2` bad usage (invalid digest or tag), `3` out of space.

### Content

| Command | What it does |
| --- | --- |
| `art init` | Create the store directories |
| `art put <file\|-> [--squash] [--tag NAME]` | Store a file (or stdin) and print its digest. `--squash` punches out zero runs; use it for disk images |
| `art get <ref> -o FILE [--writable]` | Materialize a blob. Read-only is a hardlink; `--writable` makes a private sparse copy |
| `art cat <ref>` | Write a blob to stdout |
| `art stat <ref>` | Size, allocated bytes, and link count (outstanding materializations = links - 1) |
| `art manifest <ref>` | Print a manifest |
| `art ls [--blobs\|--tags\|--manifests]` | List store contents, with labels and tags |
| `art usage` | Logical size, physical size, and free space |
| `art verify [<ref>\|--all]` | Re-hash blobs and confirm they match their names |

### Names and access

| Command | What it does |
| --- | --- |
| `art tag <name> <ref>` | Point a tag at a digest |
| `art untag <name>` | Remove a tag. What it named becomes collectable |
| `art label <ref> [--name N] [--description D\|-] [--clear]` | Set or clear a label. Both fields are replaced together; `-` reads the description from stdin |
| `art public <ref> [--off]` | Make a blob anonymously downloadable over HTTP, or private again |
| `art repo ls` | Every repository, public or private, with its tags |
| `art repo public <repo> [--off]` | Publish a repository on the hub (anonymous pulls), or make it private |
| `art repo describe <repo> <text\|->` | Set a repository's description |

### Global store

| Command | What it does |
| --- | --- |
| `art s3 backfill [--dry-run] [--overwrite-tags]` | Publish this store into the bucket. Idempotent. A tag the bucket already points elsewhere is reported, not replaced, unless `--overwrite-tags` |
| `art s3 verify [--deep]` | Check every tag in the bucket reaches content the bucket holds; `--deep` downloads and re-hashes every blob |
| `art s3 gc [--dry-run] [--min-age 24h]` | Delete content no tag reaches from the bucket, under a lease so only one region collects at a time |
| `art s3 pull <ref>` | Fetch a reference and every blob in its manifest into this store's cache |
| `art s3 sync` | Mirror the bucket's tags, labels and repositories into this store once |

### Removal

| Command | What it does |
| --- | --- |
| `art rm <ref> [--force]` | Delete a blob regardless of reachability. `--force` deletes even while materializations exist |
| `art gc [--dry-run] [--min-age 1h]` | Remove unreachable blobs. Durations accept `s`, `m`, `h`, `d`, or bare seconds |

### Dockerfiles

A Dockerfile manifest is a build **input**: the recipe plus the files it copies. The store doesn't build it; app-lb fetches it and runs `heyvm mvm build`.

| Command | What it does |
| --- | --- |
| `art dockerfile put <path> [--context DIR\|ARCHIVE] [--tag NAME] [--image-name NAME] [--size-mb N] [--source TEXT]` | Store a Dockerfile and optional context as a `heyvm.dockerfile.v1` manifest. The tag lands on the manifest |
| `art dockerfile show <ref>` | Show what a Dockerfile manifest holds |
| `art dockerfile export <ref> <dir>` | Write `Dockerfile` and `context.tar.gz` (if present) into a directory |

```sh
art dockerfile put ./Dockerfile --context ./app --tag web-rootfs \
    --image-name web --size-mb 4096
```

The context is packed deterministically into one blob, so re-pushing an unchanged tree uploads nothing. Nothing is excluded: there is no `.dockerignore` handling. Point `--context` at a clean directory, or pack the archive yourself.

### heyvm integration

| Command | What it does |
| --- | --- |
| `art heyvm sparsify [names...] [--dry-run] [--no-verify]` | Punch zero runs out of heyvm's images in place (default: every `*.ext4` in the image directory). Content is re-hashed afterwards unless `--no-verify` |
| `art heyvm import [names...\|--all]` | Import images into the store as `heyvm.rootfs.v1` manifests, tagged by filename without `.ext4`. No names means all |
| `art heyvm materialize <ref> <dest> [--grow-gb N]` | Write a writable rootfs from a tag, manifest, or blob. `--grow-gb` extends the file sparsely; heyvm still runs `resize2fs` |
| `art heyvm bundle-import <dir>` | Import a heyvm sync-bundle directory |
| `art heyvm bundle-export <ref> <dir>` | Write a stored bundle back out as a directory |

Typical flow on a heyvm host:

```sh
art heyvm sparsify            # reclaim space in the existing images first
art heyvm import --all        # take them into the store
art heyvm materialize debian-hermes /tmp/rootfs.ext4
art gc
```

Run `sparsify` before `import` on a nearly full disk: the images are fully allocated until they are sparsified. `sparsify` refuses to punch holes in a file with more than one link, because that would change a running VM's disk.

## HTTP API (`art serve`)

Uploads and downloads stream, so large images never sit in memory. Small request bodies are capped at 2 MiB; blob uploads are bounded only by the free-space guard.

| Method and route | Behaviour |
| --- | --- |
| `GET /healthz` | Always open. `ok` |
| `HEAD /blobs/{digest}` | Size and allocation headers, no body |
| `GET /blobs/{digest}` | Stream the blob |
| `PUT /blobs/{digest}` | Upload (stored squashed). `201` stored, `200` already present, `409` body's digest doesn't match the URL |
| `GET /blobs` | All blobs, with labels and tags |
| `GET /manifests` | All manifests, with labels and tags |
| `PUT /manifests` | Store a manifest (JSON body); returns its digest |
| `GET /manifests/{ref}` | The manifest's own JSON, by tag or digest |
| `GET /tags` | All tags as `{"tag", "digest"}` |
| `GET /tags/{name}` | One tag. With a global store, carries the tag's `ETag` |
| `PUT /tags/{name}` | Body is a digest (plain text). `204`. With `If-Match: <etag>`, only if the tag has not moved since (`412` otherwise) — across every region |
| `DELETE /tags/{name}` | Remove a tag |
| `GET /labels/{ref}` | Label, or nulls if unlabelled |
| `PUT /labels/{ref}` | JSON `{"name", "description"}`. Replaces the whole label |
| `DELETE /labels/{ref}` | Remove the label |
| `GET /public/{ref}` | Whether a blob is public |
| `PUT /public/{ref}` | Make a blob public |
| `DELETE /public/{ref}` | Make it private again |
| `GET /repos` | Every repository with its tags; an anonymous caller sees only public ones |
| `GET /repos/{repo}` | One repository |
| `PUT /repos/{repo}` | JSON `{"public", "description"}`. Replaces the metadata |
| `DELETE /repos/{repo}` | Forget the metadata; the repository becomes private, its tags stay |
| `GET /usage` | Logical size, physical size, free space (this region's cache) |

Blob responses carry `ETag` (the digest), `Cache-Control: public, max-age=31536000, immutable`, and `x-art-allocated` (bytes actually on disk).

Namespaced references work raw or percent-encoded: `/tags/heyo/postgres:16` and `/tags/heyo%2Fpostgres%3A16` are the same tag.

Error statuses: `400` bad digest, tag, or label; `401` bad or missing key; `403` read-only mode; `404` not found; `409` digest mismatch, ambiguous manifest, or a manifest/tag naming content the global store does not hold; `412` a lost `If-Match`; `503` the global store is unreachable (writes only); `507` out of space.

There is no `gc` and no `materialize` route. Garbage collection stays in the CLI, and a remote materialization is just `GET /blobs/{digest}`.

### Authentication

With `ART_API_KEY` set, every route except `/healthz` requires the key as `Authorization: Bearer <key>` or `X-Api-Key: <key>`. The comparison is constant-time.

Anonymous requests (no credential at all) may `GET`/`HEAD` exactly what a public repository needs to be pulled:

- `/tags/{tag}` and `/manifests/{tag}` for a tag in a public repository;
- `/manifests/{digest}` and `/blobs/{digest}` for anything such a tag reaches;
- `/blobs/{digest}` for a blob marked public on its own;
- `/repos` (filtered to public repositories) and `/repos/{repo}` for a public one.

Everything else — other listings, private repositories, every write — still needs the key. A request that presents a **wrong** key is rejected even for something public. Only key holders can make a repository public.

```sh
art public web-bundle                    # or: curl -XPUT -H "x-api-key: $KEY" $URL/public/web-bundle
curl -O https://art.example.com/blobs/<digest>   # no credential needed
```

### Example: push and tag over HTTP

```sh
D=$(sha256sum rootfs.ext4 | cut -d' ' -f1)
curl -T rootfs.ext4 -H "x-api-key: $KEY" "$URL/blobs/$D"
curl -XPUT -H "x-api-key: $KEY" --data "$D" "$URL/tags/web-v2"
```

`heyctl artifact push` does this for you and stores the key in a saved registry.

## Global store

With `ART_S3_BUCKET` set, the bucket is the system of record and each regional `art serve` is a cache in front of it. Every region sees the same tags, and the bucket alone is enough to rebuild any of them — it is the backup.

- **Writes go to the bucket first.** `PUT /blobs` answers only once the blob is in the bucket. A manifest is refused (`409`) unless the bucket holds every blob it names; a tag is refused unless the bucket holds what it points at. The bucket never holds a pointer to nothing.
- **Blobs and manifests read through.** A miss is fetched, checked against its digest and kept. Concurrent misses on one blob share one download. A corrupt object is never cached.
- **Tags revalidate.** A tag older than `ART_TAG_TTL` is checked with `If-None-Match`, so a tag moved in us3 is seen in eu1 within the TTL. If the bucket is unreachable, the cached tag is served and the failure logged: an image a region already holds keeps booting during an S3 outage. Writes fail with `503`.
- **Mutable state is mirrored.** Every `ART_SYNC_INTERVAL` the daemon lists the bucket's tags, labels, public markers and repositories and updates its local copies, so listings, the dashboard and the hub show the global state. The mirror only removes local objects it copied from the bucket; a tag that exists only in one region is left alone and logged until `art s3 backfill` publishes it.
- **The disk is a cache.** Past `ART_CACHE_MAX_BYTES`, or below `ART_CACHE_MIN_FREE_BYTES` free, blobs the bucket holds and nothing has materialized are evicted, least recently used first. A blob only on this disk is never evicted.
- **Garbage collection is `art s3 gc`, never the daemon.** It holds a lease object (`locks/gc`) taken with a conditional write, so two regions cannot sweep at once, and keeps anything younger than `--min-age` (default 24h) so another region's half-finished push survives. `art gc` on a regional store only trims its cache.

The daemon refuses to start unless the bucket honours conditional writes (`If-None-Match: *`): tag compare-and-swap and the GC lease depend on it. AWS S3, R2 and MinIO all do.

Bucket requirements: **versioning on** (tag history and undelete for free) and a lifecycle rule that **aborts incomplete multipart uploads after one day**.

### Bucket layout

```text
<prefix>blobs/<aa>/<64-hex>.asp   the blob, artsparse-encoded
<prefix>manifests/<aa>/<64-hex>   canonical JSON, byte-identical to a local store's
<prefix>labels/<aa>/<64-hex>      label JSON
<prefix>public/<aa>/<64-hex>      empty marker: blob downloads anonymously
<prefix>tags/<name>               "<digest>\n" (a namespaced tag keeps its '/')
<prefix>repos/<repo>.json         {"public", "description", "updated"}
<prefix>locks/gc                  the GC lease while a sweep runs
```

**artsparse v1** keeps a sparse rootfs small in the bucket (a 64 MiB image with 12 MiB of data is a 12 MiB object): the four bytes `ASP1`, a little-endian `u32` header length, a JSON header `{"size": <logical length>, "extents": [[offset, length], ...]}`, then each extent's bytes in order. Everything outside the extents is zeros. The blob's digest covers the full logical stream, holes included, so a reader proves what it rebuilt by re-hashing.

### Moving an existing store into the bucket

```sh
art s3 backfill --dry-run     # what would be uploaded, and any tag conflicts
art s3 backfill               # safe to re-run; tags go last
art s3 verify                 # every tag reaches content the bucket holds
```

Turning on `ART_S3_BUCKET` before backfilling is safe: local-only tags keep resolving and are reported until published.

## Public hub

`ART_HUB=1` serves a catalog of public repositories at `/hub`, readable by anyone: each repository's tags, sizes, entries, and copyable pull commands. It shows nothing anonymous pulls do not already allow, and a private repository is a `404`, not a `403`.

Publish (key holders only):

```sh
heyctl artifact push postgres.ext4 --tag heyo/postgres:16 --public
# or, for an existing tag:
art repo public heyo/postgres
art repo describe heyo/postgres "PostgreSQL 16 on Debian, for heyvm"
```

Pull (anyone):

```sh
heyctl artifact pull hub.heyo.work/heyo/postgres:16 --dest ./postgres.ext4
curl -fsSL https://hub.heyo.work/manifests/heyo/postgres:16
```

An app-lb deployment pulls with no `auth`:

```json
"artifact": { "store": "https://hub.heyo.work", "ref": "heyo/postgres:16" }
```

## Dashboard

A read-only, server-rendered dashboard (no JavaScript, no external assets) lives at `/dashboard`: an overview with capacity and usage, a blob list comparing stored and logical size, a manifest list, and detail pages showing which tags and manifests reference a blob. Deleting, tagging, and GC stay in the CLI.

| Setting | Dashboard |
| --- | --- |
| nothing set | Not mounted; `/dashboard` is `404` |
| `ART_ADMIN_PASSWORD` | Login form at `/login`; session cookie (HttpOnly, SameSite=Strict) with a random per-process token. A restart signs everyone out. `curl -u admin:<password>` also works |
| `ART_DASHBOARD_OPEN=1` | No login. Only for a listener already on a private network; logged at `warn` on every start |
| `ART_DASHBOARD_GATE=1` | No local login; requests without an `x-auth-request-user` header are refused. Only safe behind app-lb, which strips and re-sets those headers |

The dashboard credentials are separate from `ART_API_KEY`. The API key does not open the dashboard, and the dashboard login does not open the API.

## Running as a microVM behind app-lb

[`artifacts/Dockerfile`](../artifacts/Dockerfile) and `init.sh` package the daemon as a heyvm image. Build from the **repository root**, because the build needs the shared `ui/` directory:

```sh
heyvm mvm build --local-only -f artifacts/Dockerfile -n artifacts --size-mb 768
art heyvm sparsify artifacts
```

In an app-lb `build` block this is `"dockerfile": "artifacts/Dockerfile"` with `"context": "."`. The image build runs a smoke test that `art serve` starts and answers `/healthz`.

`init.sh` brings up networking, mounts `/dev/vdb` at `/workspace`, starts sshd, and prints `HEYVM_READY`. It does not start the daemon; `start_command` does, so that `env_vars` (including `ART_API_KEY`) reach it.

**Put `ART_ROOT` inside `/workspace`.** The rootfs is recopied from the base image on every cold boot, so a store on the rootfs loses every blob on restart.

Example deployments:

| File | What it is |
| --- | --- |
| [`app-lb/examples/artifacts.json`](../app-lb/examples/artifacts.json) | Store VM with an API key and password-protected dashboard |
| [`app-lb/examples/artifacts-gated.json`](../app-lb/examples/artifacts-gated.json) | Store VM built from the repo, dashboard behind app-lb Google sign-in (`ART_DASHBOARD_GATE=1`), `/blobs/` public at the gate so public blobs download anonymously |
| [`app-lb/examples/artifact-pull.json`](../app-lb/examples/artifact-pull.json) | A deployment that boots from an image pulled out of a store |

Keep a store deployment at **exactly one replica** (`min_replicas: 1`, `max_replicas: 1`). Each VM has its own disk, so multiple replicas are independent stores and round-robin would return `200` or `404` depending on which one answered.

## How app-lb uses a store

app-lb addresses a store in one of two forms, and picks the transport from the spelling:

| `store` value | Transport |
| --- | --- |
| `http(s)://host:port` | app-lb talks to `art serve` over HTTP, verifying the digest as bytes arrive. Credentials come from `auth` (a secret reference to the API key) |
| `/absolute/path` | A store root on the app-lb host. app-lb runs the `art` CLI (`art --root <path> --json ...`), which needs `art` on app-lb's `PATH` or `APP_LB_ART_BIN` set to its path |

A local store is much faster (holes are skipped, bundles are hardlinked); a URL is what lets one store serve many hosts.

### Pulling a rootfs or site (`artifact`)

```json
"artifact": {
  "store": "http://127.0.0.1:8080",
  "ref": "web-v2",
  "grow_gb": 4,
  "auth": { "secret": "art", "key": "api_key" }
}
```

| Field | Meaning |
| --- | --- |
| `store` | URL or absolute path, as above |
| `ref` | Tag or digest. A tag is resolved at pull time; name a digest to pin (for rollbacks) |
| `auth` | Secret reference for the API key (URL stores only) |
| `grow_gb` | VM images only: extend the rootfs to this size |
| `image_name` | VM images only: base name; the image is written as `<name>-<12 hex of digest>.ext4`. Defaults to the deployment id |
| `strip_components` | Sites only: like `tar --strip-components` when unpacking into `site.root` |

The digest is verified before the bytes are used, and the image file is named after it, so a re-pull of content already on disk is skipped. Trigger a pull with `heyctl pull <deployment> [--ref REF] [--wait]`.

### Building from a Dockerfile manifest (`build.store`)

A deployment's `build.store` (mutually exclusive with `build.repo`) names a store holding a `heyvm.dockerfile.v1` manifest. Push one with `art dockerfile put` or `heyctl artifact push-dockerfile`, then point the deployment at it with `heyctl set build --store <url> --ref <tag>`.

### Workspace snapshots (`vm.workspace`)

A deployment's `vm.workspace` block keeps a writable directory across VM replacement. When a replica retires, app-lb captures the workspace, stores it as a `tar.gz` blob, and moves a tag to it; the next replica is seeded from that snapshot.

| Field | Meaning |
| --- | --- |
| `path` | Guest path, default `/workspace` |
| `store` | `s3://bucket[/prefix]`, an `art serve` URL, or an absolute local store path |
| `ref` | Tag the newest snapshot is published under. Default `workspace-<deployment id>` |
| `auth` | Secret reference for the store's API key |

On the app-lb host the working copies live under `/var/lib/app-lb/workspaces/<deployment>/`. app-lb refuses to move the tag if the store holds a snapshot this host has never seen, which keeps history linear. Use a dedicated tag per deployment; never share a workspace tag between two deployments. See [app-lb](app-lb.md) for the full workspace lifecycle.

## On-disk layout

```text
$ART_ROOT/
  .store.lock              flock: shared for a commit, exclusive for gc
  blobs/<aa>/<64-hex>      mode 0444, immutable
  manifests/<aa>/<64-hex>  canonical JSON, addressed by its own sha256
  labels/<aa>/<64-hex>     name and description for a blob or manifest
  tags/<name>              one digest and a newline; a namespaced tag's '/' is '~'
  repos/<repo>.json        repository metadata; '/' is '~'
  remote-state.json        ETags of what the mirror copied from the global store
  tmp/                     incoming files on the fallback insert path
```

`<aa>` is the first two hex characters of the digest.

## Common operations

```sh
art usage                              # how much space the store is saving
art ls --tags
art stat debian-hermes                 # links > 1 means VMs are using it
art verify --all                       # re-hash everything
art gc --dry-run                       # see what would be removed
art gc --min-age 2h
curl -s -H "x-api-key: $KEY" "$URL/usage"
```

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| Exit code `3` / HTTP `507` | Write would leave less than `ART_MIN_FREE_BYTES` free |
| Materializations are full copies, not hardlinks | Store is owned by a different user than the one reading it (`protected_hardlinks`) |
| `store root must be absolute` | `ART_ROOT` or `--root` is relative |
| `HOME is not set` | Running as a service with no `HOME`; set `ART_ROOT` |
| `/dashboard` returns `404` | No dashboard mode is set; set one of the three dashboard variables |
| Startup error naming two dashboard variables | Only one of `ART_ADMIN_PASSWORD`, `ART_DASHBOARD_OPEN`, `ART_DASHBOARD_GATE` may be set |
| All mutating requests return `403` | `ART_READ_ONLY` is set |
| Store VM loses every blob on restart | `ART_ROOT` is on the rootfs; move it under `/workspace` |
| app-lb: "`art` is not on app-lb's PATH" | Local-path store with no `art` binary on the app-lb host; install it, set `APP_LB_ART_BIN`, or use a URL store |
| `ambiguous` error when getting a tag | The tag names a manifest with several entries; name the entry's digest |
| Startup error "accepted a second If-None-Match" | The bucket's store ignores conditional writes; use AWS S3, R2 or MinIO |
| `409 missing_content` on a manifest or tag | The global store lacks a blob it names: upload blobs first, or run `art s3 backfill` on the region that has them |
| `503 remote_error` on writes | The bucket is unreachable; reads keep working from the cache |
| Log: "tags exist only in this region's cache" | Tags written with the CLI or before the bucket was configured; run `art s3 backfill` |
