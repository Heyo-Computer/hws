# artifacts

A content-addressed artifact store built for **ext4**, and wired into heyvm.

The digest of a blob's bytes is its only name. Everything else — tags, manifests
— is a pointer to a digest. Ships as a library, a CLI (`art`), and a v2 daemon.

```
art heyvm sparsify        # punch the zero runs out of heyvm's base images
art heyvm import --all    # take them into the store, hashed whole, stored sparse
art heyvm materialize debian-hermes /tmp/rootfs.ext4   # a writable rootfs, fast
art gc                    # remove what nothing references
```

## Why

ext4 has no reflink. `FICLONE` returns `EOPNOTSUPP`, which mvm-ctrl's own
`reflink_or_copy` documents and works around by falling back to a full byte copy
(`heyo/mvm-ctrl/src/driver/firecracker.rs:3496-3524`). So every Firecracker boot
copies the entire base rootfs, because Firecracker opens a rootfs read-write
(`firecracker.rs:2596-2638`). For a 20 GiB image on a filesystem with 7 GiB free,
that boot simply fails.

Two measurements, taken on the machine this was written for, determine the whole
design:

**The images are dense on disk.** `stx_blocks * 512 == stx_size` for all 14 of
them; `debian-hermes.ext4` was 21.5 GB fully allocated across 9190 extents. A
`SEEK_DATA`/`SEEK_HOLE`-based "sparse copy" reclaims **exactly zero** here. That
is the trap: it ships, it passes its tests, and it does nothing.

**They are logically mostly zero.** `dumpe2fs -h` on `debian-hermes.ext4`
reported 4,935,809 of 5,242,880 blocks free — 94.1%. Only a userspace scan for
zero runs plus `FALLOC_FL_PUNCH_HOLE` finds that.

Measured result on the real image set:

| | before | after |
|---|---|---|
| `~/.heyo/images/firecracker` on disk | 30 G | 7.4 G |
| `debian-hermes.ext4` allocated | 20.0 GiB | 581 MiB |
| free space on `/` | 6.9 G (99% used) | 30 G (94%) |
| materializing a 20 GiB rootfs | 21.5 GB copied | **581 MiB in 3.3 s** |

Content is unchanged and proven so: `sha256sum -c` passes on every image and
`e2fsck -fn` reports every filesystem clean.

## What it does with ext4

- **`st_nlink` is the reference count.** A read-only materialization is a
  hardlink — zero bytes, zero time — and the kernel maintains the count in the
  same journal transaction as the link. The store keeps no counter, so there is
  no window in which its count and reality disagree, and nothing to reconcile
  after a crash. A materialization in `/tmp` is a GC root the store cannot
  enumerate and does not need to.
- **`O_TMPFILE` + `link`, never `rename`.** A blob's name is unknown until its
  bytes are hashed, so it is written to an unnamed inode and linked into place
  afterwards. `link`'s `EEXIST` *is* the deduplication hit — "we already have
  this" is the same syscall as the insert, with no pre-check race. `rename`
  would silently replace an existing blob, decoupling hardlinks already handed
  to running VMs from the store's own entry.
- **`fdatasync` before `linkat`, enforced by the type system.** Reversed, ext4's
  `data=ordered` can journal the name before the data and survive a crash as a
  correctly-named blob with the wrong bytes. `link_into` consumes a `SyncedTmp`
  that only the `fdatasync` call can construct.
- **Zero-run scanning, not hole detection.** See above.
- **Inode-ordered GC scans.** htree `readdir` returns name-hash order, which is
  uncorrelated with inode number — but inode number is strongly correlated with
  position in the on-disk inode table. `d_ino` comes free from `getdents64`, so
  sorting by it costs nothing and turns a random table walk into a sequential one.
- **`f_bavail`, not `f_bfree`.** The store root here is mounted
  `errors=remount-ro`: filling it produces a read-only root filesystem, not an
  error return. The guard runs before the first byte and, for an import whose
  final size is unknowable, every 256 MiB after.

## Install

```sh
cargo build --release      # target/release/art
```

Linux only, and deliberately so — `O_TMPFILE`, `FALLOC_FL_PUNCH_HOLE`,
`copy_file_range` and `statx` have no portable equivalents. Building elsewhere
fails with a message saying as much rather than silently degrading.

## Configuration

Every value resolves flag → environment → default.

| Env | Flag | Default | Meaning |
|---|---|---|---|
| `ART_ROOT` | `--root` | `~/.artifacts` | Store root. Must be absolute. |
| `ART_MIN_FREE_BYTES` | `--min-free-bytes` | `2147483648` (2 GiB) | Refuse writes that would leave less free than this. |
| `ART_GC_MIN_AGE_SECS` | `--min-age` (on `gc`) | `3600` | Never sweep a blob younger than this. |
| `ART_HEYVM_IMAGES_DIR` | — | `$MVM_DATA_DIR/images/firecracker`, else `~/.heyo/images/firecracker` | Where `heyvm import` and `heyvm sparsify` look. |
| `ART_LISTEN` | `--listen` | `127.0.0.1:8080` | `art serve` listen address. Use `0.0.0.0:8080` in a VM. |
| `ART_API_KEY` | `--api-key` | *(unset)* | Shared secret for every route except `/healthz`. Unset means open. |
| `ART_READ_ONLY` | `--read-only` | `false` | Reject every mutating route with `403`. For a pull-only mirror. |
| `ART_ADMIN_PASSWORD` | `--admin-password` | *(unset)* | Dashboard password. **Unset means the dashboard is not served at all.** |
| `ART_ADMIN_USER` | `--admin-user` | `admin` | Dashboard username. |
| `ART_DASHBOARD_OPEN` | `--dashboard-open` | `false` | Serve the dashboard with no login. For a listener already on a private network. Takes `1`/`true`/`yes`/`on`. Conflicts with `ART_ADMIN_PASSWORD`. |
| `ART_DASHBOARD_GATE` | `--dashboard-gate` | `false` | Serve the dashboard behind an upstream app-lb auth gate, trusting its `x-auth-request-*` identity. Conflicts with the two above. |
| `ART_FORCE_NO_TMPFILE` | — | unset | Force the named-temp-file insert path. Testing only. |
| `ART_TEST_DIR` | — | `$TMPDIR` | Where tests create their scratch directories. |
| `RUST_LOG` | — | `art=info,artifacts=info` | Tracing filter. |

The store must be **per-user**. `/proc/sys/fs/protected_hardlinks` is 1 on a
default Linux install, so only the owning uid may hardlink a mode-`0444` blob; a
shared `/var/lib` store would silently degrade every materialization to a copy.

## Commands

```
art put <file|-> [--squash] [--tag NAME]    art get <ref> -o FILE [--writable]
art cat <ref>                               art stat <ref>
art ls [--blobs|--tags|--manifests]         art usage
art tag <name> <ref>                        art untag <name>
art label <ref> [--name N] [--description D|-] [--clear]
art manifest <ref>                          art rm <ref> [--force]
art public <ref> [--off]                    art init
art verify [<ref>|--all]                    art gc [--dry-run] [--min-age 1h]

art dockerfile put <path> [--context DIR|ARCHIVE] [--tag NAME]
                          [--image-name NAME] [--size-mb N] [--source TEXT]
art dockerfile show <ref>                   art dockerfile export <ref> <dir>

art heyvm sparsify [names...] [--dry-run] [--no-verify]
art heyvm import [names...|--all]
art heyvm materialize <ref> <dest> [--grow-gb N]
art heyvm bundle-import <dir>               art heyvm bundle-export <ref> <dir>

art serve [--listen ADDR] [--api-key KEY] [--read-only]
```

`--json` on any command. Exit codes: `1` failure, `2` bad usage, `3` out of space.

## Dockerfiles

Every other manifest kind here describes a build **output**. `heyvm.dockerfile.v1`
describes a build **input** — the recipe that defines a rootfs, plus the files it
copies from:

```
art dockerfile put ./Dockerfile --context ./app --tag web-rootfs \
    --image-name web --size-mb 4096
```

```
kind: heyvm.dockerfile.v1
entries:
  Dockerfile        required
  context.tar.gz    optional; omit for a recipe that copies nothing in
annotations:
  heyvm.image       default name for the image this builds
  heyvm.size_mb     default `heyvm mvm build --size-mb`
  dockerfile.source provenance, free-form
```

The tag lands on the manifest, not on either blob — the manifest is what carries
the annotations, and a tag on the recipe alone would resolve to a Dockerfile with
no context and no image name.

The store does not build it. It has no Docker, no heyvm and no opinion about what
a `RUN` line means; app-lb's `image-build` job fetches this manifest, unpacks it
and drives `heyvm mvm build`. What the store contributes is the address: a
manifest digest covers the recipe, the context *and* the annotations, so "which
inputs produced this image" has an answer that a moving tag cannot change
underneath.

Two consequences worth stating plainly:

- **The context is one blob, not one blob per file.** A build context is consumed
  whole and exactly once, so per-file addressing buys nothing at read time and
  costs an inode and a `link` per file at write time. The price is that changing
  one byte re-uploads all of it.
- **Nothing is excluded.** No `.dockerignore` handling, no built-in skip list. A
  packer that silently dropped files would produce a build that fails on a host
  nobody is watching, with an error pointing at the Dockerfile rather than at the
  packer. Point `--context` at a clean directory, or pack it yourself and pass the
  archive.

Packing is deterministic (`tar::HeaderMode::Deterministic`), so re-pushing an
unchanged tree lands on the same digest and uploads nothing.

## Names and descriptions

A digest is the only name content has, and that is the right contract — but it
leaves a store you cannot read. `art ls --blobs` was a column of 64-hex strings,
and the dashboard was the same column with sizes beside it.

A **label** is a name and a description for a digest:

```sh
art label web-v2 --name "the web rootfs" --description "debian + hermes agents"
art label <digest> --description -   <<'EOF'
The base image every sandbox boots from.
Rebuild with `art heyvm import` after `make images`.
EOF
art label web-v2 --clear
```

```
$ art ls --blobs
1b9b737b73e2…  581 MiB   20.0 GiB  links=3  web-v2  the web rootfs
9f2ce41a0d84…  4.1 MiB   4.1 MiB   links=1  —
```

**A label is metadata *about* content, never part of it.** Naming something does
not change its digest, so every tag, manifest entry and outstanding
materialization still resolves afterwards. That is the whole reason it is a
side-car file rather than a field:

- **A blob has nowhere to put a name.** Its bytes are an ext4 image or a tarball.
- **A manifest has somewhere, and it is still wrong.** A manifest is addressed by
  the hash of its own JSON, so a `name` field inside it makes *renaming a fork*:
  a new digest, the old tags still pointing at the old manifest, and two
  manifests describing one thing. This is the same argument that keeps a
  timestamp out of a manifest, and it bites harder — nobody edits a timestamp,
  and people edit descriptions constantly.

So one mechanism serves both, because blobs and manifests are addressed the same
way. Labels are swept by `art gc` once the thing they describe is gone.

### Labels and tags answer different questions

| | tag | label |
|---|---|---|
| what it is | an address | a description |
| unique | yes | no |
| charset | `[A-Za-z0-9_.-]`, ≤64 | any text; ≤80 and ≤2000 characters |
| moving it | changes what resolves | changes nothing |
| `art get <this>` | works | does not |

Both are shown together everywhere, because between them they answer "what is
this?" — the tag says what to type, the label says whether you want it.

Limits are in characters, not bytes. A name is refused if it carries a control
character, because it is rendered inline in a table cell, an `art ls` row and a
log field, and one newline breaks all three; a description keeps its line breaks
and refuses everything else.

## Serving

`art serve` exposes the store over HTTP. Uploads and downloads stream, so a
twenty-gigabyte image never lands in memory.

```
GET    /healthz              always open, no auth — this is the readiness probe
HEAD   /blobs/{digest}       size and allocation without transferring anything
GET    /blobs/{digest}       stream the content
PUT    /blobs/{digest}       201 stored · 200 already had it · 409 digest mismatch
GET    /blobs                what is in the store, with labels and tags
GET    /manifests/{ref}      by digest or tag
GET    /manifests            the manifests, with labels and tags
PUT    /manifests            returns the manifest's digest
GET    /tags                 GET|PUT|DELETE /tags/{name}
GET    /labels/{ref}         GET|PUT|DELETE — a name and description by ref
GET    /public/{ref}         GET|PUT|DELETE — anonymous-download flag by ref
GET    /usage
```

`GET /blobs` and `GET /manifests` are the browse routes: before them a client
could only ask about a digest it already had, which made the store unlistable
over HTTP. Each row carries the label and the tags pointing at it, fetched once
per request rather than per row.

`GET /labels/{ref}` answers `200` with nulls for an unlabelled digest rather than
`404` — the digest exists, the label is what does not, and a client rendering a
row should not have to special-case an error to learn that. `PUT` replaces the
whole label; a body naming only a description clears the name. `GET /manifests/
{ref}` is deliberately **not** enriched: its body is the manifest's own bytes,
which a client may re-hash, so a label has no business in it.

Everything except `/healthz` sits behind `ART_API_KEY` when one is set
(`Authorization: Bearer` or `X-Api-Key`, compared in constant time over a hash
so the comparison cannot leak the key's length). `/healthz` stays open on
purpose: a readiness probe carries no credentials, and a health endpoint behind
auth reports the service unhealthy the day the key rotates.

One more thing may be open, and only ever on purpose: a blob marked public
(`PUT /public/{ref}`, or `art public <ref>`) answers anonymous `GET`/`HEAD
/blobs/{digest}` — download only. The flag is per-blob and resolves through
tags the way labels do, but it exempts nothing else: listings, manifests and
every mutating route still need the key, and a request that *presents* a wrong
key is rejected even for a public blob, so a stale credential fails loudly
instead of silently downgrading to anonymous. `art public --off <ref>` (or
`DELETE /public/{ref}`) closes it again, and GC removes a marker the moment
its blob is swept — a re-inserted blob starts private.

There is deliberately **no `materialize` route and no `gc` route**. A hardlink
cannot cross a wire, so asking for materialization remotely can only ever mean
"send me the bytes" — which is `GET /blobs/…`. Garbage collection is destructive
and stays in the CLI.

The daemon is behind the default-on `daemon` cargo feature. Depend with
`default-features = false` to get the library without an axum tree — which is
what mvm-ctrl should do, since it is pinned to axum 0.7.

## Dashboard

A server-rendered dashboard lives at `/dashboard`: an overview with the
effective-capacity figure, stat tiles and a filesystem meter, a blob list with a
stored-versus-logical bar per row, and detail pages showing which tags and
manifests reference a given blob.

Every listing leads with **what the thing is** — the tags that name it as chips,
and its [label](#names-and-descriptions) as text — and the digest follows. That
ordering is the point: a table whose first column was twelve hex characters made
the reader scan every row to find the one they wanted. A detail page is headed by
the label's name where there is one, with the generic word ("Blob", "Manifest")
demoted beneath it — a heading of "Blob" over a digest told the reader only what
the URL already had. An unlabelled, untagged row shows a muted dash, so "nothing
is known about this" reads as a state rather than as a broken renderer.

```sh
ART_ADMIN_PASSWORD=… art serve --listen 0.0.0.0:8080
```

**It is not served unless you ask for it** — off, not open. A store's tag names
and blob sizes describe what an organisation builds and deploys, and that should
not become public because a variable went unset.

There are two ways to ask, and the default is neither of them:

| | Dashboard |
|---|---|
| *(nothing set)* | not mounted — every path under `/dashboard` is a `404` |
| `ART_ADMIN_PASSWORD=…` | mounted, behind a login |
| `ART_DASHBOARD_OPEN=1` | mounted, no login at all |

```sh
# private network — the listener is already the access control
ART_DASHBOARD_OPEN=1 art serve --listen 10.0.0.4:8080
```

Use `ART_DASHBOARD_OPEN` when the listener is already unreachable from anywhere
you do not trust — a wireguard address, a VPC-internal bind, a VM whose port is
only forwarded to its host. It is an explicit opt-in because this process cannot
check that claim; it can only log it, which it does at `warn` on every start.
Setting both a password and `ART_DASHBOARD_OPEN` is an error rather than a
precedence rule: whichever won, half the configuration would be a lie, and the
half that lost would be the half someone believed was protecting the page.

Bind matters more than the flag. `--listen 0.0.0.0:8080` with `ART_DASHBOARD_OPEN=1`
publishes the store's contents to every network the host is on.

When it is behind a login, its credentials are **separate from `ART_API_KEY`**. That key authenticates
machines and travels in a header no browser sends; the dashboard is read by
people, so it gets a username, a password, a login form, and an HttpOnly
`SameSite=Strict` session cookie carrying a random per-process token — never the
password, and nothing derived from it. A restart invalidates outstanding
sessions. `curl -u admin:… ` also works, for scripted checks. Holding the API key
does **not** open the dashboard, and vice versa.

Everything on it is read-only. Deleting a blob, moving a tag and running a sweep
stay in the CLI: a misplaced click should not be able to collect a blob a VM is
booting from, and even a dry-run sweep takes the store lock exclusively, so a
page load would stall every writer on the host.

No JavaScript and no external assets — not minimalism for its own sake, but
because this runs in a microVM with no route to a CDN, where a remote font or
script would simply fail to load.

## Running as a Firecracker microVM

`Dockerfile` + `init.sh` package the daemon as a heyvm microVM, following the
same pattern as the vault/`tk` image:

```sh
# from the repository root — the build needs ui/ as well as this crate
heyvm mvm build --local-only -f artifacts/Dockerfile -n artifacts --size-mb 768
art heyvm sparsify artifacts     # 768 MiB -> ~110 MiB
```

`init.sh` is PID 1: it brings up networking, formats and mounts `/dev/vdb` at
`/workspace`, starts sshd, and prints `HEYVM_READY`. It does **not** start the
app — that is `start_command`'s job, because environment variables reach only
that process and `ART_API_KEY` has to travel somehow.

`ART_ROOT` must point inside `/workspace`. The base rootfs is re-copied from the
image on every cold boot, so a store on the rootfs would silently lose every blob
on restart.

A ready-to-`POST` app-lb deployment lives at
[`app-lb/examples/artifacts.json`](../app-lb/examples/artifacts.json). Note it is
pinned to a single replica: each VM has its own disk, so *N* replicas are *N*
independent stores and a round-robin proxy would answer the same `GET` with a
`200` or a `404` depending on where it landed.

## Layout

```
$ART_ROOT/
  .store.lock            flock; shared for a commit, exclusive for a sweep
  blobs/<aa>/<64-hex>    mode 0444, immutable
  manifests/<aa>/<64-hex>  canonical JSON, addressed by its own sha256
  labels/<aa>/<64-hex>   a name and description for a blob or a manifest
  tags/<name>            one digest and a newline
  tmp/                   incoming; named only on the no-O_TMPFILE path
```

Fanout is two hex characters — 256 shards, one level. ext4 directories are
htree-indexed so lookup was never the constraint; what the fanout bounds is the
directory inode's size and the cost of the whole-store `readdir` that GC
performs. Three levels would spend 65,536 directory inodes to hold a few
thousand blobs.

## Design notes

Non-obvious decisions, each verified against the behaviour it depends on.

**`linkat(AT_EMPTY_PATH)` does not work unprivileged.** It is the obvious
spelling and it returns `EPERM` without `CAP_DAC_READ_SEARCH`. The store uses
the documented unprivileged recipe instead:
`linkat(AT_FDCWD, "/proc/self/fd/N", AT_FDCWD, dest, AT_SYMLINK_FOLLOW)`.
`O_TMPFILE` must also never carry `O_EXCL`, which makes the file permanently
unlinkable.

**The digest covers the full logical stream, including skipped zeros.** Every
function that declines to read or write a region still feeds the corresponding
zeros to the hasher. Hashing the sparse representation would give addresses that
no longer match `sha256sum` or mvm-ctrl's `BlobRef.sha256`
(`heyo/mvm-ctrl/src/driver/sync.rs:79-85`) — verified against the real images:
`art`'s digest for `debian-hermes.ext4` is `c74abee2ce84…`, exactly what
`sha256sum` reports.

**A manifest has no timestamp.** A creation time would make the same logical
manifest hash differently on every write, so re-importing an unchanged image
would accumulate a fresh manifest each time instead of deduplicating to the one
already stored. `annotations` is a `BTreeMap` for the same reason: serialization
order must not depend on insertion order. The blob's own birth time already
answers "when did this enter the store".

**Tags name manifests, and `resolve_blob` steps through them.** The manifest is
what carries an image's annotations, so a tag has to point at it — but then
`art get debian-hermes`, the most likely thing anyone types, would fail with
"blob not found". A manifest with one entry resolves to it; one with several is
reported as ambiguous, naming the entries.

**No database.** The filesystem is already the source of truth for blob
existence *and* for the reference count, both maintained transactionally by the
kernel. A sqlite index would duplicate facts whose correct resolution on
disagreement is always "believe the filesystem", at which point it is a cache
that does not pay for itself at fourteen images. Crash recovery is consequently
nothing at all — no WAL, no journal, no "the DB says this blob exists".

**Tags are regular files, not symlinks.** A symlink target is a path you must
re-parse and re-validate, reintroducing the traversal boundary `Digest::parse`
just removed; the kernel does not validate targets, so a dangling tag would be
indistinguishable from a typo; symlinks do not affect `st_nlink`; and replacing
one atomically still needs temp + rename anyway.

**An untagged manifest does not keep its blobs alive.** Otherwise garbage
sustains itself and the store never shrinks.

**Never punch a hole in an inode with `nlink > 1`.** Punching acts on the inode,
so it is visible through every name and every open descriptor — including a
running VM's disk. `sparsify` asserts rather than documenting.

**Import is hash-bound, not IO-bound.** sha256 over 21 GB at ~1.5 GB/s is about
14 seconds against roughly one second to copy the live data, so every path hashes
exactly once, in `spawn_blocking`. Bundle import verifies *and* stores in the
same pass, which is strictly stronger than `blob_ref_for()` + `verify_blob()`
(`sync.rs:500`, `:530`) and reads each file once instead of twice.

**`copy_file_range` short returns are normal.** It is documented to return less
than requested, and a loop that treats that as an error, or forgets to advance
both offsets, corrupts data in a way small-file tests never catch. The loop is
extracted behind a function pointer and tested against a shim that copies one
byte per call.

**Writable materialization is a copy and is not reference-counted.** Firecracker
opens a rootfs read-write; a hardlink would let a guest rewrite content whose
name is a promise about what it contains. Mode `0444` on blobs enforces this
structurally — a caller that tries gets `EACCES`.

**`debugfs -w` injection is deliberately absent.** It is boot policy, it runs
after materialization on the writable copy, and shipping the primitive here would
invite calling it on a hardlinked blob. It stays at
`heyo/mvm-ctrl/src/driver/ssh_bootstrap.rs:191-270`.

**The heyvm wire types are redeclared, not imported.** `BlobRef` mirrors
`sync.rs:79-85` field for field, but `heyvm` is edition 2021 with a large
dependency tree and the dependency would become circular the moment mvm-ctrl
adopts this store.

## Tests

```sh
cargo test
cargo test --no-default-features        # the library as mvm-ctrl would build it
ART_FORCE_NO_TMPFILE=1 cargo test       # the fallback insert path
cargo clippy --all-targets --all-features
```

152 tests, inline `#[cfg(test)]` plus `tests/heyvm_roundtrip.rs`. The daemon's
are driven through `tower::ServiceExt::oneshot`, so they need no port. Tests
needing hole punching probe for it by capability rather than filesystem type, and
print what they skipped — a silently skipped test is worse than no test.

The integration tests write real multi-megabyte images, so they want a few
hundred megabytes free; on a filesystem that is nearly full they can fail with a
genuine `ENOSPC` rather than a defect.

## Global store and hub

Set `ART_S3_BUCKET` (with `ART_S3_ACCESS_KEY_ID` / `ART_S3_SECRET_ACCESS_KEY`)
and `art serve` becomes a regional cache in front of the bucket. The bucket is
the system of record for blobs, manifests, tags, labels and repositories, so
every region sees the same tags and the bucket alone rebuilds any of them.
Writes land in the bucket before they succeed; blobs and manifests read
through; tags revalidate by ETag every `ART_TAG_TTL`; a background mirror keeps
listings global; cold blobs are evicted from the disk once the bucket holds
them. Blobs travel as *artsparse* (`src/asp.rs`) — their allocated extents only
— so a 20 GiB rootfs costs what it occupies, not its length.

```sh
art s3 backfill               # publish an existing store into the bucket
art s3 verify --deep          # prove the backup is whole
art s3 gc --dry-run           # bucket GC, under a lease; never run by the daemon
```

Tags can be namespaced: `heyo/postgres:16` is tag `16` in repository
`heyo/postgres`. Flat tags are unchanged. A repository marked public
(`art repo public heyo/postgres`, `PUT /repos/{repo}`, or
`heyctl artifact push --public`) pulls anonymously end to end and is listed on
the hub at `/hub` (`ART_HUB=1`).

Full reference: [docs/artifacts.md](../docs/artifacts.md#global-store).

## Status

v1, plus the `art serve` daemon, a Firecracker image, the S3 global store and
the public hub. Not yet built: Range requests, streaming a cold blob to the
client while it fills (a fill completes before the first byte is served), and
advisory leases for pin reporting.

Not planned: chunking, a small-blob pack tier, and compression. Inodes are 93%
free on the target host, so a pack tier would constrain nothing while costing the
entire `st_nlink` reference-count design.
