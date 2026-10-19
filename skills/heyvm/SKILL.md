---
name: heyvm
description: Use the heyvm CLI to log in, upgrade, create and manage local or cloud sandboxes, run commands inside VMs, deploy or update apps, expose/connect/share ports and shells, manage cloud databases, build VM images, and diagnose backend readiness.
---

# heyvm

Use this skill for any Heyo VM, sandbox, preview/production deployment, proxy,
database, image, or backend-health task.

## Source Of Truth

Start with the CLI help, then use the chosen subcommand's help before acting:

```sh
heyvm --help
heyvm <command> --help
heyvm <command> <subcommand> --help
```

Prefer the CLI over raw API calls. Use `--format json` when scripting if the
subcommand supports it. Never print, log, or paste passwords, API keys, or
tokens; ask the user to run interactive login when credentials are needed.

## Operator checkpoint recovery

For a standalone Cloud Firecracker VM, use the control panel's **VM recovery**
page or `heyctl recovery`, authenticated as a fleet administrator. These are
Cloud VM IDs (`dep-…`), not app-lb-managed deployment IDs. Cloud owns admission
and progress; do not recreate its state with raw runtime restore commands.

1. Run `heyctl recovery checkpoints <cloud-id>` and `heyctl recovery destinations <cloud-id>`.
   Select a committed, retained checkpoint and an eligible destination. Explain
   the checkpoint age: recovery loses subsequent disk writes and all memory.
2. Independently fence the old source and prevent restart. A failed health check
   or timeout is not fencing. Record concrete power-off, isolation or runtime
   reclamation evidence. Keep it fenced until authorized cleanup is complete.
3. Choose and retain one operation UUID before starting:
   `heyctl recovery start <cloud-id> --checkpoint <checkpoint-uuid> --destination <backend-id> --operation-id <operation-uuid> --source-fenced --fencing-evidence '<evidence>'`.
4. Use `heyctl recovery status <cloud-id> <operation-uuid>` or
   `heyctl recovery list <cloud-id>` after interruption. Retry the **same** UUID
   and exact request only; do not create a replacement operation to bypass an error.
5. Verify the same Cloud identity, guest data, access and resources on the new
   server. Clean up only explicitly disposable test resources, through supported
   APIs, and preserve operation evidence.

This is operator-triggered cold recovery, not live migration or automatic
failover. App-lb-managed deployments and source-bound SDN services remain with
their owning controllers. The browser and CLI must never receive Cloud's
internal key. Configure it server-side through HeyoSecret; see
`app-lb/README.md` under “Operator VM recovery”. Missing discovery routes or
configuration are deployment prerequisites, not permission to bypass admission.
Distinguish backend live proof from fixture-based UI/CLI verification.

## Environment

Global options can be passed before the command or on most subcommands:

```sh
heyvm --heyo-env preview <command> ...
heyvm --heyo-env stage <command> ...
heyvm --heyo-env production <command> ...
```

Use the named environment selector first. It resolves auth/cloud URLs as:

- `preview`: `https://preview.heyo.computer/auth` and `https://preview.heyo.computer/cloud`
- `stage`: `https://stage.heyo.computer/auth` and `https://stage.heyo.computer/cloud`
- `production`: legacy split hosts until production front-door routes exist

Raw URL flags and URL environment variables override the named environment:
`--cloud-url`, `--auth-url`, `HEYO_CLOUD_URL`, `HEYO_AUTH_SERVER_URL`, and
`AUTH_SERVER_URL`. Unset those when verifying `--heyo-env`.

Preview and production backends should be Linux. For cloud dev sandboxes, use
`--cloud --backend libvirt --image ubuntu:24.04` unless the task explicitly
requires a different Linux backend or image.

## Login And Upgrade

```sh
heyvm --version
heyvm --upgrade
heyvm login --email <email>
heyvm --heyo-env preview login --email <email>
```

If login fails with TLS/certificate errors, do not bypass verification. Report
the exact host and certificate problem; that is a server-side route/cert issue.

## Local Sandboxes

Check host/backend readiness first when the user reports VM failures:

```sh
heyvm system
heyvm backends --format json
```

Create and work in a local sandbox:

```sh
heyvm create --name <name> --backend <backend> --image ubuntu:24.04 \
  --mount "$PWD:/workspace" --open-port 3000
heyvm list --all
heyvm exec <id-or-slug> --cwd /workspace -- <command> <args>
heyvm exec <id-or-slug> --session dev --cwd /workspace -- <command> <args>
heyvm sh <id-or-slug>
heyvm stop <id-or-slug>
heyvm rm --yes <id-or-slug>
```

Use `--agent codex` when the sandbox should be provisioned for Codex CLI work.
Use `--needs-network` when package installs, external APIs, or agent CLIs need
network access.

On macOS, choose the image according to the Apple backend:

- `apple_container` accepts standard OCI registry references such as `node:22`
  from Docker Hub or `ghcr.io/org/image:tag` from GHCR. `heyvm create` pulls a
  missing image automatically.
- `apple_virt` requires a bootable VM image name or ID from the heyvm image
  catalog. It cannot boot an OCI container image directly.

```sh
heyvm create --name node-box --backend apple_container --image node:22 \
  --mount "$PWD:/workspace"
heyvm create --name app-box --backend apple_container \
  --image ghcr.io/org/image:tag
heyvm create --name linux-vm --backend apple_virt \
  --image ubuntu-24.04-node --mount "$PWD:/workspace"
```

Use `heyvm pull` to prefetch or refresh an Apple Container image. It is
optional before `create` because sandbox creation also pulls missing images.

```sh
heyvm pull node:22
heyvm pull ghcr.io/org/image:tag
heyvm pull --force node:22
```

On Windows, Hyper-V and Windows Sandbox use different kinds of reusable
artifacts:

- `hyperv` boots a real Linux VM image. A public Hyper-V image is a standalone
  dynamic VHDX, not a differencing disk and not an OCI image.
- `windows_sandbox` always boots Microsoft's host-provided
  `windows-sandbox/default` base. That base is fixed; it is not a custom image
  that users download or publish.

Publish and reuse a Linux Hyper-V image on Windows:

```sh
heyvm images publish <hyperv-sandbox> --name <image-name>
heyvm images add <approved-image-id> --name <local-alias>
heyvm create --name <name> --backend hyperv --image <local-alias>
```

Publishing stops a running Hyper-V VM long enough to flatten its disk, then
restores the sandbox before upload. Only public Linux `hyperv`/`vhdx`/
`linux-amd64` images are supported; private and Windows-guest Hyper-V image
publishing are not supported yet.

For Windows Sandbox, publish and reuse an image through the same image commands:

```sh
heyvm images publish <windows-sandbox-id> --name <image-name> --description <description>
heyvm images list
heyvm images add <approved-image-id> --name <local-alias>
heyvm create --name <sandbox-name> --backend windows_sandbox --image <image-id-or-alias>
```

Publishing packages the writable `/workspace` application files plus a
versioned manifest containing the sandbox type, runtime requirements, setup
hooks, startup command, working directory, environment variables, and ports.
Publishing is public: remove secrets from the workspace, environment values,
hooks, and command first. The image does not package Windows, Node, or
arbitrary host paths. Creating from the image makes a fresh workspace on the
Windows host, boots `windows-sandbox/default`, and restores that portable
configuration. If the image requires Node, `node.exe` must be installed on the Windows host and
available on `PATH`; HeyVM maps that host runtime read-only into the sandbox.

## Cloud Linux Sandboxes

Create a fresh Linux cloud sandbox:

```sh
heyvm --heyo-env preview create --cloud \
  --name <name> \
  --backend libvirt \
  --region US \
  --image ubuntu:24.04 \
  --size-class small \
  --agent codex \
  --setup-hook 'apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git jq' \
  --port 3000
```

Cloud sandboxes do not bind-mount the host working directory at creation time.
Ship local source to `/workspace` with an archive:

```sh
archive_id=$(heyvm archive-dir . --name <name>-$(date +%Y%m%d%H%M%S) --format json | jq -r '.id')
heyvm update <sandbox-id-or-name> --archive "$archive_id"
```

For a new deployment, pass the archive during creation so the backend
materializes `/workspace` before it runs the start command:

```sh
archive_id=$(heyvm --heyo-env stage archive-dir examples/fremont-fishing --name fremont-fishing-$(date +%Y%m%d%H%M%S) --format json | jq -r '.id')
heyvm --heyo-env stage create --cloud --archive "$archive_id" --name <name> --backend <backend> --image <general-image> --region EU --working-directory /workspace --start-command 'npm ci && npm run build && exec npm start' --port 3000 --health-path /
```

Use a reusable runtime image, not an app-specific image. Image formats remain
backend-specific even though every backend receives the same source archive:

| Backend | General Node image | Source delivery |
| --- | --- | --- |
| `libvirt` | compatible Node-enabled `qcow2` catalog image | archive mounted at `/workspace` |
| `kvm` | Node-enabled `ext4` catalog image | archive converted to a workspace disk |
| `firecracker` | the same compatible Node-enabled `ext4` image | archive converted to a workspace disk |
| `firecracker_containerd` | standard OCI image such as Docker Hub `node:22` | archive copied into the container at `/workspace` |

`firecracker_containerd` pulls ordinary Docker Hub, GHCR, and other OCI
registry references automatically, just like `apple_container`. Do not publish
a Fishing-specific image, and do not use `--mount` with
`firecracker_containerd`; use `--archive` for cloud application source.

OCI image support is backend-specific:

| Backend | Runs standard OCI images directly | Host requirement |
| --- | --- | --- |
| `apple_container` | yes | Apple Container runtime on macOS |
| `firecracker_containerd` | yes | configured Firecracker-containerd runtime on a Linux KVM host |
| `windows_sandbox` | no | built-in disposable Windows environment; images that require Node need host `node.exe` on `PATH` |
| `libvirt`, `kvm`, `firecracker`, `apple_virt`, `hyperv` | no | compatible bootable VM image |

After Firecracker-containerd is installed and configured on a Linux backend
host, ordinary OCI references such as `node:22` work without conversion to a
bootable VM image. The host needs a running `firecracker-containerd` daemon,
`firecracker-ctr`, KVM, the `aws.firecracker` runtime, CNI networking, and a
devmapper snapshotter. HeyVM detects the runtime socket and CLI and advertises
`firecracker_containerd` on the host's next registration.

If Cloud reports
`No available backend ... supports firecracker_containerd`, do not replace the
OCI reference with a bootable VM image and do not claim that OCI images are
unsupported. The environment has no registered capable backend host in the
selected region; provision the Firecracker-containerd runtime on a backend host
for that region and let it register again.

`heyvm backends` lists backend types for the platform where the CLI is running;
it does not query cloud capacity. There is no user-facing cloud capacity command
yet, so use the cloud `create` request above as the operational check. The
repository also does not yet provide a pinned host installer; do not describe
an ad hoc installation as repeatable provisioning. Verify the public
application URL and restart behavior before declaring the backend ready.

To compare the same application concurrently, reuse one archive ID and create
four deployments with distinct names and the image appropriate for each row.
Each deployment gets its own public URL even when all four expose guest port
3000. Verify `/` and the JavaScript and CSS asset URLs before declaring the
comparison successful.

On macOS, prefer `create --cloud` plus `archive-dir`/`update`. Do not use
`--deploy-from` from macOS unless `heyvm create --help` says the selected source
backend can publish to the cloud; local macOS VM backends are not Linux cloud
images.

## Images

Start image work by checking the current CLI surface and inventory:

```sh
heyvm pull --help
heyvm images --help
heyvm images list --help
heyvm images publish --help
heyvm images supported
heyvm --heyo-env stage images list
heyvm --heyo-env preview images list
heyvm images list --local
```

Image concepts:

- Apple Container images are OCI registry references managed by Apple's
  `container` runtime. They can be pulled explicitly with `heyvm pull`, but do
  not need to appear in the heyvm bootable-VM or cloud image catalogs before
  use.
- Apple Virt images are bootable VM artifacts from the heyvm image catalog;
  standard OCI references such as `node:22` are not Apple Virt images.
- Linux Hyper-V public images are standalone dynamic VHDX artifacts. On
  Windows, publish with `heyvm images publish`, download an approved image with
  `heyvm images add`, then create with `--backend hyperv --image
  <id-or-alias>`.
- Windows Sandbox has a fixed `windows-sandbox/default` base, but its portable
  application artifact is presented as an image. Use `heyvm images
  publish/list/add` and `heyvm create --backend windows_sandbox --image
  <id-or-alias>`. It appears in `heyvm images list` like other images.
- Built-in supported images come from the CLI/backend catalog and are not cloud
  catalog rows. Examples: `ubuntu:24.04`, `debian:12`, `alpine:3.23`.
- Backend-local files under paths such as `/var/lib/heyvm/images` are only a
  node cache. They do not show up in `heyvm images list` until bytes are in the
  cloud image store and a cloud DB `sandbox_images` row exists.
- Published image bytes live in S3. The cloud DB `sandbox_images` row controls
  name, owner, public/private status, backend, format, arch, and S3 key.
- Images are not environment-scoped in the image schema today. Catalog sharing
  follows DB/storage topology: stage has its own DB, while preview and
  production currently share a DB. If storage buckets differ, verify the S3 key
  is readable from the cloud environment before treating an image as usable.
- Private images are scoped to the publishing user and deployable immediately.
  Public images require admin review before showing in `images list`.
- First-party reusable images should be registered as admin base images with a
  stable name, backend, arch, and version. User-submitted public images should
  go through `heyvm images publish` and admin review.

Use this workflow when comparing app behavior across images:

1. Inventory built-in and published images in the target environment.
2. Run the app on built-in Linux images first, using `--setup-hook` only for
   missing runtime packages.
3. If the same setup hook is repeated and stable, publish a private reusable
   image from a configured sandbox.
4. Run the app again with the private image.
5. Promote to public only after the image is small, documented, and reusable by
   more than one app.

Example Node app baseline:

```sh
heyvm --heyo-env preview create --cloud \
  --name <app>-ubuntu-node-setup \
  --backend libvirt \
  --region US \
  --image ubuntu:24.04 \
  --size-class small \
  --setup-hook 'apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git jq' \
  --setup-hook 'curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs' \
  --start-command 'cd /workspace && npm ci && npm run build && npm start' \
  --port 3000
```

Publish a reusable private image after validating the configured sandbox:

```sh
heyvm --heyo-env preview images publish <sandbox-id-or-name> \
  --name ubuntu-24.04-node22 \
  --description 'Ubuntu 24.04 with Node.js 22 and common app build tools' \
  --private \
  --sysprep
```

Promote a verified backend-local file to a first-party public base image only
after integrity and boot checks pass. Use the target environment intentionally;
stage has a separate catalog, while preview and production share the current
catalog.

```sh
name=ubuntu-24.04-rust-libvirt-20260522
backend=libvirt
arch=linux-amd64
version=20260522
format=qcow2
file=/var/lib/heyvm/images/ubuntu-24.04-rust-libvirt-20260522.qcow2
sha256=$(sha256sum "$file" | awk '{print $1}')

heyvm --heyo-env stage login --email <admin-email>
token=$(jq -r '.access_token' ~/.heyo/token.json)
cloud=https://stage.heyo.computer/cloud

slot=$(curl -fsS -X POST "$cloud/public-images/base/presign" \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$name\",\"backend\":\"$backend\",\"arch\":\"$arch\",\"version\":\"$version\",\"format\":\"$format\"}")

upload_url=$(printf '%s' "$slot" | jq -r '.upload_url')
curl -fS -X PUT --upload-file "$file" "$upload_url"

curl -fsS -X POST "$cloud/public-images/register-base" \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$name\",\"backend\":\"$backend\",\"arch\":\"$arch\",\"version\":\"$version\",\"format\":\"$format\",\"sha256\":\"$sha256\"}" | jq .

heyvm --heyo-env stage images list --libvirt
heyvm --heyo-env stage create --cloud --name image-smoke \
  --backend libvirt --region US --image "$name" \
  --start-command 'python3 -m http.server 3000' --port 3000
```

The `sha256` value is client-computed metadata. The server verifies that the
object exists and records the supplied hash; it does not recompute the uploaded
object hash during registration.

Do not register unknown local image IDs such as `im-*` or `img-*` as public
base images until their contents, installed toolchain, boot path, backend,
format, arch, version, integrity hash, and cleanup behavior are recorded.

To make a first-party base image available in every environment, register it in
each distinct catalog DB and upload it to each distinct storage bucket. Today
that means registering once in stage and once in the shared preview/production
catalog. If production uses a different storage bucket from preview, upload the
same deterministic base-image key to production storage too, but do not create a
second DB row when preview and production share the catalog DB.

```sh
set -euo pipefail

name=ubuntu-24.04-rust-libvirt-20260522
backend=libvirt
arch=linux-amd64
version=20260522
format=qcow2
file=/var/lib/heyvm/images/ubuntu-24.04-rust-libvirt-20260522.qcow2
sha256=$(sha256sum "$file" | awk '{print $1}')

upload_base_image() {
  slot=$(curl -fsS -X POST "$cloud/public-images/base/presign" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$name\",\"backend\":\"$backend\",\"arch\":\"$arch\",\"version\":\"$version\",\"format\":\"$format\"}")

  upload_url=$(printf '%s' "$slot" | jq -er '.upload_url')
  curl -fS -X PUT --upload-file "$file" "$upload_url"
}

register_base_image_row() {
  curl -fsS -X POST "$cloud/public-images/register-base" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"$name\",\"backend\":\"$backend\",\"arch\":\"$arch\",\"version\":\"$version\",\"format\":\"$format\",\"sha256\":\"$sha256\"}" | jq .
}

# Stage catalog.
heyvm --heyo-env stage login --email <admin-email>
token=$(jq -er '.access_token' ~/.heyo/token.json)
cloud=https://stage.heyo.computer/cloud
upload_base_image
register_base_image_row

# Shared preview/production catalog.
heyvm --heyo-env preview login --email <admin-email>
token=$(jq -er '.access_token' ~/.heyo/token.json)
cloud=https://preview.heyo.computer/cloud
upload_base_image
register_base_image_row

# If production storage is different from preview storage, repeat the upload
# against production storage too. No additional catalog row is needed when
# production and preview share the same catalog DB; the deterministic S3 key is
# the same, but the object must exist in the bucket production reads from.
heyvm --heyo-env production login --email <admin-email>
token=$(jq -er '.access_token' ~/.heyo/token.json)
cloud=https://server.heyo.computer
upload_base_image
```

Verify visibility and boot in every environment that should consume the image:

```sh
heyvm --heyo-env stage images list --libvirt
heyvm --heyo-env preview images list --libvirt
heyvm --heyo-env production images list --libvirt

heyvm --heyo-env stage create --cloud --name image-smoke-stage \
  --backend libvirt --region US --image "$name" \
  --start-command 'python3 -m http.server 3000' \
  --health-path / \
  --ttl-seconds 600 \
  --port 3000

heyvm --heyo-env preview create --cloud --name image-smoke-preview \
  --backend libvirt --region US --image "$name" \
  --start-command 'python3 -m http.server 3000' \
  --health-path / \
  --ttl-seconds 600 \
  --port 3000

heyvm --heyo-env production create --cloud --name image-smoke-production \
  --backend libvirt --region US --image "$name" \
  --start-command 'python3 -m http.server 3000' \
  --health-path / \
  --ttl-seconds 600 \
  --port 3000

heyvm --heyo-env stage rm --yes image-smoke-stage
heyvm --heyo-env preview rm --yes image-smoke-preview
heyvm --heyo-env production rm --yes image-smoke-production
```

## Networking And Access

```sh
heyvm bind <sandbox> 3000
heyvm bind --private <sandbox> 3000
heyvm proxy start 3000
heyvm proxy list
heyvm share <sandbox> --name <shortname>
heyvm ssh <heyo-ticket-or-shortname> -- <command>
heyvm connect <heyo-ticket-or-shortname>
heyvm mount <sandbox>
heyvm port-forward <sandbox> <local-port>:<guest-port>
```

Use `bind` for deployed sandbox ports and `proxy`/`share`/`connect`/`ssh` for
P2P access.

## Databases

Use `heyvm db` for cloud databases. Check help for the current engine and SQL
surface:

```sh
heyvm db --help
heyvm db create --help
heyvm db list
heyvm db exec <database> -- <sql>
heyvm db shell <database>
```

Select DuckDB only when the task calls for OLAP/columnar workflows; default to
SQLite for app state and transactional data.

## Diagnostics

```sh
heyvm images --help
heyvm mvm --help
heyvm mvm build --help
heyvm test-firecracker
heyvm test-kvm
heyvm test-apple-virt
heyvm prune --help
```

Use `heyvm mvm` only for Firecracker/rootfs image work. For ordinary preview,
stage, or production app work, a cloud Ubuntu image plus setup hooks is usually
simpler until the setup is worth publishing as a reusable image.

## Operational Rules

- Confirm the target environment before creating cloud resources: production,
  preview, stage, or local.
- If there is only one backend, list and clean up retained or stale sandboxes
  before retrying capacity-heavy work.
- Stop or remove sandboxes only when they are clearly created for the current
  task or the user asks for cleanup.
- For long setup hooks, prefer a custom image only after the setup is stable and
  repeated often enough to justify maintaining it.
- Record commands and resource IDs in the task notes or tutorial when the user
  asks for reproducible steps.
