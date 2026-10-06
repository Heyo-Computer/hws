# Image reuse and offload

Status: in progress (app-lb in `Heyo-Computer/hws`, heyvm in `Heyo-Computer/heyo`).

## Problem

Measured on us5 on 2026-10-06, after a day of the hws live E2E (five alpine VMs per run).

**app-lb keeps a copy per deployment, not per image.**
- An artifact pull names its image `<deployment>-<digest[..12]>` (`ArtifactSpec::image_for`). Five deployments of `heyo/alpine:3.24` therefore cost five pulls, five uploads to heyvm and five catalog files.
- Reuse is checked by image name, never by digest.
- 24 GB sat in `/var/lib/heyvm/images/firecracker` across 50 images, most of them the same alpine bytes.

**Nothing removes a catalog image.**
- Deleting a deployment, or rolling it onto a new image, leaves the old image in place.
- heyvm has no general image-delete API: only `evict` for `ci-img-*`, plus the unlocked `heyvm prune --images`.

**heyvm copies the rootfs on every boot.**
- `start_vm` reflinks the catalog image into `run/<id>/rootfs.ext4`, and falls back to a full byte copy when the filesystem cannot reflink.
- us5 is ext4 and cannot (`cp --reflink=always`: "Operation not supported"). So every boot is a full copy of the image: 22 GB in `run/`, with one copy per running VM.
- The only no-copy mode is `HEYO_FC_SHARED_ROOTFS=1`, and it applies to the whole host.

**Unused images are never offloaded.** pg-fc has an offload ladder for cold databases; nothing like it exists for images.

## Design

### 1. Content-addressed images (app-lb)

**Naming.** A pulled image is named by what it is, not by who asked for it: `img-<digest[..16]>` for an artifact blob. When `grow_gb` is set, the name gets `-g<N>` (`img-<digest16>-g4`), because a grown image is a different file.
- An explicit `artifact.image_name` keeps today's behaviour, as an escape hatch.
- A build is named by its build input (`<deployment>-<commit|manifest digest>`) as today, because two deployments rarely build the same thing.

**Reuse.** Before fetching, app-lb asks heyvm whether the content-addressed name already exists, and checks its size against the blob and `grow_gb`. If it does, the pull job succeeds without fetching or uploading, and rolls the deployment onto it.

**Thaw on demand.** A deployment whose `vm.image` is missing from heyvm (offloaded, or never pulled) gets a pull started automatically when its pool needs a VM.
- The autoscaler does not create a VM while the image is missing, and it never boots the default image instead.
- This replaces "register, then remember to POST /pull".

### 2. Image inventory and GC (app-lb)

**Inventory.** app-lb builds it from heyvm's `GET /images` plus a reference set.

**References**, any of which keeps an image:
- every registered deployment's `vm.image`;
- a rollout's previous and candidate images, while that rollout can still roll back;
- images named by in-flight jobs;
- an operator pin.

**Records.** Each image is stored in `app-lb-images.d/` as one record, kept for referenced and unreferenced images alike:

```
{ name, digest?, store?, ref?, source: pull|build|unknown, bytes, first_seen, last_used,
  pinned, tier: local|offloaded, offloaded_to?, offloaded_at? }
```

`last_used` is bumped whenever a VM is created from the image.

**Lifecycle.**
- `local, referenced` is never touched.
- `local, unreferenced for >= APP_LB_IMAGE_IDLE_SECS` (default 1 day) becomes an offload candidate.
- **Offload** works per source:
  1. A pull: verify the store still serves the digest (`HEAD /blobs/<digest>`, matching size). Only then delete it from heyvm. The store is the offload tier; nothing is uploaded.
  2. A build: push the image to `APP_LB_IMAGE_OFFLOAD_STORE` (an art store) as `offload/<name>`, verify the digest the store reports, and only then delete it.
  3. An unknown source (images app-lb did not make) is listed but never offloaded or deleted.
- **Thaw**: a deployment that needs an offloaded image pulls it back by digest from the recorded store, as above.

**Rules carried over from pg-fc:**
- Verify the remote copy before deleting the local one, and make the record durable before the delete.
- An image whose state cannot be classified (heyvm unreachable, references unknown) is never deleted.
- The pacer yields to boots, at most one offload runs at a time, and a failure backs off per image.
- A disk-pressure watermark (`APP_LB_IMAGE_PRESSURE_PCT`, default 85) ignores the idle age, but never deletes an image that is referenced or unverified.

**Admin API**, fleet scope:
- `GET /images`: the inventory, with references and sizes (view tier).
- `POST /images/sweep`: run the offload pass now.
- `POST /images/:name/offload`, `DELETE /images/:name`: refuse a referenced image (409, naming the referencing deployments).
- `PATCH /images/:name {pinned}`.

These appear on the `/storage` console. heyctl gets `heyctl images` / `heyctl images offload|rm|pin`.

### 3. heyvm: per-VM shared rootfs and image deletion

**`DELETE /images/:name`.**
- Takes the exclusive catalog lock.
- Refuses with 409 `{error, sandboxes: [...]}` if any live or inactive sandbox references the image by name or path.
- Never deletes kernels (`vmlinux*`), and refuses names outside `[A-Za-z0-9._-]`.
- Answers 404 when the image is absent and 204 on success.
- heyo-sdk gains `Daemon::delete_image(name)`.

**Per-sandbox `rootfs_mode: "shared" | "copy"`** in the create body. The default is `copy`, so existing behaviour is unchanged. The host-wide `HEYO_FC_SHARED_ROOTFS` keeps working and still forces `shared`.
- `shared` attaches the catalog image read-only (`root=/dev/vda ro`, `is_read_only: true`), so there is no per-boot copy.
- `shared` only works for an image whose init supplies the writable layer (below).
- Exec must not depend on injecting an ssh key into the rootfs. The key reaches a shared-rootfs guest by another route: the data disk, or the kernel command line, whichever heyvm already supports. The heyvm PR documents which one.
- Snapshot-to-image and fork must keep working with a shared rootfs: snapshot from the catalog image, and copy only the writable layer.

**`vm.rootfs: "shared"` in an app-lb deployment spec** passes `rootfs_mode: "shared"`. This is the reuse a workspace VM wants:
- `/workspace` (and anything else that must persist) lives on the data disk or the workspace mount;
- the root filesystem is the shared, read-only image.

### 4. Hub base images

`images/base/init.sh` (heyo/alpine, debian, ubuntu) supports a read-only root:
- When `/` is mounted read-only, it mounts tmpfs over `/run`, `/tmp`, `/var/tmp`, `/var/log`, `/var/cache`, `/root` and `/home`.
- It copies `/etc` into a tmpfs, so hostname, resolv.conf and sshd host keys still work.
- `HEYVM_READY` is printed as before.
- With a read-write root it behaves exactly as today.

## Order

1. heyvm PR: `DELETE /images/:name`, `rootfs_mode`, and the heyo-sdk methods. Then release heyo-sdk.
2. app-lb PR: content-addressed pulls, thaw on demand, the inventory, GC and offload, `vm.rootfs`, and `init.sh`.
   - The app-lb parts that need the new heyvm APIs detect them (404/405 on `DELETE /images`, an unknown `rootfs_mode`). Until heyvm is upgraded they degrade to "list and report" and copy mode.
3. Republish the hub base images with the new `init.sh`.
4. Live check on us5 with the hws E2E:
   - five deployments → one image;
   - `vm.rootfs: shared` → no `run/<id>/rootfs.ext4`;
   - offload of an idle image, then thaw it back on scale-up.
