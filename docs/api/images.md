# Images

These endpoints read and manage heyvm's image catalog on an app-lb host: what each image is, what holds it, and whether it has been offloaded back to the store it came from.

Back to the [API reference](overview.md). The behaviour is described under [image management](../app-lb.md#image-management) and the design in [image reuse and offload](../design/image-reuse-offload.md).

Images pulled from an artifact store are named by content (`img-<first 16 hex of digest>`), so every deployment that pulls the same bytes shares one. app-lb records what holds each image and offloads what nothing has used for a while, after proving the store still has a copy. All routes here are fleet-wide: a confined caller gets `403`.

## List images

`GET /images`

**Tier:** View, operator. **Crate:** `Client::images() -> ImageInventory`

Abridged from [`images.json`](../../app-lb/testdata/wire/images.json):

```json
{
  "generated_at": 1760090000, "complete": true, "delete_supported": true, "offload": true,
  "disk_used_pct": 41.3, "pressure_pct": 85, "local_bytes": 2684354560,
  "images": [
    {"name": "img-c74abee2ce8409f1", "source": "pull", "tier": "local",
     "digest": "c74abee2…0011", "store": "https://hub.heyo.work", "ref": "heyo/alpine:3.24",
     "bytes": 536870912, "last_used": 1760086400, "pinned": false, "present": true,
     "references": [{"kind": "deployment", "id": "web"}]}
  ]
}
```

| Inventory field | Meaning |
| --- | --- |
| `complete` | Whether app-lb could determine what references every image. When `false`, it offloads and deletes nothing. `error` says why. |
| `delete_supported` | Whether heyvm can delete images. `null` until a delete was tried. |
| `offload` | Whether automatic offload is on. |
| `disk_used_pct`, `pressure_pct` | Disk use on the image filesystem, and the threshold above which the pacer offloads more eagerly. |
| `local_bytes` | Bytes held by local images. |

| Image field | Meaning |
| --- | --- |
| `name` | heyvm's image name. |
| `source` | `pull`, `build` or `unknown`. |
| `tier` | `local`, or `offloaded` (only the remote copy remains). |
| `digest`, `store`, `ref` | Where a pulled image came from. |
| `grow_gb` | Extra space the image was grown by. |
| `bytes`, `first_seen`, `last_used` | Size and Unix-second timestamps. |
| `pinned` | Never offloaded. |
| `offloaded_to`, `offloaded_at` | Set once offloaded. |
| `failures`, `next_attempt_at`, `last_error` | Offload retry state. |
| `auth` | The store's API key as a secret reference, never a value. |
| `present` | In heyvm's catalog right now. |
| `references[]` | What holds it: `{kind, id?, deployment?, operation?, job?}`, where `kind` is `deployment`, `rollout`, `sandbox`, `job` or `pinned`. |
| `kept_because` | Why the pacer would leave it alone, when it would. |

Errors: `503` when the inventory is not running.

## Run an offload pass

`POST /images/sweep`

**Tier:** CRUD, operator. **Crate:** `Client::sweep_images() -> ImageSweep`

Runs one offload pass now and reports it:

```json
{"pressure": false, "offloaded": ["img-0000000000000000"],
 "failed": [["img-1111111111111111", "image \"img-1111111111111111\" was kept: its remote copy did not verify (HEAD … answered 404)"]]}
```

`skipped` is set, with a reason, when the pass did not run. `failed` pairs an image with why it was kept.

## Offload an image

`POST /images/:name/offload`

**Tier:** CRUD, operator. **Crate:** `Client::offload_image(name) -> ImageEntry`

Verifies that the store still has the image (or pushes it), then deletes it from heyvm. Returns the updated image record. The next deployment that needs it pulls it again.

## Pin an image

`PATCH /images/:name`

**Tier:** CRUD, operator. **Crate:** `Client::pin_image(name, pinned) -> ImageEntry`

The body is `{"pinned": true}` or `{"pinned": false}`. A pinned image is never offloaded. Returns the image record.

## Delete an image

`DELETE /images/:name`

**Tier:** CRUD, operator. **Crate:** `Client::delete_image(name) -> ()`

Removes an unreferenced image from heyvm outright. Answers `204`.

## Errors

| Status | `hws::Error` | When |
| --- | --- | --- |
| `400` | `Api` | Not an image name. |
| `404` | `NotFound` | No such image. |
| `409` | `Conflict` | The image is referenced or pinned, or not eligible. The body adds `references` (and `sandboxes`) naming what holds it. The crate keeps only the message; `GET /images` shows the same references. |
| `502` | `Upstream` | The remote copy did not verify, or the offload failed. |
| `503` | `ColdStartTimeout` | The inventory is not running, references cannot be determined, or heyvm has no delete. Despite the variant name, nothing here is about a cold start. |
