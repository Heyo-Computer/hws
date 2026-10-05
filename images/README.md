# Hub images

heyvm rootfs images published on [hub.heyo.work](https://hub.heyo.work/hub),
pullable by anyone without a key.

| Repository | Tags | Source |
| --- | --- | --- |
| `heyo/alpine` | `3.24`, `latest` | [`alpine/`](alpine/Dockerfile) |
| `heyo/debian` | `13`, `trixie`, `latest` | [`debian/`](debian/Dockerfile) |
| `heyo/ubuntu` | `26.04`, `latest`; `24.04` | [`ubuntu/`](ubuntu/Dockerfile) (`UBUNTU_VERSION`) |
| `heyo/postgres` | `18`, `latest` | [`postgres/`](postgres/README.md) |

## The base images

`alpine`, `debian` and `ubuntu` share [`base/init.sh`](base/init.sh). On boot it:

- brings up eth0;
- mounts a data disk (`disk_size_gb`) at `/workspace`, formatting it on first
  boot (anything outside `/workspace` is reset on every cold boot);
- starts sshd, key-only, for `heyvm exec` / `heyvm sh`;
- prints `HEYVM_READY`.

Nothing else runs. A deployment brings its process through `start_command`,
which is also the only process that receives `env_vars`:

```json
{
  "id": "worker",
  "vm": {
    "driver": "firecracker",
    "port": 8080,
    "start_command": "setsid nohup /workspace/app/run </dev/null >/var/log/app.log 2>&1 &",
    "disk_size_gb": 10
  },
  "artifact": { "store": "https://hub.heyo.work", "ref": "heyo/debian:13", "grow_gb": 4 }
}
```

Each image ships bash, iproute2, e2fsprogs, blkid, ca-certificates and curl. Each
Docker build runs [`base/smoke.sh`](base/smoke.sh), which fails the build if a
tool `init.sh` calls is missing or sshd would accept passwords.

## Building and publishing

From the repository root (`init.sh` is shared, so the context is `.`):

```sh
heyvm mvm build --local-only -f images/alpine/Dockerfile -c . -n heyo-alpine --size-mb 512
heyvm mvm build --local-only -f images/debian/Dockerfile -c . -n heyo-debian --size-mb 1024
heyvm mvm build --local-only -f images/ubuntu/Dockerfile -c . -n heyo-ubuntu-26.04 --size-mb 1024
```

`heyvm mvm build` has no `--build-arg`. For 24.04, build from a copy of the
Dockerfile with `ARG UBUNTU_VERSION=24.04`.

```sh
heyctl artifact push --image heyo-debian --registry-url https://hub.heyo.work --tag heyo/debian:13 --public
```

Then point the alias tags at the same digest:

```sh
d=$(curl -s -H "x-api-key: $KEY" https://hub.heyo.work/tags/heyo/debian:13 | jq -r .digest)
curl -X PUT -H "x-api-key: $KEY" --data "$d" https://hub.heyo.work/tags/heyo/debian:latest
```

The size headroom matters on a VM without a data disk: an auto-sized rootfs
is full.
