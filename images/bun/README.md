# heyo/bun

[Bun](https://bun.sh) 1.4.2 on Debian 13, as a heyvm rootfs: `heyo/debian` plus
`bun`/`bunx` (the baseline build, so no AVX2 is needed) and git. Nothing runs at
boot beyond the shared init; your app starts from `start_command`.

```json
{
  "id": "api",
  "routes": [{ "host": "api.example.com" }],
  "vm": {
    "driver": "firecracker",
    "port": 3000,
    "start_command": "cd /workspace/app && setsid nohup bun run start </dev/null >/var/log/app.log 2>&1 &",
    "disk_size_gb": 4,
    "env_vars": { "PORT": "3000" }
  },
  "artifact": { "store": "https://hub.heyo.work", "ref": "heyo/bun:1.4", "grow_gb": 2 },
  "health": { "path": "/" }
}
```

The Docker build checks that `bun --version` is the pinned one and that
`Bun.serve` answers a request. Bump `BUN_VERSION` to move; the zip is verified
against the release's `SHASUMS256.txt`.
