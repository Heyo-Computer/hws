# heyo/minecraft

A vanilla Minecraft: Java Edition server on Debian 13 with OpenJDK 25, as a
heyvm rootfs.

**The image does not contain Mojang's server jar**; the Minecraft EULA does not
allow redistributing it. On first start, `heyo-minecraft` (the `start_command`)
downloads the jar from Mojang's version manifest, checks its SHA-1, and keeps
it on `/workspace`. It refuses to start unless `EULA=TRUE`: setting that is you
accepting the [Minecraft EULA](https://aka.ms/MinecraftEULA).

| Variable | Meaning |
| --- | --- |
| `EULA` | Required: `TRUE` |
| `MC_VERSION` | A release id (`26.3`), or `latest`. Unset, the first start picks the newest release and pins it in `.heyo-version`, so a restart never upgrades the world. Set it to move |
| `JAVA_OPTS` | Default `-XX:MaxRAMPercentage=75` |
| `SERVER_PORT` | Default `25565` |
| `MOTD`, `MAX_PLAYERS`, `DIFFICULTY`, `GAMEMODE`, `ONLINE_MODE`, `LEVEL_SEED`, `VIEW_DISTANCE` | Written into `server.properties` on every start when set |
| `MC_DIR` | Default `/workspace/minecraft` |

Anything else: edit `/workspace/minecraft/server.properties`. The console log is
`/workspace/minecraft/console.log`. The server runs as the unprivileged
`minecraft` user.

Minecraft speaks its own TCP protocol, not HTTP, so app-lb's host routes do not
reach it. Players connect to the VM's port 25565 directly. Health is a TCP
connect:

```json
{
  "id": "mc",
  "vm": {
    "driver": "firecracker",
    "port": 25565,
    "start_command": "/usr/local/bin/heyo-minecraft",
    "size_class": "large",
    "disk_size_gb": 10,
    "env_vars": { "EULA": "TRUE", "MOTD": "hello from heyo" }
  },
  "artifact": { "store": "https://hub.heyo.work", "ref": "heyo/minecraft:java25", "grow_gb": 2 },
  "scaling": { "min_replicas": 1, "max_replicas": 1, "scale_to_zero_after_secs": 0 },
  "health": { "path": null }
}
```

Give it at least 2 GiB of memory. A version whose manifest asks for a newer Java
than 25 is refused with a message, not started.
