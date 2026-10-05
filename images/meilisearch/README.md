# heyo/meilisearch

[Meilisearch](https://www.meilisearch.com) 1.54.3 on Debian 13, as a heyvm
rootfs. `heyo-meilisearch` (the `start_command`) refuses to start without
`MEILI_MASTER_KEY`, and runs with `MEILI_ENV=production`, so every route but
`/health` needs a key.

| Variable | Default |
| --- | --- |
| `MEILI_MASTER_KEY` | required, at least 16 bytes |
| `MEILI_DB_PATH` | `/workspace/meilisearch/data.ms` |
| `MEILI_DUMP_DIR` | `/workspace/meilisearch/dumps` |
| `MEILI_HTTP_ADDR` | `0.0.0.0:7700` |
| `MEILI_NO_ANALYTICS` | `true` |

Any other `MEILI_*` variable passes through. The log is
`/workspace/meilisearch/meilisearch.log`.

```json
{
  "id": "search",
  "routes": [{ "host": "search.example.com" }],
  "vm": {
    "driver": "firecracker",
    "port": 7700,
    "start_command": "/usr/local/bin/heyo-meilisearch",
    "size_class": "medium",
    "disk_size_gb": 10,
    "env_from": [{ "secret": "search", "key": "master-key", "as": "MEILI_MASTER_KEY" }]
  },
  "artifact": { "store": "https://hub.heyo.work", "ref": "heyo/meilisearch:1.54", "grow_gb": 2 },
  "scaling": { "min_replicas": 1, "max_replicas": 1 },
  "health": { "path": "/health" }
}
```

Keep one replica: each VM has its own disk, so two replicas are two indexes.
A database is tied to the Meilisearch version that wrote it. Before moving to a
new tag, take a dump (`POST /dumps`) or follow Meilisearch's upgrade guide.

The Docker build checks the key contract: no key refuses to start, `/health`
answers, `/indexes` is 401 without the key and 200 with it.
