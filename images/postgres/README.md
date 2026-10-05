# heyo/postgres

PostgreSQL 18 on Debian bookworm, packaged as a heyvm rootfs and published on
the hub as `heyo/postgres:18` (and `:latest`).

This is not pg-fc's image. pg-fc's guests start Postgres from PID 1 with `trust`
auth, because the pooler's tunnel is the only way in. This image:

- refuses to start without `POSTGRES_PASSWORD`, and authenticates every TCP
  client with scram-sha-256;
- starts Postgres from `start_command` (`/usr/local/bin/heyo-postgres`), because
  `env_vars` reach only that process.

| Variable | Meaning |
| --- | --- |
| `POSTGRES_PASSWORD` | Required. The superuser's password, set when the cluster is first created. Changing it later does not rotate it; use `ALTER ROLE` |
| `POSTGRES_USER` | Superuser name. Default `postgres` |
| `POSTGRES_DB` | A database to create on first init |
| `PGDATA` | Default `/workspace/pgdata` |
| `PGPORT` | Default `5432` |

Give the VM a data disk (`disk_size_gb`). Without one, PGDATA is on the rootfs,
which is recopied on every cold boot.

```json
{
  "id": "db",
  "vm": {
    "driver": "firecracker",
    "port": 5432,
    "start_command": "/usr/local/bin/heyo-postgres",
    "disk_size_gb": 10,
    "env_vars": { "POSTGRES_DB": "app" },
    "env_from": [{ "secret": "db", "key": "password", "as": "POSTGRES_PASSWORD" }]
  },
  "artifact": { "store": "https://hub.heyo.work", "ref": "heyo/postgres:18", "grow_gb": 2 },
  "scaling": { "min_replicas": 1, "max_replicas": 1 },
  "health": { "path": null }
}
```

`health.path: null` makes the health check a TCP connect; Postgres speaks no HTTP.

## Building and publishing

From the repository root:

```sh
heyvm mvm build --local-only -f images/postgres/Dockerfile -c . -n heyo-postgres --size-mb 1024
heyctl artifact push --image heyo-postgres --registry-url https://hub.heyo.work --tag heyo/postgres:18 --public
```

`--size-mb 1024` leaves room on the rootfs; the auto-sized image is full, and
`initdb` fails with "No space left on device" on a VM without a data disk. The
Docker build runs a smoke test: no password refuses to start, the right one
connects over TCP, and a wrong one is rejected.
