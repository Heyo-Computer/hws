# Retire or rename a replicated dedicated database

This operation interrupts the affected database. It is not a writer handoff,
reseed, or global maintenance lock. Other database names remain available.
Never delete serving bindings or physical ownership journals by hand: ordinary
checkout can otherwise bootstrap an empty replacement database.

## Prerequisites

- Deploy maintenance support to both poolers before starting.
- Use each dashboard's configured Basic authentication. Peer credentials must
  allow the poolers to read each other's maintenance status.
- Confirm the exact source and replica bindings, generation and PostgreSQL
  system identity. A rename requires the physical standby to be bound. Retiring
  a bootstrap cluster also supports its replaced logical replica, but refuses
  deeper ownership histories.
- Confirm the database is dedicated and has no active physical handoff. Neither
  the destination name nor a system database may be used as the target.
- For retirement, set `PG_VM_POOL_RUN_DIR` to the actual heyvmd run directory on
  each host. Confirm no application still uses the database. Deletion refuses
  extra user databases, application clients, or prepared transactions.
- For rename, prepare the application configuration/secret URI changes on both
  regions. Preserve login/password and change only the database component.
  Stop/reconfigure consumers during the agreed interruption; do not resume them
  until both maintenance operations finish. Keep the old config available for
  diagnosis, but never reconnect to the old name after completion.

## API and ordering

Begin on **both peers**, using the same operation ID, old name and destination,
but each peer's own bound VM ID:

```json
{"id":"rename-tenant-1","database":"old_name","destination":"canonical","bound_vm":"sb-exact-local-vm"}
```

Send this to `POST /api/database-maintenance`. For retirement use
`"destination":null`. Beginning durably closes admissions for the affected
names. It does not delete anything. Read progress with
`GET /api/database-maintenance/{id}`.

Advance with `POST /api/database-maintenance/{id}` and `{"stage":"captured"}`,
substituting the stage below. Wait for each request's successful response:

| Stage | Rename order | Retirement order |
|---|---|---|
| `captured` | Both peers | Both peers |
| `prepared` | Both peers | Both peers |
| `applied` | Source, then replica | Replica, then source |
| `verified` | Replica, then source | Both peers |
| `metadata_committed` | Source, then replica | Both peers |
| `finished` | Replica, then source | Both peers |

Capture records daemon incarnation, PostgreSQL system identifier and database
OID. Preparation closes SQL admissions and, for rename, terminates tenant
sessions. Physical WAL remains connected during rename. Retirement disables
the old logical subscription before deleting the exact recorded VMs/disks.

Rename runs `ALTER DATABASE` on the source, waits for the physical standby to
replay it, then rekeys binding, credentials and replication journals. VM IDs,
database OID, slot names, generations and history are preserved. Finish checks
replay through reopening as well. Completed old names remain unavailable to
prevent accidental reprovisioning from stale consumers.

## Failure and acceptance

Retry the **same ID and stage** after investigating an error. A lost response
may mean the SQL or deletion already succeeded. The journal retains progress;
rename recognizes the captured OID under either name. Never remove the journal
to reopen admission. A missing VM with a remaining disk is not successful
cleanup and needs investigation, not an assumed deletion receipt.

After rename, update/start both consumers and execute SQL through both regional
poolers. Verify the canonical database name, preserved application data, writer
routing, physical streaming and replay through a fresh source LSN. Check both
applications' health. After retirement verify every recorded VM and its disk
is absent, while unrelated database SQL remains available. Preserve the
maintenance receipt; retire stale consumer secrets separately only after
confirming they have no remaining readers.

Linux validation: `cargo test --locked --manifest-path pg-fc/Cargo.toml
--workspace` and `python3 pg-fc/test-database-maintenance.py`. The latter uses
disposable Docker data and does not prove live daemon deletion or consumer
reconfiguration; those require the operational checks above.
