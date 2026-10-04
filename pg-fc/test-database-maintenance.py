#!/usr/bin/env python3
"""Exercise maintenance SQL on disposable PostgreSQL primary/standby data.

Run on a Linux Docker host: python3 pg-fc/test-database-maintenance.py.
No host ports or live database directories are mounted.
"""
import os
from pathlib import Path
import re
import subprocess
import time
import uuid


source = (Path(__file__).parent / "src/database_maintenance/execute.rs").read_text()
scripts = dict(re.findall(r'const (\w+): &str = r#"(.*?)"#;', source, re.S))
name = "pgfc-maintenance-test-" + uuid.uuid4().hex[:12]


def run(*args, input=None):
    return subprocess.run(args, input=input, text=True, capture_output=True,
                          check=True, timeout=60).stdout.strip()


def sql(statement, database="postgres", port=5432):
    return run("docker", "exec", "-i", name, "gosu", "postgres", "psql",
               "-XqAt", "-v", "ON_ERROR_STOP=1", "-p", str(port),
               "-d", database, input=statement)


def script(key, database="tenant", port=5432, **env):
    args = ["docker", "exec", "-i", "-e", "PGFC_DB=" + database,
            "-e", "PGPORT=" + str(port)]
    for key_env, value in env.items():
        args += ["-e", key_env + "=" + value]
    return run(*args, name, "sh", input=scripts[key])


try:
    run("docker", "run", "-d", "--name", name, "--cpus=1", "--memory=512m",
        "-e", "POSTGRES_HOST_AUTH_METHOD=trust", os.environ.get("PG_TEST_IMAGE", "postgres:17"))
    for attempt in range(60):
        try:
            sql("SELECT 1")
            break
        except subprocess.CalledProcessError:
            time.sleep(1)
    else:
        raise RuntimeError("disposable PostgreSQL did not become ready")
    sql("CREATE DATABASE tenant;")
    sql("CREATE TABLE sentinel (value int); INSERT INTO sentinel VALUES (37);", "tenant")
    sid, oid = script("IDENTITY_SQL").split("|")
    assert script("SAFE_TO_DELETE") == "t"
    sql("CREATE DATABASE unrelated;")
    assert script("SAFE_TO_DELETE") == "f", "extra database must prevent VM deletion"
    sql("DROP DATABASE unrelated;")
    run("docker", "exec", name, "gosu", "postgres", "pg_basebackup",
        "-h", "127.0.0.1", "-p", "5432", "-U", "postgres", "-D", "/tmp/standby", "-R", "-X", "stream")
    run("docker", "exec", name, "gosu", "postgres", "pg_ctl", "-D", "/tmp/standby",
        "-l", "/tmp/standby.log", "-o", "-p 5433", "-w", "start")
    assert script("DRAIN_LOGICAL") == "t"
    assert script("DRAIN_LOGICAL") == "t", "retry after connections disabled must succeed"
    sql("ALTER DATABASE tenant RENAME TO canonical;")
    assert script("IDENTITY_SQL", database="canonical") == sid + "|" + oid
    sql("ALTER DATABASE canonical ALLOW_CONNECTIONS true;")
    lsn = sql("SELECT pg_current_wal_flush_lsn();")
    proof = dict(PGFC_SID=sid, PGFC_OID=oid, PGFC_LSN=lsn)
    for attempt in range(60):
        if script("VERIFY_STANDBY", database="canonical", port=5433, **proof) == "t":
            break
        time.sleep(1)
    else:
        raise AssertionError("standby failed to replay rename/reopen barrier")
    assert sql("SELECT value FROM sentinel;", "canonical", 5433) == "37"
    assert script("VERIFY_STANDBY", database="canonical", **proof) == "f", "primary is not a standby"
    assert script("VERIFY_STANDBY", database="canonical", port=5433,
                  **(proof | {"PGFC_OID": str(int(oid) + 1)})) == "f"
    assert script("VERIFY_STANDBY", database="canonical", port=5433,
                  **(proof | {"PGFC_LSN": "FFFFFFFF/FFFFFFFF"})) == "f"
    print("PASS: drain retry, deletion guard, rename identity/data, streaming replay and negative proofs")
finally:
    subprocess.run(["docker", "rm", "-f", "-v", name], check=False, capture_output=True)
