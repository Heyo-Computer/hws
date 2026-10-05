# PostgreSQL 18 for heyvm, published on the hub as `heyo/postgres`.
#
# Built from the **repository root**:
#
#   heyvm mvm build --local-only -f images/postgres/Dockerfile -n heyo-postgres --size-mb 1024
#
# This is not pg-fc's image. pg-fc boots straight into Postgres from PID 1 with
# `trust` auth, because the only way into those VMs is the pooler's tunnel. A
# public image has no such boundary, so this one:
#
# - requires a password (`POSTGRES_PASSWORD`) and authenticates every TCP
#   client with scram-sha-256, and
# - starts Postgres from app-lb's `start_command`, because env vars reach only
#   that process, never PID 1. That is the same split `artifacts/` uses.
#
# The heyvm build pipeline is docker build -> docker export -> mke2fs, so
# ENTRYPOINT/CMD/ENV are not used; the kernel boots /init.sh. x86_64 only.

FROM debian:bookworm-slim

ARG PG_MAJOR=18
ENV DEBIAN_FRONTEND=noninteractive

# Bookworm's own repos stop at PostgreSQL 15, so pull the major from PGDG, pinned
# to its signing key — the same recipe as pg-fc/Dockerfile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-${PG_MAJOR} \
        postgresql-client-${PG_MAJOR} \
        openssh-server \
        iproute2 \
        e2fsprogs \
        util-linux \
        gosu \
        locales \
    && localedef -i en_US -f UTF-8 en_US.UTF-8 \
    && apt-get purge -y gnupg \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Debian's package creates and starts a cluster of its own under
# /var/lib/postgresql; this image keeps its data on /workspace instead, so drop
# that one rather than ship a second, passwordless cluster in the rootfs.
RUN pg_dropcluster --stop ${PG_MAJOR} main 2>/dev/null || true; \
    rm -rf /var/lib/postgresql/${PG_MAJOR}/main /etc/postgresql/${PG_MAJOR}/main; \
    ln -s /usr/lib/postgresql/${PG_MAJOR} /usr/lib/postgresql/current

# SSH for `heyvm exec` / `heyvm sh`. Key-only; the daemon supplies the keys.
RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && printf 'PermitRootLogin prohibit-password\nPermitEmptyPasswords no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-heyo.conf \
    && passwd -d root \
    && ssh-keygen -A

COPY images/postgres/init.sh /init.sh
COPY images/postgres/heyo-postgres /usr/local/bin/heyo-postgres
RUN chmod +x /init.sh /usr/local/bin/heyo-postgres

# Prove the auth contract before the image ships: no password refuses to start,
# the right password connects over TCP, and a wrong one is rejected.
RUN set -eu; \
    if PGDATA=/tmp/smoke/pgdata heyo-postgres --foreground >/tmp/nopw.log 2>&1; then \
        echo "smoke test: started without POSTGRES_PASSWORD"; exit 1; \
    fi; \
    grep -q POSTGRES_PASSWORD /tmp/nopw.log; \
    POSTGRES_PASSWORD=smoke-pw POSTGRES_DB=app PGDATA=/tmp/smoke/pgdata PGPORT=55432 \
        heyo-postgres >/tmp/smoke.log 2>&1; \
    ok=0; \
    for _ in $(seq 60); do \
        if PGPASSWORD=smoke-pw psql -h 127.0.0.1 -p 55432 -U postgres -d app -Atc 'select 1' >/dev/null 2>&1; then ok=1; break; fi; \
        sleep 0.25; \
    done; \
    if [ "$ok" != 1 ]; then echo "smoke test: no connection with the password"; cat /tmp/smoke.log /tmp/smoke/pgdata/log/* 2>/dev/null; exit 1; fi; \
    if PGPASSWORD=wrong psql -h 127.0.0.1 -p 55432 -U postgres -d app -Atc 'select 1' >/dev/null 2>&1; then \
        echo "smoke test: a wrong password connected"; exit 1; \
    fi; \
    gosu postgres /usr/lib/postgresql/current/bin/pg_ctl -D /tmp/smoke/pgdata -m fast -w stop; \
    rm -rf /tmp/smoke /tmp/nopw.log /tmp/smoke.log /run/postgresql/*

EXPOSE 22 5432

CMD ["/init.sh"]
