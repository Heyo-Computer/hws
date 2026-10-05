# Meilisearch on Debian 13 (trixie) for heyvm, published on the hub as
# `heyo/meilisearch`.
#
# Built from the **repository root**, because init.sh is shared:
#
#   heyvm mvm build --local-only -f images/meilisearch/Dockerfile -c . -n heyo-meilisearch --size-mb 1024
#
# Meilisearch starts from start_command (`/usr/local/bin/heyo-meilisearch`),
# because MEILI_MASTER_KEY reaches only that process. See README.md.

FROM debian:13-slim

ARG MEILI_VERSION=1.54.3
# The release asset's digest as GitHub reports it; Meilisearch publishes no
# checksum file. Bump it with MEILI_VERSION:
#   gh api repos/meilisearch/meilisearch/releases/tags/v<version> \
#     -q '.assets[] | select(.name=="meilisearch-linux-amd64") | .digest'
ARG MEILI_SHA256=0ece934f9791f0db83e1184f4f505a38eae7d93ff1c47efaa9426cf2b3a12ba7
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        e2fsprogs \
        util-linux \
        procps \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    curl -fsSL -o /usr/local/bin/meilisearch \
        "https://github.com/meilisearch/meilisearch/releases/download/v${MEILI_VERSION}/meilisearch-linux-amd64"; \
    echo "${MEILI_SHA256}  /usr/local/bin/meilisearch" | sha256sum -c -; \
    chmod 755 /usr/local/bin/meilisearch

RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && printf 'PermitRootLogin prohibit-password\nPermitEmptyPasswords no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-heyo.conf \
    && passwd -d root \
    && ssh-keygen -A \
    && echo meilisearch > /etc/heyo-hostname

COPY images/base/init.sh /init.sh
COPY images/base/smoke.sh /tmp/smoke.sh
COPY images/meilisearch/heyo-meilisearch /usr/local/bin/heyo-meilisearch
RUN chmod +x /init.sh /usr/local/bin/heyo-meilisearch && sh /tmp/smoke.sh && rm /tmp/smoke.sh

# The key contract: no key refuses to start; with one, /health answers and
# an unauthenticated request for the index list is refused.
RUN set -eu; \
    if MEILI_DB_PATH=/tmp/smoke/data.ms heyo-meilisearch --foreground >/tmp/nokey.log 2>&1; then \
        echo "smoke: started without MEILI_MASTER_KEY"; exit 1; \
    fi; \
    grep -q MEILI_MASTER_KEY /tmp/nokey.log; \
    MEILI_MASTER_KEY=smoke-master-key-0123456789 MEILI_DB_PATH=/tmp/smoke/data.ms \
        MEILI_HTTP_ADDR=127.0.0.1:7700 heyo-meilisearch; \
    ok=0; \
    for _ in $(seq 80); do \
        if curl -fsS -m 1 http://127.0.0.1:7700/health >/dev/null 2>&1; then ok=1; break; fi; \
        sleep 0.25; \
    done; \
    [ "$ok" = 1 ] || { echo "smoke: /health never answered"; cat /tmp/smoke/meilisearch.log; exit 1; }; \
    test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7700/indexes)" = 401; \
    test "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer smoke-master-key-0123456789' http://127.0.0.1:7700/indexes)" = 200; \
    pkill meilisearch; sleep 1; \
    rm -rf /tmp/smoke /tmp/nokey.log

EXPOSE 22 7700

CMD ["/init.sh"]
