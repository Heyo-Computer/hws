# Bun on Debian 13 (trixie) for heyvm, published on the hub as `heyo/bun`.
#
# Built from the **repository root**, because init.sh is shared:
#
#   heyvm mvm build --local-only -f images/bun/Dockerfile -c . -n heyo-bun --size-mb 1024
#
# heyo/debian plus bun. Nothing runs at boot beyond init.sh; a deployment brings
# its app through start_command. See images/README.md.

FROM debian:13-slim

# The baseline build: no AVX2 requirement, so the image boots on any host CPU
# and under any Firecracker CPU template.
ARG BUN_VERSION=1.4.2
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        e2fsprogs \
        util-linux \
        procps \
        ca-certificates \
        curl \
        git \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Verified against the release's SHASUMS256.txt before it is installed.
RUN set -eu; \
    cd /tmp; \
    base="https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}"; \
    curl -fsSLO "$base/bun-linux-x64-baseline.zip"; \
    curl -fsSLO "$base/SHASUMS256.txt"; \
    grep ' bun-linux-x64-baseline.zip$' SHASUMS256.txt | sha256sum -c -; \
    unzip -q bun-linux-x64-baseline.zip; \
    install -m 755 bun-linux-x64-baseline/bun /usr/local/bin/bun; \
    ln -s bun /usr/local/bin/bunx; \
    rm -rf /tmp/bun-linux-x64-baseline* /tmp/SHASUMS256.txt

RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && printf 'PermitRootLogin prohibit-password\nPermitEmptyPasswords no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-heyo.conf \
    && passwd -d root \
    && ssh-keygen -A \
    && echo bun > /etc/heyo-hostname

COPY images/base/init.sh /init.sh
COPY images/base/smoke.sh /tmp/smoke.sh
RUN chmod +x /init.sh && sh /tmp/smoke.sh && rm /tmp/smoke.sh \
    && test "$(bun --version)" = "${BUN_VERSION}" \
    && bun -e 'const s = Bun.serve({ port: 0, fetch: () => new Response("ok") }); const r = await fetch(`http://127.0.0.1:${s.port}/`); if (await r.text() !== "ok") process.exit(1); s.stop(); console.log("smoke: bun serves")'

CMD ["/init.sh"]
