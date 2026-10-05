# Debian 13 (trixie) for heyvm, published on the hub as `heyo/debian`.
#
# Built from the **repository root**, because init.sh is shared:
#
#   heyvm mvm build --local-only -f images/debian/Dockerfile -c . -n heyo-debian --size-mb 1024
#
# A base image: networking, sshd for `heyvm exec`, a data disk at /workspace,
# and nothing running beyond that. A deployment brings its own process through
# start_command. See images/README.md.

FROM debian:13-slim

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

# Key-only SSH for `heyvm exec` / `heyvm sh`; heyvmd supplies the keys. Host
# keys are generated now so sshd does not wait on entropy at boot.
RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && printf 'PermitRootLogin prohibit-password\nPermitEmptyPasswords no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-heyo.conf \
    && passwd -d root \
    && ssh-keygen -A \
    && echo debian > /etc/heyo-hostname

COPY images/base/init.sh /init.sh
COPY images/base/smoke.sh /tmp/smoke.sh
RUN chmod +x /init.sh && sh /tmp/smoke.sh && rm /tmp/smoke.sh

CMD ["/init.sh"]
