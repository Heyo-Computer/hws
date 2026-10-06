# Alpine 3.24 for heyvm, published on the hub as `heyo/alpine`.
#
# Built from the **repository root**, because init.sh is shared:
#
#   heyvm mvm build --local-only -f images/alpine/Dockerfile -c . -n heyo-alpine --size-mb 512
#
# A base image: networking, sshd for `heyvm exec`, a data disk at /workspace,
# and nothing running beyond that. A deployment brings its own process through
# start_command. See images/README.md.
#
# bash is installed because heyvm's serial console runs a login shell, and
# blkid/iproute2 because busybox's versions lack the flags init.sh uses.

FROM alpine:3.24

RUN apk add --no-cache \
        openssh-server \
        bash \
        iproute2 \
        e2fsprogs \
        blkid \
        ca-certificates \
        curl

# Key-only SSH for `heyvm exec` / `heyvm sh`; heyvmd supplies the keys. Host
# keys are generated now so sshd does not wait on entropy at boot.
RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && printf 'PermitRootLogin prohibit-password\nPermitEmptyPasswords no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-heyo.conf \
    && passwd -d root \
    && ssh-keygen -A \
    && echo alpine > /etc/heyo-hostname \
    && mkdir -p /workspace

COPY images/base/init.sh /init.sh
COPY images/base/smoke.sh /tmp/smoke.sh
RUN chmod +x /init.sh && sh /tmp/smoke.sh && rm /tmp/smoke.sh

CMD ["/init.sh"]
