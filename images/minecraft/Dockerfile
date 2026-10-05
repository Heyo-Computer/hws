# Minecraft: Java Edition server on Debian 13 (trixie) for heyvm, published on
# the hub as `heyo/minecraft`.
#
# Built from the **repository root**, because init.sh is shared:
#
#   heyvm mvm build --local-only -f images/minecraft/Dockerfile -c . -n heyo-minecraft --size-mb 1024
#
# The image holds Java and a launcher, not Mojang's server jar: the Minecraft
# EULA does not allow redistributing it. `heyo-minecraft` downloads the jar from
# Mojang on first start, checks its SHA-1 against Mojang's manifest, and keeps
# it on /workspace. Starting requires EULA=TRUE: whoever deploys this is the one
# accepting https://aka.ms/MinecraftEULA. See README.md.

FROM debian:13-slim

# 25 is what Minecraft 26.x asks for (`javaVersion.majorVersion` in a version's
# manifest); heyo-minecraft refuses a version that needs more than this.
ARG JAVA_MAJOR=25
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        e2fsprogs \
        util-linux \
        procps \
        ca-certificates \
        curl \
        jq \
        openjdk-${JAVA_MAJOR}-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && echo "${JAVA_MAJOR}" > /etc/heyo-java-major

RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && printf 'PermitRootLogin prohibit-password\nPermitEmptyPasswords no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-heyo.conf \
    && passwd -d root \
    && ssh-keygen -A \
    && echo minecraft > /etc/heyo-hostname \
    && useradd --system --home-dir /workspace/minecraft --no-create-home --shell /usr/sbin/nologin minecraft

COPY images/base/init.sh /init.sh
COPY images/base/smoke.sh /tmp/smoke.sh
COPY images/minecraft/heyo-minecraft /usr/local/bin/heyo-minecraft
RUN chmod +x /init.sh /usr/local/bin/heyo-minecraft && sh /tmp/smoke.sh && rm /tmp/smoke.sh \
    && java -version 2>&1 | grep -q "version \"${JAVA_MAJOR}" \
    && { if MC_DIR=/tmp/mc heyo-minecraft --foreground >/tmp/noeula.log 2>&1; then echo "smoke: started without EULA"; exit 1; fi; } \
    && grep -q EULA /tmp/noeula.log && rm -rf /tmp/mc /tmp/noeula.log

EXPOSE 22 25565

CMD ["/init.sh"]
