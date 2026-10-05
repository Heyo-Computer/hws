# Firecracker microVM rootfs for the git remote (`remote`).
#
# Built from the **repository root**, not this directory:
#
#   heyvm mvm build --local-only -f remote/Dockerfile -n remote --size-mb 768
#
# and an app-lb `build` block needs `"context": "."` beside
# `"dockerfile": "remote/Dockerfile"`: the crate depends on
# `../heyosecret-client` and includes `../ui` by path, so the context must
# hold all three.
#
# The heyvm build pipeline is docker build -> docker export -> mke2fs, which
# discards OCI metadata (ENTRYPOINT/CMD/ENV are NOT used). The VM boots straight
# into /init.sh via the kernel init= parameter. x86_64 only.

# --- build stage ---
FROM rust:1-bookworm AS builder
WORKDIR /app/remote
COPY heyosecret-client /app/heyosecret-client
# The web UI includes the shared stylesheet, fonts and top bar by path.
COPY ui /app/ui
COPY remote/Cargo.toml remote/Cargo.lock ./
COPY remote/src ./src
COPY remote/tests ./tests
RUN cargo build --release --locked

# --- runtime rootfs ---
FROM ubuntu:24.04

# git is not optional: every clone and push runs `git upload-pack` /
# `git receive-pack`, and the pre-receive hook is this binary run by git.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    openssh-server \
    iproute2 \
    e2fsprogs \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# SSH access for `heyvm exec` / `heyvm sh`. Pre-generate host keys at build time
# so sshd doesn't block on entropy at boot. The daemon supplies authorized keys.
RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && printf 'PermitRootLogin prohibit-password\nPermitEmptyPasswords no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' > /etc/ssh/sshd_config.d/00-heyo.conf \
    && passwd -d root \
    && ssh-keygen -A

COPY --from=builder /app/remote/target/release/remote /usr/local/bin/remote
COPY remote/init.sh /init.sh
RUN chmod +x /init.sh /usr/local/bin/remote

# Prove the rootfs can actually serve before it ships: a binary that cannot
# start looks, from app-lb's side, exactly like a misconfigured one — a VM that
# boots and never answers /healthz. This makes the first a build failure.
#
# A local `fs:` store and no credentials: this checks that the daemon and git
# work together here, not how it is configured in production.
RUN set -eu; \
    git --version >/dev/null; \
    REMOTE_STORE=fs:/tmp/smoke/store REMOTE_CACHE_DIR=/tmp/smoke/cache \
    REMOTE_LISTEN=127.0.0.1:9700 REMOTE_ADMIN_TOKEN=smoke \
        /usr/local/bin/remote >/tmp/smoke.log 2>&1 & \
    pid=$!; ok=0; \
    for _ in $(seq 60); do \
        if curl -fsS -m 1 http://127.0.0.1:9700/healthz >/dev/null 2>&1; then ok=1; break; fi; \
        kill -0 "$pid" 2>/dev/null || break; \
        sleep 0.25; \
    done; \
    kill "$pid" 2>/dev/null || true; \
    if [ "$ok" != 1 ]; then \
        echo "smoke test: remote never answered GET /healthz"; cat /tmp/smoke.log; exit 1; \
    fi; \
    rm -rf /tmp/smoke /tmp/smoke.log

EXPOSE 22 9700

CMD ["/init.sh"]
