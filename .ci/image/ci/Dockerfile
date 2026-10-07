# Firecracker microVM rootfs for building Rust, which is what this repository's
# own CI needs.
#
# Built with:
#   heyvm mvm build --local-only -f .ci/image/ci/Dockerfile -c .ci/image/ci \
#       -n ci-rust --size-mb 6144
#
# Any machine running heyvmd has the heyvm CLI, so this runs on the host that
# will build with it. `ci` itself never builds an image: it passes `vm.image`
# through to the daemon, which resolves a bare name against
# `~/.heyo/images/firecracker/{name}.ext4` and falls back to a public base image.
# `ci-rust` is neither until this is run.
#
# The heyvm build pipeline is docker build -> docker export -> mke2fs, and that
# has one consequence worth stating loudly: **OCI metadata is discarded.**
# ENTRYPOINT, CMD and — the one that bites — ENV are not carried into the rootfs.
# The VM boots straight into /init.sh via the kernel `init=` parameter, and
# anything that needs to be on PATH has to be put there by a file on disk, which
# is what /etc/profile.d below is for. x86_64 only.

FROM ubuntu:24.04

# Two groups, kept apart because they answer to different owners.
#
# The first is the heyvm boot contract: sshd for `heyvm exec`/`heyvm sh`,
# iproute2 to bring up eth0 from the kernel command line, e2fsprogs to format
# the attached data disk on first boot.
#
# The second is what building *this* application needs. `git` is not optional:
# `git submit` sends a git bundle and the checkout step clones it inside the
# guest, so without git a run fails before its first step. `pkg-config` and
# `libssl-dev` are not optional either — reqwest's default TLS is native-tls,
# which links OpenSSL rather than bundling it.
#
# The third is what the workflows test against: `postgresql-16` for
# `orchestrator.yml` and both it and `nats-server` for `ci.yml`'s claim and
# drain check. They used to be installed at the start of each job, which made a
# run depend on the Ubuntu mirrors and could time a step out before any of this
# repository's code ran.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        e2fsprogs \
        ca-certificates \
        curl \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        perl \
        git \
        python3 \
        pkg-config \
        libssl-dev \
        openssl \
    && apt-get install -y --no-install-recommends \
        postgresql-16 \
        nats-server \
    && rm -rf /var/lib/apt/lists/*

# SSH access for `heyvm exec` / `heyvm sh`. Host keys are generated at build
# time so sshd does not block on entropy at boot. Ubuntu 24.04 ships password
# auth disabled and Firecracker has no cloud-init to fix it, so it is enabled
# explicitly.
RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d \
    && echo "PermitRootLogin yes" >> /etc/ssh/sshd_config \
    && echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config \
    && echo "PasswordAuthentication yes" > /etc/ssh/sshd_config.d/50-heyo.conf \
    && chmod 644 /etc/ssh/sshd_config.d/50-heyo.conf \
    && passwd -d root \
    && useradd -m -s /bin/bash heyo \
    && echo 'heyo:heyo' | chpasswd \
    && ssh-keygen -A

# The toolchain, installed system-wide rather than into a user's home, because a
# step may run as root or as `heyo` and both have to find it.
#
# `--profile minimal` then adding clippy and rustfmt explicitly, rather than the
# default profile: the difference is `rust-docs`, which is hundreds of megabytes
# nothing in a build reads. Adding the two components is what makes `cargo fmt
# --check` and `cargo clippy` usable as workflow steps — with a bare minimal
# toolchain they fail with `no such command`, which reads as a broken CI rather
# than a missing component.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN curl -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
    && /usr/local/cargo/bin/rustup component add clippy rustfmt \
    && chmod -R a+w /usr/local/cargo /usr/local/rustup

# ENV above applies to the *docker build* only — the export discards it. These
# two are how the toolchain survives into the VM.
#
# The daemon renders a command as `env … sh -lc '<script>'`, and `-l` makes it a
# login shell, so /etc/profile.d is read for every step. The symlinks are the
# belt to that braces: a non-login shell, or anything exec'ing cargo directly,
# still finds it.
RUN printf '%s\n' \
      'export RUSTUP_HOME=/usr/local/rustup' \
      'export CARGO_HOME=/usr/local/cargo' \
      'export PATH=/usr/local/cargo/bin:$PATH' \
      'export CARGO_TARGET_DIR=/var/cache/ci/target' \
      > /etc/profile.d/10-rust.sh \
    && chmod 644 /etc/profile.d/10-rust.sh \
    && for b in cargo rustc rustup rustdoc; do \
         ln -sf /usr/local/cargo/bin/$b /usr/local/bin/$b; \
       done

# CARGO_TARGET_DIR above points here, outside /workspace on purpose: `ci` wipes
# the workspace on every checkout, so a `target/` inside it is rebuilt from
# scratch every run and the warm VM pool buys nothing. init.sh mounts the data
# disk over this path when the workflow asks for one.
RUN mkdir -p /var/cache/ci/target && chmod -R 1777 /var/cache/ci

COPY init.sh /init.sh
RUN chmod +x /init.sh

# Prove the toolchain works before the image ships. A rootfs whose cargo is
# broken is indistinguishable, from a run's point of view, from a workflow whose
# build command is wrong: both are a VM that boots and then fails a step. This
# turns the first class into a build failure with the error attached.
#
# Compiling something real, not just `--version`: a toolchain missing its linker
# or OpenSSL headers passes every version check and fails on the first crate.
#
# CARGO_TARGET_DIR is pinned back to the local tree for the build: 10-rust.sh
# points it at /var/cache/ci/target, so without the override the binary lands
# there and `./target/release/smoke` is a 127 — and the throwaway build's
# artifacts would be baked into the shipped rootfs.
RUN set -eu; \
    . /etc/profile.d/10-rust.sh; \
    cargo --version; rustc --version; \
    cargo clippy --version; cargo fmt --version; \
    git --version; pkg-config --modversion openssl; \
    pg_lsclusters; /usr/lib/postgresql/16/bin/postgres --version; \
    nats-server --version; \
    tmp="$(mktemp -d)"; cd "$tmp"; \
    cargo init --quiet --name smoke; \
    CARGO_TARGET_DIR="$tmp/target" cargo build --quiet --release; \
    ./target/release/smoke; \
    cd /; rm -rf "$tmp"

EXPOSE 22
CMD ["/init.sh"]
