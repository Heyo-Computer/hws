# Firecracker microVM rootfs for small Rust builds with no system libraries
# in their dependency graph (today, `art`).
#
# `ci` builds this itself: `.ci/workflows/art.yml` points
# `vm.build.dockerfile` here, and the first job to land on a host uploads this
# file plus its context to the daemon's `POST /images/build`, which runs the
# `docker build -> docker export -> mke2fs` pipeline behind `heyvm mvm build`.
# The image is named for the hash of these bytes, the context and `size_mb`, so
# an unchanged one is reused and any edit builds a new one. Nothing has to be
# run by hand on a runner.
#
# **`docker export` discards OCI metadata.** ENTRYPOINT, CMD and — the one that
# bites — ENV do not survive into the rootfs. The VM boots straight into
# /init.sh via the kernel `init=` parameter, so anything that must be on PATH
# has to be put there by a file on disk, which is what /etc/profile.d below is
# for. x86_64 only.

FROM ubuntu:24.04

# Two groups, kept apart because they answer to different owners.
#
# The first is the heyvm boot contract: sshd for `heyvm exec`/`heyvm sh`,
# iproute2 to bring up eth0 from the kernel command line, e2fsprogs to format
# the attached data disk on first boot.
#
# The second is what building `art` needs, and it is short because none of
# its 131 crates links a system library:
#
# - `build-essential` for `cc` and the linker.
# - `git` is **not optional**, and for a different reason than in a repository
#   that uses `--archive`: this repository's bundle is small enough to submit
#   as one, and a bundle is cloned *inside the guest* by the checkout step. An
#   image without git fails a run before its first step.
#
# Deliberately absent, because `cargo tree` reaches none of them:
# `pkg-config`/`libssl-dev` (no openssl-sys), `cmake` (no aws-lc-sys), `perl` (no openssl-src), `libclang-dev`
# (no bindgen). Adding a package "just in case" costs image build time on every
# runner and hides what the build actually depends on.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        iproute2 \
        e2fsprogs \
        ca-certificates \
        curl \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
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
# `--profile minimal` then adding clippy and rustfmt explicitly: the difference
# from the default profile is `rust-docs`, which is hundreds of megabytes
# nothing in a build reads. The two components are what make `cargo fmt --check`
# and `cargo clippy` usable as steps later — with a bare minimal toolchain they
# fail with `no such command`, which reads as broken CI rather than as a missing
# component.
#
# `stable`, not a pinned version: a pin here would be a second place to
# remember when the repository grows a rust-toolchain.toml, which the workflow
# already watches through `cache_key_files`.
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
# passes every version check and fails on the first crate.
#
# CARGO_TARGET_DIR is pinned back to the local tree for the build: 10-rust.sh
# points it at /var/cache/ci/target, so without the override the binary lands
# there and `./target/release/smoke` is a 127 — and the throwaway build's
# artifacts would be baked into the shipped rootfs.
RUN set -eu; \
    . /etc/profile.d/10-rust.sh; \
    cargo --version; rustc --version; \
    cargo clippy --version; cargo fmt --version; \
    git --version; cc --version | head -1; \
    tmp="$(mktemp -d)"; cd "$tmp"; \
    cargo init --quiet --name smoke; \
    CARGO_TARGET_DIR="$tmp/target" cargo build --quiet --release; \
    ./target/release/smoke; \
    cd /; rm -rf "$tmp"

EXPOSE 22
CMD ["/init.sh"]
