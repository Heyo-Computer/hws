# Firecracker microVM rootfs for building `app-lb` (with `heyctl`) and `app-obs`.
#
# `ci` builds this itself: `.ci/workflows/app-lb.yml` and `app-obs.yml` point `vm.build.dockerfile`
# here, and the first job to land on a host uploads this file plus its context
# to the daemon's `POST /images/build`, which runs the
# `docker build -> docker export -> mke2fs` pipeline behind `heyvm mvm build`.
# The image is named for the hash of these bytes, the context and `size_mb`, so
# an unchanged one is reused and any edit builds a new one. Nothing has to be
# run by hand on a runner.
#
# **One image, two jobs.** `app-lb` and `app-obs` are separate cargo workspaces
# with separate lockfiles, but their *system* requirements are the same set —
# a C compiler, cmake and perl — so a second Dockerfile would only mean a second
# 10-to-20-minute image build on every runner for no difference in contents.
# They still get separate warm VM pools, because the pool fingerprint includes
# `cache_key_files` and those differ per job. See `.ci/image/codegraph/` for the
# other case: a genuinely smaller graph that earns its own image.
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
# The second is what the two builds need, and every line of it was read off
# `cargo tree`/`Cargo.lock` rather than guessed:
#
# - `build-essential` for `cc` and `make`. Both graphs compile C: `zstd-sys`
#   (app-obs, under datafusion's async-compression; app-lb, under pingora),
#   `aws-lc-sys`, `libz-ng-sys` and vendored OpenSSL.
# - `cmake`, because `aws-lc-sys` is reached by **both** — app-lb asks for
#   `rustls/aws-lc-rs` explicitly to install a process-level CryptoProvider,
#   and app-obs gets it through `reqwest 0.13`'s rustls stack — and because
#   `libz-ng-sys` (pingora's zlib-ng backend, which wins app-lb's workspace
#   feature unification) builds zlib-ng with it.
# - `perl`, because OpenSSL's `Configure` is a Perl program and app-lb builds
#   OpenSSL from source. See the note on libssl-dev below.
# - `pkg-config`, the one package here bought as insurance rather than proven
#   necessary. `openssl-sys` lists it as a plain, non-optional build dependency
#   and its build script reaches `pkg_config::probe` on any path where the
#   `vendored` feature is off — and that feature is switched on by
#   `pingora-openssl`, a third-party crate, not by anything in this repository.
#   A dependency bump that flips it would otherwise fail on a missing binary
#   rather than on the missing library it is actually looking for.
# - `git` is **not optional**: this repository submits as a bundle (see the
#   workflow header), and a bundle is cloned *inside the guest* by the checkout
#   step. An image without git fails a run before its first step.
#
# Deliberately absent:
#
# - `libssl-dev`. This is the surprise, since app-lb links OpenSSL: it does not
#   need the distribution's copy, because `pingora-openssl` enables
#   `openssl/vendored`, so `openssl-src` compiles OpenSSL from source into the
#   binary. That is also why `perl` is above. If a future pingora drops the
#   vendored feature the build fails with "Could not find directory of OpenSSL
#   installation" — add `libssl-dev` here and the message goes away.
# - `libclang-dev`. `aws-lc-sys` ships pre-generated bindings for
#   x86_64-unknown-linux-gnu, so its `bindgen` feature is off and nothing here
#   reaches libclang.
# - `golang`. Only aws-lc-sys's from-scratch generation path wants it; the
#   published crate carries the generated assembly.
#
# The third group is what the workflows *test* with rather than build with:
# `python3` and the `openssl` CLI for app-lb's gateway smoke test (it mints a
# disposable CA), and `postgresql-16` plus `libssl-dev` for
# `regional-drain-validation.yml`. They used to be `apt-get install`ed at the
# start of each job, which made every run depend on the Ubuntu mirrors being
# fast that minute — a slow mirror timed the step out (exit 124) before any of
# this repository's code ran. Baked in, a job needs no network for tools at all.
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
        pkg-config \
        git \
    && apt-get install -y --no-install-recommends \
        python3 \
        openssl \
        libssl-dev \
        postgresql-16 \
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
# Both workspaces are `edition = "2024"`, which needs Rust 1.85 or newer.
# `stable` is well past that; pinning a version here would be a second place to
# remember when either workspace grows a rust-toolchain.toml, which the workflow
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
#
# The two jobs share this path but never a VM — each job gets its own sandbox
# from its own pool, so there is no question of one workspace's `target/`
# colliding with the other's.
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
# `cmake` and `perl` are version-checked rather than exercised. Actually
# building a vendored OpenSSL here would add ten minutes to every image build to
# re-prove something the first real run proves anyway; a missing binary is the
# failure mode worth catching at build time, and `--version` catches it.
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
    cmake --version | head -1; perl --version | sed -n 2p; \
    pkg-config --version; \
    python3 --version; openssl version; \
    pg_lsclusters; /usr/lib/postgresql/16/bin/postgres --version; \
    tmp="$(mktemp -d)"; cd "$tmp"; \
    cargo init --quiet --name smoke; \
    CARGO_TARGET_DIR="$tmp/target" cargo build --quiet --release; \
    ./target/release/smoke; \
    cd /; rm -rf "$tmp"

EXPOSE 22
CMD ["/init.sh"]
