#!/bin/sh
# Run a Cargo phase with optional shared S3 compiler caching. Never retain a VM.
# CI_RUST_CACHE_MODE: off (default), read-only, or read-write.
set -eu

[ "$#" -gt 0 ] || { echo 'usage: rust-cache.sh command [args...]' >&2; exit 2; }
mode=${CI_RUST_CACHE_MODE:-off}
case "$mode" in off|read-only|read-write) ;; *) echo 'Invalid CI_RUST_CACHE_MODE' >&2; exit 2 ;; esac
cache_active=false
cache_setup_start=$(date +%s)

if [ "$mode" != off ]; then
    : "${SCCACHE_BUCKET:?dedicated compiler-cache bucket required}"
    : "${SCCACHE_ENDPOINT:?compiler-cache HTTPS endpoint required}"
    : "${SCCACHE_REGION:?compiler-cache signing region required}"
    : "${SCCACHE_S3_KEY_PREFIX:?project/trust-scoped prefix required}"
    : "${CI_RUST_CACHE_ACCESS_KEY_ID:?dedicated cache credentials required}"
    : "${CI_RUST_CACHE_SECRET_ACCESS_KEY:?dedicated cache credentials required}"
    case "$SCCACHE_ENDPOINT" in https://*) ;; *) echo 'Cache endpoint must use HTTPS' >&2; exit 2 ;; esac
    [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo 'Cache bootstrap requires Linux x86_64' >&2; exit 2; }
    version=0.18.0
    archive=sccache-v${version}-x86_64-unknown-linux-musl.tar.gz
    digest=45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89
    # Job-local installation; this is not the compilation cache. Every fresh
    # VM can reuse remote outputs, including a job placed in another region.
    directory=${CARGO_TARGET_DIR:?}/../sccache-${version}
    mkdir -p "$directory"
    if [ ! -x "$directory/sccache" ]; then
        temporary=$(mktemp -d)
        trap 'rm -rf "$temporary"' EXIT HUP INT TERM
        if curl --fail --silent --show-error --location --retry 2 --max-time 60 \
            "https://github.com/mozilla/sccache/releases/download/v${version}/${archive}" \
            -o "$temporary/$archive"; then
            # A bad checksum is not an outage: refuse to execute those bytes.
            printf '%s  %s\n' "$digest" "$temporary/$archive" | sha256sum -c -
            tar -xzf "$temporary/$archive" -C "$temporary"
            install -m 0755 "$temporary/${archive%.tar.gz}/sccache" "$directory/sccache"
        else
            echo 'Compiler-cache download unavailable; compiling without cache' >&2
        fi
        rm -rf "$temporary"
        trap - EXIT HUP INT TERM
    fi
    if [ -x "$directory/sccache" ]; then
        # Stop the previous phase's daemon so it cannot keep old credentials
        # or cache mode. Dedicated credentials are only passed to the daemon.
        "$directory/sccache" --stop-server >/dev/null 2>&1 || true
        if [ "$mode" = read-only ]; then rw=READ_ONLY; else rw=READ_WRITE; fi
        if env AWS_ACCESS_KEY_ID="$CI_RUST_CACHE_ACCESS_KEY_ID" \
            AWS_SECRET_ACCESS_KEY="$CI_RUST_CACHE_SECRET_ACCESS_KEY" \
            AWS_SESSION_TOKEN= AWS_EC2_METADATA_DISABLED=true \
            SCCACHE_S3_RW_MODE="$rw" SCCACHE_S3_USE_SSL=true \
            "$directory/sccache" --start-server; then
            export RUSTC_WRAPPER="$directory/sccache"
            export CARGO_INCREMENTAL=0 SCCACHE_IGNORE_SERVER_IO_ERROR=1
            cache_active=true
            "$directory/sccache" --zero-stats >/dev/null || true
        else
            echo 'Compiler-cache startup unavailable; compiling without cache' >&2
        fi
    fi
fi

if [ "$cache_active" = false ]; then
    # An empty wrapper overrides Cargo configuration too; off really is off.
    export RUSTC_WRAPPER=
fi
unset CI_RUST_CACHE_ACCESS_KEY_ID CI_RUST_CACHE_SECRET_ACCESS_KEY
echo "ci-cache mode=$mode active=$cache_active setup_seconds=$(($(date +%s) - cache_setup_start))"
started=$(date +%s)
status=0
"$@" || status=$?
echo "ci-cache command_seconds=$(($(date +%s) - started)) exit_code=$status"
if [ "$cache_active" = true ]; then
    "$directory/sccache" --show-stats || true
    "$directory/sccache" --stop-server >/dev/null 2>&1 || true
fi
exit "$status"
