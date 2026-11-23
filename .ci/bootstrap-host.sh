#!/bin/sh
# Prepare a fresh Ubuntu host to join the app-lb fleet: heyvmd + app-lb,
# supervised, with ACME on :80/:443 and the admin API routed at
# admin.<domain>. It installs and starts host software only — it creates no
# workload VMs and builds nothing; workloads are registered afterwards through
# app-lb's admin API (heyctl apply), and releases roll through CI.
#
#   curl -fsSL https://raw.githubusercontent.com/Heyo-Computer/heyo-public/main/.ci/bootstrap-host.sh | sh -s -- \
#       --id us4 --domain us4.heyo.computer --public-ip 203.0.113.4 --acme-email ops@heyo.computer
#
# ## Secrets are not passed on the command line
#
# The caller writes them beforehand, mode 0600, over a channel that does not
# record them:
#
#   /etc/app-lb/env   APP_LB_DASHBOARD_PASSWORD=…  (and optionally
#                     APP_LB_OBS_TOKEN, APP_LB_DAEMON_API_KEY)
#   /etc/heyvm/env    optional; heyvmd's environment (JWT_SECRET,
#                     CLOUD_INTERNAL_API_KEY, HEYO_CLOUD_URL, …)
#
# This script refuses to continue without /etc/app-lb/env, and never prints
# either file.
#
# ## Idempotent
#
# Re-running reinstalls the binaries at the pinned (or latest) versions, keeps
# existing supervisor units (new ones land as `.new`), and re-applies the admin
# route. Nothing touches a host until someone runs this on it.
#
# ## Binaries (--binaries)
#
#   heyo      (default) the public channels, each verified:
#               heyvm, heyvmd  heyo-cli-releases tarball   HEYVM_VERSION [latest], HEYVM_SHA256
#               heyctl         heyo.computer/heyctl/install.sh  HEYCTL_VERSION [latest], HEYCTL_DIGEST
#               app-lb         hub.heyo.work/heyo/app-lb   APP_LB_TAG [latest], APP_LB_DIGEST
#             A *_SHA256/*_DIGEST pin must match or the install stops. Without
#             one, heyvm is unverified (its channel publishes no checksum);
#             heyctl and app-lb are always checked against their manifests.
#   releases  the older manifest site via install-apps.sh (--releases-url),
#             which also installs `art`
#   none      leave /usr/local/bin alone (the caller installs binaries)
#
# Firecracker (FIRECRACKER_VERSION [v1.16.1]) always comes from its GitHub
# release, checked against the release's published .sha256.txt.
#
# ## Stages
#
#   --stage all        (default) install, then configure — the line above
#   --stage install    packages, firecracker and binaries only. Needs no
#                      arguments, no /dev/kvm and no secrets, so an image
#                      builder (app-lb/deploy/ec2) can bake it ahead of time.
#   --stage configure  per-host part only: checks, supervisor units, health
#                      waits and the admin route. Expects the install stage
#                      to have run already (e.g. baked into the image).
#   --vm-api heyvm     serve the sandbox API with `heyvm --api` instead of
#                      heyvmd (the default). heyvmd needs a Heyo login
#                      (HEYO_API_KEY or `heyvm login`); `heyvm --api` needs
#                      none but binds 0.0.0.0 without auth, so the unit drops
#                      port 34099 on every interface but loopback first.

set -eu

main() {

HOST_ID=""; DOMAIN=""; PUBLIC_IP=""; ACME_EMAIL=""; ACME_STAGING=0
RELEASES_URL="${RELEASES_URL:-https://get.us2.heyo.work}"
FIRECRACKER_VERSION="${FIRECRACKER_VERSION:-v1.16.1}"
DASHBOARD_USER="${DASHBOARD_USER:-heyo}"
STAGE=all
BINARIES=heyo
HUB_URL="${HUB_URL:-https://hub.heyo.work}"
HEYVM_RELEASES_URL="${HEYVM_RELEASES_URL:-https://heyo-cli-releases.s3.amazonaws.com/heyvm}"
VM_API=heyvmd

info() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
step() { printf '    %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# verify_sha256 FILE WANT WHAT — WANT empty means "no pin"; otherwise exact.
verify_sha256() {
    case "$2" in
        '') return 0 ;;
        *[!0-9a-f]*) die "$3: expected sha256 '$2' is not lowercase hex" ;;
    esac
    [ "${#2}" = 64 ] || die "$3: expected sha256 '$2' is not 64 hex digits"
    got="$(sha256sum "$1" | awk '{print $1}')"
    [ "$got" = "$2" ] || die "$3: sha256 mismatch (want $2, got $got)"
    step "$3: sha256 verified"
}

# The public channels. Writes a `name=version (provenance)` line per binary
# to /etc/heyo/binaries, which image builders fold into their manifest.
install_heyo_binaries() {
    bin=/usr/local/bin
    work="$(mktemp -d)"

    # heyvm + heyvmd: the release tarball, fetched directly rather than through
    # heyo.computer/heyvm/install.sh, so a failed download stops here instead
    # of falling back to a cargo build, and a pinned checksum can be enforced.
    hv="${HEYVM_VERSION:-latest}"
    if [ "$hv" = latest ]; then
        hv="$(curl -fsSL "$HEYVM_RELEASES_URL/latest.txt" | tr -d '[:space:]')"
        [ -n "$hv" ] || die "could not resolve the latest heyvm version"
    fi
    hv="${hv#v}"
    info "heyvm $hv"
    curl -fsSL -o "$work/heyvm.tgz" "$HEYVM_RELEASES_URL/v$hv/heyvm-$hv-unknown-linux-gnu-$(uname -m).tar.gz"
    if [ -n "${HEYVM_SHA256:-}" ]; then
        verify_sha256 "$work/heyvm.tgz" "$HEYVM_SHA256" "heyvm $hv"
    else
        warn "heyvm $hv: no HEYVM_SHA256 pin, so the tarball is not verified"
    fi
    mkdir "$work/heyvm"
    tar -xzf "$work/heyvm.tgz" -C "$work/heyvm"
    for b in heyvm heyvmd; do
        [ -f "$work/heyvm/$b" ] || die "the heyvm $hv tarball has no $b"
        install -o root -g root -m0755 "$work/heyvm/$b" "$bin/$b.new"
        mv "$bin/$b.new" "$bin/$b"
    done

    # heyctl: its own installer verifies the blob against its manifest.
    info "heyctl ${HEYCTL_VERSION:-latest}"
    curl -fsSL -o "$work/heyctl-install.sh" https://heyo.computer/heyctl/install.sh
    set -- --prefix /usr/local
    [ "${HEYCTL_VERSION:-latest}" = latest ] || set -- "$@" --version "$HEYCTL_VERSION"
    [ -z "${HEYCTL_DIGEST:-}" ] || set -- "$@" --digest "$HEYCTL_DIGEST"
    # The installer reads HEYCTL_VERSION itself and has no "latest", so keep
    # ours out of its environment and pass flags instead.
    env -u HEYCTL_VERSION -u HEYCTL_DIGEST sh "$work/heyctl-install.sh" "$@" </dev/null >&2

    # app-lb: the hub. Resolve the tag to its blob, check the blob against that
    # digest (and the pin, if any), then against the tarball's SHA256SUMS.
    tag="${APP_LB_TAG:-latest}"
    info "app-lb $HUB_URL heyo/app-lb:$tag"
    curl -fsSL -o "$work/manifest.json" "$HUB_URL/manifests/heyo/app-lb:$tag"
    digest="$(jq -r '[.entries[] | select(.name == "app-lb")] | if length == 1 then .[0].digest else "" end' "$work/manifest.json")"
    [ -n "$digest" ] || die "hub manifest heyo/app-lb:$tag has no single app-lb entry"
    if [ -n "${APP_LB_DIGEST:-}" ] && [ "$digest" != "$APP_LB_DIGEST" ]; then
        die "heyo/app-lb:$tag now points at $digest, not the pinned APP_LB_DIGEST $APP_LB_DIGEST"
    fi
    curl -fsSL -o "$work/app-lb.tar.gz" "$HUB_URL/blobs/$digest"
    verify_sha256 "$work/app-lb.tar.gz" "$digest" "app-lb blob"
    mkdir "$work/app-lb"
    tar -xzf "$work/app-lb.tar.gz" -C "$work/app-lb"
    dist="$work/app-lb/dist"
    for f in SHA256SUMS app-lb; do
        [ -f "$dist/$f" ] || die "the app-lb tarball has no dist/$f"
    done
    (cd "$dist" && sha256sum -c --quiet SHA256SUMS) || die "app-lb SHA256SUMS check failed"
    install -o root -g root -m0755 "$dist/app-lb" "$bin/app-lb.new"
    mv "$bin/app-lb.new" "$bin/app-lb"

    install -d -m0755 /etc/heyo
    {
        printf 'app-lb=%s (hub heyo/app-lb:%s, blob %s)\n' "$("$bin/app-lb" --version 2>/dev/null | head -1)" "$tag" "$digest"
        printf 'heyctl=%s\n' "$("$bin/heyctl" --version 2>/dev/null | head -1)"
        printf 'heyvm=%s (tarball sha256 %s)\n' "$hv" "$(sha256sum "$work/heyvm.tgz" | awk '{print $1}')"
    } > /etc/heyo/binaries
    rm -rf "$work"
    sed 's/^/    /' /etc/heyo/binaries >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --id)            shift; HOST_ID="${1:-}" ;;
        --domain)        shift; DOMAIN="${1:-}" ;;
        --public-ip)     shift; PUBLIC_IP="${1:-}" ;;
        --acme-email)    shift; ACME_EMAIL="${1:-}" ;;
        --acme-staging)  ACME_STAGING=1 ;;
        --releases-url)  shift; RELEASES_URL="${1:-}" ;;
        --stage)         shift; STAGE="${1:-}" ;;
        --binaries)      shift; BINARIES="${1:-}" ;;
        --vm-api)        shift; VM_API="${1:-}" ;;
        -h|--help)       sed -n '2,59p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
        *)               die "unknown argument: $1" ;;
    esac
    shift
done

case "$STAGE" in all|install|configure) ;; *) die "--stage must be all, install or configure" ;; esac
case "$VM_API" in heyvmd|heyvm) ;; *) die "--vm-api must be heyvmd or heyvm" ;; esac
case "$BINARIES" in heyo|releases|none) ;; *) die "--binaries must be heyo, releases or none" ;; esac

[ "$(id -u)" = 0 ] || die "run as root"
command -v apt-get >/dev/null 2>&1 || die "this bootstrap supports Debian/Ubuntu hosts (apt-get)"

# Per-host checks. The install stage needs none of them: it only puts
# packages and binaries on disk.
if [ "$STAGE" != install ]; then
case "$HOST_ID" in ''|*[!a-z0-9-]*) die "--id must be a short lowercase name (us4)" ;; esac
case "$DOMAIN" in ''|*[!a-z0-9.-]*) die "--domain must be a hostname (us4.heyo.computer)" ;; esac
case "$PUBLIC_IP" in ''|*[!0-9.:a-f]*) die "--public-ip must be the host's public address" ;; esac
[ -n "$ACME_EMAIL" ] || die "--acme-email is required (Let's Encrypt account contact)"

[ -e /dev/kvm ] || die "/dev/kvm is missing — enable virtualization on this host"
[ -s /etc/app-lb/env ] || die "/etc/app-lb/env is missing; write APP_LB_DASHBOARD_PASSWORD there (0600) first"
grep -q '^APP_LB_DASHBOARD_PASSWORD=.' /etc/app-lb/env || die "/etc/app-lb/env has no APP_LB_DASHBOARD_PASSWORD"
chmod 0600 /etc/app-lb/env
if [ -f /etc/heyvm/env ]; then chmod 0600 /etc/heyvm/env; fi
fi

if [ "$STAGE" != configure ]; then
# ---- packages ---------------------------------------------------------------

info "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# docker + e2fsprogs: heyvmd builds guest images (`vm.build`) with docker and
# mke2fs. socat: guest log forwarding. supervisor runs both services, as on us2.
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl tar jq supervisor docker.io e2fsprogs socat iproute2 iptables >/dev/null
systemctl enable --now docker supervisor >/dev/null 2>&1 || true

if ! command -v firecracker >/dev/null 2>&1 || ! firecracker --version 2>/dev/null | grep -q "Firecracker ${FIRECRACKER_VERSION}"; then
    info "firecracker $FIRECRACKER_VERSION"
    arch="$(uname -m)"
    tmp="$(mktemp -d)"
    fc_url="https://github.com/firecracker-microvm/firecracker/releases/download/${FIRECRACKER_VERSION}/firecracker-${FIRECRACKER_VERSION}-${arch}.tgz"
    curl -fsSL -o "$tmp/fc.tgz" "$fc_url"
    want="$(curl -fsSL "$fc_url.sha256.txt" | awk '{print $1}')"
    verify_sha256 "$tmp/fc.tgz" "$want" "firecracker $FIRECRACKER_VERSION"
    tar -xzf "$tmp/fc.tgz" -C "$tmp"
    install -m0755 "$tmp/release-${FIRECRACKER_VERSION}-${arch}/firecracker-${FIRECRACKER_VERSION}-${arch}" /usr/local/bin/firecracker
    rm -rf "$tmp"
fi
step "$(firecracker --version | head -1)"

# ---- binaries -----------------------------------------------------------------

case "$BINARIES" in
heyo)
    install_heyo_binaries
    ;;
releases)
    info "heyvm, app-lb and art from $RELEASES_URL"
    curl -fsSL "$RELEASES_URL/install-apps.sh" -o /tmp/install-apps.sh
    # Units are written below (this host's layout differs from the shipped
    # defaults: root, ACME, shared MVM_DATA_DIR), so skip the shipped ones.
    RELEASES_URL="$RELEASES_URL" sh /tmp/install-apps.sh --no-units heyvm app-lb art
    rm -f /tmp/install-apps.sh
    ;;
none)
    step "leaving binaries alone (--binaries none)"
    ;;
esac

install -d -m0755 /var/lib/heyvm /var/lib/app-lb /var/log/heyvmd /var/log/app-lb
install -d -m0700 /var/lib/app-lb/acme
fi

if [ "$STAGE" = install ]; then
    info "install stage done; run --stage configure on the host to finish"
    return 0
fi
for bin in heyvmd heyvm app-lb heyctl; do
    command -v "$bin" >/dev/null 2>&1 || die "$bin is not installed; run --stage install first"
done
install -d -m0755 /var/lib/heyvm /var/lib/app-lb /var/log/heyvmd /var/log/app-lb
install -d -m0700 /var/lib/app-lb/acme

# ---- supervisor units -------------------------------------------------------------

write_unit() {
    dest="/etc/supervisor/conf.d/$1.conf"
    if [ -e "$dest" ]; then
        cat > "$dest.new"
        step "kept $dest (new one at $dest.new)"
    else
        cat > "$dest"
        step "wrote $dest"
    fi
}

info "supervisor units"
if [ "$VM_API" = heyvm ]; then
    # Standalone: no cloud login. `heyvm --api` binds 0.0.0.0 with auth off,
    # so before it starts, drop 34099 on everything but loopback — including
    # the guests' tap interfaces. Re-applied on every start (idempotent).
    vm_api_note="; --vm-api heyvm: \`heyvm --api\`, no Heyo login. It binds 0.0.0.0 with
; auth off, so the command drops port 34099 on all but loopback first."
    vm_api_cmd="for t in iptables ip6tables; do \$t -C INPUT ! -i lo -p tcp --dport 34099 -j DROP 2>/dev/null || \$t -I INPUT ! -i lo -p tcp --dport 34099 -j DROP || exit 1; done; exec /usr/local/bin/heyvm --api --port 34099"
else
    vm_api_note="; /etc/heyvm/env carries CLOUD_INTERNAL_API_KEY, which here is just this
; daemon's operator key (the same value app-lb presents as APP_LB_DAEMON_API_KEY)."
    vm_api_cmd="exec /usr/local/bin/heyvmd --api-port 34099"
fi
write_unit heyvmd <<EOF
; Written by bootstrap-host.sh. The sandbox API app-lb drives. Deliberately
; no BACKEND_SERVER_ID: this daemon serves app-lb only and must not register
; itself with a cloud as sandbox capacity.
$vm_api_note
[program:heyvmd]
command=/bin/sh -c 'set -a; [ -f /etc/heyvm/env ] && . /etc/heyvm/env; set +a; $vm_api_cmd'
directory=/var/lib/heyvm
user=root
environment=
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME="/var/lib/heyvm",
    MVM_DATA_DIR="/var/lib/heyvm"
autostart=true
autorestart=true
startsecs=5
startretries=3
stopsignal=TERM
stopwaitsecs=15
stopasgroup=true
killasgroup=true
redirect_stderr=true
stdout_logfile=/var/log/heyvmd/heyvmd.log
stdout_logfile_maxbytes=20MB
stdout_logfile_backups=5
EOF

acme_directory=""
[ "$ACME_STAGING" = 1 ] && acme_directory=',
    APP_LB_ACME_DIRECTORY="https://acme-staging-v02.api.letsencrypt.org/directory"'

write_unit app-lb <<EOF
; Written by bootstrap-host.sh. Secrets come from /etc/app-lb/env (0600).
[program:app-lb]
command=/bin/sh -c 'set -a; . /etc/app-lb/env; set +a; exec /usr/local/bin/app-lb'
directory=/var/lib/app-lb
user=root
priority=200
environment=
    RUST_LOG="info,app_lb=info",
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    APP_LB_NAME="$HOST_ID",
    APP_LB_STATE_PATH="/var/lib/app-lb/app-lb-state.json",
    APP_LB_DAEMON_URL="http://127.0.0.1:34099",
    APP_LB_PROXY_ADDR="0.0.0.0:80",
    APP_LB_PROXY_TLS_ADDR="0.0.0.0:443",
    APP_LB_ADMIN_ADDR="127.0.0.1:9090",
    APP_LB_DASHBOARD_USER="$DASHBOARD_USER",
    APP_LB_ADMIN_AUTH="1",
    APP_LB_PUBLIC_IPS="$PUBLIC_IP",
    APP_LB_ACME_EMAIL="$ACME_EMAIL",
    APP_LB_ACME_DIR="/var/lib/app-lb/acme",
    APP_LB_IMAGES_DIR="/var/lib/heyvm/images/firecracker",
    MVM_DATA_DIR="/var/lib/heyvm",
    APP_LB_HEYVM_HOME="/var/lib/heyvm",
    APP_LB_ART_BIN="/usr/local/bin/art",
    APP_LB_DEPLOY_BASE_DOMAIN="$DOMAIN"$acme_directory
autostart=true
autorestart=unexpected
startsecs=5
startretries=3
exitcodes=0
stopsignal=TERM
stopwaitsecs=35
stopasgroup=true
killasgroup=true
stdout_logfile=/var/log/app-lb/app-lb.log
stderr_logfile=/var/log/app-lb/app-lb.err.log
stdout_logfile_maxbytes=10MB
stdout_logfile_backups=5
stderr_logfile_maxbytes=10MB
stderr_logfile_backups=5
EOF

n=0
until supervisorctl pid >/dev/null 2>&1; do
    n=$((n + 1))
    [ "$n" -lt 15 ] || die "supervisord is not answering supervisorctl (systemctl status supervisor)"
    systemctl start supervisor >/dev/null 2>&1 || true
    sleep 2
done
supervisorctl reread >/dev/null
supervisorctl update >/dev/null

wait_for() {
    what="$1"; url="$2"; n=0
    # Any HTTP answer means the listener is up: heyvmd answers 401 here,
    # since /etc/heyvm/env gives it an operator key.
    until [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null)" != 000 ]; do
        n=$((n + 1))
        [ "$n" -lt 60 ] || die "$what did not answer at $url within 2 minutes (see /var/log/$3)"
        sleep 2
    done
    step "$what is up"
}

info "waiting for services"
wait_for heyvmd http://127.0.0.1:34099/deployed-sandboxes heyvmd/heyvmd.log
wait_for app-lb http://127.0.0.1:9090/healthz app-lb/app-lb.err.log

# ---- admin route ------------------------------------------------------------------

# Route admin.<domain> to the loopback admin listener, the same static
# deployment us2 runs as `app-lb-admin`. ACME issues its certificate once DNS
# points here. The CRUD API behind it stays gated by the dashboard password.
info "admin route admin.$DOMAIN"
password="$(sed -n 's/^APP_LB_DASHBOARD_PASSWORD=//p' /etc/app-lb/env | head -1 | sed 's/^"\(.*\)"$/\1/')"
cat > /tmp/app-lb-admin.json <<EOF
{
  "id": "app-lb-admin",
  "routes": [ { "host": "admin.$DOMAIN" } ],
  "upstreams": [ "127.0.0.1:9090" ],
  "health": { "path": "/healthz", "timeout_secs": 2 }
}
EOF
printf '%s' "$password" | heyctl login --server http://127.0.0.1:9090 --user "$DASHBOARD_USER" \
    --password-stdin --name local --no-switch >/dev/null
heyctl --context local apply -f /tmp/app-lb-admin.json >/dev/null
rm -f /tmp/app-lb-admin.json
step "applied app-lb-admin"

info "host $HOST_ID ready: https://admin.$DOMAIN (once DNS points at $PUBLIC_IP)"
}

main "$@"
