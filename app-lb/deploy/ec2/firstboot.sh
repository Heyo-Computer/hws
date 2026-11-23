#!/bin/sh
# First boot of the app-lb host AMI (app-lb-host.pkr.hcl): turn the baked image
# into a running single-server app-lb host. Run once by heyo-firstboot.service.
#
# Reads plain KEY=value lines from EC2 user-data (IMDSv2). Only these keys are
# accepted; anything else is rejected, and nothing is eval'd:
#
#   HOST_ID=edge1                          required, short lowercase name
#   DOMAIN=edge1.example.com               required, deploy base domain
#   ACME_EMAIL=ops@example.com             required, Let's Encrypt contact
#   DASHBOARD_PASSWORD_PARAM=/heyo/app-lb/edge1/dashboard-password   required
#   DAEMON_API_KEY_PARAM=/heyo/app-lb/edge1/daemon-api-key           optional
#   OBS_TOKEN_PARAM=/heyo/app-lb/edge1/obs-token                     optional
#   PUBLIC_IP=203.0.113.4                  optional, default IMDS public-ipv4
#   ACME_STAGING=1                         optional
#   ROUTE53_ZONE_ID=Z0123…                 optional: wildcard cert for DOMAIN
#                                          over DNS-01 (the role must be able
#                                          to write that zone; launch.sh does it)
#
# Secrets never travel in user-data: the *_PARAM keys name SSM parameters
# (SecureString), read with the instance role. The daemon API key only guards
# heyvmd on loopback, so when no parameter is given one is generated here.
#
# On success it writes /var/lib/heyo/firstboot.done and never runs again.

set -eu

main() {

STAMP=/var/lib/heyo/firstboot.done
BOOTSTRAP=/usr/local/sbin/heyo-bootstrap-host
IMDS=http://169.254.169.254

info() { printf '==> %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root"
[ ! -e "$STAMP" ] || { info "already configured ($STAMP)"; exit 0; }

# The one thing an AMI cannot provide: the instance must be launched with
# nested virtualization (or be a .metal type) for Firecracker to have KVM.
[ -e /dev/kvm ] || die "/dev/kvm is missing: launch on a nested-virtualization instance type (C8i/M8i/R8i family) with --cpu-options NestedVirtualization=enabled, or use a .metal type"

token="$(curl -fsS -X PUT --max-time 5 -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' "$IMDS/latest/api/token")" \
    || die "IMDSv2 token request failed"
imds() { curl -fsS --max-time 5 -H "X-aws-ec2-metadata-token: $token" "$IMDS/latest/$1"; }

HOST_ID=""; DOMAIN=""; ACME_EMAIL=""; PUBLIC_IP=""; ACME_STAGING=""; ROUTE53_ZONE_ID=""
DASHBOARD_PASSWORD_PARAM=""; DAEMON_API_KEY_PARAM=""; OBS_TOKEN_PARAM=""

userdata="$(imds user-data)" || die "no user-data; see app-lb/deploy/ec2/README.md for the expected keys"
# Read line by line; tolerate CRLF, blank lines and comments.
old_ifs="$IFS"
while IFS= read -r line || [ -n "$line" ]; do
    line="$(printf '%s' "$line" | tr -d '\r')"
    case "$line" in ''|'#'*) continue ;; esac
    key="${line%%=*}"; val="${line#*=}"
    [ "$key" != "$line" ] || die "user-data line is not KEY=value: $key"
    case "$key" in
        HOST_ID) HOST_ID="$val" ;;
        DOMAIN) DOMAIN="$val" ;;
        ACME_EMAIL) ACME_EMAIL="$val" ;;
        PUBLIC_IP) PUBLIC_IP="$val" ;;
        ACME_STAGING) ACME_STAGING="$val" ;;
        ROUTE53_ZONE_ID) ROUTE53_ZONE_ID="$val" ;;
        DASHBOARD_PASSWORD_PARAM) DASHBOARD_PASSWORD_PARAM="$val" ;;
        DAEMON_API_KEY_PARAM) DAEMON_API_KEY_PARAM="$val" ;;
        OBS_TOKEN_PARAM) OBS_TOKEN_PARAM="$val" ;;
        *) die "unknown user-data key: $key" ;;
    esac
done <<EOF
$userdata
EOF
IFS="$old_ifs"

[ -n "$HOST_ID" ] || die "user-data is missing HOST_ID"
[ -n "$DOMAIN" ] || die "user-data is missing DOMAIN"
[ -n "$ACME_EMAIL" ] || die "user-data is missing ACME_EMAIL"
[ -n "$DASHBOARD_PASSWORD_PARAM" ] || die "user-data is missing DASHBOARD_PASSWORD_PARAM"
case "$ROUTE53_ZONE_ID" in *[!A-Z0-9]*) die "ROUTE53_ZONE_ID must look like Z0123456789ABC" ;; esac

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP="$(imds meta-data/public-ipv4 2>/dev/null)" || PUBLIC_IP=""
    [ -n "$PUBLIC_IP" ] || PUBLIC_IP="$(imds meta-data/local-ipv4)" || die "cannot read the instance address from IMDS"
fi
AWS_REGION="$(imds meta-data/placement/region)" || die "cannot read the region from IMDS"
export AWS_REGION

param() {
    aws ssm get-parameter --with-decryption --name "$1" --query Parameter.Value --output text \
        || die "cannot read SSM parameter $1 (instance role needs ssm:GetParameter and kms:Decrypt; see iam-policy.json)"
}

info "secrets from SSM ($AWS_REGION)"
umask 077
password="$(param "$DASHBOARD_PASSWORD_PARAM")"
[ -n "$password" ] || die "SSM parameter $DASHBOARD_PASSWORD_PARAM is empty"
if [ -n "$DAEMON_API_KEY_PARAM" ]; then
    daemon_key="$(param "$DAEMON_API_KEY_PARAM")"
else
    daemon_key="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi
obs_token=""
[ -z "$OBS_TOKEN_PARAM" ] || obs_token="$(param "$OBS_TOKEN_PARAM")"

# One KEY=value line that both `. env` (the supervisor units) and
# bootstrap-host.sh's password read (strips surrounding double quotes) agree on.
envline() {
    case "$2" in
        *[\"\\\$\`]*|*"
"*) die "$1 contains a character the env file cannot carry (\" \\ \$ \` or newline); choose another value" ;;
        *[!A-Za-z0-9._~+/=:@%,-]*) printf '%s="%s"\n' "$1" "$2" ;;
        *) printf '%s=%s\n' "$1" "$2" ;;
    esac
}

# Written to temp files, then moved, so a failure leaves no half-written env.
install -d -m0755 /etc/app-lb /etc/heyvm
{
    envline APP_LB_DASHBOARD_PASSWORD "$password"
    envline APP_LB_DAEMON_API_KEY "$daemon_key"
    [ -z "$obs_token" ] || envline APP_LB_OBS_TOKEN "$obs_token"
    if [ -n "$ROUTE53_ZONE_ID" ]; then
        # One wildcard certificate for DOMAIN and *.DOMAIN over DNS-01, instead
        # of an HTTP-01 certificate per hostname.
        envline APP_LB_ACME_WILDCARD "$DOMAIN"
        envline APP_LB_ROUTE53_ZONE_ID "$ROUTE53_ZONE_ID"
    fi
} > /etc/app-lb/env.tmp
envline CLOUD_INTERNAL_API_KEY "$daemon_key" > /etc/heyvm/env.tmp
chmod 0600 /etc/app-lb/env.tmp /etc/heyvm/env.tmp
mv /etc/app-lb/env.tmp /etc/app-lb/env
mv /etc/heyvm/env.tmp /etc/heyvm/env
unset password daemon_key obs_token
umask 022

# bootstrap-host.sh keeps existing units (writing `.new` beside them). Before
# the stamp exists, any unit there was written by an earlier, failed attempt
# of this script, so clear those to let a retry take the current settings.
for unit in heyvmd app-lb; do
    f="/etc/supervisor/conf.d/$unit.conf"
    if [ -f "$f" ] && grep -q '^; Written by bootstrap-host.sh' "$f"; then
        rm -f "$f" "$f.new"
    fi
done

# Standalone single-server host: `heyvm --api` serves the sandbox API with no
# Heyo login (heyvmd would need one); see bootstrap-host.sh --vm-api.
set -- --stage configure --vm-api heyvm --id "$HOST_ID" --domain "$DOMAIN" --public-ip "$PUBLIC_IP" --acme-email "$ACME_EMAIL"
case "$ACME_STAGING" in 1|true|yes) set -- "$@" --acme-staging ;; esac
info "configuring host $HOST_ID ($DOMAIN, $PUBLIC_IP)"
sh "$BOOTSTRAP" "$@"

install -d -m0755 "$(dirname "$STAMP")"
date -u +%Y-%m-%dT%H:%M:%SZ > "$STAMP"
info "first boot complete"
}

main "$@"
