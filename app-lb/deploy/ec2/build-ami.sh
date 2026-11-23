#!/bin/sh
# Build the app-lb host AMI (app-lb-host.pkr.hcl) from a clean checkout.
#
#   app-lb/deploy/ec2/build-ami.sh [--region us-west-2] [--allow-dirty] [-var k=v ...]
#
# Stamps the AMI with the commit it was built from and refuses a dirty tree, so
# every AMI maps to code someone can read (--allow-dirty for experiments; the
# revision is then recorded as <sha>-dirty). Runs `packer` if it is installed,
# otherwise hashicorp/packer in docker with the caller's AWS credentials
# (exported to a 0600 temp file for the container, removed on exit).
#
# Prints the new AMI id on stdout.

set -eu

main() {

PACKER_IMAGE="${PACKER_IMAGE:-hashicorp/packer:1.11.2}"
REGION="${AWS_REGION:-us-west-2}"
ALLOW_DIRTY=0

info() { printf '==> %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(git -C "$here" rev-parse --show-toplevel)"

set -- "$@" --end
vars=""
while [ "$1" != --end ]; do
    case "$1" in
        --region)      shift; REGION="${1:?--region needs a value}" ;;
        --allow-dirty) ALLOW_DIRTY=1 ;;
        -var)          shift; set -- "$@" -var "${1:?-var needs k=v}"; vars=1 ;;
        -h|--help)     sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
        *)             die "unknown argument: $1" ;;
    esac
    shift
done
shift  # --end; what remains are the collected -var pairs
[ -n "$vars" ] || set --

revision="$(git -C "$repo" rev-parse HEAD)"
if [ -n "$(git -C "$repo" status --porcelain)" ]; then
    [ "$ALLOW_DIRTY" = 1 ] || die "the worktree has uncommitted changes; commit them, or pass --allow-dirty"
    revision="$revision-dirty"
fi
info "building from $revision in $REGION"

set -- -var "region=$REGION" -var "git_revision=$revision" "$@" .
rm -f "$here/packer-manifest.json"

if command -v packer >/dev/null 2>&1; then
    (cd "$here" && packer init . >/dev/null && packer build -color=false "$@") >&2
else
    command -v docker >/dev/null 2>&1 || die "neither packer nor docker is installed"
    envfile="$(mktemp)"
    trap 'rm -f "$envfile"' EXIT
    chmod 0600 "$envfile"
    if [ -n "${AWS_ACCESS_KEY_ID:-}" ]; then
        env | grep -E '^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)=' > "$envfile"
    else
        aws configure export-credentials --format env-no-export > "$envfile" \
            || die "no AWS credentials (set AWS_PROFILE or AWS_ACCESS_KEY_ID)"
    fi
    docker run --rm --env-file "$envfile" -v "$repo":/repo -w /repo/app-lb/deploy/ec2 \
        --entrypoint sh "$PACKER_IMAGE" -c 'packer init . >/dev/null && packer build -color=false "$@"' packer "$@" >&2
fi

ami="$(sed -n 's/.*"artifact_id": *"[^:]*:\(ami-[0-9a-f]*\)".*/\1/p' "$here/packer-manifest.json" | tail -1)"
[ -n "$ami" ] || die "packer finished but packer-manifest.json names no AMI"
info "built $ami"
printf '%s\n' "$ami"
}

main "$@"
