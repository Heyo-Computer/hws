#!/bin/sh
# Remove everything launch.sh created for one host — or old AMIs.
#
#   app-lb/deploy/ec2/teardown.sh --host edge1 [--region R] [--yes]
#   app-lb/deploy/ec2/teardown.sh --prune-amis KEEP [--region R] [--yes]
#
# --host finds resources by tag heyo:host=<id> (and the names launch.sh gives
# them), prints the list, and asks before deleting:
#   instances (terminated, and waited for), the A records for <domain> and
#   *.<domain> when they still point at this host's Elastic IP, the Elastic IP,
#   the security group, the SSM parameters under /heyo/app-lb/<id>/, and the
#   role and instance profile heyo-app-lb-<id>.
# Data on the instance's volumes is destroyed with it.
#
# --prune-amis KEEP deregisters all but the newest KEEP heyo:role=app-lb-host
# AMIs you own, and deletes their snapshots.
#
# Set AWS_CLI to use another AWS CLI command, as for launch.sh.

set -eu

main() {

HOST=""; PRUNE=""; YES=0; REGION="${AWS_REGION:-us-west-2}"

info() { printf '==> %s\n' "$*" >&2; }
step() { printf '    %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --host)       shift; HOST="${1:-}" ;;
        --prune-amis) shift; PRUNE="${1:-}" ;;
        --region)     shift; REGION="${1:-}" ;;
        --yes)        YES=1 ;;
        -h|--help)    sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
        *)            die "unknown argument: $1" ;;
    esac
    shift
done
[ -n "$HOST" ] || [ -n "$PRUNE" ] || die "pass --host ID or --prune-amis KEEP"
[ -z "$HOST" ] || case "$HOST" in *[!a-z0-9-]*) die "--host must be a short lowercase name" ;; esac
[ -z "$PRUNE" ] || case "$PRUNE" in *[!0-9]*) die "--prune-amis needs a number" ;; esac

# shellcheck disable=SC2086 # AWS_CLI may be a multi-word command
aws() { ${AWS_CLI:-command aws} --region "$REGION" --output text "$@"; }
none() { case "$1" in ''|None) return 0 ;; *) return 1 ;; esac; }
oneline() { printf '%s' "$1" | tr '\t\n' '  ' | sed 's/^ *//; s/ *$//; s/  */ /g'; }

confirm() {
    [ "$YES" = 1 ] && return 0
    [ -r /dev/tty ] || die "not a terminal; re-run with --yes to delete"
    printf 'Delete all of the above? [y/N] ' >&2
    read -r answer </dev/tty
    case "$answer" in y|Y|yes) ;; *) die "nothing deleted" ;; esac
}

if [ -n "$PRUNE" ]; then
    old="$(aws ec2 describe-images --owners self --filters Name=tag:heyo:role,Values=app-lb-host \
        --query 'sort_by(Images,&CreationDate)[].[ImageId,Name]' | awk -v keep="$PRUNE" '{ a[NR]=$0 } END { for (i = 1; i <= NR - keep; i++) print a[i] }')"
    if [ -z "$old" ]; then info "nothing to prune (keeping the newest $PRUNE)"; else
        info "AMIs to deregister (keeping the newest $PRUNE):"
        printf '%s\n' "$old" | sed 's/^/    /' >&2
        confirm
        printf '%s\n' "$old" | while read -r ami _; do
            snaps="$(aws ec2 describe-images --image-ids "$ami" --query 'Images[0].BlockDeviceMappings[].Ebs.SnapshotId')"
            aws ec2 deregister-image --image-id "$ami"
            for s in $snaps; do none "$s" || aws ec2 delete-snapshot --snapshot-id "$s"; done
            step "deregistered $ami ($snaps)"
        done
    fi
fi

[ -n "$HOST" ] || return 0

NAME="heyo-app-lb-$HOST"
instances="$(aws ec2 describe-instances --filters "Name=tag:heyo:host,Values=$HOST" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId')"
alloc="$(aws ec2 describe-addresses --filters "Name=tag:heyo:host,Values=$HOST" --query 'Addresses[0].AllocationId')"
ip=""; none "$alloc" || ip="$(aws ec2 describe-addresses --allocation-ids "$alloc" --query 'Addresses[0].PublicIp')"
domain=""; zone=""
for i in $instances; do
    domain="$(aws ec2 describe-tags --filters "Name=resource-id,Values=$i" Name=key,Values=heyo:domain --query 'Tags[0].Value')"
    zone="$(aws ec2 describe-tags --filters "Name=resource-id,Values=$i" Name=key,Values=heyo:route53-zone --query 'Tags[0].Value')"
done
none "$domain" && domain=""; none "$zone" && zone=""
sg="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$NAME" "Name=tag:heyo:host,Values=$HOST" --query 'SecurityGroups[0].GroupId')"
params="$(aws ssm describe-parameters --parameter-filters "Key=Name,Option=BeginsWith,Values=/heyo/app-lb/$HOST/" --query 'Parameters[].Name')"
role=""; aws iam get-role --role-name "$NAME" --query Role.RoleName >/dev/null 2>&1 && role="$NAME"
profile=""; aws iam get-instance-profile --instance-profile-name "$NAME" --query InstanceProfile.Arn >/dev/null 2>&1 && profile="$NAME"

records=""; shown=""
if [ -n "$zone" ] && [ -n "$domain" ] && [ -n "$ip" ]; then
    for r in "$domain." "\\052.$domain."; do
        v="$(aws route53 list-resource-record-sets --hosted-zone-id "$zone" \
            --query "ResourceRecordSets[?Name=='$r' && Type=='A'].ResourceRecords[].Value")"
        if [ "$v" = "$ip" ]; then
            records="$records $r"
            case "$r" in "$domain.") shown="$shown $domain" ;; *) shown="$shown *.$domain" ;; esac
        fi
    done
fi

info "host $HOST in $REGION:"
found=0
show() { if ! none "$2"; then step "$1: $2"; found=1; fi; }
show instances "$(oneline "$instances")"
show "DNS records ($zone)" "$(oneline "$shown")"
show "Elastic IP" "$(none "$alloc" || echo "$alloc $ip")"
show "security group" "$sg"
show "SSM parameters" "$(oneline "$params")"
show role "$role"
show "instance profile" "$profile"
[ "$found" = 1 ] || { info "nothing tagged heyo:host=$HOST"; return 0; }
confirm

if [ -n "$instances" ]; then
    # shellcheck disable=SC2086
    aws ec2 terminate-instances --instance-ids $instances >/dev/null
    # shellcheck disable=SC2086
    aws ec2 wait instance-terminated --instance-ids $instances
    step "terminated $(oneline "$instances")"
fi
for r in $records; do
    # Route 53 lists a wildcard as \052; JSON cannot carry that escape, but
    # the API takes a literal * back.
    r="$(printf '%s' "$r" | sed 's/^\\052/*/')"
    batch="{\"Changes\":[{\"Action\":\"DELETE\",\"ResourceRecordSet\":{\"Name\":\"$r\",\"Type\":\"A\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"$ip\"}]}}]}"
    aws route53 change-resource-record-sets --hosted-zone-id "$zone" --change-batch "$batch" >/dev/null
    step "deleted DNS $r"
done
if ! none "$alloc"; then aws ec2 release-address --allocation-id "$alloc"; step "released $alloc"; fi
if ! none "$sg"; then
    # A terminated instance's interface can hold the group for a little while.
    n=0
    until aws ec2 delete-security-group --group-id "$sg" 2>/dev/null; do
        n=$((n + 1)); [ "$n" -lt 24 ] || die "could not delete $sg"; sleep 5
    done
    step "deleted $sg"
fi
for p in $params; do aws ssm delete-parameter --name "$p"; step "deleted $p"; done
if [ -n "$profile" ]; then
    [ -z "$role" ] || aws iam remove-role-from-instance-profile --instance-profile-name "$NAME" --role-name "$NAME" 2>/dev/null || true
    aws iam delete-instance-profile --instance-profile-name "$NAME"; step "deleted instance profile $NAME"
fi
if [ -n "$role" ]; then
    for pol in $(aws iam list-role-policies --role-name "$NAME" --query 'PolicyNames[]'); do
        aws iam delete-role-policy --role-name "$NAME" --policy-name "$pol"
    done
    for arn in $(aws iam list-attached-role-policies --role-name "$NAME" --query 'AttachedPolicies[].PolicyArn'); do
        aws iam detach-role-policy --role-name "$NAME" --policy-arn "$arn"
    done
    aws iam delete-role --role-name "$NAME"; step "deleted role $NAME"
fi
info "host $HOST removed"
}

main "$@"
