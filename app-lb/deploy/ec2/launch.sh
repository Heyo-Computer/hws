#!/bin/sh
# Launch a single-server app-lb host from the AMI (build-ami.sh), creating what
# it needs. Everything is tagged heyo:host=<id>, so teardown.sh finds it all.
#
#   app-lb/deploy/ec2/launch.sh --host edge1 --domain edge1.example.com \
#       --acme-email ops@example.com [--route53-zone Z0123…] [options]
#
#   --host ID            short lowercase name; names every resource (heyo-app-lb-<id>)
#   --domain DOMAIN      deploy base domain; admin UI at admin.<domain>
#   --acme-email EMAIL   Let's Encrypt account contact
#   --route53-zone ZONE  hosted zone holding DOMAIN: UPSERTs A records for
#                        <domain> and *.<domain>, and turns on a DNS-01 wildcard
#                        certificate (the role may then write that zone)
#   --region REGION      default $AWS_REGION, else us-west-2
#   --instance-type T    default c7i-flex.large (needs nested virtualization)
#   --ami AMI            default: the newest heyo:role=app-lb-host AMI you own
#   --volume-gb N        root volume, default 40 (the AMI's size is the minimum)
#   --ssh-cidr CIDR      open port 22 to CIDR (default closed; use SSM Session Manager)
#   --key-name NAME      EC2 key pair for SSH (default none)
#   --no-eip             skip the Elastic IP (the address then changes on stop/start)
#   --staging            Let's Encrypt staging certificates
#
# Idempotent up to the instance: re-running reuses the parameter, role, group
# and address, and refuses to start a second instance for the same host.
# The dashboard password is generated once into SSM
# (/heyo/app-lb/<id>/dashboard-password) and never printed.
#
# Needs an AWS CLI v2 recent enough for CpuOptions NestedVirtualization (2.41
# works). Set AWS_CLI to use another command, e.g. a dockerized CLI.

set -eu

main() {

HOST=""; DOMAIN=""; ACME_EMAIL=""; ZONE=""; AMI=""; SSH_CIDR=""; KEY_NAME=""
REGION="${AWS_REGION:-us-west-2}"; INSTANCE_TYPE=c7i-flex.large; VOLUME_GB=40
EIP=1; STAGING=0

info() { printf '==> %s\n' "$*" >&2; }
step() { printf '    %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --host)          shift; HOST="${1:-}" ;;
        --domain)        shift; DOMAIN="${1:-}" ;;
        --acme-email)    shift; ACME_EMAIL="${1:-}" ;;
        --route53-zone)  shift; ZONE="${1:-}"; ZONE="${ZONE#/hostedzone/}" ;;
        --region)        shift; REGION="${1:-}" ;;
        --instance-type) shift; INSTANCE_TYPE="${1:-}" ;;
        --ami)           shift; AMI="${1:-}" ;;
        --volume-gb)     shift; VOLUME_GB="${1:-}" ;;
        --ssh-cidr)      shift; SSH_CIDR="${1:-}" ;;
        --key-name)      shift; KEY_NAME="${1:-}" ;;
        --no-eip)        EIP=0 ;;
        --staging)       STAGING=1 ;;
        -h|--help)       sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 0 ;;
        *)               die "unknown argument: $1" ;;
    esac
    shift
done

case "$HOST" in ''|*[!a-z0-9-]*) die "--host must be a short lowercase name" ;; esac
case "$DOMAIN" in ''|*[!a-z0-9.-]*) die "--domain must be a hostname" ;; esac
[ -n "$ACME_EMAIL" ] || die "--acme-email is required"
case "$VOLUME_GB" in ''|*[!0-9]*) die "--volume-gb must be a number" ;; esac

# shellcheck disable=SC2086 # AWS_CLI may be a multi-word command
aws() { ${AWS_CLI:-command aws} --region "$REGION" --output text "$@"; }
command -v openssl >/dev/null 2>&1 || die "openssl is needed to generate the dashboard password"

NAME="heyo-app-lb-$HOST"
PARAM="/heyo/app-lb/$HOST/dashboard-password"
TAGS="Key=heyo:host,Value=$HOST Key=heyo:managed-by,Value=launch.sh"
tagspec() { printf 'ResourceType=%s,Tags=[{Key=heyo:host,Value=%s},{Key=heyo:managed-by,Value=launch.sh},{Key=Name,Value=%s}]' "$1" "$HOST" "$NAME"; }

account="$(aws sts get-caller-identity --query Account)" || die "AWS credentials are not working"
info "host $HOST in $REGION (account $account)"

live="$(aws ec2 describe-instances --filters "Name=tag:heyo:host,Values=$HOST" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId')"
[ -z "$live" ] || die "host $HOST already has instance $live (start it, or teardown.sh --host $HOST first)"

if [ -z "$AMI" ]; then
    AMI="$(aws ec2 describe-images --owners self --filters Name=tag:heyo:role,Values=app-lb-host \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId')"
    case "$AMI" in ami-*) ;; *) die "no heyo:role=app-lb-host AMI in $REGION; run build-ami.sh or pass --ami" ;; esac
fi
step "AMI $AMI"

# ---- secret --------------------------------------------------------------------
if aws ssm get-parameter --name "$PARAM" --query Parameter.Name >/dev/null 2>&1; then
    step "reusing $PARAM"
else
    # shellcheck disable=SC2086
    aws ssm put-parameter --type SecureString --name "$PARAM" --tags $TAGS \
        --value "$(openssl rand -base64 24 | tr -d '\n')" --query Version >/dev/null
    step "created $PARAM"
fi

# ---- role ----------------------------------------------------------------------
policy="{\"Version\":\"2012-10-17\",\"Statement\":[
{\"Effect\":\"Allow\",\"Action\":\"ssm:GetParameter\",\"Resource\":\"arn:aws:ssm:$REGION:$account:parameter/heyo/app-lb/$HOST/*\"},
{\"Effect\":\"Allow\",\"Action\":\"kms:Decrypt\",\"Resource\":\"*\",\"Condition\":{\"StringLike\":{\"kms:ViaService\":\"ssm.$REGION.amazonaws.com\"}}}"
if [ -n "$ZONE" ]; then
    policy="$policy,
{\"Effect\":\"Allow\",\"Action\":[\"route53:ChangeResourceRecordSets\",\"route53:GetChange\"],\"Resource\":[\"arn:aws:route53:::hostedzone/$ZONE\",\"arn:aws:route53:::change/*\"]},
{\"Effect\":\"Allow\",\"Action\":\"route53:TestDNSAnswer\",\"Resource\":\"*\"}"
fi
policy="$policy]}"
if aws iam get-role --role-name "$NAME" --query Role.RoleName >/dev/null 2>&1; then
    step "reusing role $NAME"
else
    # shellcheck disable=SC2086
    aws iam create-role --role-name "$NAME" --tags $TAGS --query Role.Arn \
        --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
    step "created role $NAME"
fi
aws iam put-role-policy --role-name "$NAME" --policy-name app-lb-host --policy-document "$policy"
aws iam attach-role-policy --role-name "$NAME" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
if ! aws iam get-instance-profile --instance-profile-name "$NAME" --query InstanceProfile.Arn >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    aws iam create-instance-profile --instance-profile-name "$NAME" --tags $TAGS --query InstanceProfile.Arn >/dev/null
fi
case " $(aws iam get-instance-profile --instance-profile-name "$NAME" --query 'InstanceProfile.Roles[].RoleName') " in
    *" $NAME "*|*"	$NAME	"*) ;;
    *) aws iam add-role-to-instance-profile --instance-profile-name "$NAME" --role-name "$NAME" ;;
esac

# ---- security group --------------------------------------------------------------
vpc="$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId')"
case "$vpc" in vpc-*) ;; *) die "no default VPC in $REGION" ;; esac
sg="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=$NAME" "Name=vpc-id,Values=$vpc" --query 'SecurityGroups[0].GroupId')"
case "$sg" in
    sg-*) step "reusing security group $sg" ;;
    *)
        sg="$(aws ec2 create-security-group --group-name "$NAME" --description "app-lb host $HOST" \
            --vpc-id "$vpc" --tag-specifications "$(tagspec security-group)" --query GroupId)"
        aws ec2 authorize-security-group-ingress --group-id "$sg" --ip-permissions \
            'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}]' \
            'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}]' >/dev/null
        step "created security group $sg (80, 443)"
        ;;
esac
if [ -n "$SSH_CIDR" ]; then
    aws ec2 authorize-security-group-ingress --group-id "$sg" \
        --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$SSH_CIDR}]" >/dev/null 2>&1 || true
    step "port 22 open to $SSH_CIDR"
fi

# ---- address -----------------------------------------------------------------------
alloc=""; ip=""
if [ "$EIP" = 1 ]; then
    alloc="$(aws ec2 describe-addresses --filters "Name=tag:heyo:host,Values=$HOST" --query 'Addresses[0].AllocationId')"
    case "$alloc" in
        eipalloc-*) step "reusing Elastic IP $alloc" ;;
        *) alloc="$(aws ec2 allocate-address --domain vpc --tag-specifications "$(tagspec elastic-ip)" --query AllocationId)"
           step "allocated Elastic IP $alloc" ;;
    esac
    ip="$(aws ec2 describe-addresses --allocation-ids "$alloc" --query 'Addresses[0].PublicIp')"
fi

# ---- DNS -----------------------------------------------------------------------------
if [ -n "$ZONE" ] && [ -n "$ip" ]; then
    batch="{\"Comment\":\"app-lb host $HOST\",\"Changes\":[
{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"$DOMAIN.\",\"Type\":\"A\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"$ip\"}]}},
{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"*.$DOMAIN.\",\"Type\":\"A\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"$ip\"}]}}]}"
    change="$(aws route53 change-resource-record-sets --hosted-zone-id "$ZONE" --change-batch "$batch" --query ChangeInfo.Id)"
    aws route53 wait resource-record-sets-changed --id "$change"
    step "DNS $DOMAIN and *.$DOMAIN -> $ip"
fi

# ---- instance -------------------------------------------------------------------------
userdata="HOST_ID=$HOST
DOMAIN=$DOMAIN
ACME_EMAIL=$ACME_EMAIL
DASHBOARD_PASSWORD_PARAM=$PARAM"
[ -z "$ip" ] || userdata="$userdata
PUBLIC_IP=$ip"
[ -z "$ZONE" ] || userdata="$userdata
ROUTE53_ZONE_ID=$ZONE"
[ "$STAGING" = 0 ] || userdata="$userdata
ACME_STAGING=1"

set -- --image-id "$AMI" --instance-type "$INSTANCE_TYPE" \
    --cpu-options NestedVirtualization=enabled \
    --iam-instance-profile "Name=$NAME" --security-group-ids "$sg" \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$VOLUME_GB,VolumeType=gp3,Encrypted=true}" \
    --tag-specifications "$(tagspec instance)" "$(tagspec volume)" \
    --user-data "$userdata" --query 'Instances[0].InstanceId'
[ -z "$KEY_NAME" ] || set -- "$@" --key-name "$KEY_NAME"

# A new instance profile takes a few seconds to become usable by EC2.
n=0; err="$(mktemp)"
until iid="$(aws ec2 run-instances "$@" 2>"$err")"; do
    if grep -q 'Unknown parameter in CpuOptions' "$err"; then
        die "this AWS CLI is too old for CpuOptions NestedVirtualization; upgrade it (2.41 works) or set AWS_CLI"
    fi
    n=$((n + 1))
    if grep -q -i 'instance profile' "$err" && [ "$n" -lt 12 ]; then sleep 5; continue; fi
    cat "$err" >&2; rm -f "$err"; die "run-instances failed"
done
rm -f "$err"
step "instance $iid"
aws ec2 wait instance-running --instance-ids "$iid"
if [ -n "$alloc" ]; then
    aws ec2 associate-address --instance-id "$iid" --allocation-id "$alloc" --allow-reassociation --query AssociationId >/dev/null
fi
aws ec2 create-tags --resources "$iid" --tags "Key=heyo:domain,Value=$DOMAIN" ${ZONE:+"Key=heyo:route53-zone,Value=$ZONE"} >/dev/null

info "launched $iid"
step "first boot takes ~2 minutes: aws ssm start-session --region $REGION --target $iid"
step "then: sudo journalctl -u heyo-firstboot; https://admin.$DOMAIN (user heyo, password in $PARAM)"
if [ -z "$ZONE" ]; then
    step "DNS: point $DOMAIN and *.$DOMAIN at ${ip:-the public IP of $iid}"
fi
printf '%s\n' "$iid"
}

main "$@"
