# app-lb host AMI for EC2 (nested virtualization)

This directory builds and runs a single-server app-lb host on one EC2
instance. app-lb proxies traffic and manages the backend Firecracker microVMs
on the same machine. EC2 nested virtualization provides `/dev/kvm`, so you
don't need a `.metal` instance.

```sh
app-lb/deploy/ec2/build-ami.sh --region us-west-2               # once per release
app-lb/deploy/ec2/launch.sh --host edge1 --domain us-west.heyo.work \
    --acme-email ops@heyo.computer --route53-zone Z07907081HGPDGJ740C8L
app-lb/deploy/ec2/teardown.sh --host edge1                      # when done
```

| File | Purpose |
| --- | --- |
| `build-ami.sh` | Runs Packer, locally or in docker. Refuses a dirty worktree and stamps the AMI with the commit it was built from. |
| `app-lb-host.pkr.hcl` | Ubuntu 24.04 plus `.ci/bootstrap-host.sh --stage install` at pinned, verified versions, plus AWS CLI v2. Snapshot is encrypted. |
| `launch.sh` | Creates the SSM secret, IAM role, security group, Elastic IP, DNS records and instance for one host, all tagged `heyo:host=<id>`. |
| `teardown.sh` | Lists everything tagged `heyo:host=<id>`, confirms, then deletes it. Also prunes old AMIs. |
| `firstboot.sh` + `heyo-firstboot.service` | Run once per instance. Read user-data and SSM, write `/etc/app-lb/env` and `/etc/heyvm/env`, then run `bootstrap-host.sh --stage configure`. |

The image holds no host identity and no secrets. Every per-host setting
arrives at first boot.

## Instance types

Nested virtualization is available on Intel C8i, M8i and R8i, including the
`-flex` and `d` variants. In us-west-2 it is also offered on C7i, M7i, R7i and
I7i. Check your region:

```sh
aws ec2 describe-instance-types \
  --filters Name=processor-info.supported-features,Values=nested-virtualization \
  --query 'InstanceTypes[].InstanceType' --output text
```

Nested virtualization is off by default and must be enabled at launch
(`--cpu-options NestedVirtualization=enabled`). `launch.sh` does this for you.
An instance with it enabled cannot hibernate. Any `.metal` type also works.
If `/dev/kvm` is missing, first boot fails immediately with a message saying
so, and writes no configuration.

`c7i-flex.large` (2 vCPU, 4 GiB) is the cheapest supported type and the
default. heyvm keeps 1 GiB for the host and overcommits memory 1.5x, so it
fits one `small` (2 GiB) guest or a few `micro`/`mini` ones. Size up for real
workloads.

You need an AWS CLI v2 new enough for `NestedVirtualization` (2.41 works).
Older ones fail with "Unknown parameter in CpuOptions". `launch.sh` and
`teardown.sh` accept another CLI through `AWS_CLI`, for example
`AWS_CLI="docker run --rm -i -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN amazon/aws-cli:2.41.1"`.

## Build the AMI

```sh
app-lb/deploy/ec2/build-ami.sh --region us-west-2
```

The script uses `packer` if it is installed, otherwise `hashicorp/packer` in
docker with your AWS credentials. It refuses uncommitted changes
(`--allow-dirty` records the revision as `<sha>-dirty`) and prints the new AMI
id.

Releases are pinned in `app-lb-host.pkr.hcl`, and `bootstrap-host.sh` enforces
every digest:

| Component | Version | Verified against |
| --- | --- | --- |
| app-lb | `app_lb_tag` 0.4.0 | `app_lb_digest`, the hub manifest and the tarball's `SHA256SUMS` |
| heyvm, heyvmd | `heyvm_version` 0.64.1 | `heyvm_sha256` (the channel publishes no checksum, so we pin one) |
| heyctl | `heyctl_version` 0.2.0 | `heyctl_digest` |
| Firecracker | `firecracker_version` v1.16.1 | the release's `.sha256.txt` |

To bump a release, change its version and digest together, for example
`-var app_lb_tag=0.5.0 -var app_lb_digest=<sha256>`. To find an app-lb digest,
run `curl -fsSL https://hub.heyo.work/manifests/heyo/app-lb:<tag>`. For heyvm,
run `sha256sum` on the tarball. The AMI's `heyo:*` tags record the pins, and
`/etc/heyo/image-manifest` on the image records what was actually installed.

## Launch a host

```sh
app-lb/deploy/ec2/launch.sh --host edge1 --domain us-west.heyo.work \
    --acme-email ops@heyo.computer --route53-zone Z07907081HGPDGJ740C8L
```

`launch.sh` creates or reuses the following, all named `heyo-app-lb-<id>` and
tagged `heyo:host=<id>`:

- **Secret:** `/heyo/app-lb/<id>/dashboard-password`, a SecureString generated
  once and never printed.
- **Instance role:**
  - read that host's parameters;
  - `AmazonSSMManagedInstanceCore`, for Session Manager;
  - with `--route53-zone`, write that one zone, for DNS-01.
- **Security group** in the default VPC with only 80 and 443 open. `--ssh-cidr`
  adds port 22.
- **Elastic IP** (skip it with `--no-eip`).
- **DNS records** (with `--route53-zone`): `UPSERT`s the A records `<domain>`
  and `*.<domain>` to the Elastic IP.
- **Instance:** `c7i-flex.large` by default, from the newest AMI you own tagged
  `heyo:role=app-lb-host`, with nested virtualization on, IMDSv2 required and
  an encrypted 40 GiB root volume.

It refuses to start a second instance for a host that already has one.

### TLS

- **With `--route53-zone`:** app-lb gets one wildcard certificate for
  `<domain>` and `*.<domain>` over DNS-01 (`APP_LB_ACME_WILDCARD`). That covers
  `admin.<domain>` and every `<deployment>.<domain>`.
- **Without it:** you point the A records yourself, and each hostname gets its
  own HTTP-01 certificate.
- **`--staging`** uses Let's Encrypt staging while you experiment. Production
  allows 50 new certificates per registered domain per week.

### Operator access

```sh
aws ssm start-session --region us-west-2 --target <instance-id>
sudo journalctl -u heyo-firstboot       # first boot ran and succeeded
sudo supervisorctl status               # heyvmd and app-lb RUNNING
sudo heyctl --context local get deployments
cat /etc/heyo/image-manifest
```

Session Manager needs the [session-manager-plugin] on your machine. No key pair
or open port 22 is required. The dashboard is at `https://admin.<domain>` as
user `heyo`. Read the password with
`aws ssm get-parameter --with-decryption --name /heyo/app-lb/<id>/dashboard-password`.

[session-manager-plugin]: https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html

### Launching by hand

`launch.sh` is the reference. If you launch any other way, pass these lines as
user-data. Only these keys are accepted.

```
HOST_ID=edge1
DOMAIN=us-west.heyo.work
ACME_EMAIL=ops@heyo.computer
DASHBOARD_PASSWORD_PARAM=/heyo/app-lb/edge1/dashboard-password
# optional:
# PUBLIC_IP=203.0.113.4            (default: IMDS public-ipv4, falling back to local-ipv4)
# ROUTE53_ZONE_ID=Z0123…           (wildcard certificate over DNS-01)
# DAEMON_API_KEY_PARAM=…           (default: generated on the host)
# OBS_TOKEN_PARAM=…
# ACME_STAGING=1
```

The instance role must be able to read the named parameters (`ssm:GetParameter`
plus `kms:Decrypt` through SSM). With `ROUTE53_ZONE_ID`, it also needs
`route53:ChangeResourceRecordSets`, `route53:GetChange` and
`route53:TestDNSAnswer`. Parameter values must not contain `"`, `\`, `$`, a
backtick or a newline.

## Tear down

```sh
app-lb/deploy/ec2/teardown.sh --host edge1        # lists, asks, deletes
app-lb/deploy/ec2/teardown.sh --prune-amis 2      # keep the newest two AMIs
```

`--host` removes the following, then the IAM role and profile:
- the instance and its volumes, so data on the host is destroyed;
- the DNS records, only if they still point at this host's Elastic IP;
- the Elastic IP;
- the security group;
- the SSM parameters.

Pass `--yes` to skip the prompt.

## How the host runs

### The VM API: standalone `heyvm --api`

heyvmd won't start without a Heyo login (`HEYO_API_KEY` or `heyvm login`). This
host is standalone, so first boot passes `--vm-api heyvm` to
`bootstrap-host.sh`. The supervisor program is still named `heyvmd`, but it
runs `heyvm --api --port 34099`, which needs no cloud account.

`heyvm --api` binds 0.0.0.0 with no authentication. Before it starts, the unit
inserts iptables and ip6tables rules that drop port 34099 on every interface
except loopback. That includes the guests' `tap-fc-*` interfaces, so a guest
cannot reach it either. The security group also leaves 34099 closed.

### Guest images

heyvm's public image catalog also needs a Heyo login, so a bare
`"image": "ubuntu:24.04"` fails with "not found locally". Pull rootfs images
anonymously from the hub with an `artifact` block instead:

```json
{
  "id": "hello",
  "routes": [ { "host": "hello.us-west.heyo.work" } ],
  "vm": { "driver": "firecracker", "port": 8080, "size_class": "small",
          "start_command": "setsid nohup my-server --port 8080 </dev/null &" },
  "artifact": { "store": "https://hub.heyo.work", "ref": "heyo/ubuntu:24.04" },
  "scaling": { "min_replicas": 1, "max_replicas": 1 }
}
```

The first pull of a 1 GiB image can take several minutes. Later VMs reuse the
copy on disk.

### Retries and reconfiguration

If first boot fails (bad user-data, SSM access or KVM), it writes no stamp, so
it runs again on the next boot. You can also fix the cause and run
`systemctl reset-failed heyo-firstboot && systemctl start heyo-firstboot`
yourself. A retry replaces the units the failed attempt wrote. To reconfigure
a host that already succeeded, remove `/var/lib/heyo/firstboot.done` and start
the service again. In that case existing units are kept, and new ones are
written as `.conf.new` (see `bootstrap-host.sh`).

## Scope

This is a standalone host. Orchestrator discovery, the fleet Postgres store,
federated auth and app-obs are all off. They can be enabled later through more
`APP_LB_*` variables, with matching `*_PARAM` keys for any secrets. Guest
images are not baked into the AMI. The `art` CLI is not installed; app-lb needs
it only for workspace and artifact push features. `bootstrap-host.sh
--binaries releases` installs it on hosts that need it.
