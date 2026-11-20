# AMI for a single-server app-lb host: app-lb + heyvmd + Firecracker microVMs on
# one EC2 instance, using EC2 nested virtualization for /dev/kvm.
#
#   app-lb/deploy/ec2/build-ami.sh --region us-west-2    (wraps packer; see README)
#
# The image carries packages and binaries only (bootstrap-host.sh --stage
# install). Everything per-host — id, domain, address, secrets, supervisor
# units, admin route — is applied on first boot by heyo-firstboot.service from
# user-data + SSM. See README.md.

packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "instance_type" {
  type        = string
  description = "Build instance. The bake needs no KVM, so any x86_64 type works."
  default     = "c7i-flex.large"
}

# Release pins. A rebuild bakes these exact bits; bump a pair (version and
# digest) together, deliberately. bootstrap-host.sh enforces every digest.
variable "app_lb_tag" {
  type        = string
  description = "Tag of hub.heyo.work/heyo/app-lb."
  default     = "0.4.0"
}

variable "app_lb_digest" {
  type        = string
  description = "sha256 of the app-lb blob the tag must resolve to."
  default     = "fd5888dcd4e925a7de8fc4d54bdfdd37ea8b44c5c52b919395bcd7f08a6d3450"
}

variable "heyvm_version" {
  type    = string
  default = "0.64.1"
}

variable "heyvm_sha256" {
  type        = string
  description = "sha256 of heyvm-<version>-unknown-linux-gnu-x86_64.tar.gz (its channel publishes none)."
  default     = "8d5e499594ae9c76e05de9c5e4849b397fcea0a1e174f045d2389a82679fa6f8"
}

variable "heyctl_version" {
  type    = string
  default = "0.2.0"
}

variable "heyctl_digest" {
  type        = string
  description = "sha256 of the heyctl linux-x86_64 blob."
  default     = "ce31b970f1d0e9ccb2768c67cc9ec2d82248d9f0d2aad043c0265293f39cbb45"
}

variable "firecracker_version" {
  type        = string
  description = "Checked against the release's own .sha256.txt."
  default     = "v1.16.1"
}

variable "ami_name_prefix" {
  type    = string
  default = "heyo-app-lb-host"
}

variable "git_revision" {
  type        = string
  description = "Commit of this repo the image is built from. build-ami.sh sets it and refuses a dirty tree."
  default     = "unknown"
}

variable "volume_size_gb" {
  type    = number
  default = 40
}

locals {
  timestamp = formatdate("YYYYMMDD-hhmmss", timestamp())
}

source "amazon-ebs" "app_lb_host" {
  region        = var.region
  instance_type = var.instance_type
  ssh_username  = "ubuntu"
  ami_name      = "${var.ami_name_prefix}-${local.timestamp}"
  imds_support  = "v2.0"

  # The AMI's snapshot is encrypted with the account's default EBS key.
  encrypt_boot = true

  # The temporary SSH security group admits only the machine running Packer.
  temporary_security_group_source_public_ip = true

  # The releases are linux-x86_64 only.
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"]
    most_recent = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = var.volume_size_gb
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name                = "${var.ami_name_prefix}-${local.timestamp}"
    "heyo:role"         = "app-lb-host"
    "heyo:git-revision" = var.git_revision
    "heyo:app-lb"       = "${var.app_lb_tag} ${substr(var.app_lb_digest, 0, 12)}"
    "heyo:heyvm"        = "${var.heyvm_version} ${substr(var.heyvm_sha256, 0, 12)}"
    "heyo:heyctl"       = "${var.heyctl_version} ${substr(var.heyctl_digest, 0, 12)}"
    "heyo:firecracker"  = var.firecracker_version
    "heyo:needs"        = "NestedVirtualization=enabled or .metal"
  }
}

build {
  sources = ["source.amazon-ebs.app_lb_host"]

  provisioner "file" {
    source      = "${path.root}/../../../.ci/bootstrap-host.sh"
    destination = "/tmp/bootstrap-host.sh"
  }
  provisioner "file" {
    source      = "${path.root}/firstboot.sh"
    destination = "/tmp/firstboot.sh"
  }
  provisioner "file" {
    source      = "${path.root}/heyo-firstboot.service"
    destination = "/tmp/heyo-firstboot.service"
  }

  # Wait for cloud-init's own apt run so ours does not race the dpkg lock.
  provisioner "shell" {
    inline = ["cloud-init status --wait >/dev/null || true"]
  }

  provisioner "shell" {
    environment_vars = [
      "FIRECRACKER_VERSION=${var.firecracker_version}",
      "APP_LB_TAG=${var.app_lb_tag}",
      "APP_LB_DIGEST=${var.app_lb_digest}",
      "HEYVM_VERSION=${var.heyvm_version}",
      "HEYVM_SHA256=${var.heyvm_sha256}",
      "HEYCTL_VERSION=${var.heyctl_version}",
      "HEYCTL_DIGEST=${var.heyctl_digest}",
    ]
    execute_command = "sudo {{ .Vars }} sh -eu '{{ .Path }}'"
    inline = [
      "install -m0755 /tmp/bootstrap-host.sh /usr/local/sbin/heyo-bootstrap-host",
      "sh /usr/local/sbin/heyo-bootstrap-host --stage install",
    ]
  }

  # AWS CLI v2: first boot reads SSM with it, and app-lb shells out to `aws`
  # for Route 53 DNS-01 and S3 disk archives.
  provisioner "shell" {
    execute_command = "sudo {{ .Vars }} sh -eu '{{ .Path }}'"
    inline = [
      "export DEBIAN_FRONTEND=noninteractive",
      "apt-get install -y -qq --no-install-recommends unzip >/dev/null",
      "curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip",
      "rm -rf /tmp/aws && unzip -q /tmp/awscliv2.zip -d /tmp",
      "/tmp/aws/install --update",
      "rm -rf /tmp/aws /tmp/awscliv2.zip",
      "aws --version",
    ]
  }

  provisioner "shell" {
    environment_vars = [
      "GIT_REVISION=${var.git_revision}",
    ]
    execute_command = "sudo {{ .Vars }} sh -eu '{{ .Path }}'"
    inline = [
      "install -m0755 /tmp/firstboot.sh /usr/local/sbin/heyo-firstboot",
      "install -m0644 /tmp/heyo-firstboot.service /etc/systemd/system/heyo-firstboot.service",
      "systemctl daemon-reload",
      "systemctl enable heyo-firstboot.service",
      "install -d -m0755 /etc/heyo",
      "{ echo \"built=$(date -u +%Y-%m-%dT%H:%M:%SZ)\"; echo \"git_revision=$GIT_REVISION\"; echo \"firecracker=$(firecracker --version 2>/dev/null | head -1)\"; cat /etc/heyo/binaries; } > /etc/heyo/image-manifest",
      "rm -f /etc/heyo/binaries",
      "cat /etc/heyo/image-manifest",
    ]
  }

  # Generalize: no host identity, keys or logs carried into instances.
  provisioner "shell" {
    execute_command = "sudo {{ .Vars }} sh -eu '{{ .Path }}'"
    inline = [
      "rm -f /tmp/bootstrap-host.sh /tmp/firstboot.sh /tmp/heyo-firstboot.service",
      "rm -f /var/lib/heyo/firstboot.done",
      "apt-get clean && rm -rf /var/lib/apt/lists/*",
      "rm -f /etc/ssh/ssh_host_*",
      "truncate -s 0 /etc/machine-id",
      "rm -f /var/lib/dbus/machine-id",
      "find /var/log -type f -exec truncate -s 0 {} +",
      "cloud-init clean --logs",
    ]
  }

  post-processor "manifest" {
    output     = "packer-manifest.json"
    strip_path = true
  }
}
