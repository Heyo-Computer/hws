#!/bin/sh
# Build-time check that a base image has everything init.sh calls. A missing
# tool would otherwise surface as a VM that boots and never answers exec.
set -eu
for tool in bash ip blkid mkfs.ext4 mount dmesg mknod hostname curl cp touch; do
    command -v "$tool" >/dev/null || { echo "smoke: $tool is missing"; exit 1; }
done
/usr/sbin/sshd -t
# Effective config, not the file: an sshd_config without the Include would
# silently ignore it.
/usr/sbin/sshd -T | grep -qi '^passwordauthentication no'
sh -n /init.sh
# A read-only (shared) root cannot create mountpoints at boot.
[ -d /workspace ] || { echo "smoke: /workspace must exist in the image"; exit 1; }
echo "smoke: ok"
