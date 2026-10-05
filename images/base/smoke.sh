#!/bin/sh
# Build-time check that a base image has everything init.sh calls. A missing
# tool would otherwise surface as a VM that boots and never answers exec.
set -eu
for tool in bash ip blkid mkfs.ext4 mount dmesg mknod hostname curl; do
    command -v "$tool" >/dev/null || { echo "smoke: $tool is missing"; exit 1; }
done
/usr/sbin/sshd -t
# Effective config, not the file: an sshd_config without the Include would
# silently ignore it.
/usr/sbin/sshd -T | grep -qi '^passwordauthentication no'
sh -n /init.sh
echo "smoke: ok"
