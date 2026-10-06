#!/bin/sh
# Build-time check that a base image has everything init.sh calls. A missing
# tool would otherwise surface as a VM that boots and never answers exec.
set -eu
for tool in bash ip blkid mkfs.ext4 mount dmesg mknod hostname curl cp touch socat tail; do
    command -v "$tool" >/dev/null || { echo "smoke: $tool is missing"; exit 1; }
done
/usr/sbin/sshd -t
# Effective config, not the file: an sshd_config without the Include would
# silently ignore it.
/usr/sbin/sshd -T | grep -qi '^passwordauthentication no'
sh -n /init.sh
# heyvm forwards the start_command's stdout/stderr to the host over vsock with
# socat; without VSOCK support the app's logs never leave the guest.
socat -V | grep -q 'WITH_VSOCK 1' || { echo "smoke: socat lacks VSOCK support"; exit 1; }
# A read-only (shared) root cannot create mountpoints at boot.
[ -d /workspace ] || { echo "smoke: /workspace must exist in the image"; exit 1; }
echo "smoke: ok"
