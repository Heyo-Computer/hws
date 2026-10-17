#!/bin/sh
# PID 1 for a Firecracker guest whose image brought none. Added by app-lb at
# build time when the Dockerfile never mentions /init.sh; see `guest_init` in
# jobs.rs. The kernel boots `init=/init.sh`, so without this an ordinary
# application image has no PID 1 and panics on every boot.
#
# POSIX sh only, and every step tolerates a missing tool: this runs in
# whatever base image the Dockerfile chose. It does not start the app; the
# deployment's `start_command` does, after HEYVM_READY.

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
if [ ! -c /dev/null ]; then
    mknod -m 666 /dev/null c 1 3 2>/dev/null
    mknod -m 666 /dev/zero c 1 5 2>/dev/null
    mknod -m 444 /dev/random c 1 8 2>/dev/null
    mknod -m 444 /dev/urandom c 1 9 2>/dev/null
    mknod -m 666 /dev/tty c 5 0 2>/dev/null
    mknod -m 666 /dev/ptmx c 5 2 2>/dev/null
fi
mkdir -p /dev/pts /run /tmp 2>/dev/null
mount -t devpts devpts /dev/pts 2>/dev/null
chmod 1777 /tmp 2>/dev/null

# A docker-exported rootfs keeps none of the image's ENV; give processes a
# PATH that finds the usual runtimes.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

grep -q nameserver /etc/resolv.conf 2>/dev/null || echo "nameserver 8.8.8.8" > /etc/resolv.conf 2>/dev/null

# The kernel's ip= parameter normally configures eth0; finish the job when a
# tool is there to do it.
if command -v ip >/dev/null 2>&1; then
    ip link set lo up 2>/dev/null
    ip link set eth0 up 2>/dev/null
    if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
        for param in $(cat /proc/cmdline); do
            case "$param" in
                ip=*)
                    GUEST_IP="${param#ip=}"; GUEST_IP="${GUEST_IP%%::*}"
                    TAIL="${param#*::}"; GW="${TAIL%%:*}"
                    ip addr add "$GUEST_IP/30" dev eth0 2>/dev/null
                    [ -n "$GW" ] && ip route add default via "$GW" dev eth0 2>/dev/null
                    ;;
            esac
        done
    fi
fi

# The `disk_size_gb` data disk. heyvmd attaches it blank at /dev/vdb and
# leaves it to the guest: format it on first boot, mount it at /workspace on
# every boot. A disk labelled `mount<N>` is a heyvmd guest mount (`vm.workspace`,
# `mounts[]`) that heyvmd mounts itself after HEYVM_READY, so it is left alone.
# Read from the superblock with dd/od, since the image may have no blkid.
if [ -b /dev/vdb ]; then
    magic="$(od -An -tx1 -j1080 -N2 /dev/vdb 2>/dev/null | tr -d ' \n')"
    if [ "$magic" = "53ef" ]; then
        label="$(dd if=/dev/vdb bs=1 skip=1144 count=16 2>/dev/null | tr -d '\000')"
    else
        label=""
        if [ -z "$(od -An -N4096 /dev/vdb 2>/dev/null | tr -d ' 0*\n')" ]; then
            if command -v mkfs.ext4 >/dev/null 2>&1; then
                echo "init: formatting blank data disk /dev/vdb" > /dev/kmsg 2>/dev/null
                mkfs.ext4 -q -L workspace /dev/vdb >/dev/null 2>&1
            else
                echo "init: /dev/vdb is blank and the image has no mkfs.ext4 (install e2fsprogs); /workspace is on the rootfs" > /dev/kmsg 2>/dev/null
            fi
        fi
    fi
    case "$label" in
        mount[0-9]*) ;;
        *)
            mkdir -p /workspace 2>/dev/null
            mount /dev/vdb /workspace 2>/dev/null
            ;;
    esac
fi

# sshd, when the image has one, for `heyvm exec` / `heyvm sh`. Never log to
# the serial console: it carries heyvmd's command protocol.
if [ -x /usr/sbin/sshd ]; then
    mkdir -p /run/sshd 2>/dev/null
    [ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null 2>&1
    /usr/sbin/sshd -e 2>/tmp/sshd.log
fi

echo "HEYVM_READY"

# PID 1 must never exit; a shell when there is one, for the serial console.
while :; do
    if [ -x /bin/sh ]; then /bin/sh; fi
    sleep 1
done
