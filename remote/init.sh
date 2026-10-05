#!/bin/sh
# PID 1 for the Firecracker microVM (no systemd). The kernel boots this via
# init=/init.sh. It must set up the environment, start sshd, mount the
# persistent data disk, print the HEYVM_READY marker, and never exit.
#
# NOTE: the `remote` process itself is NOT started here. It is launched after
# boot by app-lb's start_command, which is the only channel that carries its
# credentials — env vars reach only the start_command process, not init.

mount -t proc proc /proc
mount -t sysfs sysfs /sys

# Populate /dev via devtmpfs. A docker-exported rootfs has an empty /dev, so
# sshd would fail without device nodes. Fall back to manual mknod.
mount -t devtmpfs devtmpfs /dev 2>/dev/null
if [ ! -c /dev/null ]; then
    echo "init: devtmpfs unavailable, creating device nodes manually"
    mknod -m 666 /dev/null    c 1 3
    mknod -m 666 /dev/zero    c 1 5
    mknod -m 444 /dev/random  c 1 8
    mknod -m 444 /dev/urandom c 1 9
    mknod -m 666 /dev/tty     c 5 0
    mknod -m 666 /dev/ptmx    c 5 2
    ln -sf /proc/self/fd /dev/fd
fi
mkdir -p /dev/pts && mount -t devpts devpts /dev/pts

dmesg -n 1 2>/dev/null
echo "nameserver 8.8.8.8" > /etc/resolv.conf
hostname remote

# Network: the kernel ip= param may not be fully applied before init runs.
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

# /dev/vdb, when present, is the `vm.disk_size_gb` data disk: heyvmd attaches
# it blank and leaves mounting to the guest. It holds the repo cache
# (REMOTE_CACHE_DIR), which is only a cache — the bucket is the authority, so a
# blank disk on a new VM costs a re-hydrate, never data. A disk labelled
# mount<N> is a heyvmd guest mount that heyvmd mounts itself after HEYVM_READY;
# mounting it here makes heyvmd's own mount fail (see artifacts/init.sh).
if [ -b /dev/vdb ]; then
    label="$(blkid -s LABEL -o value /dev/vdb 2>/dev/null || true)"
    case "$label" in
        mount[0-9]*)
            echo "init: /dev/vdb is a heyvmd guest mount ($label); leaving it for heyvmd to mount at /workspace"
            ;;
        *)
            if ! blkid /dev/vdb >/dev/null 2>&1; then
                echo "init: formatting blank data disk /dev/vdb"
                mkfs.ext4 -q -L remote /dev/vdb
            fi
            mkdir -p /workspace
            mount /dev/vdb /workspace 2>/dev/null
            ;;
    esac
fi
mkdir -p /workspace/cache

# sshd for `heyvm exec` / `heyvm sh`. Log to a file, never to the serial
# console, which carries the marker-delimited command protocol.
mkdir -p /run/sshd
chown root:root /run/sshd
chmod 755 /run/sshd
chown root:root /etc/ssh/ssh_host_* 2>/dev/null
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null
chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
/usr/sbin/sshd -D -e 2>/tmp/sshd.log &

echo "HEYVM_READY"

# Keep PID 1 alive with an interactive shell for `heyvm sh`. The loop survives
# the user exiting the shell (a PID 1 exit would panic the kernel).
while :; do /bin/bash --login; sleep 0.1; done
