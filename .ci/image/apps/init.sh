#!/bin/sh
# PID 1 for the Firecracker microVM (no systemd). The kernel boots this via
# init=/init.sh. It sets up the environment, mounts the data disk at the build
# cache, starts sshd, prints the HEYVM_READY marker, and never exits.
#
# Nothing is started here for the build itself: `ci` drives every step through
# the daemon's exec-operations, so this only has to leave a machine that can
# accept one.

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

# Docker's /dev/shm mount is not part of the exported rootfs, and mounting
# devtmpfs above hides any image directory. PostgreSQL creates its POSIX shared
# memory control segment at startup, before the first test can connect.
mkdir -p /dev/shm || exit 1
mount -t tmpfs -o mode=1777,nosuid,nodev tmpfs /dev/shm || exit 1

# Quiet the console. The firecracker serial path frames a command's output with
# newline-delimited markers, so anything else printed there can be read as part
# of a step's output — or worse, swallow the end marker.
#
# This does hide ext4 and block-layer errors from the captured serial log, which
# is exactly what you want to read when a build dies of SIGBUS. It stays anyway,
# because the ring buffer still has them and the workflow's build step prints
# `dmesg | tail` on failure — so the diagnosis is available without letting a
# kernel error storm interleave with the marker protocol. Raise it to `-n 3` if
# a failure ever kills the VM so hard that no step survives to run dmesg.
dmesg -n 1 2>/dev/null
echo "nameserver 8.8.8.8" > /etc/resolv.conf
hostname ci-apps
# Docker supplies /etc/hosts as a container mount; its exported rootfs has an
# empty file. Restore local names at boot instead of sending localhost to DNS.
printf '127.0.0.1 localhost ci-apps\n::1 localhost ip6-localhost ip6-loopback\n' > /etc/hosts
ip link set lo up

# Network: the kernel ip= param may not be fully applied before init runs. A
# build needs it working — `cargo` fetches crates from the registry.
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

# The data disk, attached as /dev/vdb when the workflow's `vm:` block sets
# `disk_size_gb`. Mounted at /var/cache/ci and **not** at /workspace, which is
# the whole trick of this image.
#
# `ci` wipes /workspace on every checkout — it runs
# `find /workspace -mindepth 1 -maxdepth 1 ... -exec rm -rf {} +` before
# unpacking the source — so anything cached there is destroyed once per run. A
# build cache has to live outside it to survive, and that is what makes reusing
# a warm VM worth anything: /var/cache/ci/target is where CARGO_TARGET_DIR
# points, so a second run relinks instead of recompiling from scratch.
#
# Blank on first boot, so format it; reused on later boots of the same VM.
if [ -b /dev/vdb ]; then
    if ! blkid /dev/vdb >/dev/null 2>&1; then
        echo "init: formatting blank data disk /dev/vdb"
        mkfs.ext4 -q -L cicache /dev/vdb
    fi
    mkdir -p /var/cache/ci
    mount /dev/vdb /var/cache/ci 2>/dev/null
    # Self-heal a nearly full cache disk. Cargo never garbage-collects a
    # target/, so across enough reuse it grows to fill the disk — at which
    # point rustc dies with SIGBUS, because its output files are written
    # through mmap and a mapped page that can't be backed on a full
    # filesystem kills the process. Wiping costs one cold build; a full disk
    # costs every build until someone shells in.
    usage=$(df -P /var/cache/ci 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}')
    if [ -n "$usage" ] && [ "$usage" -ge 85 ]; then
        echo "init: cache disk at ${usage}%, wiping /var/cache/ci/target"
        rm -rf /var/cache/ci/target
    fi
else
    # Loud on purpose: without the data disk the cache lands on the rootfs, and
    # a full filesystem under rustc's mmap'd output is a SIGBUS, not a readable
    # ENOSPC. This line in the captured VM console is the difference between
    # diagnosing that in one look and chasing a "memory error" that is really
    # a disk.
    echo "init: WARNING: no data disk /dev/vdb; the build cache will land on the rootfs"
fi
# Both created either way. Without a data disk the cache lands on the rootfs,
# which works but is sized for a toolchain rather than for a `target/`.
mkdir -p /var/cache/ci/target /workspace
# One line of ground truth in every VM console: which device backs the cache,
# and how full it starts.
df -P /var/cache/ci 2>/dev/null | awk 'NR==2 {print "init: cache disk " $1 " " $5 " used (" $4 " KB free)"}'
chmod 1777 /var/cache/ci /var/cache/ci/target

# sshd for `heyvm exec` / `heyvm sh`. Logs to a file, never to the serial
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
# the user exiting the shell — a PID 1 exit would panic the kernel.
while :; do /bin/bash --login; sleep 0.1; done
