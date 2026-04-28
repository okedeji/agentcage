#!/bin/bash
set -euo pipefail

# Builds a minimal Alpine Linux rootfs image for the agentcage macOS VM.
# The image boots, mounts VirtioFS, and runs agentcage init.
#
# Usage: ./scripts/build-vm-rootfs.sh [output-path]
# Requires: qemu-img (or dd), tar, root/sudo for mount

ALPINE_VERSION="3.19"

# Target architecture: first positional arg (amd64/arm64) or detect from host.
TARGET_ARCH="${1:-$(uname -m)}"
case "$TARGET_ARCH" in
    arm64|aarch64) ALPINE_ARCH="aarch64" ;;
    x86_64|amd64)  ALPINE_ARCH="x86_64" ;;
    *) echo "unsupported architecture: $TARGET_ARCH"; exit 1 ;;
esac

OUTPUT="${2:-rootfs-${TARGET_ARCH}.img}"
WORKDIR=$(mktemp -d)
MOUNTPOINT="${WORKDIR}/mnt"
IMG_SIZE="512M"

cleanup() {
    if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
        sudo umount "$MOUNTPOINT"
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "Building VM rootfs image..."
echo "  Alpine: ${ALPINE_VERSION} (${ALPINE_ARCH})"
echo "  Output: ${OUTPUT}"
echo

# Download Alpine minirootfs
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"
ALPINE_TAR="${WORKDIR}/alpine.tar.gz"

echo "Downloading Alpine minirootfs..."
curl -fsSL -o "$ALPINE_TAR" "$ALPINE_URL"

# Create raw disk image
echo "Creating disk image (${IMG_SIZE})..."
dd if=/dev/zero of="$OUTPUT" bs=1 count=0 seek=$IMG_SIZE 2>/dev/null

# Format as ext4
mkfs.ext4 -q -F "$OUTPUT"

# Mount and populate
mkdir -p "$MOUNTPOINT"
sudo mount -o loop "$OUTPUT" "$MOUNTPOINT"

echo "Extracting Alpine rootfs..."
sudo tar xzf "$ALPINE_TAR" -C "$MOUNTPOINT"

# Write init script that mounts VirtioFS and launches agentcage
echo "Writing init script..."
sudo tee "$MOUNTPOINT/sbin/init-agentcage" > /dev/null << 'INITEOF'
#!/bin/sh
set -e

# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev

# Set hostname
hostname agentcage-vm

# Bring up loopback
ip link set lo up

# Bring up eth0 via DHCP
ip link set eth0 up
udhcpc -i eth0 -s /etc/udhcpc/default.script -q 2>/dev/null || true

# Mount VirtioFS shared directory
mkdir -p /mnt/agentcage
mount -t virtiofs agentcage /mnt/agentcage

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    aarch64) GO_ARCH="arm64" ;;
    x86_64)  GO_ARCH="amd64" ;;
esac

BINARY="/mnt/agentcage/vm/agentcage-linux-${GO_ARCH}"

if [ ! -x "$BINARY" ]; then
    echo "agentcage binary not found at $BINARY"
    exec /bin/sh
fi

# Run agentcage inside the VM
export AGENTCAGE_HOME=/mnt/agentcage
exec "$BINARY" init --grpc-addr 0.0.0.0:9090 --log-format json
INITEOF
sudo chmod 755 "$MOUNTPOINT/sbin/init-agentcage"

# Create udhcpc script directory
sudo mkdir -p "$MOUNTPOINT/etc/udhcpc"
sudo tee "$MOUNTPOINT/etc/udhcpc/default.script" > /dev/null << 'DHCPEOF'
#!/bin/sh
case "$1" in
    bound|renew)
        ip addr add "$ip/$mask" dev "$interface"
        if [ -n "$router" ]; then
            ip route add default via "$router" dev "$interface"
        fi
        if [ -n "$dns" ]; then
            echo "nameserver $dns" > /etc/resolv.conf
        fi
        ;;
esac
DHCPEOF
sudo chmod 755 "$MOUNTPOINT/etc/udhcpc/default.script"

# Set DNS fallback
sudo tee "$MOUNTPOINT/etc/resolv.conf" > /dev/null << 'DNSEOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
DNSEOF

# Unmount
sudo umount "$MOUNTPOINT"

echo
echo "Rootfs image built: ${OUTPUT}"
echo "Kernel boot args should use: init=/sbin/init-agentcage"
