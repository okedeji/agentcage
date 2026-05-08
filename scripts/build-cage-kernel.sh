#!/bin/bash
set -euo pipefail

# Builds a minimal Linux kernel for Firecracker cage microVMs.
# Optimized for fast boot, small size. Includes virtio, vsock, and
# netfilter for cage networking and host-guest communication.
#
# Usage: ./scripts/build-cage-kernel.sh <arch> [output-path]
#   arch: arm64 or amd64

# v2: vsock + netfilter for cage host-guest communication
KERNEL_VERSION="6.12.84"
KERNEL_MAJOR="6.12"

TARGET_ARCH="${1:?usage: build-cage-kernel.sh <arm64|amd64> [output-path]}"
case "$TARGET_ARCH" in
    arm64|aarch64)
        LINUX_ARCH="arm64"
        CROSS_COMPILE="aarch64-linux-gnu-"
        IMAGE_NAME="Image"
        ;;
    amd64|x86_64)
        LINUX_ARCH="x86_64"
        CROSS_COMPILE=""
        IMAGE_NAME="bzImage"
        ;;
    *) echo "unsupported architecture: $TARGET_ARCH"; exit 1 ;;
esac

OUTPUT="${2:-cage-vmlinux-${KERNEL_MAJOR}-${TARGET_ARCH}}"
WORKDIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "Building cage kernel..."
echo "  Kernel:  ${KERNEL_VERSION} (${LINUX_ARCH})"
echo "  Output:  ${OUTPUT}"
echo

KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
echo "Downloading kernel source..."
curl -fsSL -o "$WORKDIR/linux.tar.xz" "$KERNEL_URL"
echo "Extracting..."
tar xf "$WORKDIR/linux.tar.xz" -C "$WORKDIR"
SRCDIR="$WORKDIR/linux-${KERNEL_VERSION}"

cat > "$SRCDIR/.config" << 'KCONFIG'
# Base
CONFIG_64BIT=y
CONFIG_SMP=y
CONFIG_PREEMPT_VOLUNTARY=y
CONFIG_HZ_250=y
CONFIG_NO_HZ_IDLE=y
CONFIG_HIGH_RES_TIMERS=y
CONFIG_POSIX_MQUEUE=y
CONFIG_SYSVIPC=y
CONFIG_CGROUPS=y
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
CONFIG_PID_NS=y
CONFIG_USER_NS=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y

# TTY / Console
CONFIG_TTY=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_EARLYCON=y
CONFIG_SERIAL_OF_PLATFORM=y

# Virtio (Firecracker uses virtio-mmio)
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VIRTIO_BALLOON=y
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_VIRTIO=y

# Vsock (host-guest communication for logs, directives, holds)
CONFIG_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS=y

# Network
CONFIG_NET=y
CONFIG_INET=y
CONFIG_NETDEVICES=y
CONFIG_TUN=y
CONFIG_PACKET=y
CONFIG_UNIX=y
CONFIG_IPV6=y

# Netfilter / iptables (payload proxy redirect)
CONFIG_NETFILTER=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NFT_CT=y
CONFIG_NFT_REJECT=y
CONFIG_NFT_NAT=y
CONFIG_NF_NAT=y
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_FILTER=y
CONFIG_IP_NF_NAT=y

# Filesystem
CONFIG_EXT4_FS=y
CONFIG_EXT4_USE_FOR_EXT2=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y

# Block layer
CONFIG_BLOCK=y
CONFIG_BLK_DEV=y

# Executable formats
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y

# Minimal required subsystems
CONFIG_MULTIUSER=y
CONFIG_SHMEM=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_AIO=y
CONFIG_EPOLL=y
CONFIG_FILE_LOCKING=y
CONFIG_FUTEX=y
CONFIG_INOTIFY_USER=y

# Disable unnecessary features
# CONFIG_MODULES is not set
# CONFIG_BLK_DEV_INITRD is not set
# CONFIG_WIRELESS is not set
# CONFIG_WLAN is not set
# CONFIG_SOUND is not set
# CONFIG_USB_SUPPORT is not set
# CONFIG_INPUT is not set
# CONFIG_SELINUX is not set
# CONFIG_AUDIT is not set
# CONFIG_SECURITY is not set
# CONFIG_DRM is not set
# CONFIG_FB is not set
# CONFIG_SWAP is not set
# CONFIG_VIRTUALIZATION is not set
KCONFIG

echo "Configuring kernel..."
make -C "$SRCDIR" ARCH="$LINUX_ARCH" CROSS_COMPILE="$CROSS_COMPILE" olddefconfig -j"$(nproc)"

# Verify vsock survived olddefconfig
REQUIRED_CONFIGS="VIRTIO_MMIO VIRTIO_BLK VIRTIO_NET VSOCKETS VIRTIO_VSOCKETS NETFILTER NF_TABLES IP_NF_IPTABLES SERIAL_OF_PLATFORM SERIAL_EARLYCON"
for cfg in $REQUIRED_CONFIGS; do
    if ! grep -q "CONFIG_${cfg}=y" "$SRCDIR/.config"; then
        echo "FATAL: CONFIG_${cfg} not enabled after olddefconfig"
        grep "CONFIG_${cfg}" "$SRCDIR/.config" || echo "  (not present)"
        exit 1
    fi
done
echo "All required configs verified."

BUILD_LOG="$WORKDIR/build.log"
echo "Building kernel (this takes a few minutes)..."
if ! make -C "$SRCDIR" ARCH="$LINUX_ARCH" CROSS_COMPILE="$CROSS_COMPILE" "$IMAGE_NAME" -j"$(nproc)" > "$BUILD_LOG" 2>&1; then
    echo "Kernel build failed. Last 50 lines:"
    tail -50 "$BUILD_LOG"
    exit 1
fi

cp "$SRCDIR/arch/${LINUX_ARCH}/boot/${IMAGE_NAME}" "$OUTPUT"
echo
echo "Cage kernel built: ${OUTPUT} ($(du -h "$OUTPUT" | awk '{print $1}'))"
