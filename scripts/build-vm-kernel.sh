#!/bin/bash
set -euo pipefail

# Builds a minimal Linux kernel for the agentcage macOS VM.
# All virtio drivers and virtiofs are built-in (=y), so no initramfs
# or module loading is needed. Boots directly into the init script.
#
# Usage: ./scripts/build-vm-kernel.sh <arch> [output-path]
#   arch: arm64 or amd64
#
# Requires: gcc cross-compiler (gcc-aarch64-linux-gnu for arm64)

KERNEL_VERSION="6.12.84"
KERNEL_MAJOR="6.12"

TARGET_ARCH="${1:?usage: build-vm-kernel.sh <arm64|amd64> [output-path]}"
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

OUTPUT="${2:-vmlinux-${KERNEL_MAJOR}-${TARGET_ARCH}}"
WORKDIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "Building VM kernel..."
echo "  Kernel:  ${KERNEL_VERSION} (${LINUX_ARCH})"
echo "  Output:  ${OUTPUT}"
echo

# Download kernel source
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
echo "Downloading kernel source..."
curl -fsSL -o "$WORKDIR/linux.tar.xz" "$KERNEL_URL"
echo "Extracting..."
tar xf "$WORKDIR/linux.tar.xz" -C "$WORKDIR"
SRCDIR="$WORKDIR/linux-${KERNEL_VERSION}"

# Write minimal kernel config. Every driver the VM needs is =y.
# No modules, no initramfs, smallest possible boot time.
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
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
CONFIG_HW_CONSOLE=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y

# Virtio core (PCI transport for Apple VZ)
CONFIG_PCI=y
CONFIG_PCI_HOST_GENERIC=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_BALLOON=y

# Virtio block (rootfs disk)
CONFIG_BLK_DEV=y
CONFIG_VIRTIO_BLK=y

# Virtio network
CONFIG_NET=y
CONFIG_INET=y
CONFIG_NETDEVICES=y
CONFIG_VIRTIO_NET=y
CONFIG_PACKET=y
CONFIG_UNIX=y
CONFIG_IPV6=y

# Virtio console (serial output)
CONFIG_VIRTIO_CONSOLE=y

# Virtio entropy
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_VIRTIO=y

# VirtioFS (directory sharing with macOS host)
CONFIG_FUSE_FS=y
CONFIG_VIRTIO_FS=y

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
CONFIG_IO_URING=y
CONFIG_EPOLL=y
CONFIG_FILE_LOCKING=y
CONFIG_FUTEX=y
CONFIG_INOTIFY_USER=y

# Networking (DHCP needs raw sockets)
CONFIG_PACKET=y
CONFIG_NET_UNIX=y

# Memory management
CONFIG_MEMORY_BALLOON=y

# KVM (nested virtualization — Firecracker runs inside this VM)
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=y
CONFIG_KVM_ARM_HOST=y

# BPF + BTF (Falco modern-bpf needs these for syscall monitoring)
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_DWARF5=y

# Tracepoints + perf (Falco modern eBPF attaches BPF_PROG_TYPE_TRACING programs)
CONFIG_TRACEPOINTS=y
CONFIG_HAVE_SYSCALL_TRACEPOINTS=y
CONFIG_FTRACE=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_PERF_EVENTS=y
CONFIG_PROFILING=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBES=y
CONFIG_UPROBE_EVENTS=y

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
KCONFIG

echo "Configuring kernel..."
make -C "$SRCDIR" ARCH="$LINUX_ARCH" CROSS_COMPILE="$CROSS_COMPILE" olddefconfig -j"$(nproc)"

BUILD_LOG="$WORKDIR/build.log"
echo "Building kernel (this takes a few minutes)..."
if ! make -C "$SRCDIR" ARCH="$LINUX_ARCH" CROSS_COMPILE="$CROSS_COMPILE" "$IMAGE_NAME" -j"$(nproc)" > "$BUILD_LOG" 2>&1; then
    echo "Kernel build failed. Last 50 lines:"
    tail -50 "$BUILD_LOG"
    exit 1
fi

cp "$SRCDIR/arch/${LINUX_ARCH}/boot/${IMAGE_NAME}" "$OUTPUT"
echo
echo "Kernel built: ${OUTPUT} ($(du -h "$OUTPUT" | awk '{print $1}'))"
