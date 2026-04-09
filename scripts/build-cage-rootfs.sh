#!/bin/bash
set -euo pipefail

# Builds the base cage rootfs image for Firecracker microVMs.
# This image contains: Alpine Linux, pre-installed security tools,
# cage-internal binaries (cage-init, payload-proxy, findings-sidecar),
# and runtime environments (python3, node).
#
# Usage: ./scripts/build-cage-rootfs.sh [output-path]
# Requires: root/sudo for mount and chroot

ALPINE_VERSION="3.19"
ARCH=$(uname -m)
case "$ARCH" in
    arm64|aarch64) ALPINE_ARCH="aarch64" ;;
    x86_64|amd64)  ALPINE_ARCH="x86_64" ;;
    *) echo "unsupported architecture: $ARCH"; exit 1 ;;
esac

OUTPUT="${1:-cage-rootfs-${ALPINE_ARCH}.ext4}"
WORKDIR=$(mktemp -d)
MOUNTPOINT="${WORKDIR}/mnt"
IMG_SIZE="2G"
BINDIR="${BINDIR:-bin/cage-internal}"

cleanup() {
    if mountpoint -q "$MOUNTPOINT" 2>/dev/null; then
        sudo umount "$MOUNTPOINT"
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "Building cage base rootfs..."
echo "  Alpine: ${ALPINE_VERSION} (${ALPINE_ARCH})"
echo "  Output: ${OUTPUT}"
echo

# Download Alpine minirootfs
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ALPINE_ARCH}.tar.gz"
ALPINE_TAR="${WORKDIR}/alpine.tar.gz"

echo "Downloading Alpine minirootfs..."
curl -fsSL -o "$ALPINE_TAR" "$ALPINE_URL"

# Create ext4 image
echo "Creating disk image (${IMG_SIZE})..."
dd if=/dev/zero of="$OUTPUT" bs=1 count=0 seek=$IMG_SIZE 2>/dev/null
mkfs.ext4 -q -F "$OUTPUT"

# Mount and populate
mkdir -p "$MOUNTPOINT"
sudo mount -o loop "$OUTPUT" "$MOUNTPOINT"

echo "Extracting Alpine rootfs..."
sudo tar xzf "$ALPINE_TAR" -C "$MOUNTPOINT"

# Set up DNS for package installation
sudo cp /etc/resolv.conf "$MOUNTPOINT/etc/resolv.conf"

# Set up Alpine repositories
sudo tee "$MOUNTPOINT/etc/apk/repositories" > /dev/null << REPOEOF
https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main
https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/community
REPOEOF

# Get tool packages from the Go source of truth
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOL_PACKAGES=$(go run "${SCRIPT_DIR}/list_tool_packages.go")

# Install runtime environments and base system packages
echo "Installing base system packages..."
sudo chroot "$MOUNTPOINT" apk add --no-cache \
    python3 \
    py3-pip \
    nodejs \
    npm \
    iptables \
    iproute2 \
    bash

# Install security tools from the Go-defined tool list.
# Most are Alpine packages. Tools not in the repos get a dedicated
# install block below; the loop skips them.
MANUAL_INSTALL="nuclei interactsh subfinder httpx katana"

echo "Installing security tools..."
for pkg in $TOOL_PACKAGES; do
    case " $MANUAL_INSTALL " in
        *" $pkg "*) continue ;;
    esac
    echo "  installing $pkg..."
    sudo chroot "$MOUNTPOINT" apk add --no-cache "$pkg" || {
        echo "  ERROR: $pkg not found in Alpine repos"; exit 1
    }
done

# nuclei and interactsh are Go binaries distributed via GitHub.
# All projectdiscovery tools follow the same release pattern:
#   {tool}_{version}_linux_{arch}.zip containing a single binary.
# interactsh is the exception: asset and binary are named interactsh-client.
case "$ALPINE_ARCH" in
    aarch64) PD_ARCH="arm64" ;;
    x86_64)  PD_ARCH="amd64" ;;
esac

install_pd_tool() {
    local tool="$1" version="$2" binary="${3:-$1}"
    echo "  installing ${binary} v${version}..."
    curl -fsSL "https://github.com/projectdiscovery/${tool}/releases/download/v${version}/${binary}_${version}_linux_${PD_ARCH}.zip" -o "${WORKDIR}/${binary}.zip"
    unzip -q "${WORKDIR}/${binary}.zip" -d "${WORKDIR}/${binary}-bin"
    sudo cp "${WORKDIR}/${binary}-bin/${binary}" "$MOUNTPOINT/usr/local/bin/${binary}"
    sudo chmod 755 "$MOUNTPOINT/usr/local/bin/${binary}"
}

install_pd_tool nuclei     3.7.1
install_pd_tool interactsh 1.3.1  interactsh-client
install_pd_tool subfinder  2.13.0
install_pd_tool httpx      1.9.0
install_pd_tool katana     1.5.0

# Create standard directories
sudo mkdir -p "$MOUNTPOINT/usr/local/bin"
sudo mkdir -p "$MOUNTPOINT/opt/agent"
sudo mkdir -p "$MOUNTPOINT/etc/agentcage"
sudo mkdir -p "$MOUNTPOINT/var/run/agentcage"

# Install cage-internal binaries
echo "Installing cage-internal binaries..."
for svc in cage-init payload-proxy findings-sidecar; do
    if [ -f "${BINDIR}/${svc}" ]; then
        sudo cp "${BINDIR}/${svc}" "$MOUNTPOINT/usr/local/bin/${svc}"
        sudo chmod 755 "$MOUNTPOINT/usr/local/bin/${svc}"
    else
        echo "  WARNING: ${BINDIR}/${svc} not found — skipping"
    fi
done

# Write init script (cage-init is PID 1 in the cage)
sudo tee "$MOUNTPOINT/sbin/init" > /dev/null << 'INITEOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev

exec /usr/local/bin/cage-init
INITEOF
sudo chmod 755 "$MOUNTPOINT/sbin/init"

# Clean up package cache
sudo rm -rf "$MOUNTPOINT/var/cache/apk/"*
sudo rm -rf "$MOUNTPOINT/tmp/"*

# Unmount
sudo umount "$MOUNTPOINT"

echo
echo "Cage rootfs built: ${OUTPUT}"
echo "Size: $(du -h "$OUTPUT" | cut -f1)"
