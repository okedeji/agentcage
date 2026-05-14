#!/bin/bash
set -euo pipefail

# Builds a custom Firecracker-compatible vmlinux with vsock and
# netfilter support. Uses the Firecracker CI config as a base and
# patches in the options agentcage needs.
#
# Usage: ./scripts/build-kernel.sh <arch> [output-path]
#   arch: amd64 or arm64
# Requires: build-essential, bc, flex, bison, libelf-dev, libssl-dev

KERNEL_VERSION="6.1.155"
FC_MINOR="1.14"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET_ARCH="${1:?usage: build-kernel.sh <amd64|arm64> [output-path]}"
case "$TARGET_ARCH" in
    amd64|x86_64)  KARCH="x86_64"; MAKE_TARGET="vmlinux"; OUTPUT_FILE="vmlinux" ;;
    arm64|aarch64) KARCH="aarch64"; MAKE_TARGET="Image"; OUTPUT_FILE="arch/arm64/boot/Image" ;;
    *) echo "unsupported architecture: $TARGET_ARCH"; exit 1 ;;
esac

OUTPUT="${2:-vmlinux-${TARGET_ARCH}}"
WORKDIR=$(mktemp -d)

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "Building custom Firecracker kernel..."
echo "  Kernel:  ${KERNEL_VERSION}"
echo "  Arch:    ${KARCH}"
echo "  Output:  ${OUTPUT}"
echo

# 1. Download the Firecracker CI base config.
BASE_CONFIG_URL="https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/resources/guest_configs/microvm-kernel-ci-${KARCH}-6.1.config"
echo "Downloading Firecracker CI config..."
curl -fsSL -o "${WORKDIR}/base.config" "$BASE_CONFIG_URL"

# 2. Patch in vsock + netfilter options.
cp "${WORKDIR}/base.config" "${WORKDIR}/.config"
bash "${SCRIPT_DIR}/kconfig-patch.sh" "${WORKDIR}/.config"

# 3. Download kernel source tarball from kernel.org.
#    Tarballs are faster and more reliable than git clone for CI.
TARBALL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VERSION}.tar.xz"
echo "Downloading Linux ${KERNEL_VERSION}..."
curl -fsSL -o "${WORKDIR}/linux.tar.xz" "$TARBALL_URL"
echo "Extracting..."
tar xf "${WORKDIR}/linux.tar.xz" -C "${WORKDIR}"
mv "${WORKDIR}/linux-${KERNEL_VERSION}" "${WORKDIR}/linux"

# 4. Copy patched config into kernel source.
cp "${WORKDIR}/.config" "${WORKDIR}/linux/.config"

# 5. Resolve dependency chains. This is the critical step that
#    auto-enables options our patches depend on and prevents
#    broken configs from silent dependency mismatches.
echo "Resolving config dependencies (make olddefconfig)..."
make -C "${WORKDIR}/linux" olddefconfig 2>&1 | tail -5

# 6. Verify our options survived olddefconfig.
echo "Verifying patched options..."
MISSING=0
for opt in CONFIG_VSOCKETS CONFIG_VIRTIO_VSOCKETS CONFIG_NETFILTER \
           CONFIG_NF_TABLES CONFIG_IP_NF_IPTABLES CONFIG_IP_NF_NAT \
           CONFIG_NETFILTER_XT_TARGET_REDIRECT CONFIG_NF_CONNTRACK; do
    if ! grep -q "^${opt}=y" "${WORKDIR}/linux/.config"; then
        echo "  MISSING: ${opt}"
        MISSING=$((MISSING + 1))
    fi
done
if [ "$MISSING" -gt 0 ]; then
    echo "error: ${MISSING} required options not set after olddefconfig"
    echo "Check dependency chains. The full config is at ${WORKDIR}/linux/.config"
    # Don't clean up so the user can inspect
    trap - EXIT
    exit 1
fi
echo "  All required options present."

# 7. Build.
NPROC=$(nproc 2>/dev/null || echo 4)
echo "Building kernel (${NPROC} jobs)..."
make -C "${WORKDIR}/linux" -j"${NPROC}" "${MAKE_TARGET}" 2>&1 | tail -3

# 8. Verify output exists and is the right format.
#    x86_64: uncompressed ELF vmlinux
#    arm64:  uncompressed Image (not ELF, but Firecracker expects it)
KERNEL_FILE="${WORKDIR}/linux/${OUTPUT_FILE}"
if [ ! -f "$KERNEL_FILE" ]; then
    echo "error: kernel not found at ${KERNEL_FILE}"
    exit 1
fi

FILE_TYPE=$(file -b "$KERNEL_FILE")
case "$KARCH" in
    x86_64)
        if [[ "$FILE_TYPE" != *"ELF"* ]]; then
            echo "error: x86_64 kernel is not ELF: ${FILE_TYPE}"
            exit 1
        fi
        ;;
    aarch64)
        if [[ "$FILE_TYPE" != *"ARM64"* ]] && [[ "$FILE_TYPE" != *"boot executable"* ]]; then
            echo "error: arm64 kernel is not a boot Image: ${FILE_TYPE}"
            exit 1
        fi
        ;;
esac

# 9. Copy to output path.
cp "$KERNEL_FILE" "$OUTPUT"
echo
echo "Kernel built: ${OUTPUT}"
echo "Size: $(du -h "$OUTPUT" | cut -f1)"
echo "Type: ${FILE_TYPE}"
