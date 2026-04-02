#!/usr/bin/env bash
# embed-checksums.sh — compute SHA-256 of VM assets and patch knownChecksums in download.go.
#
# Usage: ./scripts/embed-checksums.sh <assets-dir>
#
# The assets directory must contain the files named exactly as download.go expects:
#   vmlinux-6.1-arm64, vmlinux-6.1-amd64,
#   rootfs-3.19-arm64.img, rootfs-3.19-amd64.img,
#   agentcage-linux-arm64, agentcage-linux-amd64
#
# Only files that exist in the directory are patched. Missing files are skipped.

set -euo pipefail

ASSETS_DIR="${1:?usage: embed-checksums.sh <assets-dir>}"
DOWNLOAD_GO="internal/vm/download.go"

if [ ! -f "$DOWNLOAD_GO" ]; then
    echo "error: $DOWNLOAD_GO not found — run from repo root" >&2
    exit 1
fi

EXPECTED_FILES=(
    "vmlinux-6.1-arm64"
    "vmlinux-6.1-amd64"
    "rootfs-3.19-arm64.img"
    "rootfs-3.19-amd64.img"
    "agentcage-linux-arm64"
    "agentcage-linux-amd64"
)

patched=0
for name in "${EXPECTED_FILES[@]}"; do
    filepath="$ASSETS_DIR/$name"
    if [ ! -f "$filepath" ]; then
        echo "skip: $name (not found in $ASSETS_DIR)"
        continue
    fi

    checksum=$(shasum -a 256 "$filepath" | awk '{print $1}')

    # Replace the commented-out placeholder with an active entry.
    # Matches lines like: // "vmlinux-6.1-arm64":          "sha256-hex-here",
    # Also matches already-patched lines: "vmlinux-6.1-arm64":          "abc123...",
    escaped_name=$(printf '%s' "$name" | sed 's/\./\\./g')
    if grep -q "\"$name\":" "$DOWNLOAD_GO"; then
        sed -i.bak -E "s|//[[:space:]]*\"${escaped_name}\":[[:space:]]*\"[^\"]*\",|\"${name}\": \"${checksum}\",|" "$DOWNLOAD_GO"
        sed -i.bak -E "s|\"${escaped_name}\":[[:space:]]*\"[^\"]*\",|\"${name}\": \"${checksum}\",|" "$DOWNLOAD_GO"
    fi

    echo "  $name: $checksum"
    patched=$((patched + 1))
done

# Clean up sed backup files
rm -f "${DOWNLOAD_GO}.bak"

echo ""
echo "Patched $patched checksum(s) in $DOWNLOAD_GO"

if [ "$patched" -eq 0 ]; then
    echo "warning: no assets found — checksums map unchanged" >&2
fi
