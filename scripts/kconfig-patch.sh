#!/bin/bash
set -euo pipefail

# Patches a Firecracker CI kernel config to add vsock and netfilter
# support. All options are built-in (=y) since CONFIG_MODULES is not
# set and the boot args include nomodule.
#
# Usage: ./scripts/kconfig-patch.sh <config-file>

CONFIG="${1:?usage: kconfig-patch.sh <config-file>}"

if [ ! -f "$CONFIG" ]; then
    echo "error: config file not found: $CONFIG"
    exit 1
fi

# enable_option sets a kconfig option to =y. If the option is
# explicitly disabled (# CONFIG_X is not set), it replaces the line.
# If the option doesn't exist, it appends it.
enable_option() {
    local opt="$1"
    if grep -q "# ${opt} is not set" "$CONFIG"; then
        sed -i "s/# ${opt} is not set/${opt}=y/" "$CONFIG"
    elif grep -q "^${opt}=" "$CONFIG"; then
        sed -i "s/^${opt}=.*/${opt}=y/" "$CONFIG"
    else
        echo "${opt}=y" >> "$CONFIG"
    fi
}

echo "Patching $CONFIG..."

# --- vsock ---
enable_option CONFIG_VSOCKETS
enable_option CONFIG_VIRTIO_VSOCKETS
enable_option CONFIG_VIRTIO_VSOCKETS_COMMON

# --- netfilter core ---
enable_option CONFIG_NETFILTER
enable_option CONFIG_NETFILTER_ADVANCED
enable_option CONFIG_NF_CONNTRACK
enable_option CONFIG_NF_NAT
enable_option CONFIG_NF_TABLES
enable_option CONFIG_NF_TABLES_INET
enable_option CONFIG_NF_TABLES_IPV4
enable_option CONFIG_NF_TABLES_IPV6
enable_option CONFIG_NFT_NAT
enable_option CONFIG_NFT_CT
enable_option CONFIG_NFT_COUNTER
enable_option CONFIG_NFT_LOG
enable_option CONFIG_NFT_REJECT
enable_option CONFIG_NFT_COMPAT
enable_option CONFIG_NFT_MASQ
enable_option CONFIG_NFT_REDIR

# --- iptables (cage-init uses iptables for HTTP redirect) ---
enable_option CONFIG_NETFILTER_XTABLES
enable_option CONFIG_NETFILTER_XT_TARGET_REDIRECT
enable_option CONFIG_NETFILTER_XT_TARGET_MASQUERADE
enable_option CONFIG_NETFILTER_XT_TARGET_NAT
enable_option CONFIG_NETFILTER_XT_TARGET_LOG
enable_option CONFIG_NETFILTER_XT_TARGET_MARK
enable_option CONFIG_NETFILTER_XT_MATCH_CONNTRACK
enable_option CONFIG_NETFILTER_XT_MATCH_STATE
enable_option CONFIG_NETFILTER_XT_MATCH_MULTIPORT
enable_option CONFIG_NETFILTER_XT_MATCH_COMMENT
enable_option CONFIG_NETFILTER_XT_MATCH_LIMIT
enable_option CONFIG_NETFILTER_XT_MATCH_MARK
enable_option CONFIG_IP_NF_IPTABLES
enable_option CONFIG_IP_NF_FILTER
enable_option CONFIG_IP_NF_NAT
enable_option CONFIG_IP_NF_TARGET_REJECT
enable_option CONFIG_IP_NF_TARGET_MASQUERADE
enable_option CONFIG_IP_NF_MANGLE
enable_option CONFIG_IP6_NF_IPTABLES
enable_option CONFIG_IP6_NF_FILTER
enable_option CONFIG_IP6_NF_NAT

echo "Patched $(grep -c '=y' "$CONFIG") options set to =y"
