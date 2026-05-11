#!/bin/bash
set -euo pipefail

echo "=== agentcage AMI provisioning (v${AGENTCAGE_VERSION}) ==="

ARCH="amd64"
REPO="https://github.com/okedeji/agentcage/releases/download/v${AGENTCAGE_VERSION}"

# ---------------------------------------------------------------
# System packages
# ---------------------------------------------------------------
echo "Installing system packages..."
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  curl jq unzip \
  postgresql-common postgresql \
  nodejs npm \
  python3 python3-pip python3-venv \
  golang-go \
  bash iptables iproute2

# ---------------------------------------------------------------
# TimescaleDB
# ---------------------------------------------------------------
echo "Installing TimescaleDB..."
echo "deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/timescaledb.list
curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey | \
  sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/timescaledb.gpg
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq timescaledb-2-postgresql-16

# ---------------------------------------------------------------
# Disable system PostgreSQL (agentcage manages its own)
# ---------------------------------------------------------------
sudo systemctl stop postgresql || true
sudo systemctl disable postgresql || true

# ---------------------------------------------------------------
# agentcage binary
# ---------------------------------------------------------------
echo "Installing agentcage v${AGENTCAGE_VERSION}..."
sudo curl -fsSL -o /usr/local/bin/agentcage "${REPO}/agentcage-linux-${ARCH}"
sudo chmod +x /usr/local/bin/agentcage

# ---------------------------------------------------------------
# Config directory
# ---------------------------------------------------------------
sudo mkdir -p /etc/agentcage

# ---------------------------------------------------------------
# systemd service
# ---------------------------------------------------------------
echo "Installing systemd service..."
sudo tee /etc/systemd/system/agentcage.service > /dev/null << 'SVCEOF'
[Unit]
Description=agentcage orchestrator
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agentcage init
ExecStop=/usr/local/bin/agentcage stop
TimeoutStopSec=120
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# systemd doesn't set HOME; agentcage needs it for ~/.agentcage
Environment=HOME=/root
Environment=AGENTCAGE_CONFIG=/etc/agentcage/config.yaml
Environment=AGENTCAGE_SECRETS=/etc/agentcage/secrets.env

[Install]
WantedBy=multi-user.target
SVCEOF

sudo systemctl daemon-reload
sudo systemctl enable agentcage

# ---------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------
echo "Cleaning up..."
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
sudo truncate -s 0 /var/log/*.log 2>/dev/null || true

echo "=== agentcage AMI provisioning complete ==="
