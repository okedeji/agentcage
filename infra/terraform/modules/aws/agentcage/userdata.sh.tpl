#!/bin/bash
set -euo pipefail

VERSION="${agentcage_version}"
ARCH="amd64"
REPO="https://github.com/okedeji/agentcage/releases/download/v$${VERSION}"

echo "=== agentcage host setup (v$${VERSION}) ==="

# Dependencies
apt-get update -qq
apt-get install -y -qq curl jq postgresql-common postgresql

# TimescaleDB — agentcage requires it for time-series metrics
echo "deb https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/timescaledb.list
curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey | gpg --dearmor -o /etc/apt/trusted.gpg.d/timescaledb.gpg
apt-get update -qq
apt-get install -y -qq timescaledb-2-postgresql-16

# Stop the system postgres — agentcage manages its own instance
systemctl stop postgresql || true
systemctl disable postgresql || true

# Verify KVM is available
if [ ! -e /dev/kvm ]; then
  echo "FATAL: /dev/kvm not present. Instance type must support nested virtualization (C8i/M8i/R8i)."
  exit 1
fi

# Install agentcage binary
curl -fsSL -o /usr/local/bin/agentcage "$${REPO}/agentcage-linux-$${ARCH}"
chmod +x /usr/local/bin/agentcage

# Write config
mkdir -p /etc/agentcage
%{ if config != "" }
cat > /etc/agentcage/config.yaml << 'CONFIGEOF'
${config}
CONFIGEOF
%{ endif }

%{ if secrets != "" }
cat > /etc/agentcage/secrets.env << 'SECRETSEOF'
${secrets}
SECRETSEOF
chmod 600 /etc/agentcage/secrets.env
%{ endif }

# Build init command
INIT_ARGS="init"
if [ -f /etc/agentcage/config.yaml ]; then
  INIT_ARGS="$${INIT_ARGS} --config /etc/agentcage/config.yaml"
fi
if [ -f /etc/agentcage/secrets.env ]; then
  INIT_ARGS="$${INIT_ARGS} --secrets /etc/agentcage/secrets.env"
fi

# Systemd service
cat > /etc/systemd/system/agentcage.service << SVCEOF
[Unit]
Description=agentcage orchestrator
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agentcage $${INIT_ARGS}
ExecStop=/usr/local/bin/agentcage stop
TimeoutStopSec=120
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now agentcage

echo "=== agentcage host ready ==="
