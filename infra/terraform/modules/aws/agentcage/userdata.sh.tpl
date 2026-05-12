#!/bin/bash
set -euo pipefail

# Everything is pre-installed in the AMI. This script only handles
# per-instance customization: version override, config, and secrets.

%{ if agentcage_version_override != "" }
# Dev override: download a different agentcage version
echo "Overriding agentcage with v${agentcage_version_override}..."
curl -fsSL -o /usr/local/bin/agentcage \
  "https://github.com/okedeji/agentcage/releases/download/v${agentcage_version_override}/agentcage-linux-amd64"
chmod +x /usr/local/bin/agentcage
%{ endif }

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

# Build init args based on what files exist
INIT_ARGS="init"
if [ -f /etc/agentcage/config.yaml ]; then
  INIT_ARGS="$${INIT_ARGS} --config /etc/agentcage/config.yaml"
fi
if [ -f /etc/agentcage/secrets.env ]; then
  INIT_ARGS="$${INIT_ARGS} --secrets /etc/agentcage/secrets.env"
fi

# Update the systemd service with the correct init args
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

# systemd doesn't set HOME; agentcage needs it for ~/.agentcage
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl restart agentcage
