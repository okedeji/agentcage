#!/bin/bash
set -euo pipefail

# Install Node.js
dnf install -y nodejs npm git

# Clone and deploy the webhook
git clone https://github.com/okedeji/agentcage.git /tmp/agentcage
cp -r /tmp/agentcage/sdk/typescript/examples/webhook /opt/webhook
rm -rf /tmp/agentcage

cd /opt/webhook
npm install
npm run build

# Systemd service
cat > /etc/systemd/system/agentcage-webhook.service << 'SVCEOF'
[Unit]
Description=agentcage LLM webhook gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/webhook
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=5

Environment=WEBHOOK_API_KEY=${webhook_api_key}
Environment=LLM_PROVIDER_URL=${llm_provider_url}
Environment=LLM_PROVIDER_KEY=${llm_provider_key}
Environment=LLM_MODEL=${llm_model}
Environment=PORT=${port}

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now agentcage-webhook
