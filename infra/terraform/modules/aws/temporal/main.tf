# Self-hosted Temporal server on EC2 backed by the Postgres module.
#
# After apply:
#   Set infrastructure.temporal.address in agentcage config
#   The schema is applied automatically on first boot.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-*"]
  }

  filter {
    name   = "architecture"
    values = [var.arch]
  }
}

resource "aws_instance" "temporal" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.temporal.id]

  user_data_replace_on_change = true
  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail

    # Install Temporal server + admin-tools (includes temporal-sql-tool)
    TEMPORAL_VERSION="1.26.2"
    ARCH="${var.arch == "arm64" ? "arm64" : "amd64"}"
    curl -fsSL "https://github.com/temporalio/temporal/releases/download/v$${TEMPORAL_VERSION}/temporal_$${TEMPORAL_VERSION}_linux_$${ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin

    curl -fsSL "https://github.com/temporalio/temporal/releases/download/v$${TEMPORAL_VERSION}/temporal-sql-tool_$${TEMPORAL_VERSION}_linux_$${ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin

    mkdir -p /etc/temporal

    # Apply schema to Postgres (idempotent)
    export SQL_PLUGIN=postgres12
    export SQL_HOST=${var.postgres_host}
    export SQL_PORT=${var.postgres_port}
    export SQL_USER=${var.postgres_user}
    export SQL_PASSWORD='${var.postgres_password}'

    temporal-sql-tool --database temporal create-database || true
    SQL_DATABASE=temporal temporal-sql-tool setup-schema -v 0.0 || true
    SQL_DATABASE=temporal temporal-sql-tool update-schema -d /usr/local/share/temporal/schema/postgresql/v12/temporal/versioned || true

    temporal-sql-tool --database temporal_visibility create-database || true
    SQL_DATABASE=temporal_visibility temporal-sql-tool setup-schema -v 0.0 || true
    SQL_DATABASE=temporal_visibility temporal-sql-tool update-schema -d /usr/local/share/temporal/schema/postgresql/v12/visibility/versioned || true

    cat > /etc/temporal/config.yaml <<CONF
    persistence:
      defaultStore: default
      visibilityStore: visibility
      datastores:
        default:
          sql:
            pluginName: postgres12
            databaseName: temporal
            connectAddr: "${var.postgres_host}:${var.postgres_port}"
            user: "${var.postgres_user}"
            password: "${var.postgres_password}"
        visibility:
          sql:
            pluginName: postgres12
            databaseName: temporal_visibility
            connectAddr: "${var.postgres_host}:${var.postgres_port}"
            user: "${var.postgres_user}"
            password: "${var.postgres_password}"
    global:
      membership:
        maxJoinDuration: 30s
    services:
      frontend:
        rpc:
          grpcPort: 7233
          bindOnIP: "0.0.0.0"
    CONF

    cat > /etc/systemd/system/temporal.service <<'SERVICE'
    [Unit]
    Description=Temporal Server
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/temporal-server start --config /etc/temporal
    Restart=always
    Environment=TEMPORAL_DEFAULT_NAMESPACE=${var.namespace}
    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable --now temporal
  EOF

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name    = "${var.name}-temporal"
    Service = "agentcage"
  }
}

resource "aws_security_group" "temporal" {
  name_prefix = "${var.name}-temporal-"
  vpc_id      = var.vpc_id
  description = "agentcage Temporal server"

  ingress {
    from_port       = 7233
    to_port         = 7233
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    description     = "Temporal gRPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Service = "agentcage" }
}
