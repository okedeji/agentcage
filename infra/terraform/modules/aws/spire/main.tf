# SPIRE server on EC2.
#
# After apply:
#   Set infrastructure.spire.server_address to <private_ip>:8081

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

resource "aws_instance" "spire_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.spire.id]

  user_data_replace_on_change = true
  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail
    SPIRE_VERSION="1.14.1"
    ARCH="${var.arch == "arm64" ? "arm64" : "x86_64"}"
    curl -fsSL "https://github.com/spiffe/spire/releases/download/v$${SPIRE_VERSION}/spire-$${SPIRE_VERSION}-linux-$${ARCH}-musl.tar.gz" \
      | tar xz -C /opt
    ln -sf /opt/spire-$${SPIRE_VERSION}/bin/* /usr/local/bin/

    mkdir -p /opt/spire/data /opt/spire/conf

    cat > /opt/spire/conf/server.conf <<'CONF'
    server {
      bind_address = "0.0.0.0"
      bind_port = "8081"
      trust_domain = "${var.trust_domain}"
      data_dir = "/opt/spire/data"
      log_level = "WARN"
    }
    plugins {
      DataStore "sql" {
        plugin_data { database_type = "sqlite3"; connection_string = "/opt/spire/data/datastore.sqlite3" }
      }
      NodeAttestor "join_token" { plugin_data {} }
      KeyManager "disk" {
        plugin_data { keys_path = "/opt/spire/data/keys.json" }
      }
    }
    CONF

    cat > /etc/systemd/system/spire-server.service <<'SERVICE'
    [Unit]
    Description=SPIRE Server
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/spire-server run -config /opt/spire/conf/server.conf
    Restart=always
    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable --now spire-server
  EOF

  root_block_device {
    volume_type = "gp3"
    volume_size = var.volume_size_gb
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = {
    Name    = "${var.name}-spire-server"
    Service = "agentcage"
  }
}

resource "aws_security_group" "spire" {
  name_prefix = "${var.name}-spire-"
  vpc_id      = var.vpc_id
  description = "agentcage SPIRE server - allows 8081 from orchestrator"

  ingress {
    from_port       = 8081
    to_port         = 8081
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    description     = "SPIRE gRPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Service = "agentcage" }
}
