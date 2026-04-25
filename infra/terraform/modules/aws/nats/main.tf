# NATS with JetStream on an EC2 instance.
#
# Store the output in Vault:
#   agentcage vault put orchestrator nats-url "nats://<private_ip>:4222"

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

resource "aws_instance" "nats" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.nats.id]

  user_data_replace_on_change = true
  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail
    NATS_ARCH="${var.arch == "arm64" ? "arm64" : "amd64"}"
    curl -fsSL "https://github.com/nats-io/nats-server/releases/download/v2.12.7/nats-server-v2.12.7-linux-$${NATS_ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin --strip-components=1
    mkdir -p /var/lib/nats
    cat > /etc/systemd/system/nats.service <<'SERVICE'
    [Unit]
    Description=NATS Server
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/nats-server --jetstream --store_dir /var/lib/nats --addr 0.0.0.0 --port 4222 --monitor 8222
    Restart=always
    LimitNOFILE=65536
    [Install]
    WantedBy=multi-user.target
    SERVICE
    systemctl daemon-reload
    systemctl enable --now nats
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
    Name    = "${var.name}-nats"
    Service = "agentcage"
  }
}

resource "aws_security_group" "nats" {
  name_prefix = "${var.name}-nats-"
  vpc_id      = var.vpc_id
  description = "agentcage NATS - allows 4222/8222 from orchestrator"

  ingress {
    from_port       = 4222
    to_port         = 4222
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    description     = "NATS client"
  }

  ingress {
    from_port       = 8222
    to_port         = 8222
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    description     = "NATS monitoring"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Service = "agentcage" }
}
