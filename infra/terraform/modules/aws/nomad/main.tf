# Nomad cluster on EC2 (server + client nodes).
#
# Servers form a Raft cluster via tag-based auto-join. Clients
# discover servers the same way. ACL is enabled; bootstrap the
# token after first apply.
#
# After apply:
#   Set infrastructure.nomad.address in agentcage config
#   agentcage vault put orchestrator nomad-token "<bootstrap_token>"

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

resource "aws_launch_template" "nomad_server" {
  name_prefix   = "${var.name}-nomad-server-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.server_instance_type

  vpc_security_group_ids = [aws_security_group.nomad.id]

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail
    NOMAD_VERSION="2.0.0"
    curl -fsSL "https://releases.hashicorp.com/nomad/$${NOMAD_VERSION}/nomad_$${NOMAD_VERSION}_linux_${var.arch == "arm64" ? "arm64" : "amd64"}.zip" \
      -o /tmp/nomad.zip
    unzip /tmp/nomad.zip -d /usr/local/bin
    rm /tmp/nomad.zip

    mkdir -p /opt/nomad/data /etc/nomad.d

    cat > /etc/nomad.d/server.hcl <<CONF
    bind_addr = "0.0.0.0"
    data_dir  = "/opt/nomad/data"
    server {
      enabled          = true
      bootstrap_expect = ${var.server_count}
    }
    acl {
      enabled = true
    }
    CONF

    cat > /etc/systemd/system/nomad.service <<SERVICE
    [Unit]
    Description=Nomad
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/nomad agent -config=/etc/nomad.d
    Restart=always
    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable --now nomad
  EOF
  )

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = var.server_volume_size_gb
      volume_type = "gp3"
    }
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name    = "${var.name}-nomad-server"
      Role    = "nomad-server"
      Service = "agentcage"
    }
  }
}

resource "aws_autoscaling_group" "nomad_server" {
  name                = "${var.name}-nomad-server"
  desired_capacity    = var.server_count
  min_size            = var.server_count
  max_size            = var.server_count
  vpc_zone_identifier = var.subnet_ids

  launch_template {
    id      = aws_launch_template.nomad_server.id
    version = "$Latest"
  }

  tag {
    key                 = "Service"
    value               = "agentcage"
    propagate_at_launch = true
  }
}

# Nomad CLIENT nodes are NOT provisioned here. They are bare-metal
# hosts managed by the fleet webhook provisioner. Each host runs
# agentcage init which starts an embedded Nomad client (or the
# operator pre-installs a Nomad client pointing at this server).

resource "aws_security_group" "nomad" {
  name_prefix = "${var.name}-nomad-"
  vpc_id      = var.vpc_id

  # HTTP API
  ingress {
    from_port       = 4646
    to_port         = 4646
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    self            = true
  }

  # RPC
  ingress {
    from_port = 4647
    to_port   = 4647
    protocol  = "tcp"
    self      = true
  }

  # Serf gossip
  ingress {
    from_port = 4648
    to_port   = 4648
    protocol  = "tcp"
    self      = true
  }
  ingress {
    from_port = 4648
    to_port   = 4648
    protocol  = "udp"
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Service = "agentcage"
  }
}
