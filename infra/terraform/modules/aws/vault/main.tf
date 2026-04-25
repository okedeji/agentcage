# Self-hosted Vault on EC2 with Raft storage and KMS auto-unseal.
#
# After apply:
#   Set infrastructure.vault.address in agentcage config
#   Initialize Vault: vault operator init -recovery-shares=1 -recovery-threshold=1
#   The unseal is automatic via KMS.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

resource "aws_kms_key" "vault_unseal" {
  description = "Vault auto-unseal key for ${var.name}"
  tags        = { Service = "agentcage" }
}

resource "aws_kms_alias" "vault_unseal" {
  name          = "alias/${var.name}-vault-unseal"
  target_key_id = aws_kms_key.vault_unseal.key_id
}

resource "aws_iam_role" "vault" {
  name = "${var.name}-vault"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Service = "agentcage" }
}

resource "aws_iam_role_policy" "vault_kms" {
  name = "${var.name}-vault-kms"
  role = aws_iam_role.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
      Resource = aws_kms_key.vault_unseal.arn
    }]
  })
}

resource "aws_iam_role_policy" "vault_ec2_discover" {
  name = "${var.name}-vault-ec2-discover"
  role = aws_iam_role.vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "vault" {
  name = "${var.name}-vault"
  role = aws_iam_role.vault.name
}

resource "aws_launch_template" "vault" {
  name_prefix   = "${var.name}-vault-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.vault.arn
  }

  vpc_security_group_ids = [aws_security_group.vault.id]

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail
    VAULT_VERSION="1.21.4"
    ARCH="${var.arch == "arm64" ? "arm64" : "amd64"}"
    curl -fsSL "https://releases.hashicorp.com/vault/$${VAULT_VERSION}/vault_$${VAULT_VERSION}_linux_$${ARCH}.zip" \
      -o /tmp/vault.zip
    unzip /tmp/vault.zip -d /usr/local/bin
    rm /tmp/vault.zip
    useradd --system --shell /bin/false vault || true
    mkdir -p /opt/vault/data /etc/vault.d
    chown -R vault:vault /opt/vault

    PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)

    cat > /etc/vault.d/vault.hcl <<CONF
    listener "tcp" {
      address     = "0.0.0.0:8200"
      tls_disable = 1
    }
    storage "raft" {
      path    = "/opt/vault/data"
      node_id = "$(hostname)"
      retry_join {
        auto_join        = "provider=aws tag_key=agentcage-vault tag_value=${var.name}"
        auto_join_scheme = "http"
      }
    }
    seal "awskms" {
      region     = "${var.region}"
      kms_key_id = "${aws_kms_key.vault_unseal.key_id}"
    }
    api_addr     = "http://$${PRIVATE_IP}:8200"
    cluster_addr = "http://$${PRIVATE_IP}:8201"
    ui           = false
    disable_mlock = true
    CONF

    cat > /etc/systemd/system/vault.service <<'SERVICE'
    [Unit]
    Description=HashiCorp Vault
    After=network-online.target
    [Service]
    User=vault
    Group=vault
    ExecStart=/usr/local/bin/vault server -config=/etc/vault.d
    ExecReload=/bin/kill -HUP $MAINPID
    Restart=on-failure
    LimitNOFILE=65536
    LimitMEMLOCK=infinity
    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable --now vault
  EOF
  )

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = var.volume_size_gb
      volume_type = "gp3"
      encrypted   = true
    }
  }

  metadata_options {
    http_tokens = "required"
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name            = "${var.name}-vault"
      Service         = "agentcage"
      agentcage-vault = var.name
    }
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

resource "aws_autoscaling_group" "vault" {
  name                = "${var.name}-vault"
  desired_capacity    = var.server_count
  min_size            = var.server_count
  max_size            = var.server_count
  vpc_zone_identifier = var.subnet_ids

  launch_template {
    id      = aws_launch_template.vault.id
    version = "$Latest"
  }

  tag {
    key                 = "Service"
    value               = "agentcage"
    propagate_at_launch = true
  }
}

resource "aws_security_group" "vault" {
  name_prefix = "${var.name}-vault-"
  vpc_id      = var.vpc_id
  description = "agentcage Vault cluster"

  ingress {
    from_port       = 8200
    to_port         = 8200
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    self            = true
    description     = "Vault API"
  }

  ingress {
    from_port   = 8201
    to_port     = 8201
    protocol    = "tcp"
    self        = true
    description = "Vault cluster (Raft)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Service = "agentcage" }
}
