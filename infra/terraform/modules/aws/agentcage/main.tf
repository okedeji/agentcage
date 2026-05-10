terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.33" }
  }
}

# ---------------------------------------------------------------------
# AMI
# ---------------------------------------------------------------------

data "aws_ami" "agentcage" {
  count       = var.create_instance ? 1 : 0
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["agentcage-*"]
  }

  filter {
    name   = "tag:ManagedBy"
    values = ["packer"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ---------------------------------------------------------------------
# IAM — minimal role for SSM Session Manager fallback
# ---------------------------------------------------------------------

resource "aws_iam_role" "agentcage" {
  name = "${var.name}-agentcage"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = { Service = "agentcage" }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.agentcage.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "agentcage" {
  name = "${var.name}-agentcage"
  role = aws_iam_role.agentcage.name
}

# ---------------------------------------------------------------------
# Security group
# ---------------------------------------------------------------------

resource "aws_security_group" "agentcage" {
  name_prefix = "${var.name}-agentcage-"
  vpc_id      = var.vpc_id
  description = "agentcage orchestrator - gRPC API and optional SSH"

  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
    description = "gRPC API"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.name}-agentcage"
    Service = "agentcage"
  }
}

resource "aws_security_group_rule" "ssh" {
  count             = var.enable_ssh ? 1 : 0
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = var.ssh_cidrs
  security_group_id = aws_security_group.agentcage.id
  description       = "SSH"
}

# ---------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------

resource "aws_instance" "agentcage" {
  count         = var.create_instance ? 1 : 0
  ami           = data.aws_ami.agentcage[0].id
  instance_type = var.instance_type
  subnet_id     = var.subnet_id
  key_name      = var.enable_ssh ? var.key_name : null

  vpc_security_group_ids = [aws_security_group.agentcage.id]
  iam_instance_profile   = aws_iam_instance_profile.agentcage.name

  cpu_options {
    nested_virtualization = "enabled"
  }

  dynamic "instance_market_options" {
    for_each = var.spot ? [1] : []
    content {
      market_type = "spot"
      spot_options {
        spot_instance_type = "one-time"
      }
    }
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.volume_size_gb
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tpl", {
    agentcage_version_override = var.agentcage_version_override
    config                     = var.config
    secrets                    = var.secrets
  })

  tags = {
    Name    = "${var.name}-agentcage"
    Service = "agentcage"
  }
}
