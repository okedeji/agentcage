terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.33" }
  }
}

# ---------------------------------------------------------------------
# AMI — latest Amazon Linux 2023 (free-tier eligible)
# ---------------------------------------------------------------------

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

# ---------------------------------------------------------------------
# Security group — only the agentcage instance can reach the webhook
# ---------------------------------------------------------------------

resource "aws_security_group" "webhook" {
  name_prefix = "${var.name}-webhook-"
  vpc_id      = var.vpc_id
  description = "agentcage LLM webhook gateway"

  ingress {
    from_port       = var.port
    to_port         = var.port
    protocol        = "tcp"
    security_groups = [var.agentcage_security_group_id]
    description     = "LLM webhook from agentcage"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Outbound to LLM provider"
  }

  tags = {
    Name    = "${var.name}-webhook"
    Service = "agentcage"
  }
}

# ---------------------------------------------------------------------
# Instance — t3.micro (free tier)
# ---------------------------------------------------------------------

resource "aws_instance" "webhook" {
  ami           = data.aws_ami.al2023.id
  instance_type = "t3.micro"
  subnet_id     = var.subnet_id

  vpc_security_group_ids = [aws_security_group.webhook.id]

  root_block_device {
    volume_type = "gp3"
    volume_size = 8
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/userdata.sh.tpl", {
    webhook_api_key  = var.webhook_api_key
    llm_provider_url = var.llm_provider_url
    llm_provider_key = var.llm_provider_key
    llm_model        = var.llm_model
    port             = var.port
  })

  tags = {
    Name    = "${var.name}-webhook"
    Service = "agentcage"
  }
}
