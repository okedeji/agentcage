# Deploy an agentcage host from scratch.
#
# Usage:
#   terraform init
#   terraform apply
#
# Connect from macOS:
#   agentcage connect $(terraform output -raw grpc_addr)
#   agentcage run --target example.com
#
# SSH (when enable_ssh = true):
#   $(terraform output -raw ssh_command)
#
# Tear down:
#   terraform destroy

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.33"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Auto-generate SSH key pair when SSH is enabled.
resource "tls_private_key" "ssh" {
  count     = var.enable_ssh ? 1 : 0
  algorithm = "ED25519"
}

resource "aws_key_pair" "ssh" {
  count      = var.enable_ssh ? 1 : 0
  key_name   = "${var.name}-ssh"
  public_key = tls_private_key.ssh[0].public_key_openssh
}

resource "local_file" "ssh_key" {
  count           = var.enable_ssh ? 1 : 0
  filename        = "${path.module}/agentcage-ssh.pem"
  content         = tls_private_key.ssh[0].private_key_openssh
  file_permission = "0600"
}

module "network" {
  source = "../modules/aws/network"

  name               = var.name
  region             = var.region
  single_nat_gateway = true
}

module "agentcage" {
  source = "../modules/aws/agentcage"

  name              = var.name
  agentcage_version = var.agentcage_version
  instance_type     = var.instance_type
  spot              = var.spot
  enable_ssh        = var.enable_ssh
  key_name          = var.enable_ssh ? aws_key_pair.ssh[0].key_name : ""
  vpc_id            = module.network.vpc_id
  subnet_id         = module.network.public_subnet_id
  allowed_cidrs     = [var.my_ip]
  ssh_cidrs         = [var.my_ip]
  config            = fileexists(var.config_file) ? file(var.config_file) : ""
  secrets           = fileexists(var.secrets_file) ? file(var.secrets_file) : ""
}
