# Deploy an agentcage host from scratch.
#
# Usage:
#   terraform init
#   terraform apply -var agentcage_version=0.1.0 -var enable_ssh=true -var key_name=my-key -var my_ip="$(curl -s ifconfig.me)/32"
#
# Connect from macOS:
#   agentcage connect $(terraform output -raw grpc_addr)
#   agentcage run --target example.com
#
# Tear down:
#   terraform destroy

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
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
  key_name          = var.key_name
  vpc_id            = module.network.vpc_id
  subnet_id         = module.network.public_subnet_id
  allowed_cidrs     = [var.my_ip]
  ssh_cidrs         = [var.my_ip]
  config            = fileexists(var.config_file) ? file(var.config_file) : ""
  secrets           = fileexists(var.secrets_file) ? file(var.secrets_file) : ""
}
