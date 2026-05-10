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

# ---------------------------------------------------------------------
# GitHub Actions OIDC — lets CI build AMIs without static AWS keys
# ---------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

resource "aws_iam_role" "packer" {
  name = "${var.name}-packer"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github_actions.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:okedeji/agentcage:*" }
      }
    }]
  })

  tags = { Service = "agentcage" }
}

resource "aws_iam_role_policy" "packer_ec2" {
  name = "${var.name}-packer-ec2"
  role = aws_iam_role.packer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:AttachVolume", "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage", "ec2:CreateImage", "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup", "ec2:CreateSnapshot", "ec2:CreateTags",
        "ec2:CreateVolume", "ec2:DeleteKeyPair", "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot", "ec2:DeleteVolume", "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute", "ec2:DescribeImages",
        "ec2:DescribeInstances", "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions", "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots", "ec2:DescribeSubnets", "ec2:DescribeTags",
        "ec2:DescribeVolumes", "ec2:DetachVolume", "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute", "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute", "ec2:RegisterImage",
        "ec2:RunInstances", "ec2:StopInstances", "ec2:TerminateInstances",
      ]
      Resource = "*"
    }]
  })
}

# ---------------------------------------------------------------------
# agentcage host
# ---------------------------------------------------------------------

module "agentcage" {
  source = "../modules/aws/agentcage"

  name                       = var.name
  create_instance            = var.create_instance
  agentcage_version_override = var.agentcage_version_override
  instance_type              = var.instance_type
  spot                       = var.spot
  enable_ssh                 = var.enable_ssh
  key_name                   = var.enable_ssh ? aws_key_pair.ssh[0].key_name : ""
  vpc_id                     = module.network.vpc_id
  subnet_id                  = module.network.public_subnet_id
  allowed_cidrs              = [var.my_ip]
  ssh_cidrs                  = [var.my_ip]
  config                     = fileexists(var.config_file) ? file(var.config_file) : ""
  secrets                    = fileexists(var.secrets_file) ? file(var.secrets_file) : ""
}
