# One-time account setup. Run once, never destroy.
# Creates the OIDC provider and IAM roles needed by CI.
#
# Usage:
#   terraform init
#   terraform apply

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.33"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "agentcage"
}

variable "github_repo" {
  type    = string
  default = "okedeji/agentcage"
}

# ---------------------------------------------------------------------
# GitHub Actions OIDC
# ---------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github_actions" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["1c58a3a8518e8759bf075b76b750d4f2df264fcd"]
}

# ---------------------------------------------------------------------
# Packer IAM role (AMI builds)
# ---------------------------------------------------------------------

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
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:*" }
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

output "packer_role_arn" {
  description = "Set as vars.PACKER_ROLE_ARN in GitHub repo Settings > Actions > Variables"
  value       = aws_iam_role.packer.arn
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github_actions.arn
}
