packer {
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "agentcage_version" {
  description = "Release version to bake into the AMI (e.g. 0.1.0)"
  type        = string
}

variable "instance_type" {
  description = "Instance type for the build (not the final instance)"
  type        = string
  default     = "t3.small"
}

locals {
  timestamp = regex_replace(timestamp(), "[- TZ:]", "")
}

source "amazon-ebs" "agentcage" {
  ami_name      = "agentcage-${var.agentcage_version}-${local.timestamp}"
  instance_type = var.instance_type
  region        = var.aws_region

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
      architecture        = "x86_64"
    }
    most_recent = true
    owners      = ["099720109477"]
  }

  ssh_username = "ubuntu"

  force_deregister       = true
  force_delete_snapshot  = true
  force_delete_snapshot = true

  tags = {
    Name      = "agentcage-${var.agentcage_version}"
    Version   = var.agentcage_version
    ManagedBy = "packer"
    Service   = "agentcage"
    OS        = "Ubuntu 24.04 LTS"
    Arch      = "x86_64"
  }
}

build {
  sources = ["source.amazon-ebs.agentcage"]

  provisioner "shell" {
    environment_vars = [
      "AGENTCAGE_VERSION=${var.agentcage_version}",
    ]
    script = "${path.root}/provision.sh"
  }
}
