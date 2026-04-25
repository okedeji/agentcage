variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "agentcage"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_id" {
  description = "VPC to deploy into"
  type        = string
}

variable "arch" {
  description = "CPU architecture for EC2 instances: arm64 or x86_64"
  type        = string
  default     = "arm64"
}

variable "production" {
  description = "Enable production settings (Multi-AZ, longer backups, retention)"
  type        = bool
  default     = false
}

variable "postgres_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "nats_instance_type" {
  type    = string
  default = "t4g.small"
}

variable "spire_trust_domain" {
  description = "SPIFFE trust domain"
  type        = string
  default     = "agentcage.local"
}


# Nomad client nodes (bare-metal cage hosts) are provisioned by the
# fleet webhook provisioner, not by this Terraform configuration.
