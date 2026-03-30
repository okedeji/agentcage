variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (production, staging, demo)"
  type        = string
}

variable "agentcage_version" {
  description = "agentcage release version for resource tagging"
  type        = string
}

variable "fleet_min_hosts" {
  description = "Minimum number of bare metal hosts in the warm pool"
  type        = number
  default     = 3
}

variable "fleet_max_hosts" {
  description = "Maximum number of bare metal hosts"
  type        = number
  default     = 20
}

variable "instance_type" {
  description = "EC2 bare metal instance type (must support KVM)"
  type        = string
  default     = "c5.metal"
}

variable "db_instance_class" {
  description = "RDS instance class for Postgres"
  type        = string
  default     = "db.r6g.large"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
