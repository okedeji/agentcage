variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "agentcage"
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.medium"
}

variable "allocated_storage" {
  description = "Initial storage in GB"
  type        = number
  default     = 20
}

variable "max_allocated_storage" {
  description = "Max autoscaling storage in GB"
  type        = number
  default     = 100
}

variable "multi_az" {
  type    = bool
  default = true
}

variable "backup_retention_days" {
  type    = number
  default = 7
}

variable "deletion_protection" {
  description = "Prevent accidental deletion (set false for dev)"
  type        = bool
  default     = true
}

variable "skip_final_snapshot" {
  type    = bool
  default = false
}

variable "vpc_id" {
  description = "VPC ID for the security group"
  type        = string
}

variable "db_subnet_group_name" {
  description = "DB subnet group for RDS placement"
  type        = string
}

variable "allowed_security_groups" {
  description = "Security groups allowed to connect (the orchestrator host)"
  type        = list(string)
  default     = []
}
