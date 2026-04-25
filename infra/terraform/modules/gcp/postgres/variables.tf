variable "name" {
  type    = string
  default = "agentcage"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-2-8192"
}

variable "disk_size_gb" {
  type    = number
  default = 20
}

variable "ha" {
  description = "Enable regional HA (primary + standby in different zones)"
  type        = bool
  default     = true
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "backup_retained_count" {
  type    = number
  default = 7
}

variable "vpc_id" {
  description = "VPC self_link for private IP"
  type        = string
}
