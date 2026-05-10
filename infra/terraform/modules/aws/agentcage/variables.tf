variable "name" {
  type    = string
  default = "agentcage"
}

variable "create_instance" {
  description = "Set false to skip instance creation (e.g. when AMI hasn't been built yet)"
  type        = bool
  default     = true
}

variable "agentcage_version_override" {
  description = "Override the AMI's baked-in agentcage version (dev only, leave empty for prod)"
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "Must be C8i, M8i, or R8i family for nested virtualization"
  type        = string
  default     = "m8i.large"
}

variable "volume_size_gb" {
  type    = number
  default = 30
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "spot" {
  type    = bool
  default = false
}

variable "enable_ssh" {
  type    = bool
  default = false
}

variable "key_name" {
  type    = string
  default = ""
}

variable "allowed_cidrs" {
  description = "CIDRs allowed to reach the gRPC API (port 9090)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "ssh_cidrs" {
  description = "CIDRs allowed SSH access (only when enable_ssh = true)"
  type        = list(string)
  default     = []
}

variable "config" {
  description = "Raw config.yaml content written to /etc/agentcage/config.yaml"
  type        = string
  default     = ""
}

variable "secrets" {
  description = "Raw secrets.env content written to /etc/agentcage/secrets.env"
  type        = string
  default     = ""
  sensitive   = true
}
