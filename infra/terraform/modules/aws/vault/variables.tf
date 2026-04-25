variable "name" {
  type    = string
  default = "agentcage"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "arch" {
  type    = string
  default = "arm64"
}

variable "server_count" {
  description = "Number of Vault nodes (1 for dev, 3 for production HA)"
  type        = number
  default     = 1
}

variable "volume_size_gb" {
  type    = number
  default = 20
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "allowed_security_groups" {
  type    = list(string)
  default = []
}
