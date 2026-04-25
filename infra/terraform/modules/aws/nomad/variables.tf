variable "name" {
  type    = string
  default = "agentcage"
}

variable "arch" {
  type    = string
  default = "arm64"
}

variable "server_count" {
  description = "Number of Nomad server nodes (1 for dev, 3 or 5 for production)"
  type        = number
  default     = 1
}

variable "server_instance_type" {
  type    = string
  default = "t4g.small"
}

variable "server_volume_size_gb" {
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
