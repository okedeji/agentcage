variable "name" {
  type    = string
  default = "agentcage"
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "arch" {
  description = "CPU architecture: arm64 or x86_64"
  type        = string
  default     = "arm64"
}

variable "volume_size_gb" {
  type    = number
  default = 20
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "allowed_security_groups" {
  type    = list(string)
  default = []
}
