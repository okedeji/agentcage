variable "name" {
  type    = string
  default = "agentcage"
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "arch" {
  type    = string
  default = "arm64"
}

variable "trust_domain" {
  description = "SPIFFE trust domain for workload identities"
  type        = string
  default     = "agentcage.local"
}

variable "volume_size_gb" {
  type    = number
  default = 10
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
