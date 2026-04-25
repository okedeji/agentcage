variable "name" {
  type    = string
  default = "agentcage"
}

variable "instance_type" {
  type    = string
  default = "t4g.medium"
}

variable "arch" {
  type    = string
  default = "arm64"
}

variable "namespace" {
  description = "Temporal default namespace"
  type        = string
  default     = "agentcage"
}

variable "postgres_host" {
  description = "Postgres host for Temporal's backend"
  type        = string
}

variable "postgres_port" {
  type    = string
  default = "5432"
}

variable "postgres_user" {
  type    = string
  default = "agentcage"
}

variable "postgres_password" {
  type      = string
  sensitive = true
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
