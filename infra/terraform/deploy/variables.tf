variable "name" {
  type    = string
  default = "agentcage"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "agentcage_version_override" {
  description = "Override the AMI's baked-in agentcage version (dev only, leave empty for prod)"
  type        = string
  default     = ""
}

variable "create_instance" {
  description = "Set false on first run before AMI is built"
  type        = bool
  default     = true
}

variable "instance_type" {
  type    = string
  default = "m8i.large"
}

variable "spot" {
  type    = bool
  default = false
}

variable "enable_ssh" {
  type    = bool
  default = false
}

variable "my_ip" {
  description = "Your IP for SSH and gRPC access (e.g. 1.2.3.4/32)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "config_file" {
  description = "Path to config.yaml (auto-detected if present next to this file)"
  type        = string
  default     = "config.yaml"
}

variable "secrets_file" {
  description = "Path to secrets.env (auto-detected if present next to this file)"
  type        = string
  default     = "secrets.env"
}
