variable "name" {
  type    = string
  default = "agentcage"
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "zone" {
  type    = string
  default = "us-central1-a"
}

variable "machine_type" {
  type    = string
  default = "e2-small"
}

variable "arch" {
  type    = string
  default = "amd64"
}

variable "server_count" {
  description = "Number of Nomad server nodes (1 for dev, 3 or 5 for production)"
  type        = number
  default     = 1
}

variable "disk_size_gb" {
  type    = number
  default = 20
}

variable "network" {
  type = string
}

variable "subnetwork" {
  type = string
}

variable "allowed_source_tags" {
  type    = list(string)
  default = []
}
