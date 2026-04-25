variable "name" {
  type    = string
  default = "agentcage"
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

variable "trust_domain" {
  type    = string
  default = "agentcage.local"
}

variable "disk_size_gb" {
  type    = number
  default = 10
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
