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
  default = "e2-medium"
}

variable "namespace" {
  type    = string
  default = "agentcage"
}

variable "postgres_host" {
  type = string
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
