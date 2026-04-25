variable "name" {
  type    = string
  default = "agentcage"
}

variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "network_name" {
  description = "VPC network name"
  type        = string
}

variable "subnetwork_name" {
  description = "Subnetwork name"
  type        = string
}

variable "production" {
  type    = bool
  default = false
}

variable "postgres_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-2-8192"
}

variable "nats_machine_type" {
  type    = string
  default = "e2-small"
}

variable "spire_trust_domain" {
  type    = string
  default = "agentcage.local"
}
