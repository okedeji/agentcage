variable "name" {
  type    = string
  default = "agentcage"
}

variable "hvn_id" {
  description = "HCP HashiCorp Virtual Network ID"
  type        = string
}

variable "tier" {
  description = "HCP Vault tier: dev, starter, standard, plus"
  type        = string
  default     = "starter"
}

variable "public_endpoint" {
  description = "Enable public access to Vault (otherwise HVN peering required)"
  type        = bool
  default     = true
}
