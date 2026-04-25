variable "name" {
  type    = string
  default = "agentcage"
}

variable "resource_group_name" {
  type = string
}

variable "vnet_name" {
  type = string
}

variable "subnet_name" {
  type    = string
  default = "default"
}

variable "production" {
  type    = bool
  default = false
}

variable "ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
}

variable "postgres_sku" {
  type    = string
  default = "GP_Standard_D2s_v3"
}

variable "postgres_dns_zone_id" {
  description = "Private DNS zone ID for Postgres Flexible Server"
  type        = string
}

variable "tenant_id" {
  description = "Azure AD tenant ID for Vault Key Vault auto-unseal"
  type        = string
}

variable "spire_trust_domain" {
  type    = string
  default = "agentcage.local"
}
