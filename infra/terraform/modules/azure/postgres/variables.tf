variable "name" {
  type    = string
  default = "agentcage"
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "sku_name" {
  description = "Flexible Server SKU (e.g. GP_Standard_D2s_v3)"
  type        = string
  default     = "GP_Standard_D2s_v3"
}

variable "storage_mb" {
  type    = number
  default = 32768
}

variable "ha" {
  type    = bool
  default = true
}

variable "standby_zone" {
  type    = string
  default = "2"
}

variable "backup_retention_days" {
  type    = number
  default = 7
}

variable "geo_redundant_backup" {
  type    = bool
  default = false
}

variable "delegated_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers"
  type        = string
}

variable "private_dns_zone_id" {
  description = "Private DNS zone ID for Flexible Server"
  type        = string
}
