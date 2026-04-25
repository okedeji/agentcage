# Postgres (Azure Database for PostgreSQL Flexible Server).
#
# Store the output in Vault:
#   agentcage vault put orchestrator postgres-url "$(terraform output -raw connection_url)"

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
    random  = { source = "hashicorp/random", version = ">= 3.0" }
  }
}

resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "azurerm_postgresql_flexible_server" "postgres" {
  name                = var.name
  resource_group_name = var.resource_group_name
  location            = var.location

  version                      = "16"
  sku_name                     = var.sku_name
  storage_mb                   = var.storage_mb
  backup_retention_days        = var.backup_retention_days
  geo_redundant_backup_enabled = var.geo_redundant_backup

  administrator_login    = "agentcage"
  administrator_password = random_password.postgres.result

  delegated_subnet_id = var.delegated_subnet_id
  private_dns_zone_id = var.private_dns_zone_id

  high_availability {
    mode                      = var.ha ? "ZoneRedundant" : "Disabled"
    standby_availability_zone = var.ha ? var.standby_zone : null
  }

  lifecycle {
    ignore_changes = [
      administrator_password,
      zone,
      high_availability[0].standby_availability_zone,
    ]
  }

  tags = {
    Service = "agentcage"
  }
}

resource "azurerm_postgresql_flexible_server_database" "agentcage" {
  name      = "agentcage"
  server_id = azurerm_postgresql_flexible_server.postgres.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_configuration" "timescaledb" {
  name      = "shared_preload_libraries"
  server_id = azurerm_postgresql_flexible_server.postgres.id
  value     = "timescaledb"
}

resource "azurerm_postgresql_flexible_server_configuration" "require_ssl" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.postgres.id
  value     = "ON"
}
