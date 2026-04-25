# Full Azure deployment of agentcage infrastructure.
#
# After apply, store connection details in Vault and config:
#   agentcage vault put orchestrator postgres-url "$(terraform output -raw postgres_connection_url)"
#   agentcage vault put orchestrator nats-url "$(terraform output -raw nats_connection_url)"
#   agentcage vault put orchestrator nomad-token "<bootstrap-token>"
#   # Set infrastructure.* addresses in config.yaml
#   agentcage init

terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
    # Uncomment for managed services:
    # temporalcloud = {
    #   source  = "temporalio/temporalcloud"
    #   version = ">= 0.7"
    # }
    # hcp = {
    #   source  = "hashicorp/hcp"
    #   version = ">= 0.98"
    # }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_resource_group" "selected" {
  name = var.resource_group_name
}

data "azurerm_virtual_network" "selected" {
  name                = var.vnet_name
  resource_group_name = var.resource_group_name
}

data "azurerm_subnet" "default" {
  name                 = var.subnet_name
  virtual_network_name = var.vnet_name
  resource_group_name  = var.resource_group_name
}

resource "azurerm_network_security_group" "agentcage" {
  name                = "${var.name}-agentcage"
  location            = data.azurerm_resource_group.selected.location
  resource_group_name = var.resource_group_name

  tags = { Service = "agentcage" }
}

module "postgres" {
  source = "../../modules/azure/postgres"

  name                  = var.name
  resource_group_name   = var.resource_group_name
  location              = data.azurerm_resource_group.selected.location
  sku_name              = var.postgres_sku
  ha                    = var.production
  geo_redundant_backup  = var.production
  backup_retention_days = var.production ? 35 : 7
  delegated_subnet_id   = data.azurerm_subnet.default.id
  private_dns_zone_id   = var.postgres_dns_zone_id
}

module "nats" {
  source = "../../modules/azure/nats"

  name                = var.name
  resource_group_name = var.resource_group_name
  location            = data.azurerm_resource_group.selected.location
  subnet_id           = data.azurerm_subnet.default.id
  ssh_public_key      = var.ssh_public_key
  nsg_name            = azurerm_network_security_group.agentcage.name
  allowed_cidrs       = [data.azurerm_virtual_network.selected.address_space[0]]
}

# Self-hosted Temporal backed by Flexible Server Postgres. For Temporal Cloud,
# use source = "../../modules/temporal-cloud" instead.
module "temporal" {
  source = "../../modules/azure/temporal"

  name                = var.name
  resource_group_name = var.resource_group_name
  location            = data.azurerm_resource_group.selected.location
  postgres_host       = module.postgres.fqdn
  postgres_password   = module.postgres.connection_url
  subnet_id           = data.azurerm_subnet.default.id
  ssh_public_key      = var.ssh_public_key
  nsg_name            = azurerm_network_security_group.agentcage.name
  allowed_cidrs       = [data.azurerm_virtual_network.selected.address_space[0]]
}

# Self-hosted Vault with Azure Key Vault auto-unseal. For HCP Vault,
# use source = "../../modules/vault-hcp" instead.
module "vault" {
  source = "../../modules/azure/vault"

  name                = var.name
  resource_group_name = var.resource_group_name
  location            = data.azurerm_resource_group.selected.location
  tenant_id           = var.tenant_id
  server_count        = var.production ? 3 : 1
  subnet_id           = data.azurerm_subnet.default.id
  ssh_public_key      = var.ssh_public_key
  nsg_name            = azurerm_network_security_group.agentcage.name
  allowed_cidrs       = [data.azurerm_virtual_network.selected.address_space[0]]
}

module "spire" {
  source = "../../modules/azure/spire"

  name                = var.name
  resource_group_name = var.resource_group_name
  location            = data.azurerm_resource_group.selected.location
  trust_domain        = var.spire_trust_domain
  subnet_id           = data.azurerm_subnet.default.id
  ssh_public_key      = var.ssh_public_key
  nsg_name            = azurerm_network_security_group.agentcage.name
  allowed_cidrs       = [data.azurerm_virtual_network.selected.address_space[0]]
}

module "nomad" {
  source = "../../modules/azure/nomad"

  name                = var.name
  resource_group_name = var.resource_group_name
  location            = data.azurerm_resource_group.selected.location
  server_count        = var.production ? 3 : 1
  subnet_id           = data.azurerm_subnet.default.id
  ssh_public_key      = var.ssh_public_key
  nsg_name            = azurerm_network_security_group.agentcage.name
  allowed_cidrs       = [data.azurerm_virtual_network.selected.address_space[0]]
}
