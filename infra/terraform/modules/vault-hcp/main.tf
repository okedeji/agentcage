# HashiCorp Vault via HCP (managed).
#
# After apply, set infrastructure.vault.address in agentcage config.
# Use the admin token output to authenticate initial secret setup.

terraform {
  required_providers {
    hcp = {
      source  = "hashicorp/hcp"
      version = ">= 0.98"
    }
  }
}

resource "hcp_vault_cluster" "agentcage" {
  cluster_id      = var.name
  hvn_id          = var.hvn_id
  tier            = var.tier
  public_endpoint = var.public_endpoint

  min_vault_version = "1.21.4"

  lifecycle {
    prevent_destroy = true
  }
}

resource "hcp_vault_cluster_admin_token" "bootstrap" {
  cluster_id = hcp_vault_cluster.agentcage.cluster_id
}
