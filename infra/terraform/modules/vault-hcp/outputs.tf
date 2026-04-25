output "vault_public_endpoint" {
  value = hcp_vault_cluster.agentcage.vault_public_endpoint_url
}

output "vault_private_endpoint" {
  value = hcp_vault_cluster.agentcage.vault_private_endpoint_url
}

output "admin_token" {
  description = "Bootstrap admin token. Rotate after initial setup."
  value       = hcp_vault_cluster_admin_token.bootstrap.token
  sensitive   = true
}
