output "fqdn" {
  value = azurerm_postgresql_flexible_server.postgres.fqdn
}

output "connection_url" {
  description = "Store in Vault: agentcage vault put orchestrator postgres-url <this value>"
  value       = "postgres://agentcage:${random_password.postgres.result}@${azurerm_postgresql_flexible_server.postgres.fqdn}:5432/agentcage?sslmode=require"
  sensitive   = true
}
