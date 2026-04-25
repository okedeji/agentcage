output "endpoint" {
  value = aws_db_instance.postgres.endpoint
}

output "connection_url" {
  description = "Store in Vault: agentcage vault put orchestrator postgres-url <this value>"
  value       = "postgres://agentcage:${random_password.postgres.result}@${aws_db_instance.postgres.endpoint}/agentcage"
  sensitive   = true
}

output "security_group_id" {
  value = aws_security_group.postgres.id
}
