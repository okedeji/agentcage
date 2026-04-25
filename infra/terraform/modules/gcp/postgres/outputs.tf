output "instance_name" {
  value = google_sql_database_instance.postgres.name
}

output "private_ip" {
  value = google_sql_database_instance.postgres.private_ip_address
}

output "connection_url" {
  description = "Store in Vault: agentcage vault put orchestrator postgres-url <this value>"
  value       = "postgres://agentcage:${random_password.postgres.result}@${google_sql_database_instance.postgres.private_ip_address}:5432/agentcage"
  sensitive   = true
}
