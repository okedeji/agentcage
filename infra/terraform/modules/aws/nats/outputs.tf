output "private_ip" {
  value = aws_instance.nats.private_ip
}

output "connection_url" {
  description = "Store in Vault: agentcage vault put orchestrator nats-url <this value>"
  value       = "nats://${aws_instance.nats.private_ip}:4222"
}

output "monitor_url" {
  value = "http://${aws_instance.nats.private_ip}:8222"
}

output "security_group_id" {
  value = aws_security_group.nats.id
}
