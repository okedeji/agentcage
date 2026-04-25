output "private_ip" {
  value = aws_instance.spire_server.private_ip
}

output "server_address" {
  description = "Set as infrastructure.spire.server_address in agentcage config"
  value       = "${aws_instance.spire_server.private_ip}:8081"
}

output "security_group_id" {
  value = aws_security_group.spire.id
}
