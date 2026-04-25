output "private_ip" {
  value = aws_instance.temporal.private_ip
}

output "address" {
  description = "Set as infrastructure.temporal.address in agentcage config"
  value       = "${aws_instance.temporal.private_ip}:7233"
}

output "security_group_id" {
  value = aws_security_group.temporal.id
}
