output "instance_id" {
  value = var.create_instance ? aws_instance.agentcage[0].id : ""
}

output "public_ip" {
  value = var.create_instance ? aws_instance.agentcage[0].public_ip : ""
}

output "private_ip" {
  value = var.create_instance ? aws_instance.agentcage[0].private_ip : ""
}

output "grpc_addr" {
  description = "Use with: agentcage connect <this value>"
  value       = var.create_instance ? "${aws_instance.agentcage[0].public_ip}:9090" : ""
}

output "ssh_command" {
  value = var.create_instance && var.enable_ssh ? "ssh ubuntu@${aws_instance.agentcage[0].public_ip}" : ""
}

output "connect_command" {
  value = var.create_instance ? "agentcage connect ${aws_instance.agentcage[0].public_ip}:9090" : ""
}

output "security_group_id" {
  value = aws_security_group.agentcage.id
}
