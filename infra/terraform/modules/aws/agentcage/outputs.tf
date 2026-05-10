output "instance_id" {
  value = aws_instance.agentcage.id
}

output "public_ip" {
  value = aws_instance.agentcage.public_ip
}

output "private_ip" {
  value = aws_instance.agentcage.private_ip
}

output "grpc_addr" {
  description = "Use with: agentcage connect <this value>"
  value       = "${aws_instance.agentcage.public_ip}:9090"
}

output "ssh_command" {
  value = var.enable_ssh ? "ssh ubuntu@${aws_instance.agentcage.public_ip}" : ""
}

output "connect_command" {
  value = "agentcage connect ${aws_instance.agentcage.public_ip}:9090"
}

output "security_group_id" {
  value = aws_security_group.agentcage.id
}
