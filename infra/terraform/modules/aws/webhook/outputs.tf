output "instance_id" {
  value = aws_instance.webhook.id
}

output "private_ip" {
  value = aws_instance.webhook.private_ip
}

output "endpoint" {
  description = "Webhook URL for agentcage llm.endpoint config"
  value       = "http://${aws_instance.webhook.private_ip}:${var.port}/llm"
}
