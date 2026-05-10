output "instance_id" {
  value = module.agentcage.instance_id
}

output "public_ip" {
  value = module.agentcage.public_ip
}

output "grpc_addr" {
  value = module.agentcage.grpc_addr
}

output "ssh_command" {
  value = var.enable_ssh && module.agentcage.public_ip != "" ? "ssh -i ${path.module}/agentcage-ssh.pem ubuntu@${module.agentcage.public_ip}" : ""
}

output "connect_command" {
  value = module.agentcage.connect_command
}

output "pause_command" {
  description = "Stop the instance (keeps disk, no compute cost)"
  value       = module.agentcage.instance_id != "" ? "aws ec2 stop-instances --instance-ids ${module.agentcage.instance_id}" : ""
}

output "resume_command" {
  description = "Start the instance back up"
  value       = module.agentcage.instance_id != "" ? "aws ec2 start-instances --instance-ids ${module.agentcage.instance_id}" : ""
}
