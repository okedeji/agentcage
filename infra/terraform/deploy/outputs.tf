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
  value = module.agentcage.ssh_command
}

output "connect_command" {
  value = module.agentcage.connect_command
}
