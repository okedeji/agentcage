output "namespace" {
  value = temporalcloud_namespace.agentcage.name
}

output "endpoint" {
  description = "Set as infrastructure.temporal.address in agentcage config"
  value       = temporalcloud_namespace.agentcage.endpoints[0].grpc_address
}
