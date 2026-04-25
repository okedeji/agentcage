# After apply, store secrets in Vault:
#   agentcage vault put orchestrator postgres-url "$(terraform output -raw postgres_connection_url)"
#   agentcage vault put orchestrator nats-url "$(terraform output -raw nats_connection_url)"
#   agentcage vault put orchestrator nomad-token "<run: NOMAD_ADDR=http://<nomad_ip>:4646 nomad acl bootstrap>"
#
# Set in agentcage config.yaml:
#   infrastructure.postgres.external: true
#   infrastructure.nats.external: true
#   infrastructure.temporal.address: <temporal_address>
#   infrastructure.vault.address: http://<vault_address>:8200
#   infrastructure.spire.server_address: <spire_server_address>
#   infrastructure.nomad.address: http://<nomad_address>:4646

output "postgres_connection_url" {
  value     = module.postgres.connection_url
  sensitive = true
}

output "nats_connection_url" {
  value = module.nats.connection_url
}

output "temporal_address" {
  value = module.temporal.address
}

output "spire_server_address" {
  value = module.spire.server_address
}

output "nomad_server_asg" {
  value = module.nomad.server_asg_name
}
