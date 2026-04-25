# Temporal Cloud namespace (fully managed).
#
# After apply:
#   Set infrastructure.temporal.address in agentcage config
#   agentcage vault put orchestrator temporal-api-key "<api_key>"

terraform {
  required_providers {
    temporalcloud = {
      source  = "temporalio/temporalcloud"
      version = ">= 0.7"
    }
  }
}

resource "temporalcloud_namespace" "agentcage" {
  name               = var.namespace
  regions            = [var.region]
  retention_days     = var.retention_days
  accepted_client_ca = var.client_ca_cert
}
