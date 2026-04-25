# Full GCP deployment of agentcage infrastructure.
#
# After apply, store connection details in Vault and config:
#   agentcage vault put orchestrator postgres-url "$(terraform output -raw postgres_connection_url)"
#   agentcage vault put orchestrator nats-url "$(terraform output -raw nats_connection_url)"
#   agentcage vault put orchestrator nomad-token "<bootstrap-token>"
#   # Set infrastructure.* addresses in config.yaml
#   agentcage init

terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
    # Uncomment for managed services:
    # temporalcloud = {
    #   source  = "temporalio/temporalcloud"
    #   version = ">= 0.7"
    # }
    # hcp = {
    #   source  = "hashicorp/hcp"
    #   version = ">= 0.98"
    # }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_compute_network" "selected" {
  name = var.network_name
}

data "google_compute_subnetwork" "selected" {
  name   = var.subnetwork_name
  region = var.region
}

module "postgres" {
  source = "../../modules/gcp/postgres"

  name                = var.name
  region              = var.region
  tier                = var.postgres_tier
  ha                  = var.production
  deletion_protection = var.production
  backup_retained_count = var.production ? 14 : 3
  vpc_id              = data.google_compute_network.selected.self_link
}

module "nats" {
  source = "../../modules/gcp/nats"

  name                = var.name
  zone                = "${var.region}-a"
  machine_type        = var.nats_machine_type
  network             = data.google_compute_network.selected.name
  subnetwork          = data.google_compute_subnetwork.selected.self_link
  allowed_source_tags = ["agentcage-orchestrator"]
}

# Self-hosted Temporal backed by Cloud SQL Postgres. For Temporal Cloud,
# use source = "../../modules/temporal-cloud" instead.
module "temporal" {
  source = "../../modules/gcp/temporal"

  name                = var.name
  zone                = "${var.region}-a"
  postgres_host       = module.postgres.private_ip
  postgres_password   = module.postgres.connection_url
  network             = data.google_compute_network.selected.name
  subnetwork          = data.google_compute_subnetwork.selected.self_link
  allowed_source_tags = ["agentcage-orchestrator"]
}

# Self-hosted Vault with Cloud KMS auto-unseal. For HCP Vault,
# use source = "../../modules/vault-hcp" instead.
module "vault" {
  source = "../../modules/gcp/vault"

  name                = var.name
  project_id          = var.project_id
  region              = var.region
  zone                = "${var.region}-a"
  server_count        = var.production ? 3 : 1
  network             = data.google_compute_network.selected.name
  subnetwork          = data.google_compute_subnetwork.selected.self_link
  allowed_source_tags = ["agentcage-orchestrator"]
}

module "spire" {
  source = "../../modules/gcp/spire"

  name                = var.name
  zone                = "${var.region}-a"
  trust_domain        = var.spire_trust_domain
  network             = data.google_compute_network.selected.name
  subnetwork          = data.google_compute_subnetwork.selected.self_link
  allowed_source_tags = ["agentcage-orchestrator"]
}

module "nomad" {
  source = "../../modules/gcp/nomad"

  name                = var.name
  region              = var.region
  zone                = "${var.region}-a"
  server_count        = var.production ? 3 : 1
  network             = data.google_compute_network.selected.name
  subnetwork          = data.google_compute_subnetwork.selected.self_link
  allowed_source_tags = ["agentcage-orchestrator"]
}
