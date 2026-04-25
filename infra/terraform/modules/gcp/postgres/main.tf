# Postgres (Cloud SQL with TimescaleDB) on GCP.
#
# Store the output in Vault:
#   agentcage vault put orchestrator postgres-url "$(terraform output -raw connection_url)"

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
    random = { source = "hashicorp/random", version = ">= 3.0" }
  }
}

resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "postgres" {
  name             = var.name
  database_version = "POSTGRES_16"
  region           = var.region

  deletion_protection = var.deletion_protection

  settings {
    tier              = var.tier
    availability_type = var.ha ? "REGIONAL" : "ZONAL"
    disk_autoresize   = true
    disk_size         = var.disk_size_gb
    disk_type         = "PD_SSD"

    database_flags {
      name  = "shared_preload_libraries"
      value = "timescaledb"
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = var.vpc_id
      require_ssl     = true
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = var.backup_retained_count
      }
    }

    insights_config {
      query_insights_enabled = true
    }
  }
}

resource "google_sql_database" "agentcage" {
  name     = "agentcage"
  instance = google_sql_database_instance.postgres.name
}

resource "google_sql_user" "agentcage" {
  name     = "agentcage"
  instance = google_sql_database_instance.postgres.name
  password = random_password.postgres.result
}
