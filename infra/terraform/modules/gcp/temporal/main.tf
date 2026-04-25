# Self-hosted Temporal server on GCE backed by Cloud SQL Postgres.

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

resource "google_compute_instance" "temporal" {
  name         = "${var.name}-temporal"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts"
      size  = 20
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = var.subnetwork
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -euo pipefail
    TEMPORAL_VERSION="1.26.2"
    curl -fsSL "https://github.com/temporalio/temporal/releases/download/v$${TEMPORAL_VERSION}/temporal_$${TEMPORAL_VERSION}_linux_amd64.tar.gz" \
      | tar xz -C /usr/local/bin
    curl -fsSL "https://github.com/temporalio/temporal/releases/download/v$${TEMPORAL_VERSION}/temporal-sql-tool_$${TEMPORAL_VERSION}_linux_amd64.tar.gz" \
      | tar xz -C /usr/local/bin
    mkdir -p /etc/temporal

    export SQL_PLUGIN=postgres12
    export SQL_HOST=${var.postgres_host}
    export SQL_PORT=${var.postgres_port}
    export SQL_USER=${var.postgres_user}
    export SQL_PASSWORD='${var.postgres_password}'

    temporal-sql-tool --database temporal create-database || true
    SQL_DATABASE=temporal temporal-sql-tool setup-schema -v 0.0 || true
    SQL_DATABASE=temporal temporal-sql-tool update-schema -d /usr/local/share/temporal/schema/postgresql/v12/temporal/versioned || true
    temporal-sql-tool --database temporal_visibility create-database || true
    SQL_DATABASE=temporal_visibility temporal-sql-tool setup-schema -v 0.0 || true
    SQL_DATABASE=temporal_visibility temporal-sql-tool update-schema -d /usr/local/share/temporal/schema/postgresql/v12/visibility/versioned || true

    cat > /etc/temporal/config.yaml <<CONF
    persistence:
      defaultStore: default
      visibilityStore: visibility
      datastores:
        default:
          sql:
            pluginName: postgres12
            databaseName: temporal
            connectAddr: "${var.postgres_host}:${var.postgres_port}"
            user: "${var.postgres_user}"
            password: "${var.postgres_password}"
        visibility:
          sql:
            pluginName: postgres12
            databaseName: temporal_visibility
            connectAddr: "${var.postgres_host}:${var.postgres_port}"
            user: "${var.postgres_user}"
            password: "${var.postgres_password}"
    global:
      membership:
        maxJoinDuration: 30s
    services:
      frontend:
        rpc:
          grpcPort: 7233
          bindOnIP: "0.0.0.0"
    CONF

    cat > /etc/systemd/system/temporal.service <<'SERVICE'
    [Unit]
    Description=Temporal Server
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/temporal-server start --config /etc/temporal
    Restart=always
    Environment=TEMPORAL_DEFAULT_NAMESPACE=${var.namespace}
    [Install]
    WantedBy=multi-user.target
    SERVICE
    systemctl daemon-reload
    systemctl enable --now temporal
  EOF

  shielded_instance_config {
    enable_secure_boot = true
  }

  tags = ["agentcage-temporal"]
  labels = { service = "agentcage" }
}

resource "google_compute_firewall" "temporal" {
  name    = "${var.name}-temporal"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["7233"]
  }

  source_tags = var.allowed_source_tags
  target_tags = ["agentcage-temporal"]
}
