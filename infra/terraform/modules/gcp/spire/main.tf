# SPIRE server on GCE.
#
# After apply:
#   Set infrastructure.spire.server_address to <private_ip>:8081

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

resource "google_compute_instance" "spire_server" {
  name         = "${var.name}-spire-server"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts"
      size  = var.disk_size_gb
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = var.subnetwork
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -euo pipefail
    SPIRE_VERSION="1.14.1"
    ARCH="${var.arch == "arm64" ? "arm64" : "x86_64"}"
    curl -fsSL "https://github.com/spiffe/spire/releases/download/v$${SPIRE_VERSION}/spire-$${SPIRE_VERSION}-linux-$${ARCH}-musl.tar.gz" \
      | tar xz -C /opt
    ln -sf /opt/spire-$${SPIRE_VERSION}/bin/* /usr/local/bin/
    mkdir -p /opt/spire/data /opt/spire/conf

    cat > /opt/spire/conf/server.conf <<'CONF'
    server {
      bind_address = "0.0.0.0"
      bind_port = "8081"
      trust_domain = "${var.trust_domain}"
      data_dir = "/opt/spire/data"
      log_level = "WARN"
    }
    plugins {
      DataStore "sql" {
        plugin_data { database_type = "sqlite3"; connection_string = "/opt/spire/data/datastore.sqlite3" }
      }
      NodeAttestor "join_token" { plugin_data {} }
      KeyManager "disk" {
        plugin_data { keys_path = "/opt/spire/data/keys.json" }
      }
    }
    CONF

    cat > /etc/systemd/system/spire-server.service <<'SERVICE'
    [Unit]
    Description=SPIRE Server
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/spire-server run -config /opt/spire/conf/server.conf
    Restart=always
    [Install]
    WantedBy=multi-user.target
    SERVICE
    systemctl daemon-reload
    systemctl enable --now spire-server
  EOF

  shielded_instance_config {
    enable_secure_boot = true
  }

  tags = ["agentcage-spire"]

  labels = {
    service = "agentcage"
  }
}

resource "google_compute_firewall" "spire" {
  name    = "${var.name}-spire"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["8081"]
  }

  source_tags = var.allowed_source_tags
  target_tags = ["agentcage-spire"]
}
