# NATS with JetStream on GCE.
#
# Store the output in Vault:
#   agentcage vault put orchestrator nats-url "nats://<private_ip>:4222"

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

resource "google_compute_instance" "nats" {
  name         = "${var.name}-nats"
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
    NATS_ARCH="${var.arch == "arm64" ? "arm64" : "amd64"}"
    curl -fsSL "https://github.com/nats-io/nats-server/releases/download/v2.12.7/nats-server-v2.12.7-linux-$${NATS_ARCH}.tar.gz" \
      | tar xz -C /usr/local/bin --strip-components=1
    mkdir -p /var/lib/nats
    cat > /etc/systemd/system/nats.service <<'SERVICE'
    [Unit]
    Description=NATS Server
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/nats-server --jetstream --store_dir /var/lib/nats --addr 0.0.0.0 --port 4222 --monitor 8222
    Restart=always
    LimitNOFILE=65536
    [Install]
    WantedBy=multi-user.target
    SERVICE
    systemctl daemon-reload
    systemctl enable --now nats
  EOF

  shielded_instance_config {
    enable_secure_boot = true
  }

  tags = ["agentcage-nats"]

  labels = {
    service = "agentcage"
  }
}

resource "google_compute_firewall" "nats" {
  name    = "${var.name}-nats"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["4222", "8222"]
  }

  source_tags = var.allowed_source_tags
  target_tags = ["agentcage-nats"]
}
