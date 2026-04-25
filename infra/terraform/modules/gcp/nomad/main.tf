# Nomad server cluster on GCE (Managed Instance Group).
#
# After apply:
#   Set infrastructure.nomad.address in agentcage config
#   agentcage vault put orchestrator nomad-token "<bootstrap-token>"

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

resource "google_compute_instance_template" "nomad_server" {
  name_prefix  = "${var.name}-nomad-server-"
  machine_type = var.machine_type
  region       = var.region

  disk {
    source_image = "ubuntu-os-cloud/ubuntu-2404-lts"
    disk_size_gb = var.disk_size_gb
    disk_type    = "pd-ssd"
    auto_delete  = true
    boot         = true
  }

  network_interface {
    subnetwork = var.subnetwork
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -euo pipefail
    NOMAD_VERSION="2.0.0"
    ARCH="${var.arch == "arm64" ? "arm64" : "amd64"}"
    curl -fsSL "https://releases.hashicorp.com/nomad/$${NOMAD_VERSION}/nomad_$${NOMAD_VERSION}_linux_$${ARCH}.zip" \
      -o /tmp/nomad.zip
    unzip /tmp/nomad.zip -d /usr/local/bin
    rm /tmp/nomad.zip
    mkdir -p /opt/nomad/data /etc/nomad.d

    cat > /etc/nomad.d/server.hcl <<'CONF'
    bind_addr = "0.0.0.0"
    data_dir  = "/opt/nomad/data"
    server {
      enabled          = true
      bootstrap_expect = ${var.server_count}
    }
    acl {
      enabled = true
    }
    CONF

    cat > /etc/systemd/system/nomad.service <<'SERVICE'
    [Unit]
    Description=Nomad
    After=network.target
    [Service]
    ExecStart=/usr/local/bin/nomad agent -config=/etc/nomad.d
    Restart=always
    [Install]
    WantedBy=multi-user.target
    SERVICE
    systemctl daemon-reload
    systemctl enable --now nomad
  EOF

  shielded_instance_config {
    enable_secure_boot = true
  }

  tags = ["agentcage-nomad"]

  labels = {
    service = "agentcage"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_instance_group_manager" "nomad_server" {
  name               = "${var.name}-nomad-server"
  base_instance_name = "${var.name}-nomad-server"
  zone               = var.zone
  target_size        = var.server_count

  version {
    instance_template = google_compute_instance_template.nomad_server.id
  }
}

resource "google_compute_firewall" "nomad" {
  name    = "${var.name}-nomad"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["4646", "4647", "4648"]
  }

  allow {
    protocol = "udp"
    ports    = ["4648"]
  }

  source_tags = var.allowed_source_tags
  target_tags = ["agentcage-nomad"]
}
