# Self-hosted Vault on GCE with Raft storage and Cloud KMS auto-unseal.

terraform {
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0" }
  }
}

resource "google_kms_key_ring" "vault" {
  name     = "${var.name}-vault"
  location = var.region
}

resource "google_kms_crypto_key" "vault_unseal" {
  name     = "${var.name}-vault-unseal"
  key_ring = google_kms_key_ring.vault.id
  purpose  = "ENCRYPT_DECRYPT"
}

resource "google_service_account" "vault" {
  account_id   = "${var.name}-vault"
  display_name = "agentcage Vault"
}

resource "google_kms_crypto_key_iam_member" "vault_unseal" {
  crypto_key_id = google_kms_crypto_key.vault_unseal.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.vault.email}"
}

resource "google_compute_instance_template" "vault" {
  name_prefix  = "${var.name}-vault-"
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

  service_account {
    email  = google_service_account.vault.email
    scopes = ["cloud-platform"]
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -euo pipefail
    VAULT_VERSION="1.21.4"
    curl -fsSL "https://releases.hashicorp.com/vault/$${VAULT_VERSION}/vault_$${VAULT_VERSION}_linux_amd64.zip" \
      -o /tmp/vault.zip
    unzip /tmp/vault.zip -d /usr/local/bin
    rm /tmp/vault.zip
    useradd --system --shell /bin/false vault || true
    mkdir -p /opt/vault/data /etc/vault.d
    chown -R vault:vault /opt/vault

    PRIVATE_IP=$(curl -sH "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/ip)

    cat > /etc/vault.d/vault.hcl <<CONF
    listener "tcp" {
      address     = "0.0.0.0:8200"
      tls_disable = 1
    }
    storage "raft" {
      path    = "/opt/vault/data"
      node_id = "$(hostname)"
      retry_join {
        auto_join        = "provider=gce tag_value=${var.name}-vault"
        auto_join_scheme = "http"
      }
    }
    seal "gcpckms" {
      project    = "${var.project_id}"
      region     = "${var.region}"
      key_ring   = "${google_kms_key_ring.vault.name}"
      crypto_key = "${google_kms_crypto_key.vault_unseal.name}"
    }
    api_addr     = "http://$${PRIVATE_IP}:8200"
    cluster_addr = "http://$${PRIVATE_IP}:8201"
    ui           = false
    disable_mlock = true
    CONF

    cat > /etc/systemd/system/vault.service <<'SERVICE'
    [Unit]
    Description=HashiCorp Vault
    After=network-online.target
    [Service]
    User=vault
    Group=vault
    ExecStart=/usr/local/bin/vault server -config=/etc/vault.d
    Restart=on-failure
    LimitNOFILE=65536
    [Install]
    WantedBy=multi-user.target
    SERVICE

    systemctl daemon-reload
    systemctl enable --now vault
  EOF

  shielded_instance_config {
    enable_secure_boot = true
  }

  tags = ["${var.name}-vault"]

  labels = {
    service = "agentcage"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_compute_instance_group_manager" "vault" {
  name               = "${var.name}-vault"
  base_instance_name = "${var.name}-vault"
  zone               = var.zone
  target_size        = var.server_count

  version {
    instance_template = google_compute_instance_template.vault.id
  }
}

resource "google_compute_firewall" "vault" {
  name    = "${var.name}-vault"
  network = var.network

  allow {
    protocol = "tcp"
    ports    = ["8200", "8201"]
  }

  source_tags = var.allowed_source_tags
  target_tags = ["${var.name}-vault"]
}
