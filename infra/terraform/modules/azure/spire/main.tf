# SPIRE server on Azure Linux VM.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
  }
}

resource "azurerm_network_interface" "spire" {
  name                = "${var.name}-spire"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }

  tags = { Service = "agentcage" }
}

resource "azurerm_linux_virtual_machine" "spire" {
  name                = "${var.name}-spire"
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size

  admin_username                  = "azureuser"
  disable_password_authentication = true
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  network_interface_ids = [azurerm_network_interface.spire.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.disk_size_gb
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  custom_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail
    SPIRE_VERSION="1.14.1"
    curl -fsSL "https://github.com/spiffe/spire/releases/download/v$${SPIRE_VERSION}/spire-$${SPIRE_VERSION}-linux-x86_64-musl.tar.gz" \
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
  )

  tags = { Service = "agentcage" }
}

resource "azurerm_network_security_rule" "spire" {
  name                        = "${var.name}-spire"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8081"
  source_address_prefixes     = var.allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}
