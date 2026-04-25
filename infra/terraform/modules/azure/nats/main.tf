# NATS with JetStream on Azure Linux VM.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
  }
}

resource "azurerm_network_interface" "nats" {
  name                = "${var.name}-nats"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }

  tags = { Service = "agentcage" }
}

resource "azurerm_linux_virtual_machine" "nats" {
  name                = "${var.name}-nats"
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size

  admin_username                  = "azureuser"
  disable_password_authentication = true
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  network_interface_ids = [azurerm_network_interface.nats.id]

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
    curl -fsSL "https://github.com/nats-io/nats-server/releases/download/v2.12.7/nats-server-v2.12.7-linux-amd64.tar.gz" \
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
  )

  tags = { Service = "agentcage" }
}

resource "azurerm_network_security_rule" "nats_client" {
  name                        = "${var.name}-nats-client"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "4222"
  source_address_prefixes     = var.allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}
