# Nomad server cluster on Azure (VMSS).
#
# After apply:
#   Set infrastructure.nomad.address in agentcage config
#   agentcage vault put orchestrator nomad-token "<bootstrap-token>"

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
  }
}

resource "azurerm_linux_virtual_machine_scale_set" "nomad_server" {
  name                = "${var.name}-nomad-server"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = var.vm_size
  instances           = var.server_count

  admin_username                  = "azureuser"
  disable_password_authentication = true
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_size_gb         = var.disk_size_gb
  }

  network_interface {
    name    = "primary"
    primary = true

    ip_configuration {
      name      = "internal"
      primary   = true
      subnet_id = var.subnet_id
    }
  }

  custom_data = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail
    NOMAD_VERSION="2.0.0"
    curl -fsSL "https://releases.hashicorp.com/nomad/$${NOMAD_VERSION}/nomad_$${NOMAD_VERSION}_linux_amd64.zip" \
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
  )

  tags = { Service = "agentcage" }
}

resource "azurerm_network_security_rule" "nomad_http" {
  name                        = "${var.name}-nomad-http"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "4646"
  source_address_prefixes     = var.allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}

resource "azurerm_network_security_rule" "nomad_rpc" {
  name                        = "${var.name}-nomad-rpc"
  priority                    = 121
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "4647-4648"
  source_address_prefixes     = var.allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}
