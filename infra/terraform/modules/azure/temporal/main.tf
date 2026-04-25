# Self-hosted Temporal server on Azure VM backed by Flexible Server Postgres.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
  }
}

resource "azurerm_network_interface" "temporal" {
  name                = "${var.name}-temporal"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }

  tags = { Service = "agentcage" }
}

resource "azurerm_linux_virtual_machine" "temporal" {
  name                = "${var.name}-temporal"
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size

  admin_username                  = "azureuser"
  disable_password_authentication = true
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  network_interface_ids = [azurerm_network_interface.temporal.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
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
  )

  tags = { Service = "agentcage" }
}

resource "azurerm_network_security_rule" "temporal" {
  name                        = "${var.name}-temporal"
  priority                    = 140
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "7233"
  source_address_prefixes     = var.allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}
