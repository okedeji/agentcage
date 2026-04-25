# Self-hosted Vault on Azure VM with Raft storage and Key Vault auto-unseal.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
  }
}

resource "azurerm_key_vault" "vault_unseal" {
  name                = "${var.name}-vault-unseal"
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  tags = { Service = "agentcage" }
}

resource "azurerm_key_vault_key" "vault_unseal" {
  name         = "${var.name}-vault-unseal"
  key_vault_id = azurerm_key_vault.vault_unseal.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["wrapKey", "unwrapKey"]
}

resource "azurerm_user_assigned_identity" "vault" {
  name                = "${var.name}-vault"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = { Service = "agentcage" }
}

resource "azurerm_key_vault_access_policy" "vault" {
  key_vault_id = azurerm_key_vault.vault_unseal.id
  tenant_id    = var.tenant_id
  object_id    = azurerm_user_assigned_identity.vault.principal_id

  key_permissions = ["Get", "WrapKey", "UnwrapKey"]
}

resource "azurerm_network_interface" "vault" {
  count               = var.server_count
  name                = "${var.name}-vault-${count.index}"
  location            = var.location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic"
  }

  tags = { Service = "agentcage" }
}

resource "azurerm_linux_virtual_machine" "vault" {
  count               = var.server_count
  name                = "${var.name}-vault-${count.index}"
  resource_group_name = var.resource_group_name
  location            = var.location
  size                = var.vm_size

  admin_username                  = "azureuser"
  disable_password_authentication = true
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vault.id]
  }

  network_interface_ids = [azurerm_network_interface.vault[count.index].id]

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
    VAULT_VERSION="1.21.4"
    curl -fsSL "https://releases.hashicorp.com/vault/$${VAULT_VERSION}/vault_$${VAULT_VERSION}_linux_amd64.zip" \
      -o /tmp/vault.zip
    unzip /tmp/vault.zip -d /usr/local/bin
    rm /tmp/vault.zip
    useradd --system --shell /bin/false vault || true
    mkdir -p /opt/vault/data /etc/vault.d
    chown -R vault:vault /opt/vault

    cat > /etc/vault.d/vault.hcl <<'CONF'
    listener "tcp" {
      address     = "0.0.0.0:8200"
      tls_disable = 1
    }
    storage "raft" {
      path    = "/opt/vault/data"
      node_id = "vault-${count.index}"
    }
    seal "azurekeyvault" {
      tenant_id  = "${var.tenant_id}"
      vault_name = "${azurerm_key_vault.vault_unseal.name}"
      key_name   = "${azurerm_key_vault_key.vault_unseal.name}"
    }
    api_addr     = "http://$(hostname -I | awk '{print $1}'):8200"
    cluster_addr = "http://$(hostname -I | awk '{print $1}'):8201"
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
  )

  tags = { Service = "agentcage" }
}

resource "azurerm_network_security_rule" "vault_api" {
  name                        = "${var.name}-vault-api"
  priority                    = 130
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8200"
  source_address_prefixes     = var.allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}

resource "azurerm_network_security_rule" "vault_cluster" {
  name                        = "${var.name}-vault-cluster"
  priority                    = 131
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "8201"
  source_address_prefixes     = var.allowed_cidrs
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}
