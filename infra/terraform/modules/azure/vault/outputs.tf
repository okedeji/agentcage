output "key_vault_name" {
  value = azurerm_key_vault.vault_unseal.name
}

output "identity_id" {
  value = azurerm_user_assigned_identity.vault.id
}
