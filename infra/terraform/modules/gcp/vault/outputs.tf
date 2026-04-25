output "kms_key_ring" {
  value = google_kms_key_ring.vault.name
}

output "kms_crypto_key" {
  value = google_kms_crypto_key.vault_unseal.name
}

output "service_account_email" {
  value = google_service_account.vault.email
}
