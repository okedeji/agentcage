output "kms_key_id" {
  value = aws_kms_key.vault_unseal.key_id
}

output "security_group_id" {
  value = aws_security_group.vault.id
}

output "iam_role_arn" {
  value = aws_iam_role.vault.arn
}
