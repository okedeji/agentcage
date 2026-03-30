resource "aws_db_subnet_group" "main" {
  name       = "agentcage-${var.environment}"
  subnet_ids = aws_subnet.private[*].id

  tags = local.common_tags
}

resource "aws_db_instance" "postgres" {
  identifier        = "agentcage-${var.environment}"
  engine            = "postgres"
  engine_version    = "16"
  instance_class    = var.db_instance_class
  allocated_storage = 100
  storage_encrypted = true

  db_name  = "agentcage"
  username = "agentcage"
  password = var.db_password

  db_subnet_group_name = aws_db_subnet_group.main.name
  multi_az             = var.environment == "production"

  backup_retention_period = 7
  skip_final_snapshot     = var.environment != "production"

  tags = local.common_tags
}

variable "db_password" {
  description = "Postgres master password (use Vault in production)"
  type        = string
  sensitive   = true
}
