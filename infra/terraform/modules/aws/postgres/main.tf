# Postgres (TimescaleDB) on AWS RDS.
#
# agentcage init handles migrations automatically when it connects.
# Store the output connection_url in Vault:
#   agentcage vault put orchestrator postgres-url "$(terraform output -raw connection_url)"

terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = ">= 5.0" }
    random = { source = "hashicorp/random", version = ">= 3.0" }
  }
}

resource "random_password" "postgres" {
  length  = 32
  special = false
}

resource "aws_db_parameter_group" "timescale" {
  family = "postgres16"
  name   = "${var.name}-timescaledb"

  parameter {
    name  = "shared_preload_libraries"
    value = "timescaledb"
  }

  # Enforce SSL connections.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = { Service = "agentcage" }
}

resource "aws_db_instance" "postgres" {
  identifier     = var.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.instance_class

  db_name  = "agentcage"
  username = "agentcage"
  password = random_password.postgres.result

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true

  parameter_group_name   = aws_db_parameter_group.timescale.name
  vpc_security_group_ids = [aws_security_group.postgres.id]
  db_subnet_group_name   = var.db_subnet_group_name

  multi_az                = var.multi_az
  publicly_accessible     = false
  backup_retention_period = var.backup_retention_days
  copy_tags_to_snapshot   = true
  deletion_protection     = var.deletion_protection
  skip_final_snapshot     = var.skip_final_snapshot

  performance_insights_enabled = true
  monitoring_interval          = 60

  iam_database_authentication_enabled = true

  tags = { Service = "agentcage" }

  lifecycle {
    ignore_changes = [password]
  }
}

resource "aws_security_group" "postgres" {
  name_prefix = "${var.name}-pg-"
  vpc_id      = var.vpc_id
  description = "agentcage Postgres - allows inbound 5432 from orchestrator"

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = var.allowed_security_groups
    description     = "Postgres from orchestrator"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Service = "agentcage" }
}
