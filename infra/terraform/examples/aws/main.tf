# Full AWS deployment of agentcage infrastructure (all 7 services).
#
# After apply, store connection details in Vault and config:
#   agentcage vault put orchestrator postgres-url "$(terraform output -raw postgres_connection_url)"
#   agentcage vault put orchestrator nats-url "nats://$(terraform output -raw nats_private_ip):4222"
#   agentcage vault put orchestrator temporal-api-key "<your-temporal-cloud-api-key>"
#   agentcage vault put orchestrator nomad-token "$(terraform output -raw nomad_bootstrap_note)"
#   # Set infrastructure.* addresses in config.yaml
#   agentcage init

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    # Uncomment for managed services:
    # temporalcloud = {
    #   source  = "temporalio/temporalcloud"
    #   version = ">= 0.7"
    # }
    # hcp = {
    #   source  = "hashicorp/hcp"
    #   version = ">= 0.98"
    # }
  }
}

provider "aws" {
  region = var.region
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }

  tags = {
    Tier = "private"
  }
}

resource "aws_db_subnet_group" "agentcage" {
  name       = "${var.name}-db"
  subnet_ids = data.aws_subnets.private.ids

  tags = {
    Service = "agentcage"
  }
}

# Orchestrator host security group (passed to modules so they
# can allow inbound traffic from the orchestrator only).
resource "aws_security_group" "orchestrator" {
  name_prefix = "${var.name}-orchestrator-"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.name}-orchestrator"
    Service = "agentcage"
  }
}

module "postgres" {
  source = "../../modules/aws/postgres"

  name                    = var.name
  instance_class          = var.postgres_instance_class
  allocated_storage       = 20
  max_allocated_storage   = 100
  multi_az                = var.production
  backup_retention_days   = var.production ? 14 : 1
  skip_final_snapshot     = !var.production
  vpc_id                  = var.vpc_id
  db_subnet_group_name    = aws_db_subnet_group.agentcage.name
  allowed_security_groups = [aws_security_group.orchestrator.id]
}

module "nats" {
  source = "../../modules/aws/nats"

  name                    = var.name
  instance_type           = var.nats_instance_type
  arch                    = var.arch
  volume_size_gb          = 20
  vpc_id                  = var.vpc_id
  subnet_id               = data.aws_subnets.private.ids[0]
  allowed_security_groups = [aws_security_group.orchestrator.id]
}

# Self-hosted Temporal backed by RDS Postgres. For Temporal Cloud (managed),
# use source = "../../modules/temporal-cloud" instead.
module "temporal" {
  source = "../../modules/aws/temporal"

  name                    = var.name
  arch                    = var.arch
  postgres_host           = module.postgres.endpoint
  postgres_password       = module.postgres.connection_url
  vpc_id                  = var.vpc_id
  subnet_id               = data.aws_subnets.private.ids[0]
  allowed_security_groups = [aws_security_group.orchestrator.id]
}

# Self-hosted Vault with KMS auto-unseal. For HCP Vault (managed),
# use source = "../../modules/vault-hcp" instead.
module "vault" {
  source = "../../modules/aws/vault"

  name                    = var.name
  region                  = var.region
  arch                    = var.arch
  server_count            = var.production ? 3 : 1
  vpc_id                  = var.vpc_id
  subnet_ids              = data.aws_subnets.private.ids
  allowed_security_groups = [aws_security_group.orchestrator.id]
}

module "spire" {
  source = "../../modules/aws/spire"

  name                    = var.name
  instance_type           = "t4g.small"
  arch                    = var.arch
  trust_domain            = var.spire_trust_domain
  vpc_id                  = var.vpc_id
  subnet_id               = data.aws_subnets.private.ids[0]
  allowed_security_groups = [aws_security_group.orchestrator.id]
}

module "nomad" {
  source = "../../modules/aws/nomad"

  name                    = var.name
  arch                    = var.arch
  server_count            = var.production ? 3 : 1
  server_instance_type    = "t4g.small"
  vpc_id                  = var.vpc_id
  subnet_ids              = data.aws_subnets.private.ids
  allowed_security_groups = [aws_security_group.orchestrator.id]
}
# Nomad client nodes are bare-metal hosts provisioned by the fleet
# webhook provisioner, not by Terraform. Each host runs agentcage
# init which starts embedded Nomad client, Falco, and SPIRE agent.
