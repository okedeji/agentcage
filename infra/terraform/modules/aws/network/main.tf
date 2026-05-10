terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.33" }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = length(var.availability_zones) > 0 ? var.availability_zones : slice(data.aws_availability_zones.available.names, 0, 2)
}

# ---------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "${var.name}-vpc"
    Service = "agentcage"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name    = "${var.name}-igw"
    Service = "agentcage"
  }
}

# ---------------------------------------------------------------------
# Public subnets
# ---------------------------------------------------------------------

resource "aws_subnet" "public" {
  count                   = length(local.azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.name}-public-${local.azs[count.index]}"
    Service = "agentcage"
    Tier    = "public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name    = "${var.name}-public"
    Service = "agentcage"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ---------------------------------------------------------------------
# Private subnets
# ---------------------------------------------------------------------

resource "aws_subnet" "private" {
  count             = length(local.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 100)
  availability_zone = local.azs[count.index]

  tags = {
    Name    = "${var.name}-private-${local.azs[count.index]}"
    Service = "agentcage"
    Tier    = "private"
  }
}

# ---------------------------------------------------------------------
# NAT gateway (optional, for private subnet outbound)
# ---------------------------------------------------------------------

resource "aws_eip" "nat" {
  count  = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(local.azs)) : 0
  domain = "vpc"

  tags = {
    Name    = "${var.name}-nat-${count.index}"
    Service = "agentcage"
  }
}

resource "aws_nat_gateway" "main" {
  count         = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : length(local.azs)) : 0
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name    = "${var.name}-nat-${count.index}"
    Service = "agentcage"
  }
}

resource "aws_route_table" "private" {
  count  = var.enable_nat_gateway ? length(local.azs) : 0
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[var.single_nat_gateway ? 0 : count.index].id
  }

  tags = {
    Name    = "${var.name}-private-${local.azs[count.index]}"
    Service = "agentcage"
  }
}

resource "aws_route_table_association" "private" {
  count          = var.enable_nat_gateway ? length(local.azs) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
