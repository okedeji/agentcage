variable "name" {
  type    = string
  default = "agentcage"
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "AZs for subnets. Defaults to first two in the region."
  type        = list(string)
  default     = []
}

variable "enable_nat_gateway" {
  description = "Create a NAT gateway for private subnet outbound access"
  type        = bool
  default     = true
}

variable "single_nat_gateway" {
  description = "Use one NAT gateway instead of one per AZ (cheaper, less redundant)"
  type        = bool
  default     = true
}
