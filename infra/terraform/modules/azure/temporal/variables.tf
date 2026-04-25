variable "name" {
  type    = string
  default = "agentcage"
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "vm_size" {
  type    = string
  default = "Standard_B2s"
}

variable "namespace" {
  type    = string
  default = "agentcage"
}

variable "postgres_host" {
  type = string
}

variable "postgres_port" {
  type    = string
  default = "5432"
}

variable "postgres_user" {
  type    = string
  default = "agentcage"
}

variable "postgres_password" {
  type      = string
  sensitive = true
}

variable "subnet_id" {
  type = string
}

variable "ssh_public_key" {
  type = string
}

variable "nsg_name" {
  type = string
}

variable "allowed_cidrs" {
  type    = list(string)
  default = []
}
