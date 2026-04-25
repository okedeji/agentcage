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

variable "disk_size_gb" {
  type    = number
  default = 16
}

variable "trust_domain" {
  type    = string
  default = "agentcage.local"
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
