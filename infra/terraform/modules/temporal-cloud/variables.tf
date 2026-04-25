variable "namespace" {
  description = "Temporal Cloud namespace name"
  type        = string
  default     = "agentcage"
}

variable "region" {
  description = "Temporal Cloud region"
  type        = string
  default     = "us-east-1"
}

variable "retention_days" {
  description = "Workflow history retention in days"
  type        = number
  default     = 30
}

variable "client_ca_cert" {
  description = "PEM-encoded CA certificate for mTLS client authentication"
  type        = string
  default     = ""
}
