variable "name" {
  type    = string
  default = "agentcage"
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "agentcage_security_group_id" {
  description = "Security group of the agentcage instance, allowed to reach the webhook"
  type        = string
}

variable "webhook_api_key" {
  description = "API key that agentcage sends to authenticate with the webhook"
  type        = string
  sensitive   = true
}

variable "llm_provider_url" {
  description = "LLM provider endpoint (e.g. https://api.openai.com/v1/chat/completions)"
  type        = string
  default     = "https://api.openai.com/v1/chat/completions"
}

variable "llm_provider_key" {
  description = "API key for the LLM provider (e.g. OpenAI API key)"
  type        = string
  sensitive   = true
}

variable "llm_model" {
  description = "Model to use for LLM requests"
  type        = string
  default     = "gpt-4.1-mini"
}

variable "port" {
  type    = number
  default = 8082
}
