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

variable "agentcage_version" {
  description = "agentcage release version (used to download the CLI on the webhook instance for `agentcage sdk install`)"
  type        = string
  default     = "0.1.0"
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
  default     = "gpt-5.5"
}

variable "judge_provider_url" {
  description = "LLM provider endpoint for judge calls. Empty string reuses llm_provider_url."
  type        = string
  default     = ""
}

variable "judge_provider_key" {
  description = "API key for the judge LLM provider. Empty string reuses llm_provider_key (same provider account). Set explicitly when judge runs against a different provider or you want separate billing."
  type        = string
  sensitive   = true
  default     = ""
}

variable "judge_model" {
  description = "Model to use for judge requests. Defaults to a cheaper model than llm_model since judge runs on every flagged request."
  type        = string
  default     = "gpt-5.5"
}

variable "port" {
  type    = number
  default = 8082
}
