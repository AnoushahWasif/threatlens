variable "name" {
  type = string
}

variable "package" {
  description = "Path to the Lambda zip."
  type        = string
}

variable "api_id" {
  description = "The HTTP API (created in the root module, so CloudFront can use its domain)."
  type        = string
}

variable "api_execution_arn" {
  type = string
}

variable "cognito_issuer" {
  type = string
}

variable "cognito_user_pool_id" {
  type = string
}

variable "cognito_client_id" {
  type = string
}

variable "kms_key_arn" {
  type = string
}

variable "table_name" {
  type = string
}

variable "table_arn" {
  type = string
}

variable "uploads_bucket" {
  type = string
}

variable "uploads_bucket_arn" {
  type = string
}

variable "queue_url" {
  type = string
}

variable "queue_arn" {
  type = string
}

variable "llm_secret_arn" {
  type = string
}

variable "worker_timeout_seconds" {
  description = "Must stay under SCAN_TIMEOUT (worker.py, 15 min), so a live scan is never taken over."
  type        = number

  validation {
    condition     = var.worker_timeout_seconds >= 60 && var.worker_timeout_seconds < 900
    error_message = "worker_timeout_seconds must be at least 60 and under 900 (SCAN_TIMEOUT)."
  }
}

variable "environment" {
  description = "Extra THREATLENS_* settings."
  type        = map(string)
  default     = {}
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "throttle_rate" {
  description = "Requests per second across the whole API. The shared limit that the per-process budgets in the app can't be (decision 39)."
  type        = number
  default     = 20
}

variable "throttle_burst" {
  type    = number
  default = 40
}
