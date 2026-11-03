variable "name" {
  type = string
}

variable "package" {
  description = "Path to the Lambda zip."
  type        = string
}

variable "cognito_issuer" {
  type = string
}

variable "cognito_client_id" {
  type = string
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
