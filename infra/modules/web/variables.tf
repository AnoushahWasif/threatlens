variable "name" {
  type = string
}

variable "api_domain" {
  description = "execute-api host name; CloudFront sends /api/* there."
  type        = string
}

variable "script_hashes" {
  description = "sha256-... hashes of the export's inline scripts."
  type        = list(string)
}

variable "cognito_domain" {
  description = "Hosted UI origin, or empty before day 16."
  type        = string
  default     = ""
}
