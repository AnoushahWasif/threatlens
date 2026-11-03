variable "region" {
  description = "AWS region for everything except what CloudFront needs in us-east-1."
  type        = string
  default     = "eu-west-2"
}

variable "name" {
  description = "Prefix for resource names."
  type        = string
  default     = "threatlens"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.name))
    error_message = "name must be 3 to 21 lower-case letters, digits or dashes."
  }
}

variable "budget_email" {
  description = "Where the monthly budget alerts go."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_email))
    error_message = "budget_email must be an email address."
  }
}

variable "monthly_budget_usd" {
  description = "Alert when actual or forecast spend passes parts of this."
  type        = number
  default     = 10

  validation {
    condition     = var.monthly_budget_usd > 0 && var.monthly_budget_usd <= 100
    error_message = "monthly_budget_usd must be between 0 and 100."
  }
}

variable "api_package" {
  description = "Path to the API Lambda zip (apps/api/scripts/package_lambda.py)."
  type        = string
  default     = "../apps/api/build/api.zip"
}

variable "web_script_hashes" {
  description = "sha256-... hashes of the export's inline scripts (infra/scripts/csp-hashes.mjs)."
  type        = list(string)

  validation {
    condition     = length(var.web_script_hashes) > 0 && alltrue([for h in var.web_script_hashes : can(regex("^sha256-[A-Za-z0-9+/]{43}=$", h))])
    error_message = "web_script_hashes must be a non-empty list of sha256-<base64> hashes."
  }
}

# Filled in on day 16, when the Cognito pool exists.
variable "cognito_issuer" {
  description = "Issuer URL of the Cognito user pool, for the API Gateway JWT authorizer."
  type        = string
  default     = "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_placeholder"

  validation {
    condition     = can(regex("^https://cognito-idp\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9-]+_[A-Za-z0-9]+$", var.cognito_issuer))
    error_message = "cognito_issuer must be a Cognito user pool issuer URL."
  }
}

variable "cognito_client_id" {
  description = "The web app client id. The authorizer accepts only its access tokens."
  type        = string
  default     = "placeholder"
}

variable "cognito_domain" {
  description = "Hosted UI origin, e.g. https://threatlens.auth.eu-west-2.amazoncognito.com. The browser calls its token endpoint, so the CSP has to allow it."
  type        = string
  default     = ""

  validation {
    condition     = var.cognito_domain == "" || can(regex("^https://[a-z0-9.-]+$", var.cognito_domain))
    error_message = "cognito_domain must be an https origin with no path."
  }
}

variable "api_environment" {
  description = "Extra THREATLENS_* settings for the API (table, queue, bucket: day 16). Never secrets: the LLM key comes from Secrets Manager."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.api_environment) : can(regex("^THREATLENS_[A-Z0-9_]+$", k)) && !can(regex("KEY|SECRET|TOKEN|PASSWORD", k))])
    error_message = "api_environment keys must be THREATLENS_* and must not hold secrets."
  }
}
