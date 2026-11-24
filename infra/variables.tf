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
  description = "Where the monthly budget alerts and the CloudWatch alarms go."
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

variable "auth_domain_prefix" {
  description = "Cognito hosted UI prefix (https://<prefix>.auth.<region>.amazoncognito.com). Globally unique, so no default."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$", var.auth_domain_prefix)) && !can(regex("aws|amazon|cognito", var.auth_domain_prefix))
    error_message = "auth_domain_prefix must be lower-case letters, digits and dashes, without aws, amazon or cognito."
  }
}

variable "api_environment" {
  description = "Extra THREATLENS_* settings, e.g. THREATLENS_LLM_PROVIDER=anthropic once the key secret has a value. Never secrets: the LLM key comes from Secrets Manager."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.api_environment) : can(regex("^THREATLENS_[A-Z0-9_]+$", k)) && !can(regex("KEY|SECRET|TOKEN|PASSWORD", k))])
    error_message = "api_environment keys must be THREATLENS_* and must not hold secrets."
  }
}
