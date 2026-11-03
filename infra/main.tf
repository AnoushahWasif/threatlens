provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project    = var.name
      managed_by = "terraform"
      repo       = "github.com/AnoushahWasif/threatlens"
    }
  }
}

module "api" {
  source = "./modules/api"

  name              = var.name
  package           = var.api_package
  cognito_issuer    = var.cognito_issuer
  cognito_client_id = var.cognito_client_id
  environment       = var.api_environment
}

module "web" {
  source = "./modules/web"

  name           = var.name
  api_domain     = module.api.domain
  script_hashes  = var.web_script_hashes
  cognito_domain = var.cognito_domain
}

# Set up before anything else is ever applied: alerts on actual spend and on the month's
# forecast, so a runaway cost shows up days early rather than on the bill.
resource "aws_budgets_budget" "monthly" {
  name         = "${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  dynamic "notification" {
    for_each = [
      { type = "ACTUAL", threshold = 50 },
      { type = "ACTUAL", threshold = 100 },
      { type = "FORECASTED", threshold = 100 },
    ]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value.threshold
      threshold_type             = "PERCENTAGE"
      notification_type          = notification.value.type
      subscriber_email_addresses = [var.budget_email]
    }
  }
}
