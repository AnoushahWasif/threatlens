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

locals {
  # Under SCAN_TIMEOUT (worker.py, 15 min), so a live scan is never taken over.
  worker_timeout_seconds = 600
}

# Created here, not in the api module, so its domain is known before anything else:
# web needs it for the /api origin, auth needs web's URL, and api needs auth's client id.
resource "aws_apigatewayv2_api" "api" {
  name          = "${var.name}-api"
  protocol_type = "HTTP"
  # No cors_configuration: browsers reach the API through CloudFront on the site's origin.
}

module "data" {
  source = "./modules/data"

  name                   = var.name
  worker_timeout_seconds = local.worker_timeout_seconds
}

module "web" {
  source = "./modules/web"

  name           = var.name
  api_domain     = replace(aws_apigatewayv2_api.api.api_endpoint, "https://", "")
  script_hashes  = var.web_script_hashes
  cognito_domain = "https://${var.auth_domain_prefix}.auth.${var.region}.amazoncognito.com"
}

module "auth" {
  source = "./modules/auth"

  name          = var.name
  domain_prefix = var.auth_domain_prefix
  site_url      = "https://${module.web.domain}"
}

module "api" {
  source = "./modules/api"

  name                   = var.name
  package                = var.api_package
  api_id                 = aws_apigatewayv2_api.api.id
  api_execution_arn      = aws_apigatewayv2_api.api.execution_arn
  cognito_issuer         = module.auth.issuer
  cognito_user_pool_id   = module.auth.user_pool_id
  cognito_client_id      = module.auth.client_id
  kms_key_arn            = module.data.kms_key_arn
  table_name             = module.data.table_name
  table_arn              = module.data.table_arn
  uploads_bucket         = module.data.uploads_bucket
  uploads_bucket_arn     = module.data.uploads_bucket_arn
  queue_url              = module.data.queue_url
  queue_arn              = module.data.queue_arn
  llm_secret_arn         = module.data.llm_secret_arn
  worker_timeout_seconds = local.worker_timeout_seconds
  environment            = var.api_environment
}

# Only the API's role may put scans on the queue. The worker trusts a message's ids, so
# the right to send is part of the trust boundary (review of #26).
data "aws_iam_policy_document" "queue" {
  statement {
    sid       = "OnlyTheApiSends"
    effect    = "Deny"
    actions   = ["sqs:SendMessage"]
    resources = [module.data.queue_arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [module.api.api_role_arn]
    }
  }
  statement {
    sid       = "HttpsOnly"
    effect    = "Deny"
    actions   = ["sqs:*"]
    resources = [module.data.queue_arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sqs_queue_policy" "scans" {
  queue_url = module.data.queue_url
  policy    = data.aws_iam_policy_document.queue.json
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
