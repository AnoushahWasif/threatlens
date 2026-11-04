data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  region = data.aws_region.current.region

  # The same zip runs both: the HTTP API, and the scan worker fed by SQS.
  functions = {
    api = {
      handler = "threatlens_api.lambda_api.handler"
      # API Gateway gives up at 30 s, so there's no point running longer.
      timeout = 29
      memory  = 512
    }
    worker = {
      handler = "threatlens_api.worker.lambda_handler"
      timeout = var.worker_timeout_seconds
      memory  = 1024
    }
  }

  # Settings both functions share. Never secrets: the LLM key is read from Secrets Manager.
  environment = merge(var.environment, {
    THREATLENS_ENVIRONMENT           = "prod"
    THREATLENS_AWS_REGION            = local.region
    THREATLENS_AUTH_MODE             = "cognito"
    THREATLENS_COGNITO_REGION        = local.region
    THREATLENS_COGNITO_USER_POOL_ID  = var.cognito_user_pool_id
    THREATLENS_AUTH_CLIENT_ID        = var.cognito_client_id
    THREATLENS_STORE                 = "dynamodb"
    THREATLENS_DYNAMODB_TABLE        = var.table_name
    THREATLENS_SCAN_QUEUE_URL        = var.queue_url
    THREATLENS_UPLOADS_BUCKET        = var.uploads_bucket
    THREATLENS_LLM_API_KEY_SECRET_ID = var.llm_secret_arn
    # Same origin as the web app (CloudFront /api), so no browser ever needs CORS.
    THREATLENS_CORS_ORIGINS = "[]"
  })
}

# --- per function: log group, role, logs + tracing ---------------------------------------

resource "aws_cloudwatch_log_group" "function" {
  for_each          = local.functions
  name              = "/aws/lambda/${var.name}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "function" {
  for_each           = local.functions
  name               = "${var.name}-${each.key}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "base" {
  for_each = local.functions
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.function[each.key].arn}:*"]
  }
  statement {
    # X-Ray has no resource-level permissions for these two.
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "base" {
  for_each = local.functions
  name     = "logs-and-tracing"
  role     = aws_iam_role.function[each.key].id
  policy   = data.aws_iam_policy_document.base[each.key].json
}

# --- what each one may touch (least privilege, decision 56) --------------------------------

data "aws_iam_policy_document" "api" {
  statement {
    sid = "Table"
    # No Scan, no DeleteItem, no table admin. Transactions are checked per item action.
    actions = [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query",
    ]
    resources = [var.table_arn]
  }
  statement {
    sid       = "PutUploads"
    actions   = ["s3:PutObject"]
    resources = ["${var.uploads_bucket_arn}/uploads/*"]
  }
  statement {
    sid       = "ReadFindings"
    actions   = ["s3:GetObject"]
    resources = ["${var.uploads_bucket_arn}/findings/*"]
  }
  statement {
    sid       = "QueueScans"
    actions   = ["sqs:SendMessage"]
    resources = [var.queue_arn]
  }
  statement {
    sid       = "LlmKey"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.llm_secret_arn]
  }
  statement {
    sid       = "Key"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "dynamodb.${local.region}.amazonaws.com", "s3.${local.region}.amazonaws.com",
        "sqs.${local.region}.amazonaws.com", "secretsmanager.${local.region}.amazonaws.com",
      ]
    }
  }
}

data "aws_iam_policy_document" "worker" {
  statement {
    sid = "Table"
    # Reads a scan, saves its state, moves the project's latest-scan pointer. Nothing else.
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [var.table_arn]
  }
  statement {
    sid       = "ReadUploads"
    actions   = ["s3:GetObject"]
    resources = ["${var.uploads_bucket_arn}/uploads/*"]
  }
  statement {
    sid       = "WriteFindings"
    actions   = ["s3:PutObject"]
    resources = ["${var.uploads_bucket_arn}/findings/*"]
  }
  statement {
    sid       = "ConsumeQueue"
    actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    resources = [var.queue_arn]
  }
  statement {
    sid       = "Key"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [var.kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "dynamodb.${local.region}.amazonaws.com", "s3.${local.region}.amazonaws.com",
        "sqs.${local.region}.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy" "api" {
  name   = "data"
  role   = aws_iam_role.function["api"].id
  policy = data.aws_iam_policy_document.api.json
}

resource "aws_iam_role_policy" "worker" {
  name   = "data"
  role   = aws_iam_role.function["worker"].id
  policy = data.aws_iam_policy_document.worker.json
}

# --- the functions ----------------------------------------------------------------------------

resource "aws_lambda_function" "function" {
  for_each         = local.functions
  function_name    = "${var.name}-${each.key}"
  role             = aws_iam_role.function[each.key].arn
  filename         = var.package
  source_code_hash = filebase64sha256(var.package)
  handler          = each.value.handler
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  memory_size      = each.value.memory
  timeout          = each.value.timeout
  kms_key_arn      = var.kms_key_arn

  environment {
    variables = local.environment
  }

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.function[each.key].name
  }

  depends_on = [aws_iam_role_policy.base, aws_iam_role_policy.api, aws_iam_role_policy.worker]
}

resource "aws_lambda_event_source_mapping" "scans" {
  event_source_arn        = var.queue_arn
  function_name           = aws_lambda_function.function["worker"].arn
  batch_size              = 1
  function_response_types = ["ReportBatchItemFailures"]

  # At most this many scans at once, so we stay polite to OSV, EPSS and KEV.
  scaling_config {
    maximum_concurrency = 2
  }
}

# --- HTTP API (the gateway itself is in the root module) --------------------------------------

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = var.api_id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.function["api"].invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 30000
}

# Checked here first so bad tokens never cost a Lambda call, and again inside the app,
# which doesn't trust this (decision 26).
resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = var.api_id
  name             = "cognito"
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]

  jwt_configuration {
    issuer = var.cognito_issuer
    # Cognito access tokens have no aud; API Gateway then checks client_id against this.
    audience = [var.cognito_client_id]
  }
}

resource "aws_apigatewayv2_route" "health" {
  api_id    = var.api_id
  route_key = "GET /health"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "everything_else" {
  api_id             = var.api_id
  route_key          = "$default"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${var.name}-api"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = var.api_id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = var.throttle_rate
    throttling_burst_limit = var.throttle_burst
  }

  # No headers, query strings or bodies: those can hold tokens and user text.
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn
    format = jsonencode({
      requestId      = "$context.requestId"
      time           = "$context.requestTime"
      method         = "$context.httpMethod"
      route          = "$context.routeKey"
      path           = "$context.path"
      status         = "$context.status"
      latencyMs      = "$context.responseLatency"
      sourceIp       = "$context.identity.sourceIp"
      authError      = "$context.authorizer.error"
      integrationErr = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_lambda_permission" "gateway" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.function["api"].function_name
  principal     = "apigateway.amazonaws.com"
  # This API only, any stage and route.
  source_arn = "${var.api_execution_arn}/*/*"
}
