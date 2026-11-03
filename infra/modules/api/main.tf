data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  function_name = "${var.name}-api"
}

# --- Lambda --------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "function" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
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
  name               = "${local.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# Its own log group only. Table, queue, bucket and secret permissions come on day 16, each
# scoped to that one resource.
data "aws_iam_policy_document" "logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.function.arn}:*"]
  }
}

data "aws_iam_policy_document" "tracing" {
  statement {
    # X-Ray has no resource-level permissions for these two.
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "tracing" {
  name   = "tracing"
  role   = aws_iam_role.function.id
  policy = data.aws_iam_policy_document.tracing.json
}

resource "aws_iam_role_policy" "logs" {
  name   = "logs"
  role   = aws_iam_role.function.id
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_lambda_function" "api" {
  function_name    = local.function_name
  role             = aws_iam_role.function.arn
  filename         = var.package
  source_code_hash = filebase64sha256(var.package)
  handler          = "threatlens_api.lambda_api.handler"
  runtime          = "python3.12"
  architectures    = ["x86_64"]
  memory_size      = 512
  # API Gateway gives up at 30 s, so there's no point running longer.
  timeout = 29

  environment {
    variables = merge(var.environment, {
      THREATLENS_ENVIRONMENT    = "prod"
      THREATLENS_AUTH_MODE      = "cognito"
      THREATLENS_AWS_REGION     = data.aws_region.current.region
      THREATLENS_AUTH_CLIENT_ID = var.cognito_client_id
      # Same origin as the web app (CloudFront /api), so no browser ever needs CORS.
      THREATLENS_CORS_ORIGINS = "[]"
    })
  }

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.function.name
  }

  depends_on = [aws_iam_role_policy.logs, aws_iam_role_policy.tracing]
}

# --- HTTP API --------------------------------------------------------------------------

resource "aws_apigatewayv2_api" "api" {
  name          = local.function_name
  protocol_type = "HTTP"
  # No cors_configuration: browsers reach the API through CloudFront on the site's origin.
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 30000
}

# Checked here first so bad tokens never cost a Lambda call, and again inside the app,
# which doesn't trust this (decision 26).
resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.api.id
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
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "GET /health"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_route" "everything_else" {
  api_id             = aws_apigatewayv2_api.api.id
  route_key          = "$default"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${local.function_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
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
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  # This API only, any stage and route.
  source_arn = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}
