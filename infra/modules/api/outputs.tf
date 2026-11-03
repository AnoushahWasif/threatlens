output "domain" {
  description = "execute-api host name, the CloudFront origin for /api."
  value       = replace(aws_apigatewayv2_api.api.api_endpoint, "https://", "")
}

output "function_name" {
  value = aws_lambda_function.api.function_name
}
