output "api_role_arn" {
  description = "The only principal allowed to send scan messages (queue policy, root module)."
  value       = aws_iam_role.function["api"].arn
}

output "function_names" {
  value = { for k, f in aws_lambda_function.function : k => f.function_name }
}
