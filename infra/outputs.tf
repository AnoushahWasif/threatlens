output "web_url" {
  description = "The site. The API is under /api on the same origin."
  value       = "https://${module.web.domain}"
}

output "web_bucket" {
  description = "Where the deploy uploads apps/web/out."
  value       = module.web.bucket
}

output "web_distribution_id" {
  description = "For cache invalidation after a deploy."
  value       = module.web.distribution_id
}

output "functions" {
  value = module.api.function_names
}

output "llm_secret_arn" {
  description = "Put the key in by hand: aws secretsmanager put-secret-value --secret-id <this>."
  value       = module.data.llm_secret_arn
}

output "web_build_env" {
  description = "Values the web build needs (NEXT_PUBLIC_*). None of them is secret."
  value = {
    NEXT_PUBLIC_API_URL           = "/api"
    NEXT_PUBLIC_AUTH_MODE         = "cognito"
    NEXT_PUBLIC_COGNITO_DOMAIN    = module.auth.hosted_ui
    NEXT_PUBLIC_COGNITO_CLIENT_ID = module.auth.client_id
  }
}
