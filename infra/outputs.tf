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

output "api_function" {
  value = module.api.function_name
}
