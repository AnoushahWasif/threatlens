data "aws_region" "current" {}

output "user_pool_id" {
  value = aws_cognito_user_pool.users.id
}

output "issuer" {
  value = "https://cognito-idp.${data.aws_region.current.region}.amazonaws.com/${aws_cognito_user_pool.users.id}"
}

output "client_id" {
  value = aws_cognito_user_pool_client.web.id
}

output "hosted_ui" {
  value = "https://${aws_cognito_user_pool_domain.hosted_ui.domain}.auth.${data.aws_region.current.region}.amazoncognito.com"
}
