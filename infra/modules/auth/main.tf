resource "aws_cognito_user_pool" "users" {
  name                     = var.name
  deletion_protection      = "ACTIVE"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = "OPTIONAL"

  # No self sign-up: accounts are created by an admin. With sign-up open, anyone could make
  # throwaway accounts, each with its own caps and budgets (review of #18, decision 36).
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 12
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  software_token_mfa_configuration {
    enabled = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }
}

resource "aws_cognito_user_pool_domain" "hosted_ui" {
  domain       = var.domain_prefix
  user_pool_id = aws_cognito_user_pool.users.id
}

# The web app's client: public (a static site can't keep a secret), so authorization code
# with PKCE, which the web app already does (decision 29).
resource "aws_cognito_user_pool_client" "web" {
  name            = "${var.name}-web"
  user_pool_id    = aws_cognito_user_pool.users.id
  generate_secret = false

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["${var.site_url}/auth/callback"]
  logout_urls                          = ["${var.site_url}/"]

  # Only the hosted UI signs users in; no password or SRP flows straight against the API.
  explicit_auth_flows = ["ALLOW_REFRESH_TOKEN_AUTH"]

  # The web app keeps only the access token (one hour) and drops the refresh token, so the
  # refresh token is as short as Cognito allows.
  access_token_validity  = 60
  id_token_validity      = 60
  refresh_token_validity = 60
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "minutes"
  }
  auth_session_validity         = 3
  enable_token_revocation       = true
  prevent_user_existence_errors = "ENABLED"
}
