terraform {
  required_version = ">= 1.16.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.68.0"
    }
  }

  # State lives in S3 with a lock file. The bucket and key are passed at `terraform init`
  # by the deploy pipeline (day 17), so no account details are committed here.
  backend "s3" {
    use_lockfile = true
    encrypt      = true
  }
}
