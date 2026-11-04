variable "name" {
  type = string
}

variable "domain_prefix" {
  description = "Hosted UI prefix: https://<prefix>.auth.<region>.amazoncognito.com. Globally unique."
  type        = string
}

variable "site_url" {
  description = "https://<cloudfront domain>, for the callback and logout URLs."
  type        = string
}
