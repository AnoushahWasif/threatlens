variable "name" {
  type = string
}

variable "alarm_email" {
  description = "Where alarms are emailed. The address has to confirm the subscription once."
  type        = string
}

variable "kms_key_arn" {
  description = "Encrypts the alarm topic."
  type        = string
}

variable "api_id" {
  type = string
}

variable "function_names" {
  description = "Lambda function names by role: api, worker."
  type        = map(string)
}

variable "log_group_names" {
  description = "Lambda log group names by role: api, worker."
  type        = map(string)
}

variable "queue_name" {
  type = string
}

variable "dead_letter_queue_name" {
  type = string
}

variable "latency_p95_ms" {
  description = "Alarm when the API's 95th percentile latency stays above this."
  type        = number
  default     = 3000
}
