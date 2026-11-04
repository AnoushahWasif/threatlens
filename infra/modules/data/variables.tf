variable "name" {
  type = string
}

variable "worker_timeout_seconds" {
  description = "The worker Lambda's timeout; the queue's visibility timeout is 6x this."
  type        = number
}
