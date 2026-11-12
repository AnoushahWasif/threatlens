output "kms_key_arn" {
  value = aws_kms_key.data.arn
}

output "table_name" {
  value = aws_dynamodb_table.main.name
}

output "table_arn" {
  value = aws_dynamodb_table.main.arn
}

output "uploads_bucket" {
  value = aws_s3_bucket.uploads.bucket
}

output "uploads_bucket_arn" {
  value = aws_s3_bucket.uploads.arn
}

output "queue_url" {
  value = aws_sqs_queue.scans.id
}

output "queue_arn" {
  value = aws_sqs_queue.scans.arn
}

output "queue_name" {
  value = aws_sqs_queue.scans.name
}

output "dead_letter_queue_name" {
  value = aws_sqs_queue.scans_dead.name
}

output "dead_letter_queue_arn" {
  value = aws_sqs_queue.scans_dead.arn
}

output "llm_secret_arn" {
  value = aws_secretsmanager_secret.llm_key.arn
}
