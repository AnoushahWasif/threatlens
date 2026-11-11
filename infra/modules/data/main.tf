data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account = data.aws_caller_identity.current.account_id
  region  = data.aws_region.current.region
}

# --- one customer-managed key for everything stored -------------------------------------

data "aws_iam_policy_document" "key" {
  # The account administers the key through IAM; who may use it is decided by each
  # role's own policy (kms:ViaService keeps those to the one service).
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account}:root"]
    }
  }

  # CloudWatch Logs encrypts log groups itself, so it needs the key directly, and only for
  # this account's log groups.
  statement {
    sid = "CloudWatchLogs"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${local.region}:${local.account}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "data" {
  description             = "${var.name}: table, uploads, queue, secret and logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.name}-data"
  target_key_id = aws_kms_key.data.key_id
}

# --- DynamoDB (layout in docs/ARCHITECTURE.md) --------------------------------------------

resource "aws_dynamodb_table" "main" {
  name                        = var.name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }
  attribute {
    name = "sk"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }
}

# --- uploads and findings -----------------------------------------------------------------

resource "aws_s3_bucket" "uploads" {
  bucket_prefix = "${var.name}-uploads-"
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    # One KMS call per bucket key rather than per object: same protection, far fewer
    # (billed) KMS requests.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  # A scan reads its upload within minutes. After a week the file is only a customer's
  # dependency list sitting around, including uploads whose scan record never got written.
  rule {
    id     = "uploads-expire"
    status = "Enabled"
    filter {
      prefix = "uploads/"
    }
    expiration {
      days = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  # Same for a GitHub scan's lockfiles: the repo itself is the lasting copy.
  rule {
    id     = "snapshots-expire"
    status = "Enabled"
    filter {
      prefix = "snapshots/"
    }
    expiration {
      days = 7
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  # Findings files are kept (the newest scan's is what the web app shows); overwritten or
  # deleted versions go after a month.
  rule {
    id     = "findings-old-versions"
    status = "Enabled"
    filter {
      prefix = "findings/"
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "abort-incomplete"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

data "aws_iam_policy_document" "uploads" {
  statement {
    sid       = "HttpsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  # Every object must be written with this key. The app asks for KMS on each put (scans.py).
  statement {
    sid       = "OnlyOurKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.data.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads" {
  bucket     = aws_s3_bucket.uploads.id
  policy     = data.aws_iam_policy_document.uploads.json
  depends_on = [aws_s3_bucket_public_access_block.uploads]
}

# --- scan queue ---------------------------------------------------------------------------

resource "aws_sqs_queue" "scans_dead" {
  name                      = "${var.name}-scans-dead"
  kms_master_key_id         = aws_kms_key.data.arn
  message_retention_seconds = 1209600 # 14 days, the maximum, to look at what failed
}

resource "aws_sqs_queue" "scans" {
  name              = "${var.name}-scans"
  kms_master_key_id = aws_kms_key.data.arn
  # AWS advises at least 6x the consumer's timeout. It also has to outlast SCAN_TIMEOUT
  # (worker.py, 15 min), or a live scan's message comes back and gets a twin.
  visibility_timeout_seconds = var.worker_timeout_seconds * 6
  message_retention_seconds  = 86400
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.scans_dead.arn
    # The worker gives up after 3 attempts by itself; this catches crashes it never saw.
    maxReceiveCount = 5
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "scans_dead" {
  queue_url = aws_sqs_queue.scans_dead.id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.scans.arn]
  })
}

# --- the LLM API key ------------------------------------------------------------------------

# Only the container. The value is put in by hand (aws secretsmanager put-secret-value), so
# it never passes through Terraform state or this repo.
resource "aws_secretsmanager_secret" "llm_key" {
  name                    = "${var.name}/llm-api-key"
  description             = "Anthropic API key for threat-model drafting"
  kms_key_id              = aws_kms_key.data.arn
  recovery_window_in_days = 7
}
