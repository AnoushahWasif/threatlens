data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account   = data.aws_caller_identity.current.account_id
  region    = data.aws_region.current.region
  namespace = "ThreatLens"

  # Counted from the JSON log lines (decision 73). Everything else uses AWS's own metrics,
  # which cost nothing extra.
  log_metrics = {
    UnhandledErrors    = { log = "api", message = "unhandled error" }
    ScanAttemptsFailed = { log = "worker", message = "scan attempt failed" }
    ScansFailed        = { log = "worker", message = "scan failed" }
    ScansDone          = { log = "worker", message = "scan done" }
  }

  # 8 alarms, inside CloudWatch's 10 free ones. Each one is something to act on; "scan
  # failed" isn't alarmed, since a bad file or a missing repo is the user's, not ours.
  # All entries have the same shape, so for_each sees one map type.
  aws_alarms = merge(
    {
      api-5xx = {
        about     = "The API answered with 5 or more server errors in 5 minutes."
        namespace = "AWS/ApiGateway"
        metric    = "5xx"
        dimension = ["ApiId", var.api_id]
        stat      = "Sum"
        period    = 300
        periods   = 1
        threshold = 5
      }
      api-latency = {
        about     = "The API's p95 latency stayed above ${var.latency_p95_ms} ms for 15 minutes."
        namespace = "AWS/ApiGateway"
        metric    = "Latency"
        dimension = ["ApiId", var.api_id]
        stat      = "p95"
        period    = 300
        periods   = 3
        threshold = var.latency_p95_ms
      }
      dead-letters = {
        about     = "A scan message reached the dead-letter queue: the worker crashed on it 5 times."
        namespace = "AWS/SQS"
        metric    = "ApproximateNumberOfMessagesVisible"
        dimension = ["QueueName", var.dead_letter_queue_name]
        stat      = "Maximum"
        period    = 300
        periods   = 1
        threshold = 1
      }
      # A retry waits out the queue's 1 hour visibility timeout, so 2 retries are ~2 hours.
      scans-stuck = {
        about     = "A scan message has waited over 3 hours: the worker isn't taking scans."
        namespace = "AWS/SQS"
        metric    = "ApproximateAgeOfOldestMessage"
        dimension = ["QueueName", var.queue_name]
        stat      = "Maximum"
        period    = 300
        periods   = 1
        threshold = 10800
      }
    },
    {
      for role, fn in var.function_names : "${role}-errors" => {
        about     = "The ${role} Lambda crashed or timed out."
        namespace = "AWS/Lambda"
        metric    = "Errors"
        dimension = ["FunctionName", fn]
        stat      = "Sum"
        period    = 300
        periods   = 1
        threshold = 1
      }
    },
  )

  # From the log metrics above, which have no dimensions.
  log_alarms = {
    unhandled-errors = {
      about     = "The API hit an error it doesn't handle (logged as 'unhandled error')."
      metric    = "UnhandledErrors"
      period    = 300
      threshold = 1
    }
    scan-attempts-failing = {
      about     = "3 or more scan attempts failed in 15 minutes: OSV, EPSS, GitHub or storage trouble."
      metric    = "ScanAttemptsFailed"
      period    = 900
      threshold = 3
    }
  }
}

# --- where alarms go ------------------------------------------------------------------------

resource "aws_sns_topic" "alarms" {
  name              = "${var.name}-alarms"
  kms_master_key_id = var.kms_key_arn
}

data "aws_iam_policy_document" "alarms" {
  statement {
    sid       = "OurAlarmsPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alarms.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudwatch:${local.region}:${local.account}:alarm:${var.name}-*"]
    }
  }
  statement {
    sid       = "HttpsOnly"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alarms.arn]
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
}

resource "aws_sns_topic_policy" "alarms" {
  arn    = aws_sns_topic.alarms.arn
  policy = data.aws_iam_policy_document.alarms.json
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# --- metrics from the logs -------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "log" {
  for_each       = local.log_metrics
  name           = "${var.name}-${each.key}"
  log_group_name = var.log_group_names[each.value.log]
  pattern        = "{ $.message = \"${each.value.message}\" }"

  metric_transformation {
    name      = each.key
    namespace = local.namespace
    value     = "1"
    unit      = "Count"
  }
}

# --- alarms ----------------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "aws" {
  for_each            = local.aws_alarms
  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.about
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  dimensions          = { (each.value.dimension[0]) = each.value.dimension[1] }
  statistic           = startswith(each.value.stat, "p") ? null : each.value.stat
  extended_statistic  = startswith(each.value.stat, "p") ? each.value.stat : null
  period              = each.value.period
  evaluation_periods  = each.value.periods
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"

  # No data means no requests or no scans, which is fine.
  treat_missing_data = "notBreaching"
  alarm_actions      = [aws_sns_topic.alarms.arn]
  ok_actions         = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "log" {
  for_each            = local.log_alarms
  alarm_name          = "${var.name}-${each.key}"
  alarm_description   = each.value.about
  namespace           = local.namespace
  metric_name         = each.value.metric
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alarms.arn]
  ok_actions          = [aws_sns_topic.alarms.arn]

  depends_on = [aws_cloudwatch_log_metric_filter.log]
}

# --- one dashboard (3 are free) --------------------------------------------------------------

locals {
  api_dims = ["ApiId", var.api_id]

  widget = {
    type   = "metric"
    width  = 12
    height = 6
  }
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = var.name
  dashboard_body = jsonencode({
    widgets = [
      merge(local.widget, {
        properties = {
          title  = "API requests and errors"
          region = local.region
          stat   = "Sum"
          period = 300

          metrics = [
            concat(["AWS/ApiGateway", "Count"], local.api_dims),
            concat(["AWS/ApiGateway", "4xx"], local.api_dims),
            concat(["AWS/ApiGateway", "5xx"], local.api_dims),
            [local.namespace, "UnhandledErrors"],
          ]
        }
      }),
      merge(local.widget, {
        properties = {
          title  = "API latency (ms)"
          region = local.region
          period = 300

          metrics = [
            concat(["AWS/ApiGateway", "Latency"], local.api_dims, [{ stat = "p50" }]),
            concat(["AWS/ApiGateway", "Latency"], local.api_dims, [{ stat = "p95" }]),
          ]

          annotations = { horizontal = [{ label = "alarm", value = var.latency_p95_ms }] }
        }
      }),
      merge(local.widget, {
        properties = {
          title  = "Scans"
          region = local.region
          stat   = "Sum"
          period = 3600

          metrics = [
            [local.namespace, "ScansDone"],
            [local.namespace, "ScansFailed"],
            [local.namespace, "ScanAttemptsFailed"],
          ]
        }
      }),
      merge(local.widget, {
        properties = {
          title  = "Scan queue"
          region = local.region
          stat   = "Maximum"
          period = 300

          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.queue_name],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.dead_letter_queue_name],
            ["AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName", var.queue_name, { yAxis = "right" }],
          ]
        }
      }),
      merge(local.widget, {
        properties = {
          title  = "Lambda errors, throttles and p95 duration (ms)"
          region = local.region
          period = 300

          # concat, not flatten: flatten would also flatten each metric's own array.
          metrics = concat([
            for role, fn in var.function_names : [
              ["AWS/Lambda", "Errors", "FunctionName", fn, { stat = "Sum", label = "${role} errors" }],
              ["AWS/Lambda", "Throttles", "FunctionName", fn, { stat = "Sum", label = "${role} throttles" }],
              ["AWS/Lambda", "Duration", "FunctionName", fn, { stat = "p95", label = "${role} p95", yAxis = "right" }],
            ]
          ]...)
        }
      }),
      {
        type   = "log"
        width  = 12
        height = 6

        properties = {
          title  = "Latest errors"
          region = local.region
          view   = "table"
          query  = "SOURCE '${var.log_group_names["api"]}' | SOURCE '${var.log_group_names["worker"]}' | fields @timestamp, message, error, route, scan_id, request_id | filter level = 'ERROR' | sort @timestamp desc | limit 20"
        }
      },
    ]
  })
}
