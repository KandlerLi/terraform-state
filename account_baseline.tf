# Account-wide baseline: see README, "Account Baseline Security Hardening".

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "jkandler-cloudtrail-logs"
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning needs its own noncurrent-version expiration, see the lifecycle rule below.
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.shared.arn
    }
  }
}

# Self-logging under a distinct prefix (trivy AWS-0089/0163), no separate log bucket.
resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket        = aws_s3_bucket.cloudtrail_logs.id
  target_bucket = aws_s3_bucket.cloudtrail_logs.id
  target_prefix = "access-logs/"
}

# For investigation, not audit retention: 365 days, noncurrent versions included.
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# AWS's required shape, scoped to this account's trail via SourceArn.
data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/account-baseline"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/account-baseline"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

# CloudWatch Logs delivery too (trivy AWS-0162), encrypted with the shared CMK.
resource "aws_cloudwatch_log_group" "account_baseline" {
  name              = "/aws/cloudtrail/account-baseline"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.shared.arn
}

resource "aws_iam_role" "cloudtrail_cloudwatch_logs" {
  name = "cloudtrail-cloudwatch-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "cloudtrail.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_logs" {
  name = "deliver-to-cloudwatch-logs"
  role = aws_iam_role.cloudtrail_cloudwatch_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteCloudTrailLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.account_baseline.arn}:*"
      },
    ]
  })
}

# Explicit depends_on: CloudTrail checks bucket write access at creation time.
resource "aws_cloudtrail" "account_baseline" {
  name                          = "account-baseline"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  # Trail delivery itself encrypted with the shared CMK (trivy AWS-0015).
  kms_key_id = aws_kms_key.shared.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.account_baseline.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_logs.arn

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch_logs,
  ]
}

resource "aws_accessanalyzer_analyzer" "account_baseline" {
  analyzer_name = "account-baseline"
  type          = "ACCOUNT"
}

resource "aws_s3_account_public_access_block" "account_baseline" {
  account_id = data.aws_caller_identity.current.account_id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
