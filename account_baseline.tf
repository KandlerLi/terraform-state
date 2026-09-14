# Account-wide baseline security hardening (PARKED.md, came up
# 2026-08-31 while diagnosing an unrelated flaky dyndns PR check that
# surfaced this as a general account-hygiene gap, not tied to that
# incident). Lives here, not in a new root or in repo-infra: these are
# account-wide, essentially-set-once settings with no natural
# per-repository owner -- repo-infra covers per-repository GitHub/AWS
# deploy-role config, this root already covers the state bucket and the
# julian operator identity, so it's the natural home for "owns
# account-wide baseline settings" too, applied at the same root-only
# cadence and trust level (see this root's own README: applying here
# always needs the AWS root identity, never julian).
#
# Deliberately excludes GuardDuty, AWS Config, and Security Hub: real
# ongoing cost, disproportionate to this account's own $10/month budget
# (aws-budget), and largely redundant with everything already going
# through Terraform -- there's no untracked drift for them to catch.
# Root account MFA isn't here either -- no Terraform resource exists for
# a login profile or MFA device, so it has to stay a one-time manual
# console check (IAM -> Users -> julian's own account root user security
# credentials).

# One trail covering management events, all regions -- free from
# CloudTrail itself; the only ongoing cost is S3 storage for the log
# files, fractions of a cent/month at this account's actual event
# volume. The lifecycle rule below keeps that true indefinitely rather
# than letting logs accumulate forever.
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

# Fixes trivy's AWS-0090 (bucket versioning) and AWS-0132 (bucket should
# use a CMK, not the default AES256) together with the encryption
# resource below -- versioning needs its own noncurrent-version
# expiration rule (added to the lifecycle configuration below) since the
# existing 365-day rule only ever covered the current version.
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

# Fixes trivy's AWS-0089/AWS-0163 (bucket access logging) -- this bucket
# logs to itself under a distinct prefix rather than a separate dedicated
# logging-target bucket. AWS explicitly supports this; a second bucket
# for access logs this rarely read would be pure overhead at this
# account's actual scale (same "fractions of a cent/month" cost
# reasoning as the lifecycle rule below).
resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket        = aws_s3_bucket.cloudtrail_logs.id
  target_bucket = aws_s3_bucket.cloudtrail_logs.id
  target_prefix = "access-logs/"
}

# These logs are for after-the-fact investigation, not long-term audit
# retention -- expire them well before their storage cost could ever
# become noticeable. noncurrent_version_expiration added alongside
# versioning above, or noncurrent versions from S3's own access-log
# writes and CloudTrail's log deliveries would accumulate forever
# instead of following the same 365-day intent as the current version.
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

# CloudTrail's own required trust policy for the bucket it logs to --
# the exact shape AWS documents, scoped to this account's own trail ARN
# via the SourceArn condition on both statements so no other account's
# CloudTrail could ever write here.
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

# Fixes trivy's AWS-0162 -- CloudTrail should deliver to CloudWatch Logs
# in addition to S3, not only S3. Low added ingestion cost at this
# account's actual management-event volume, same cost reasoning as
# everything else in this file. Encrypted with the same shared CMK as
# every other log group in this workspace.
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

# The trail itself. Needs the bucket policy above to already exist --
# CloudTrail validates write access to the bucket at creation time --
# hence the explicit depends_on rather than relying on the implicit
# resource-attribute dependency alone. Same reasoning extends to the
# CloudWatch Logs delivery role's own policy.
resource "aws_cloudtrail" "account_baseline" {
  name                          = "account-baseline"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  # Fixes trivy's AWS-0015 -- CloudTrail's own log delivery encrypted
  # with the shared CMK, not just relying on the destination bucket's
  # own (also now CMK-encrypted) default encryption.
  kms_key_id = aws_kms_key.shared.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.account_baseline.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_logs.arn

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs,
    aws_iam_role_policy.cloudtrail_cloudwatch_logs,
  ]
}

# Flags any IAM user, role, or S3 bucket reachable from outside this
# account (the traefik-acme-dns01/ses-relay-smtp users included) --
# zero cost, purely account-wide analysis with no resource of its own
# to store data in.
resource "aws_accessanalyzer_analyzer" "account_baseline" {
  analyzer_name = "account-baseline"
  type          = "ACCOUNT"
}

# A blanket safety net on top of whatever each individual bucket's own
# aws_s3_bucket_public_access_block already does (this root's own
# terraform_state and cloudtrail_logs buckets included) -- account-wide,
# so a future bucket created without its own explicit block still can't
# be made public by accident.
resource "aws_s3_account_public_access_block" "account_baseline" {
  account_id = data.aws_caller_identity.current.account_id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
