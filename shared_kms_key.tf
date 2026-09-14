# Shared CMK for AWS-managed encryption across every resource in this
# account -- account-wide security baseline, same category as this root's
# other shared resources (the state bucket, the operator identity). One
# key rather than one per repo/service, per an explicit choice ("Could we
# for now use 1 KMS Key for all AWS resources?", 2026-09-14): a single
# ~$1/month base charge instead of one per repo/bucket/trail that wants
# encryption.
#
# The root statement below is what makes reuse across services possible
# without a service-principal grant for each one: S3 (bucket SSE-KMS) and
# CloudTrail's own kms_key_id both just need the *calling* IAM principal
# to have kms:GenerateDataKey*/kms:Decrypt/kms:DescribeKey via its own IAM
# policy, which a key policy granting the account root already allows --
# only CloudWatch Logs needs an explicit service-principal statement here
# (it authenticates as the logs.<region>.amazonaws.com service itself,
# not as whatever IAM principal owns the log group).
resource "aws_kms_key" "shared" {
  description             = "Shared CMK for AWS-managed encryption across this account"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        # CloudWatch Logs handles encryption transparently to whatever
        # role writes log events -- only this key policy grant is
        # needed, not any change to a log-writing role's own IAM policy.
        # Scoped to log groups in this account/region only, matching the
        # least-privilege pattern every other key/role in this workspace
        # follows.
        Sid    = "AllowCloudWatchLogs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      },
      {
        # CloudTrail's own required key-policy shape for kms_key_id
        # encryption, per AWS's documentation for this exact scenario --
        # CloudTrail authenticates as the cloudtrail.amazonaws.com
        # service, same reasoning as the CloudWatch Logs statement above.
        # Scoped to this account's own trail via the encryption context
        # condition, matching the account_baseline.tf trail's own ARN
        # pattern.
        Sid    = "AllowCloudTrailToEncryptLogs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:GenerateDataKey*"
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailToDescribeKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      },
      {
        # Whoever needs to read the delivered (encrypted) log files back
        # -- scoped the same way AWS's own docs scope it: any principal
        # in this account, but only for ciphertext produced under this
        # trail's own encryption context.
        Sid    = "AllowPrincipalsToDecryptLogFiles"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
        Action = [
          "kms:Decrypt",
          "kms:ReEncryptFrom",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:CallerAccount" = data.aws_caller_identity.current.account_id
          }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        # CloudFront's own required key-policy shape for an
        # OAC-protected S3 origin using SSE-KMS, per AWS's documentation
        # for this exact scenario (private-content-restricting-access-to-s3.html,
        # "SSE-KMS" section) -- fixes website's own AWS-0132. Scoped to
        # any CloudFront distribution in this account rather than one
        # specific distribution ARN: this key is deliberately shared
        # account-wide, so a future second distribution needing the same
        # grant is already covered without editing this file again.
        Sid    = "AllowCloudFrontServicePrincipalSSEKMS"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "AWS:SourceArn" = "arn:aws:cloudfront::${data.aws_caller_identity.current.account_id}:distribution/*"
          }
        }
      },
      {
        # CloudWatch Alarms' own required key-policy shape for
        # publishing to an SSE-KMS-encrypted SNS topic, per AWS's own
        # documentation for this exact scenario (sns-key-management.html,
        # "Enable compatibility between event sources from AWS services
        # and encrypted topics") -- fixes homeserver-health-check's own
        # AWS-0095. aws:SourceAccount scopes this to alarms in this
        # account specifically, the confused-deputy protection AWS's own
        # docs recommend for this grant. Scoped to any CloudWatch alarm
        # in this account rather than one specific alarm ARN, same
        # "shared account-wide key" reasoning as the CloudFront statement
        # above.
        Sid    = "AllowCloudWatchAlarmsToPublishToSNS"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
    ]
  })
}

resource "aws_kms_alias" "shared" {
  name          = "alias/shared"
  target_key_id = aws_kms_key.shared.key_id
}
