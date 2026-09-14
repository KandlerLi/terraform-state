# Shared CMK for CloudWatch Logs encryption across every AWS-deploying
# repo in this workspace -- account-wide security baseline, same category
# as this root's other shared resources (the state bucket, the operator
# identity). One key rather than one per repo, per an explicit choice
# (dyndns's own AWS-0017 trivy finding, 2026-09-14): a single ~$1/month
# base charge instead of one per repo that wants encrypted log groups.
resource "aws_kms_key" "logs" {
  description             = "Shared CMK for CloudWatch Logs encryption across this AWS account"
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
    ]
  })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/cloudwatch-logs"
  target_key_id = aws_kms_key.logs.key_id
}
