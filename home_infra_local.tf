# Scripted identity for home-infra's Ansible secret lookups: see README, "Scripted identities".

resource "aws_iam_user" "home_infra_local" {
  name = "home-infra-local"

  lifecycle {
    prevent_destroy = true
  }
}

#trivy:ignore:AVD-AWS-0123
resource "aws_iam_group" "home_infra_local" {
  # Group for trivy AWS-0143; MFA can't apply to a static-key identity, so AWS-0123 is suppressed.
  name = "home-infra-local"
}

resource "aws_iam_group_policy" "home_infra_local_read_secrets" {
  name  = "read-secrets"
  group = aws_iam_group.home_infra_local.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "IdentifyAccount"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
      {
        # Read-only: only julian edits or rotates these values.
        Sid    = "ReadHomeInfraSecrets"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/monitoring-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/nextcloud-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/prometheus-*",
        ]
      },
    ]
  })
}

resource "aws_iam_group_membership" "home_infra_local" {
  name  = "home-infra-local-members"
  group = aws_iam_group.home_infra_local.name
  users = [aws_iam_user.home_infra_local.name]
}

variable "home_infra_local_pgp_key" {
  description = <<-EOT
    Base64-encoded PGP public key (the raw binary export, NOT
    --armor'd -- see repo_infra_local_pgp_key's own description for
    why that distinction matters, confirmed live). Reuses this
    workspace's existing pass/sops GPG key
    (6D8B16CB662983A54B4AF1466F0B5C2AB1509600):

        gpg --export 6D8B16CB662983A54B4AF1466F0B5C2AB1509600 | base64

    Pass the result via TF_VAR_home_infra_local_pgp_key at apply time
    -- never written to a file in this repo.
  EOT
  type        = string
  sensitive   = true
}

# No prevent_destroy: rotation is -replace. See README.
resource "aws_iam_access_key" "home_infra_local" {
  user    = aws_iam_user.home_infra_local.name
  pgp_key = var.home_infra_local_pgp_key
}

output "home_infra_local_access_key_id" {
  description = "Access key ID for home-infra-local -- not sensitive on its own, an access key ID alone grants nothing without the matching secret."
  value       = aws_iam_access_key.home_infra_local.id
}

output "home_infra_local_encrypted_secret_access_key" {
  description = <<-EOT
    PGP-encrypted secret access key (base64). Decrypt once with:

        terraform output -raw home_infra_local_encrypted_secret_access_key | base64 -d | gpg -d

    then store both this and home_infra_local_access_key_id in pass --
    see README.md's own "home-infra-local Identity" section for the
    exact commands.
  EOT
  value       = aws_iam_access_key.home_infra_local.encrypted_secret
  sensitive   = true
}
