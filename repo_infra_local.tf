# Scripted identity for repo-infra's roll-out.sh: see README, "Scripted identities".

resource "aws_iam_user" "repo_infra_local" {
  name = "repo-infra-local"

  lifecycle {
    prevent_destroy = true
  }
}

#trivy:ignore:AVD-AWS-0123
resource "aws_iam_group" "repo_infra_local" {
  # Group for trivy AWS-0143; MFA can't apply to a static-key identity, so AWS-0123 is suppressed.
  name = "repo-infra-local"
}

# julian's operator policy minus AllowLocalDevelopmentSignIn and ViewOnlyAccess.
resource "aws_iam_group_policy" "repo_infra_local_terraform_operator" {
  name  = "terraform-operator"
  group = aws_iam_group.repo_infra_local.name

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
        Sid      = "ListRepoInfraState"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = local.state_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["repo-infra/*"]
          }
        }
      },
      {
        Sid      = "ReadWriteRepoInfraState"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${local.state_bucket_arn}/repo-infra/*"
      },
      {
        Sid    = "ManageGitHubOidcProvider"
        Effect = "Allow"
        Action = [
          "iam:CreateOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
      },
      {
        # Only modules/repo's deploy/plan role names, never "*".
        Sid    = "ManageRepoDeployRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:GetRole",
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:UpdateRoleDescription",
          "iam:UpdateAssumeRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:ListRoleTags",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*-github-actions",
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*-github-plan",
        ]
      },
      {
        # For aws_policies.tf's alias/shared lookup; no resource-level scoping.
        Sid      = "ListKmsAliases"
        Effect   = "Allow"
        Action   = "kms:ListAliases"
        Resource = "*"
      },
      {
        # Resolving the alias also calls DescribeKey.
        Sid      = "DescribeSharedKmsKey"
        Effect   = "Allow"
        Action   = "kms:DescribeKey"
        Resource = aws_kms_key.shared.arn
      },
    ]
  })
}

resource "aws_iam_group_membership" "repo_infra_local" {
  name  = "repo-infra-local-members"
  group = aws_iam_group.repo_infra_local.name
  users = [aws_iam_user.repo_infra_local.name]
}

variable "repo_infra_local_pgp_key" {
  description = <<-EOT
    Base64-encoded PGP public key (the raw binary export, NOT
    --armor'd -- confirmed live: aws_iam_access_key's pgp_key wants
    base64(binary key packet), and base64'ing the ASCII-armored text
    instead double-encodes it, failing with "openpgp: invalid data:
    tag byte does not have MSB set") used to encrypt this identity's
    access key secret at creation, so it never lands in Terraform
    state as plaintext (unlike julian's own OAuth session, this
    identity's static key has no expiry of its own -- worth the extra
    step). Reuses this workspace's existing pass/sops GPG key
    (6D8B16CB662983A54B4AF1466F0B5C2AB1509600), already used for
    KandlerLi/home-infra's own scripts/sync_secrets_to_pass.py:

        gpg --export 6D8B16CB662983A54B4AF1466F0B5C2AB1509600 | base64

    Pass the result via TF_VAR_repo_infra_local_pgp_key at apply time --
    never written to a file in this repo.
  EOT
  type        = string
  sensitive   = true
}

# No prevent_destroy: rotation is -replace. See README.
resource "aws_iam_access_key" "repo_infra_local" {
  user    = aws_iam_user.repo_infra_local.name
  pgp_key = var.repo_infra_local_pgp_key
}

output "repo_infra_local_access_key_id" {
  description = "Access key ID for repo-infra-local -- not sensitive on its own, an access key ID alone grants nothing without the matching secret."
  value       = aws_iam_access_key.repo_infra_local.id
}

output "repo_infra_local_encrypted_secret_access_key" {
  description = <<-EOT
    PGP-encrypted secret access key (base64). Decrypt once with:

        terraform output -raw repo_infra_local_encrypted_secret_access_key | base64 -d | gpg -d

    then store both this and repo_infra_local_access_key_id in pass --
    see README.md's own "repo-infra-local: initial setup and rotation"
    section for the exact commands.
  EOT
  value       = aws_iam_access_key.repo_infra_local.encrypted_secret
  sensitive   = true
}
