# A second, narrower identity for the same repo-infra local-apply
# use case julian's own operator.tf already covers -- but this one for
# scripted, non-interactive use (infra/github-repo-infra's own
# scripts/roll-out.sh) instead of julian's own MFA-backed, browser-OAuth
# `aws login` flow (ADR 0018). Kept deliberately separate from julian
# rather than giving julian a static key of its own: ADR 0018's own
# "neither should flow through an agent session or get written
# anywhere, committed or not" principle was specifically about julian's
# own credential shape, chosen for exactly this reason -- this identity
# is the accepted, scoped exception to that for one narrow purpose,
# not a reason to weaken julian's own guarantee.
#
# Same self-escalation guarantee julian's own resources rely on: this
# identity's policy grants it no IAM action over IAM users, groups, or
# itself, and this file lives in the same root julian has zero access
# to (see operator.tf's own header comment for why that placement is
# what makes the guarantee hold at all) -- so this identity can never
# widen its own access, same as julian can't widen its.

resource "aws_iam_user" "repo_infra_local" {
  name = "repo-infra-local"

  lifecycle {
    prevent_destroy = true
  }
}

# Copied from julian's own terraform-operator policy in operator.tf,
# minus two things this identity doesn't need: AllowLocalDevelopmentSignIn
# (that's specifically for `aws login`'s browser OAuth exchange -- this
# identity only ever authenticates via static AWS_ACCESS_KEY_ID/
# AWS_SECRET_ACCESS_KEY, never signs in interactively) and ViewOnlyAccess
# (that's for julian's own ad-hoc human investigation across the whole
# account -- this identity only ever runs a scripted plan/apply against
# repo-infra specifically, nothing broader).
resource "aws_iam_user_policy" "repo_infra_local_terraform_operator" {
  name = "terraform-operator"
  user = aws_iam_user.repo_infra_local.name

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
        # Same naming-convention scoping as julian's own identical
        # statement -- this identity can manage per-repo CI roles but no
        # other IAM principal (including itself).
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
    ]
  })
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
    infra/home-infra's own scripts/sync_secrets_to_pass.py:

        gpg --export 6D8B16CB662983A54B4AF1466F0B5C2AB1509600 | base64

    Pass the result via TF_VAR_repo_infra_local_pgp_key at apply time --
    never written to a file in this repo.
  EOT
  type        = string
  sensitive   = true
}

# terraform apply -replace=aws_iam_access_key.repo_infra_local, then
# repeat the decrypt-and-store step in README.md, rotates this -- no
# automated reminder yet (see PARKED.md in the workspace root), just a
# documented manual procedure with a recommended cadence.
#
# Deliberately NO prevent_destroy here, unlike the user above --
# confirmed live: it directly blocks that exact rotation command (and
# blocked recovering from a first apply attempt's own tainted state
# after an unrelated pgp_key-format error). This resource is designed
# to be replaced; only the identity it belongs to needs protecting.
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
