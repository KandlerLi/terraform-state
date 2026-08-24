# The operator IAM identity used to run repo-infra locally, replacing
# routine use of the AWS root user for that work (ADR 0018). Lives here,
# not in repo-infra itself, and not in a separate root: this root and
# repo-infra are the only two Terraform roots ever applied locally, and
# both already require a trusted human identity rather than a CI role.
# terraform-state in particular is applied rarely -- essentially once,
# at bootstrap -- exactly the same cadence and trust level this identity
# management needs, so a third barely-touched root just for this would
# be pure overhead. Keeping it out of repo-infra specifically matters:
# julian's policy below grants it no access to *this* root's own state,
# so repo-infra's own day-to-day plans (even for something unrelated,
# like adding a new repository to config.yml) never risk trying to
# refresh these identity resources under julian's own restricted
# credentials.
#
# This root is applied only as root (or another identity already
# holding admin-equivalent access) -- never as julian. That's what makes
# the guarantee below hold: julian can never widen its own permissions,
# because the resources managing julian's own identity live somewhere
# julian has no access to.

data "aws_caller_identity" "current" {}

locals {
  state_bucket_arn = aws_s3_bucket.terraform_state.arn
}

# Brings the pre-existing IAM user `julian` (created 2021, previously
# managed only by hand) under Terraform.
import {
  to = aws_iam_user.julian
  id = "julian"
}

resource "aws_iam_user" "julian" {
  name = "julian"

  lifecycle {
    prevent_destroy = true
  }
}

# AdministratorAccess was imported here, verified alongside the scoped
# policy below via real repo-infra plans under julian (both a clean
# refresh and a clean "no changes" plan), and detached on 2026-08-23 --
# see ADR 0018 and this root's README for the two-apply sequence this
# came from.

# Scoped to exactly what running repo-infra locally needs, and nothing
# else -- deliberately excludes any IAM action over IAM users, groups,
# or this policy/user itself, and excludes any access to this root's own
# state (the "repo-infra/*" prefix only, never "terraform-state/*").
# julian never applies terraform-state itself; that stays root-only.
resource "aws_iam_user_policy" "julian_terraform_operator" {
  name = "terraform-operator"
  user = aws_iam_user.julian.name

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
        # `aws login`'s browser-based OAuth flow for IAM users (as
        # opposed to root, which bypasses IAM policy checks entirely)
        # needs these two actions -- normally granted via AWS's own
        # SignInLocalDevelopmentAccess managed policy. Found live: without
        # this, `aws login` as julian failed at token exchange with a 400
        # the moment AdministratorAccess was detached, since logging in as
        # julian at all turned out to be a prerequisite this policy had
        # overlooked, not something "running repo-infra needs" already
        # covered implicitly.
        Sid      = "AllowLocalDevelopmentSignIn"
        Effect   = "Allow"
        Action   = ["signin:AuthorizeOAuth2Access", "signin:CreateOAuth2Token"]
        Resource = "arn:aws:signin:*:*:oauth2/public-client/*"
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
        # Scoped to modules/repo's exact naming convention for every
        # repository's own deploy/plan roles -- never a bare "*", so this
        # identity can manage per-repo CI roles but no other IAM
        # principal (including itself).
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
