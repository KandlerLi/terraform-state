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

# Read-only, account-wide visibility -- for ad-hoc verification (did a
# deploy actually work, what does this role/alarm/subscription look
# like) that julian's write-scoped policy below deliberately doesn't
# cover. AWS's own ViewOnlyAccess, not the broader ReadOnlyAccess: it
# grants List/Describe/Get on resource *configuration* everywhere, but
# deliberately excludes actions that return actual data (s3:GetObject,
# secretsmanager:GetSecretValue, dynamodb:GetItem, kms:Decrypt, etc.), so
# it can't be used to read Terraform state contents or secrets. Being
# read-only, it doesn't touch the self-escalation guarantee below --
# read access can reveal permissions, never grant them.
resource "aws_iam_user_policy_attachment" "julian_view_only" {
  user       = aws_iam_user.julian.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Scoped to exactly what running repo-infra locally needs, and nothing
# else -- deliberately excludes any IAM action over IAM users, groups,
# or this policy/user itself, and excludes any access to this root's own
# state (the "repo-infra/*" prefix only, never "terraform-state/*").
# julian never applies terraform-state itself; that stays root-only.
#
# Customer-managed policy (aws_iam_policy + a separate attachment
# below), not an inline aws_iam_user_policy -- found live 2026-09-09:
# adding the Secrets Manager statement below pushed this policy's JSON
# past AWS's hard 2048-byte cap on inline user policies (a fixed
# ceiling for that resource type, not something a quota increase can
# raise). A managed policy's own quota (6144 bytes) has real headroom
# for this policy to keep growing the way it already has.
resource "aws_iam_policy" "julian_terraform_operator" {
  name = "terraform-operator"

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
      {
        # The workspace's move off SOPS onto AWS Secrets Manager
        # (PARKED.md's "Secrets sprawl" item). julian's grant on every
        # secret container stays here -- the containers themselves are
        # migrating out to bootstrap/secrets-manager one at a time, but
        # the grant machinery does not follow them (it belongs next to
        # julian's other operator permissions, in one file). PutSecretValue
        # is included alongside the reads: julian edits/rotates these
        # values (aws secretsmanager put-secret-value), replacing the old
        # `sops <file>` flow -- an operator managing their own secrets
        # needs write, not just read.
        #
        # Two kinds of entry below: real resource references for the
        # containers still defined in this root's own secrets_manager.tf
        # (can't drift from what exists), and wildcard ARN strings for
        # the ones already migrated to bootstrap/secrets-manager (the
        # trailing -* covers the random suffix AWS appends). As each
        # container migrates, its line moves from the first group to the
        # second.
        Sid    = "ManageSecretsManagerSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
        ]
        Resource = [
          aws_secretsmanager_secret.home_infra_authelia.arn,
          aws_secretsmanager_secret.home_infra_nextcloud.arn,
          aws_secretsmanager_secret.home_infra_blocky.arn,
          aws_secretsmanager_secret.home_infra_github_runner.arn,

          # migrated to bootstrap/secrets-manager:
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/sankey-export-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/grafana-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/open-webui-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/home-agent-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/ingress-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/monitoring-*",
        ]
      },
    ]
  })
}

resource "aws_iam_user_policy_attachment" "julian_terraform_operator" {
  user       = aws_iam_user.julian.name
  policy_arn = aws_iam_policy.julian_terraform_operator.arn
}
