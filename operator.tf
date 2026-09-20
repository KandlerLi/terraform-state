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

resource "aws_iam_group" "julian" {
  # Fixes trivy's AWS-0143 (policies attached directly to a user) --
  # covers both policy attachments below, moved from user- to
  # group-scoped attachments with julian as this group's only member.
  name = "julian"
}

resource "aws_iam_group_membership" "julian" {
  name  = "julian-members"
  group = aws_iam_group.julian.name
  users = [aws_iam_user.julian.name]
}

# Fixes trivy's AWS-0123 for real (not suppressed) -- the console
# sign-in + MFA device README.md's own "Enabling console sign-in and MFA
# for julian" section walks through are confirmed set up and working
# (2026-09-14), so this is no longer deferred pending that confirmation.
#
# A separate inline group policy rather than folded into
# julian_terraform_operator above, deliberately: this is a DENY that
# affects nearly every action, fundamentally different in kind from the
# ALLOW statements everything else here grants, and keeping it separate
# means it can be detached in one step (one resource to remove) if it
# ever needs to be rolled back, without touching julian's actual
# permission grants at all.
#
# Follows AWS's own documented pattern for this exact scenario
# (reference_policies_examples_iam_mfa-selfmanage.html) -- BoolIfExists
# rather than Bool, since aws:MultiFactorAuthPresent is simply absent
# (not false) on a request that never authenticated with MFA at all, and
# Bool can't evaluate a condition key that isn't present.
#
# NotAction here has two additions beyond AWS's own standard example,
# both required for julian's own sign-in mechanism specifically (a
# browser OAuth exchange via `aws login`, not the classic console-
# password + GetSessionToken flow that example targets):
# signin:AuthorizeOAuth2Access/CreateOAuth2Token -- the exchange that
# *establishes* an MFA-backed session in the first place. Without these
# exempted, this statement would deny the very sign-in call that
# produces the MFA-authenticated session, permanently locking julian out
# with no way back in except as root. sts:GetCallerIdentity is exempted
# too, as a harmless read-only escape hatch for diagnosing exactly this
# kind of problem if it ever comes up again.
resource "aws_iam_group_policy" "julian_require_mfa" {
  name  = "require-mfa"
  group = aws_iam_group.julian.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BlockMostAccessUnlessSignedInWithMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ListMFADevices",
          "iam:ListUsers",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "signin:AuthorizeOAuth2Access",
          "signin:CreateOAuth2Token",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
    ]
  })
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
resource "aws_iam_group_policy_attachment" "julian_view_only" {
  group      = aws_iam_group.julian.name
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
        # migrating out to aws/secrets-manager one at a time, but
        # the grant machinery does not follow them (it belongs next to
        # julian's other operator permissions, in one file). PutSecretValue
        # is included alongside the reads: julian edits/rotates these
        # values (aws secretsmanager put-secret-value), replacing the old
        # `sops <file>` flow -- an operator managing their own secrets
        # needs write, not just read.
        #
        # Every group has now migrated to aws/secrets-manager
        # (home-infra/authelia, 2026-09-12, was the last) -- every entry
        # below is a wildcard ARN string (the trailing -* covers the
        # random suffix AWS appends), not a real resource reference,
        # since secrets_manager.tf no longer defines any of these
        # containers itself. This whole statement is a candidate for
        # the campaign's final sweep: deleting secrets_manager.tf's
        # `removed` blocks doesn't require deleting this grant (julian
        # still needs read/write on these secrets regardless of which
        # repo owns the container), so it stays as-is even once that
        # cleanup happens.
        Sid    = "ManageSecretsManagerSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
        ]
        Resource = [
          # migrated to aws/secrets-manager:
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/sankey-export-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/grafana-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/open-webui-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/home-agent-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/ingress-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/monitoring-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/nextcloud-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/github-runner-*",

          # dyndns/fritzbox is different from every entry above: it was
          # never a real resource reference in this file at all -- its
          # container was created directly in aws/dyndns (a real
          # CI/PR-gated repo, not this root's own secrets_manager.tf),
          # so julian never had an explicit grant on it until this
          # migration added one. Migrated to aws/secrets-manager
          # 2026-09-12 the same way as everything else, just arriving
          # here for the first time rather than moving from the first
          # group.
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:dyndns/fritzbox-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/blocky-*",

          # A genuinely new secret, not a migration -- split out of
          # home-infra/home-agent 2026-09-12 (see
          # aws/secrets-manager's own module for why).
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/ghcr-pull-token-*",

          # home-infra/authelia: the last group in the campaign, migrated
          # to aws/secrets-manager 2026-09-12.
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/authelia-*",

          # k3s-apps/bulwark: a genuinely new secret, not a migration --
          # Bulwark webmail's own Authelia OIDC client secret (plaintext
          # half; home-infra/authelia holds the matching hash).
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/bulwark-*",
        ]
      },
    ]
  })
}

resource "aws_iam_group_policy_attachment" "julian_terraform_operator" {
  group      = aws_iam_group.julian.name
  policy_arn = aws_iam_policy.julian_terraform_operator.arn
}
