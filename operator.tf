# julian, the operator identity for local repo-infra applies: see README. This root is applied as root, never as julian.

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
  # Group for trivy AWS-0143; julian is its only member.
  name = "julian"
}

resource "aws_iam_group_membership" "julian" {
  name  = "julian-members"
  group = aws_iam_group.julian.name
  users = [aws_iam_user.julian.name]
}

# A separate deny, detachable in one step; NotAction keeps aws login's OAuth exchange working. See README.
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


# ViewOnlyAccess, not ReadOnlyAccess: configuration reads only, never state or secret contents.
resource "aws_iam_group_policy_attachment" "julian_view_only" {
  group      = aws_iam_group.julian.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# A managed policy: the 2048-byte inline-policy cap was too small. Never this root's own state.
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
        # aws login's browser OAuth flow for IAM users needs these two.
        Sid      = "AllowLocalDevelopmentSignIn"
        Effect   = "Allow"
        Action   = ["signin:AuthorizeOAuth2Access", "signin:CreateOAuth2Token"]
        Resource = "arn:aws:signin:*:*:oauth2/public-client/*"
      },
      {
        Sid      = "ListOperatorState"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = local.state_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["repo-infra/*", "fritzbox/*"]
          }
        }
      },
      {
        Sid      = "ReadWriteOperatorState"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = ["${local.state_bucket_arn}/repo-infra/*", "${local.state_bucket_arn}/fritzbox/*"]
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
        # PutSecretValue too, julian rotates the values. Wildcard ARNs: the containers live in secrets-manager.
        Sid    = "ManageSecretsManagerSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
        ]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/sankey-export-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/grafana-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/open-webui-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/home-agent-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/ingress-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/monitoring-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/nextcloud-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/github-runner-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:dyndns/fritzbox-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:fritzbox/terraform-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/blocky-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/ghcr-pull-token-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/authelia-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/bulwark-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/stalwart-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:k3s-apps/paperless-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/prometheus-*",
        ]
      },
    ]
  })
}

resource "aws_iam_group_policy_attachment" "julian_terraform_operator" {
  group      = aws_iam_group.julian.name
  policy_arn = aws_iam_policy.julian_terraform_operator.arn
}
