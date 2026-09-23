# A scripted, non-interactive identity for bootstrap/k3s-bootstrap's
# own local-apply use case, mirroring repo_infra_local.tf's exact
# reasoning and lessons learned -- see that file's own header comment
# for why this is a deliberate, scoped exception to ADR 0018 rather
# than a weakening of it, and why it's kept in this root specifically
# (self-escalation guarantee: this identity's policy grants it no IAM
# action over IAM users, groups, or itself).
#
# Simpler than repo_infra_local: k3s-bootstrap's own Terraform never
# touches IAM/the GitHub OIDC provider at all (it manages Kubernetes
# RBAC and PersistentVolumes via the kubernetes provider, not AWS
# resources) -- the only AWS access it ever needs is read/write on its
# own state prefix.
#
# This only ever removes the `aws login` step from
# k3s-bootstrap/scripts/roll-out.sh -- applying that repo still needs
# the k3s node's own cluster-admin kubeconfig regardless of which AWS
# identity runs alongside it, since it manages privilege-defining
# Kubernetes RBAC (see that repo's own README for why that stays a
# human-only credential either way).

resource "aws_iam_user" "k3s_bootstrap_local" {
  name = "k3s-bootstrap-local"

  lifecycle {
    prevent_destroy = true
  }
}

#trivy:ignore:AVD-AWS-0123
resource "aws_iam_group" "k3s_bootstrap_local" {
  # Fixes trivy's AWS-0143, same reasoning and same AWS-0123 suppression
  # as home_infra_local's own identical fix -- a scripted,
  # non-interactive identity with only a static access key, no console
  # login to attach an MFA condition to.
  name = "k3s-bootstrap-local"
}

resource "aws_iam_group_policy" "k3s_bootstrap_local_terraform_operator" {
  name  = "terraform-operator"
  group = aws_iam_group.k3s_bootstrap_local.name

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
        Sid      = "ListK3sBootstrapState"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = local.state_bucket_arn
        Condition = {
          StringLike = {
            "s3:prefix" = ["k3s-bootstrap/*"]
          }
        }
      },
      {
        Sid      = "ReadWriteK3sBootstrapState"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${local.state_bucket_arn}/k3s-bootstrap/*"
      },
      {
        # This root's own github_runner_github_token comes straight
        # from home-infra/github-runner's own Secrets Manager
        # container instead of a human-supplied TF_VAR_* at apply
        # time. Read-only -- unlike julian's own
        # ManageSecretsManagerSecrets statement (operator.tf), this is
        # a scripted, non-interactive identity; julian's own
        # credentials stay the only way to edit/rotate the value.
        # Wildcard ARN string, not a resource reference, since the
        # container itself lives in aws/secrets-manager, not this
        # repo's own Terraform.
        Sid      = "ReadGithubRunnerSecret"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/github-runner-*"
      },
    ]
  })
}

resource "aws_iam_group_membership" "k3s_bootstrap_local" {
  name  = "k3s-bootstrap-local-members"
  group = aws_iam_group.k3s_bootstrap_local.name
  users = [aws_iam_user.k3s_bootstrap_local.name]
}

variable "k3s_bootstrap_local_pgp_key" {
  description = <<-EOT
    Base64-encoded PGP public key (the raw binary export, NOT
    --armor'd -- see repo_infra_local_pgp_key's own description for
    why that distinction matters, confirmed live). Reuses this
    workspace's existing pass/sops GPG key
    (6D8B16CB662983A54B4AF1466F0B5C2AB1509600):

        gpg --export 6D8B16CB662983A54B4AF1466F0B5C2AB1509600 | base64

    Pass the result via TF_VAR_k3s_bootstrap_local_pgp_key at apply
    time -- never written to a file in this repo.
  EOT
  type        = string
  sensitive   = true
}

# terraform apply -replace=aws_iam_access_key.k3s_bootstrap_local, then
# repeat the decrypt-and-store step in README.md, rotates this. No
# prevent_destroy here (unlike the user above) -- same reasoning as
# repo_infra_local's own identical resource: this one is designed to
# be replaced, prevent_destroy would just block that.
resource "aws_iam_access_key" "k3s_bootstrap_local" {
  user    = aws_iam_user.k3s_bootstrap_local.name
  pgp_key = var.k3s_bootstrap_local_pgp_key
}

output "k3s_bootstrap_local_access_key_id" {
  description = "Access key ID for k3s-bootstrap-local -- not sensitive on its own, an access key ID alone grants nothing without the matching secret."
  value       = aws_iam_access_key.k3s_bootstrap_local.id
}

output "k3s_bootstrap_local_encrypted_secret_access_key" {
  description = <<-EOT
    PGP-encrypted secret access key (base64). Decrypt once with:

        terraform output -raw k3s_bootstrap_local_encrypted_secret_access_key | base64 -d | gpg -d

    then store both this and k3s_bootstrap_local_access_key_id in pass
    -- see README.md's own "k3s-bootstrap-local Identity" section for
    the exact commands.
  EOT
  value       = aws_iam_access_key.k3s_bootstrap_local.encrypted_secret
  sensitive   = true
}
