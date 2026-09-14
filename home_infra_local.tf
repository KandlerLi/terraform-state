# A scripted, non-interactive identity for infra/home-infra's own
# Ansible runs, mirroring repo_infra_local.tf/k3s_bootstrap_local.tf's
# exact reasoning and lessons learned -- see repo_infra_local.tf's own
# header comment for why this is a deliberate, scoped exception to
# ADR 0018 rather than a weakening of it, and why it's kept in this
# root specifically (self-escalation guarantee: this identity's policy
# grants it no IAM action over IAM users, groups, or itself).
#
# Simplest of the three: infra/home-infra has no Terraform state of
# its own at all (pure Ansible) -- no S3 statements needed. Its only
# AWS touchpoint is `ansible-playbook site.yml`'s own
# lookup('amazon.aws.secretsmanager_secret', ...) calls for exactly
# two secret groups (home-infra/monitoring, home-infra/nextcloud),
# previously read under whatever ambient AWS session happened to be
# active locally (in practice, julian's own `aws login`) -- this
# identity replaces that with a static, minimally-scoped key stored in
# pass, the same way repo-infra's and k3s-bootstrap's own local applies
# already stopped needing julian's browser OAuth flow at all.

resource "aws_iam_user" "home_infra_local" {
  name = "home-infra-local"

  lifecycle {
    prevent_destroy = true
  }
}

#trivy:ignore:AVD-AWS-0123
resource "aws_iam_group" "home_infra_local" {
  # Fixes trivy's AWS-0143 (policy attached directly to a user) --
  # home-infra-local is a scripted, non-interactive credential (see this
  # file's own header comment), so this group will only ever have this
  # one member; the indirection is cheap and clears the finding without
  # changing the effective permissions.
  #
  # Also suppresses the AWS-0123 (MFA not enforced) this in turn trips:
  # this identity has no console password or login profile at all, only
  # a static access key for Ansible's own boto3 calls -- MFA has no
  # session to attach a condition to for raw access-key auth.
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
        # Read-only -- this identity never rotates these values,
        # exactly like k3s-bootstrap-local's own ReadGithubRunnerSecret
        # statement. julian's own credentials stay the only way to
        # edit/rotate either group. Wildcard ARN strings, matching the
        # convention every migrated secret's grant already uses.
        Sid    = "ReadHomeInfraSecrets"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/monitoring-*",
          "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:home-infra/nextcloud-*",
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

# terraform apply -replace=aws_iam_access_key.home_infra_local, then
# repeat the decrypt-and-store step in README.md, rotates this. No
# prevent_destroy here (unlike the user above) -- same reasoning as
# repo_infra_local's/k3s_bootstrap_local's own identical resource:
# this one is designed to be replaced, prevent_destroy would just
# block that.
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
