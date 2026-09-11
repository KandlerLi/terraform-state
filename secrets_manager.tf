# Secret *containers* for the workspace's move off SOPS onto AWS
# Secrets Manager (PARKED.md's "Secrets sprawl" item). Follows
# aws/dyndns's own existing precedent (its "credentials" secret,
# main.tf) exactly: Terraform creates the container only -- name,
# recovery window -- and never a value. Real secret material is set
# out-of-band via `aws secretsmanager put-secret-value`, the same way
# SOPS currently keeps it out of plaintext git; putting real values
# into Terraform config/state here would just relocate the exact
# problem this migration exists to solve.
#
# Grouped one entry per logical service (not one per SOPS file, and
# not one per individual key) -- see PARKED.md's own writeup for the
# cost/isolation tradeoff this splits. Named "<owning-repo>/<service>",
# matching which SOPS file each group's keys live in today:
# home-infra/secrets.sops.yml for the "home-infra/*" secrets below,
# k3s-apps/secrets.sops.yml for "k3s-apps/sankey-export". Each
# resource's own comment lists exactly which SOPS keys migrate into it
# -- kept here rather than only in PARKED.md so this file stays the
# living source of truth once the SOPS files themselves are eventually
# deleted.
#
# lifecycle.prevent_destroy on every one of these, matching this root's
# own aws_iam_user.julian above -- these are as foundational as that
# identity once real consumers depend on them (deferred to a follow-up
# session, not yet true the moment this file lands).

locals {
  secrets_manager_recovery_window_days = 7
}

# authelia_session_secret, authelia_storage_encryption_key,
# authelia_reset_password_jwt_secret, authelia_admin_password_hash,
# authelia_oidc_hmac_secret, authelia_oidc_issuer_private_key,
# authelia_oidc_grafana_client_secret_hash,
# authelia_oidc_openwebui_client_secret_hash,
# authelia_oidc_nextcloud_client_secret_hash
resource "aws_secretsmanager_secret" "home_infra_authelia" {
  name                    = "home-infra/authelia"
  description             = "Authelia's own session/storage/OIDC secrets (infra/k3s-apps' modules/authelia)"
  recovery_window_in_days = local.secrets_manager_recovery_window_days

  lifecycle {
    prevent_destroy = true
  }
}

# authelia_oidc_grafana_client_secret (monitoring_grafana_admin_password
# was dropped from the JSON 2026-09-10 -- see bootstrap/secrets-manager).
# Migrated to bootstrap/secrets-manager 2026-09-10 via the ADR 0006 /
# ADR 0010 no-destroy handoff: imported there, relinquished here.
removed {
  from = aws_secretsmanager_secret.home_infra_grafana

  lifecycle {
    destroy = false
  }
}

# authelia_oidc_openwebui_client_secret. Migrated to
# bootstrap/secrets-manager 2026-09-11 via the ADR 0006 / ADR 0010
# no-destroy handoff: imported there, relinquished here.
removed {
  from = aws_secretsmanager_secret.home_infra_open_webui

  lifecycle {
    destroy = false
  }
}

# authelia_oidc_nextcloud_client_secret
resource "aws_secretsmanager_secret" "home_infra_nextcloud" {
  name                    = "home-infra/nextcloud"
  description             = "Nextcloud's own Authelia OIDC client secret (consumed by infra/home-infra's Ansible only -- Nextcloud AIO stays on the homeserver, not k3s)"
  recovery_window_in_days = local.secrets_manager_recovery_window_days

  lifecycle {
    prevent_destroy = true
  }
}

# shared_ingress_auth_password, shared_ingress_auth_password_hash,
# k3s_ingress_acme_dns01_access_key_id,
# k3s_ingress_acme_dns01_secret_access_key
resource "aws_secretsmanager_secret" "home_infra_ingress" {
  name                    = "home-infra/ingress"
  description             = "Shared-ingress Basic Auth credential and the ACME DNS-01 Route53 IAM keypair"
  recovery_window_in_days = local.secrets_manager_recovery_window_days

  lifecycle {
    prevent_destroy = true
  }
}

# home_agent_openai_api_key, home_agent_ghcr_token,
# nextcloud_tools_app_password. Migrated to bootstrap/secrets-manager
# 2026-09-11 via the ADR 0006 / ADR 0010 no-destroy handoff: imported
# there, relinquished here.
removed {
  from = aws_secretsmanager_secret.home_infra_home_agent

  lifecycle {
    destroy = false
  }
}

# monitoring_ses_smtp_username, monitoring_ses_smtp_password,
# monitoring_ntfy_topic
resource "aws_secretsmanager_secret" "home_infra_monitoring" {
  name                    = "home-infra/monitoring"
  description             = "Alertmanager/Authelia's shared SES SMTP identity and the ntfy relay topic"
  recovery_window_in_days = local.secrets_manager_recovery_window_days

  lifecycle {
    prevent_destroy = true
  }
}

# blocky_postgres_password
resource "aws_secretsmanager_secret" "home_infra_blocky" {
  name                    = "home-infra/blocky"
  description             = "Blocky's own Postgres query-log password (also read by Grafana's datasource config)"
  recovery_window_in_days = local.secrets_manager_recovery_window_days

  lifecycle {
    prevent_destroy = true
  }
}

# github_runner_github_token
resource "aws_secretsmanager_secret" "home_infra_github_runner" {
  name                    = "home-infra/github-runner"
  description             = "Shared PAT for every repo's self-hosted GitHub Actions runner (bootstrap/k3s-bootstrap's own modules/github_runner)"
  recovery_window_in_days = local.secrets_manager_recovery_window_days

  lifecycle {
    prevent_destroy = true
  }
}

# sankey_export_app_password -- migrated to bootstrap/secrets-manager
# 2026-09-10 (the pilot), via the ADR 0006 / ADR 0010 no-destroy handoff:
# imported there, relinquished here. `destroy = false` keeps the live
# secret; Terraform just drops it from this root's state. GC this block in
# the final sweep once every group has migrated.
removed {
  from = aws_secretsmanager_secret.k3s_apps_sankey_export

  lifecycle {
    destroy = false
  }
}
