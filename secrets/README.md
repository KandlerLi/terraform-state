# Secret documentation

Per-secret documentation for every `aws_secretsmanager_secret` resource
in `secrets_manager.tf` — one file per Secrets Manager group, path
mirroring the group's own name (`home-infra/authelia` →
`home-infra/authelia.md`). Each file covers what the group's keys are,
who consumes them, and exactly how to rotate each one; see
`docs/home-infra-docs/docs/runbooks/rotate-secrets.md` for the
cross-cutting rotation categories and automated-rotation feasibility
this folder's own files draw from.

- [home-infra/authelia](home-infra/authelia.md) — Authelia's own
  session/storage/OIDC crypto material, plus one personal login
- [home-infra/grafana](home-infra/grafana.md) — Grafana's admin
  password (functionally dead, flagged for removal) and its OIDC
  client secret
- [home-infra/open-webui](home-infra/open-webui.md) — Open WebUI's
  OIDC client secret
- [home-infra/nextcloud](home-infra/nextcloud.md) — Nextcloud's OIDC
  client secret (Ansible-consumed, not Terraform)
- [home-infra/ingress](home-infra/ingress.md) — the dormant shared
  Basic Auth rollback credential and the ACME DNS-01 IAM keypair
- [home-infra/home-agent](home-infra/home-agent.md) — home_agent's
  OpenAI/GHCR credentials and its nextcloud_tools app password
- [home-infra/monitoring](home-infra/monitoring.md) — the SES SMTP
  identity (a derived, not chosen, password) and the ntfy topic
- [home-infra/blocky](home-infra/blocky.md) — Blocky's own Postgres
  password
- [home-infra/github-runner](home-infra/github-runner.md) — the
  shared GitHub Actions runner PAT
- [k3s-apps/sankey-export](k3s-apps/sankey-export.md) — the
  sankey-export CronJob's Nextcloud app password

Every group here also has a `lifecycle { prevent_destroy = true }` in
`secrets_manager.tf` — these are foundational, load-bearing resources
for every service migrated off SOPS, not something a stray
`terraform apply` should ever remove.
