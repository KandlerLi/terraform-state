# Secret: `home-infra/open-webui`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_open_webui`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/k3s-apps`' `modules/open_webui`, read via
`secrets.tf`.

## Keys

### `authelia_oidc_openwebui_client_secret`
Plaintext half of Open WebUI's OIDC client secret pair — Authelia
holds the matching hash (`home-infra/authelia`'s
`authelia_oidc_openwebui_client_secret_hash`; see that file's own
"Rotating this pair" note for the full two-secret procedure). Never
rotate this alone — Open WebUI's SSO breaks until both sides match
again, and native login stays disabled regardless (same protocol-level
lock as Grafana's, see `home-infra/grafana.md`), so a mismatch here is
a real, if temporary, outage for the whole service.

## Automated rotation

Structurally resistant, same as every OIDC pair — needs a coordinated
update with `home-infra/authelia` plus a Terraform apply that rolls
both Deployments together, not something a scheduled job should do
unattended.
