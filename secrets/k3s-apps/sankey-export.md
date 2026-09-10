# Secret: `k3s-apps/sankey-export`

**Terraform resource**: `aws_secretsmanager_secret.k3s_apps_sankey_export`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/k3s-apps`' `modules/sankey_export`, read via
`secrets.tf`.

## Keys

### `sankey_export_app_password`
Nextcloud app password for the dedicated `sankey-export` bot account
(never `admin`) — used to download the budget spreadsheet and upload
the rendered PNG back over WebDAV. No dedicated rotation playbook
exists. Manual flow:
```bash
docker exec nextcloud-aio-nextcloud php occ user:auth-tokens:add \
  --user sankey-export --name "<new token name>"
```
capture the printed token, `put-secret-value`, `terraform apply`.
Revoke the superseded token only after confirming the new one works
(`occ user:auth-tokens:list --user sankey-export`, then
`occ user:auth-tokens:delete` on the old one by ID) — both tokens stay
valid until you revoke one, so there's no blackout window if you check
first.

## Automated rotation

Possible but needs a Lambda that can reach the homeserver's own `occ`
CLI (via Docker exec or an equivalent API) — a real build, not a
native AWS rotation template. Same shape as
`home-infra/home-agent.md`'s `nextcloud_tools_app_password`.
