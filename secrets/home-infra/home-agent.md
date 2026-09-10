# Secret: `home-infra/home-agent`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_home_agent`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/k3s-apps`' `modules/home_agent`, read via
`secrets.tf`. `home_agent_ghcr_token` is also reused directly by
`modules/sankey_export` (same GHCR pull credential, not duplicated).

## Keys

### `home_agent_openai_api_key`
OpenAI API key for `home_agent`'s own chat/completions calls. Generate
a new key in the OpenAI dashboard, `put-secret-value`, `terraform
apply`, then revoke the old key once the new Deployment is confirmed
healthy.

### `home_agent_ghcr_token`
GHCR pull token for `home_agent`'s (and `sankey_export`'s) own private
image (`modules/home_agent/secret.tf`'s `imagePullSecrets` auth).
Generate a new fine-grained PAT with read:packages on the relevant
GHCR package, `put-secret-value`, `terraform apply`.

### `nextcloud_tools_app_password`
Nextcloud app password for `home_agent`'s own read-only Nextcloud
integration (a dedicated bot account, not `admin`). No dedicated
rotation playbook exists any more — `infra/home-infra`'s own
`nextcloud_tools` role and its rotation playbook were retired entirely
when `home_agent`/`open_webui` moved to k3s-native (commit `018c5ff`).
Manual flow:
```bash
docker exec nextcloud-aio-nextcloud php occ user:auth-tokens:add \
  --user nextcloud_tools --name "<new token name>"
```
capture the printed token, `put-secret-value`, `terraform apply`.
Revoke the superseded token only after confirming the new one works
(`occ user:auth-tokens:list --user nextcloud_tools`, then
`occ user:auth-tokens:delete` on the old one by ID) — both tokens stay
valid until you revoke one, so there's no blackout window if you check
first.

## Automated rotation

`home_agent_openai_api_key`/`home_agent_ghcr_token`: worth automating
— mechanically simple, low blast radius. `nextcloud_tools_app_password`:
possible but needs a Lambda that can reach the homeserver's own
`occ` CLI (via Docker exec or an equivalent API), a real build, not a
native AWS rotation template.
