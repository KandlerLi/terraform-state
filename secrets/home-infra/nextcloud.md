# Secret: `home-infra/nextcloud`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_nextcloud`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/home-infra`'s own Ansible
(`ansible/playbooks/site.yml`'s `pre_tasks`, gated on
`nextcloud_aio_oidc_enabled`), **not** Terraform — Nextcloud AIO runs
on the homeserver itself, not in k3s, unlike every other OIDC client.

## Keys

### `authelia_oidc_nextcloud_client_secret`
Plaintext half of Nextcloud's OIDC client secret pair — Authelia holds
the matching hash (`home-infra/authelia`'s
`authelia_oidc_nextcloud_client_secret_hash`; see that file's own
"Rotating this pair" note). Never rotate this alone. Because this side
lives in Ansible rather than Terraform, the redeploy step differs from
Grafana/Open WebUI's: after `put-secret-value` on both this group and
`home-infra/authelia`, `terraform apply` in `infra/k3s-apps` rolls
Authelia, but reaching Nextcloud's own config needs a separate
`ansible-playbook ansible/playbooks/site.yml --ask-become-pass` run
against the homeserver (`infra/home-infra`).

## Automated rotation

Structurally resistant, same as every OIDC pair — and this one spans
two different repos/tools (Terraform for Authelia, Ansible for
Nextcloud) for a single logical rotation, making unattended automation
even less appropriate than the Grafana/Open WebUI pairs.
