# Secret: `home-infra/grafana`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_grafana`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/k3s-apps`' `modules/grafana`, read via
`secrets.tf`.

## Keys

### `monitoring_grafana_admin_password`
**Functionally dead — flagged for removal, not rotation.** Grafana's
native login form *and* HTTP Basic Auth are both disabled at the
protocol level (`infra/k3s-apps/modules/grafana/main.tf`'s own
comment: "the `GF_SECURITY_ADMIN_*` account above still technically
exists, it just can no longer log in by any means — Authelia is now
the only way in"). There is no login path left that accepts this
value, so it cannot be rotated into a *working* credential — only
regenerated as unused busywork. The real fix, not yet done: refactor
`modules/grafana` to a fixed, non-secret placeholder string instead of
reading this from Secrets Manager at all, and drop the key from this
group and from `infra/home-infra/scripts/sync_secrets_to_pass.py`'s
`pass` copy.

### `authelia_oidc_grafana_client_secret`
Plaintext half of Grafana's OIDC client secret pair — Authelia holds
the matching hash (`home-infra/authelia`'s
`authelia_oidc_grafana_client_secret_hash`; see that file's own
"Rotating this pair" note for the full two-secret procedure and why
order matters). Never rotate this alone.

## Automated rotation

`monitoring_grafana_admin_password`: not worth automating rotation for
a credential that can't be used — worth automating its *removal*
instead (a one-time Terraform refactor, not a recurring job).
`authelia_oidc_grafana_client_secret`: structurally resistant, same as
every OIDC pair — needs a coordinated update with `home-infra/authelia`
plus a Terraform apply, not something a scheduled job should do
unattended.
