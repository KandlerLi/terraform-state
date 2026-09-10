# Secret: `home-infra/monitoring`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_monitoring`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/k3s-apps`' `modules/alertmanager` (SES creds)
and `modules/authelia` (same SES identity, reused for Authelia's own
password-reset emails rather than provisioning a second one), both via
`secrets.tf`; also `infra/home-infra`'s own Ansible
(`ansible/playbooks/site.yml`'s `pre_tasks`, gated on
`monitoring_enabled`) for all three keys directly.

## Keys

### `monitoring_ses_smtp_username`
SES SMTP identity's username — tied to the underlying IAM access key,
not usually rotated independent of the password below.

### `monitoring_ses_smtp_password`
**Derived, not chosen.** This isn't a password you invent — it's
derived from a real SES secret access key via
`aws/ses-relay/scripts/derive_smtp_password.py`, AWS's own published
SigV4-based algorithm. To rotate: rotate the underlying IAM access key
first (`aws/ses-relay`'s own Terraform-managed SES user), run the
derive script against the new key, `put-secret-value` the result here,
then `terraform apply` in `infra/k3s-apps` (Alertmanager) *and*
re-run `infra/home-infra`'s `site.yml` (Ansible also reads this group
directly).

### `monitoring_ntfy_topic`
**Not a credential in the usual sense** — an identifier, not material
to regenerate. ntfy's own security model treats an unguessable topic
*name* as the actual secret (anyone who knows it can publish to it),
so it still belongs in Secrets Manager, but "rotating" it just means
picking a new unguessable string and updating both the publisher
(wherever alerts get sent from) and subscriber (the ntfy app/client)
to match — no cryptographic material involved.

## Automated rotation

`monitoring_ses_smtp_username`/`_password`: possible in principle (the
underlying SES IAM access key *is* a normal AWS credential AWS tooling
understands), but the derive-script step means this isn't a native
Secrets Manager rotation template out of the box — would need a custom
Lambda running the same derivation. `monitoring_ntfy_topic`: no real
automation need, just pick a new string when rotating.
