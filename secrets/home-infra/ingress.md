# Secret: `home-infra/ingress`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_ingress`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/k3s-apps`' `modules/ingress`, read via
`secrets.tf`.

## Keys

### `shared_ingress_auth_password` / `shared_ingress_auth_password_hash`
**Personal credential** (Traefik HTTP Basic Auth for user `julian`) —
**currently dormant**, not wired into any live route. Traefik's own
config (`modules/ingress/configmap.tf`) defines the `basicAuth`
middleware but doesn't reference it from any `*-chain` — kept
deliberately as a one-chain-edit rollback path in case Authelia's own
SQLite storage issue (`BACKLOG.md`'s "Ingress auth: Authelia SQLite
storage lost data twice") recurs. **This is why it stays in Secrets
Manager rather than moving to local-only storage**: Terraform actively
keeps the Kubernetes Secret populated so the rollback stays an instant
swap, no rebuild — worth revisiting if the underlying issue goes long
enough without recurring that the rollback path stops earning its
keep.

To rotate: generate a new password, hash it with any bcrypt tool
(Traefik's `basicAuth` middleware just wants a standard htpasswd-format
hash — the same tool used for `authelia_admin_password_hash` works
fine here too), `put-secret-value` both keys, `terraform apply`, then
re-run `infra/home-infra/scripts/sync_secrets_to_pass.py` so the
`pass` copy (`ingress/password`) doesn't go stale.

### `k3s_ingress_acme_dns01_access_key_id` / `k3s_ingress_acme_dns01_secret_access_key`
`dyndns`'s own `traefik-acme-dns01` IAM user credentials, scoped to
exactly `route53:ChangeResourceRecordSets`/`GetChange` on the
`jkandler.de` zone — used continuously for Let's Encrypt's DNS-01
challenge, real certificate issuance/renewal. Rotate via
`aws iam create-access-key` on that user, `put-secret-value`,
`terraform apply`. Delete the old access key from IAM only after
confirming the new one issued a real certificate — renewal runs
continuously, so there's no safe credential-less window.

## Automated rotation

`k3s_ingress_acme_dns01_*`: worth automating — mechanically simple IAM
key rotation, low blast radius. `shared_ingress_auth_password`/`_hash`:
a human has to actually know the new plaintext to use it, so this
can't be meaningfully unattended regardless of mechanics.
