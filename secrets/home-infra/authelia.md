# Secret: `home-infra/authelia`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_authelia`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value; the value is set out-of-band via `aws secretsmanager
put-secret-value` (never `aws_secretsmanager_secret_version` in
Terraform).

**Consumed by**: `infra/k3s-apps`' `modules/authelia`, read via
`secrets.tf`'s `data "aws_secretsmanager_secret_version"` +
`jsondecode()` at every `terraform plan`/`apply` (both the apply and
plan CI roles need `GetSecretValue` for this, unlike `aws/dyndns`'s own
metadata-only plan role — `jsondecode()` needs the real value to
compute a diff).

Authelia's own internal crypto material plus the hash half of each
OIDC client secret pair — mostly not things a human types or
remembers, with one exception.

## Keys

### `authelia_session_secret`
Encryption key for Authelia's session cookies (config's
`session.secret`) — pure random noise. Generate with `authelia crypto
rand --length 64 --charset alphanumeric` (the CLI ships in Authelia's
own image, `ghcr.io/authelia/authelia:4.39.22` per
`infra/k3s-apps/modules/authelia/main.tf`'s pinned digest).
**Rotation impact**: logs out every active session immediately
(everyone re-authenticates, MFA included). Otherwise safe to rotate
any time.

### `authelia_storage_encryption_key`
Encrypts Authelia's own SQLite storage at rest (session/TOTP
registration state). **Do not just swap the value** — run Authelia's
own `authelia storage encryption change-key` against the live database
first, or the database stays encrypted with the old key while Authelia
expects the new one, breaking every existing TOTP registration.

### `authelia_reset_password_jwt_secret`
Signs the password-reset email's JWT link (config's
`identity_validation.reset_password.jwt_secret`). Generate the same
way as the session secret. **Rotation impact**: low — only invalidates
any reset link currently in flight (rare).

### `authelia_admin_password_hash`
**Personal credential** — Argon2id hash of Julian's own Authelia login
password (the file `authentication_backend`'s `users_database.yml`).
Only the hash lives here; the plaintext stays in a password manager,
never in this secret or in git. Generate with:
```bash
docker run --rm authelia/authelia:4.39.22 \
  authelia crypto hash generate argon2 --password '<password>'
```
Update the password manager entry *before* rotating this value, not
after — there's no way to recover the plaintext once only the hash
exists.

### `authelia_oidc_hmac_secret`
Signing secret for Authelia's own OIDC provider (config's
`identity_providers.oidc.hmac_secret`) — pure random noise. Generate
with `authelia crypto rand --length 64 --charset alphanumeric`.
**Rotation impact**: invalidates every live OIDC session across
Grafana, Open WebUI, and Nextcloud at once (all three services' users
get logged out and must re-authenticate through Authelia).

### `authelia_oidc_issuer_private_key`
RSA private key (PEM, 4096-bit) Authelia's OIDC provider signs tokens
with (config's `identity_providers.oidc.jwks`). Generate with
`authelia crypto pair rsa generate -b 4096`. **Rotation impact**: same
as the HMAC secret above — invalidates every live OIDC session
simultaneously.

### `authelia_oidc_grafana_client_secret_hash`, `authelia_oidc_openwebui_client_secret_hash`, `authelia_oidc_nextcloud_client_secret_hash`
pbkdf2-sha512 hash of each client's own OIDC client secret — only the
hash lives here, the matching plaintext lives in that client's own
Secrets Manager group (`home-infra/grafana`, `home-infra/open-webui`,
`home-infra/nextcloud` respectively — see each of those files' own
"Rotating this pair" note). **Rotating one half without the other
breaks that client's SSO outright.** Generate hash + plaintext
together, in one command:
```bash
docker run --rm authelia/authelia:4.39.22 \
  authelia crypto hash generate pbkdf2 --variant sha512 \
  --random --random.length 64 --random.charset alphanumeric
```
This prints both the random plaintext and its pbkdf2 hash — keep both,
they go to two different secrets. Full rotation order: `put-secret-value`
the hash here, `put-secret-value` the plaintext in the client's own
group, then `terraform apply` in `infra/k3s-apps` (rolls Authelia and
the client Deployment together, so hash and plaintext land in sync —
except Nextcloud, which needs a re-run of `infra/home-infra`'s
`site.yml` instead, since its plaintext flows through Ansible, not
Terraform).

## Automated rotation

Not a good candidate. Every key here is either Authelia's own internal
crypto material (unattended rotation is actively harmful given the
logout/re-auth blast radius on session or OIDC-signing material, not
merely unnecessary) or the coordinated OIDC pairs (need a redeploy of
the *other* secret's consumer too, in lockstep). See
`docs/home-infra-docs/docs/runbooks/rotate-secrets.md`'s own "reality
check" section for the fuller reasoning.
