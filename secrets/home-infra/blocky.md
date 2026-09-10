# Secret: `home-infra/blocky`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_blocky`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `infra/k3s-apps`' `modules/blocky` (the Postgres
container and Grafana's own datasource config), read via `secrets.tf`.

## Keys

### `blocky_postgres_password`
Self-hosted, in-cluster Postgres password for Blocky's query-log
database — **not** an AWS-managed database, so Secrets Manager's
native RDS-style rotation templates don't apply. The database itself
needs the change made directly; Secrets Manager having the new value
isn't enough on its own:

```bash
kubectl exec -it deploy/blocky -c postgres -- psql -U blocky -c \
  "ALTER USER blocky WITH PASSWORD '<new-password>';"
```

then `put-secret-value` and `terraform apply` (updates the Kubernetes
Secret Blocky itself reads) — in that order, so the old value still
works during the brief gap between the `ALTER USER` and the apply
picking it up, rather than locking Blocky out.

## Automated rotation

Worth automating — mechanically simple, low blast radius, exactly the
kind of thing a Lambda with `kubectl exec` access (or a
`kubernetes_exec`-equivalent API call) could safely do unattended. The
one real build cost: there's no AWS-native template for this, since
it's not RDS — the Lambda has to run the `ALTER USER` step itself.
