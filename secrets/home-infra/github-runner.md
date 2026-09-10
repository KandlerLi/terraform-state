# Secret: `home-infra/github-runner`

**Terraform resource**: `aws_secretsmanager_secret.home_infra_github_runner`
(`bootstrap/terraform-state/secrets_manager.tf`) — container only, no
value.

**Consumed by**: `bootstrap/k3s-bootstrap`'s `modules/github_runner`,
read via that repo's own `secrets.tf`. The `k3s-bootstrap-local` IAM
identity that applies that repo has a dedicated, **read-only** grant
on this one secret (`bootstrap/terraform-state/k3s_bootstrap_local.tf`)
— unlike `julian`'s own read/write grant on every other secret here,
since `k3s-bootstrap-local` is a scripted, non-interactive identity;
only `julian`'s own credentials edit/rotate this value.

## Keys

### `github_runner_github_token`
Fine-grained GitHub PAT with `Administration: write` on every
self-hosted-runner repository (all 7 currently opted in via
`config.yml`'s `runner: true`). Generate a new one in GitHub's own PAT
settings with the same scope, `put-secret-value`, then an actual
`bootstrap/k3s-bootstrap` apply — all 7 repos' runner Deployments
share one Kubernetes Secret (`modules/github_runner`), so one apply
rolls every runner at once. Revoke the old PAT in GitHub only after
confirming at least one runner re-registered successfully post-apply.

## Automated rotation

Possible but needs a Lambda that can call GitHub's own PAT-management
API (fine-grained PATs currently have no programmatic rotation
endpoint as of this writing — check GitHub's own API docs before
assuming one exists) and trigger a `bootstrap/k3s-bootstrap` apply
afterward. Not a natural fit for AWS Secrets Manager's own native
rotation Lambda shape (which expects to manage the credential's
lifecycle entirely within AWS) since the credential itself lives in
GitHub, not AWS.
