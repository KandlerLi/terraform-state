# terraform-state

This root holds the state bucket every other root depends on, the `julian`
operator identity (ADR 0018) and the account-wide security baseline. A
mistake here can lock every repo out of its state, so the bar is higher
than elsewhere in the workspace:

- Leave state, state backups, saved plans, crash logs and `.terraform`
  backend metadata unopened; never print, copy or commit them.
- Validate offline only: `terraform fmt -check -recursive`,
  `terraform init -backend=false -input=false`, `terraform validate`.
  `plan`/`apply` are Julian's, run locally via `scripts/roll-out.sh`.
- Backend reconfiguration, state migration, `import`, `force-unlock` or
  anything that weakens the bucket (versioning, encryption, public-access
  block, `force_destroy`) needs Julian's explicit approval and a verified
  recovery path first. The README's backend section has the details.
