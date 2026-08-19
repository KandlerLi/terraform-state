# Repository Instructions

This repository is the source of truth for the central Terraform S3 state
bucket. It does not contain the infrastructure managed by the consuming
Terraform repositories.

## Safety

- Never commit, print, copy into chat, or add to documentation any Terraform
  state, state backup, saved plan, crash log, credentials, or backend metadata.
- Do not inspect state contents during routine repository or documentation work.
- Do not reconfigure or migrate the backend, import resources, force-unlock
  state, or destroy the bucket without explicit approval and a verified
  recovery plan.
- Keep the bucket versioned, encrypted, blocked from public access, and without
  `force_destroy` unless an approved design change says otherwise.
- Preserve user changes and inspect `git status --short --branch` before edits.

## Validation

Run these checks for Terraform source changes:

```bash
terraform fmt -check -recursive
terraform init -backend=false -input=false
terraform validate
```

Do not run `terraform plan` or `terraform apply` merely to validate a
documentation or repository-governance change.

## Documentation synchronization

When a change affects the backend, state keys, access controls, security,
recovery, operations, architecture, or deployed state, review and update both:

- `/home/julian/projects/home-infra-docs`
- `/home/julian/projects/home-infra-ai-context`

Keep human-facing C4 and operational detail in `home-infra-docs`; keep compact,
secret-free cross-task context and safety invariants in
`home-infra-ai-context`.
