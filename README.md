# Terraform State Bootstrap

This Terraform configuration creates the central S3 bucket used as the remote
state backend by the infrastructure repositories. State locking uses S3 lock
files, so no DynamoDB table is required.

It also manages the `julian` operator IAM identity (`operator.tf`) — see the
"Operator Identity" section below. The two live in the same root
deliberately: both this bucket and that identity are foundational,
essentially-bootstrap-once resources applied only by root, unlike
`repo-infra`, which is applied routinely (by `julian`, once its policy here
is live).

## Prerequisites

- Terraform 1.10 or newer
- AWS credentials with permission to create and configure the S3 bucket
- An AWS account in which the bucket name is globally unique

Use short-lived credentials where possible, such as an AWS IAM Identity Center
profile or an assumed role. Do not put credentials in Terraform files.

To use an existing AWS CLI profile:

```bash
export AWS_PROFILE=terraform
aws sts get-caller-identity
```

The AWS CLI is useful for verifying credentials but is not required by
Terraform itself.

## Current Backend

This project originally used local state to create the bucket. It now uses the
existing bucket as its own remote backend:

```text
bucket: jkandler-terraform-state
key: terraform-state/terraform.tfstate
region: eu-central-1
locking: native S3 lock file
```

For normal work with the existing backend:

```bash
terraform init
terraform plan
terraform apply
terraform output
```

Do not remove or change the backend block, reinitialize with `-reconfigure`, or
migrate state unless the existing remote state and recovery path have first
been verified. Terraform state and plan files must not be committed.

## Bootstrap a New Backend

A new account or replacement bucket has a dependency cycle: the S3 backend
cannot be initialized until the bucket exists. Resolve that with a deliberate,
temporary local-backend bootstrap and then run `terraform init -migrate-state`
after configuring the new backend. Preserve and protect the migration copy
until remote-state recovery has been verified.

The defaults create `jkandler-terraform-state` in `eu-central-1`. Override them
when necessary:

```bash
terraform apply \
  -var="aws_region=eu-central-1" \
  -var="state_bucket_name=my-unique-terraform-state-bucket"
```

## Configure a Repository Backend

Each consuming repository should use a unique state key and enable native S3
locking:

```hcl
terraform {
  required_version = ">= 1.10.0"

  backend "s3" {
    bucket       = "jkandler-terraform-state"
    key          = "dyndns/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    use_lockfile = true
  }
}
```

After adding or changing a backend, initialize it explicitly:

```bash
terraform init -migrate-state
```

Change `key` for every independent Terraform root module so their state files
do not overlap.

## Backend IAM Permissions

A role that only accesses state under this bucket needs the following S3
permissions. Its deployment permissions for the infrastructure it manages are
separate.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListStateBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::jkandler-terraform-state"
    },
    {
      "Sid": "ReadWriteStateAndLocks",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::jkandler-terraform-state/*"
    },
    {
      "Sid": "DeleteLockFiles",
      "Effect": "Allow",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::jkandler-terraform-state/*.tflock"
    }
  ]
}
```

For CI, prefer workload identity federation, such as GitHub Actions OIDC, over
long-lived access keys stored as repository secrets.

## Security and Recovery

- S3 versioning retains previous state object versions for recovery.
- Server-side encryption with Amazon S3 managed keys is enforced at the bucket.
- All forms of public access are blocked.
- S3 lock files prevent concurrent Terraform runs from writing the same state.

Terraform state can contain secrets. Restrict both read and write access to the
bucket and never publish state files or plan files.

## Operator Identity (`julian`)

`operator.tf` brings the pre-existing IAM user `julian` (created 2021,
previously managed only by hand, carrying `AdministratorAccess`) under
Terraform, and attaches a policy scoped to exactly what running
`repo-infra` locally needs — the shared state bucket's `repo-infra/*`
prefix, the GitHub Actions OIDC provider, and IAM role/policy management
restricted to the `*-github-actions`/`*-github-plan` naming convention
`repo-infra`'s `modules/repo` uses. See
`home-infra-docs/docs/adr/0018-scoped-operator-identity.md` for the full
reasoning, including why this identity is deliberately given no access to
*this* root's own state (`terraform-state/*`) or to itself.

Applying this root always needs the AWS root identity (or another already
admin-equivalent identity) — never `julian`. That's what makes the
guarantee hold: the resources managing `julian`'s own identity live
somewhere `julian` has no access to.

### First apply: importing `julian`

```bash
cd bootstrap/terraform-state
terraform init
terraform plan
terraform apply
```

The `import` blocks bring the existing `julian` user and its
`AdministratorAccess` attachment under management with no live change; the
same apply attaches the new `terraform-operator` scoped inline policy.
After this, `julian` has **both** `AdministratorAccess` and the scoped
policy — deliberately, so nothing breaks mid-migration.

### Removing `AdministratorAccess`: a second, deliberate apply

Terraform can only stop managing a resource already in its state, so
detaching `AdministratorAccess` needs a second pass: once the apply above
has run cleanly and `julian`'s scoped policy is confirmed to work, delete
the `import` block and the `aws_iam_user_policy_attachment.julian_admin`
resource block from `operator.tf`, then run `terraform plan && terraform
apply` again. Terraform will show exactly one planned change — detaching
the policy — and nothing else.

### Enabling console sign-in and MFA for `julian`

Neither can be done via Terraform (a login profile password and an MFA
device both need direct human interaction) — do this once via the AWS
Console:

1. IAM → Users → `julian` → Security credentials tab → "Console access" →
   enable it and set a password.
2. Same tab → "Assign MFA device" → scan the QR code with an authenticator
   app and enter two consecutive codes to confirm.
3. Next time you run `aws login`, choose "IAM user" sign-in (not "Root
   user"), enter this account's ID, `julian`, and the password, then the
   MFA code.

### Read access vs. write access

`julian`'s *write* permissions (the `terraform-operator` inline policy)
are scoped to exactly what `repo-infra` touches today — nothing broader.
`julian` cannot manage this bucket or apply `terraform-state` itself; only
root can. `julian` also has AWS's managed `ViewOnlyAccess` policy attached
(added 2026-08-24), which covers the kind of ad-hoc, cross-service
read-only verification (Route 53 health checks, CloudWatch alarms, IAM
role/policy configs, most `List`/`Describe`/`Get` calls) that root had
been used for throughout this workspace's history — deliberately not the
broader `ReadOnlyAccess`, since `ViewOnlyAccess` excludes any action that
returns actual data (`s3:GetObject`, `secretsmanager:GetSecretValue`,
`dynamodb:GetItem`, `kms:Decrypt`, etc.), so it can't be used to read this
root's own Terraform state or any secrets. Being read-only, it doesn't
weaken the self-escalation guarantee above — it can reveal permissions,
never grant them.

A few things `ViewOnlyAccess` still doesn't cover, since AWS's own policy
excludes them: AWS Budgets (no `budgets:*` actions at all) and a handful
of per-resource `Get*` calls that aren't paired with a `List*` action
(for example `sns:GetSubscriptionAttributes` — only `sns:List*` is
included). Those specific gaps still need root, or a small additional
grant here if they come up often enough to be worth adding.

## repo-infra-local Identity

`repo_infra_local.tf` brings a second, narrower identity for the same
`repo-infra` local-apply use case `julian` already covers, but for
`repo-infra`'s own `scripts/roll-out.sh` (scripted, non-interactive)
instead of `julian`'s MFA-backed browser `aws login` flow. Its policy is
`julian`'s own `terraform-operator` policy, minus the two things a
scripted identity doesn't need: the `AllowLocalDevelopmentSignIn`
statement (browser OAuth only) and `ViewOnlyAccess` (ad-hoc human
investigation only). Same self-escalation guarantee as `julian`: no IAM
action over IAM users/groups/itself, and this root's own state stays
out of reach either way.

### First apply: creating `repo-infra-local` and its access key

Needs `repo_infra_local_pgp_key` — a base64-encoded **raw binary** PGP
public key (not `--armor`'d — confirmed live: `aws_iam_access_key`'s
`pgp_key` wants `base64(binary key packet)`, and base64'ing the
ASCII-armored text instead double-encodes it, failing with `openpgp:
invalid data: tag byte does not have MSB set`), reusing this
workspace's existing `pass`/`sops` GPG key
(`6D8B16CB662983A54B4AF1466F0B5C2AB1509600`):

```bash
export TF_VAR_repo_infra_local_pgp_key="$(gpg --export 6D8B16CB662983A54B4AF1466F0B5C2AB1509600 | base64)"
terraform plan
terraform apply
```

Then, once, decrypt the new access key's secret and store both halves in
`pass` (`repo-infra/scripts/roll-out.sh` reads from these two entries):

```bash
pass insert --force --multiline aws/repo-infra-local/access-key-id <<< "$(terraform output -raw repo_infra_local_access_key_id)"
terraform output -raw repo_infra_local_encrypted_secret_access_key \
  | base64 -d | gpg -d \
  | pass insert --force --multiline aws/repo-infra-local/secret-access-key
```

Nothing above writes the decrypted secret to a file or this repo — it
only ever passes through this one pipeline into `pass`.

### Rotating `repo-infra-local`

No automated reminder yet (tracked in the workspace's own `PARKED.md`)
— a recommended cadence of every 90 days, done by hand:

```bash
terraform apply -replace=aws_iam_access_key.repo_infra_local
```

then repeat the `pass insert` pair above — the old key stops working
the moment the new one is created (AWS allows at most two access keys
per user, and this identity only ever has one managed here), so there's
no separate deactivation step.

## k3s-bootstrap-local Identity

`k3s_bootstrap_local.tf` is the same shape as `repo-infra-local` above,
for `bootstrap/k3s-bootstrap`'s own `scripts/roll-out.sh` instead.
Simpler policy — that repo's Terraform only ever needs S3 read/write on
its own `k3s-bootstrap/*` state prefix, never IAM/OIDC management (it
manages Kubernetes RBAC and PersistentVolumes via the `kubernetes`
provider, not AWS resources). Only removes the `aws login` step from
that repo's own `roll-out.sh` — applying it still needs the k3s node's
own cluster-admin kubeconfig regardless, since it manages
privilege-defining Kubernetes RBAC (see that repo's own README).

### First apply: creating `k3s-bootstrap-local` and its access key

```bash
export TF_VAR_k3s_bootstrap_local_pgp_key="$(gpg --export 6D8B16CB662983A54B4AF1466F0B5C2AB1509600 | base64)"
terraform plan
terraform apply
```

```bash
pass insert --force --multiline aws/k3s-bootstrap-local/access-key-id <<< "$(terraform output -raw k3s_bootstrap_local_access_key_id)"
terraform output -raw k3s_bootstrap_local_encrypted_secret_access_key \
  | base64 -d | gpg -d \
  | pass insert --force --multiline aws/k3s-bootstrap-local/secret-access-key
```

### Rotating `k3s-bootstrap-local`

Same procedure and cadence as `repo-infra-local` above:

```bash
terraform apply -replace=aws_iam_access_key.k3s_bootstrap_local
```

then repeat the `pass insert` pair above.

## Account Baseline Security Hardening

`account_baseline.tf` manages a handful of account-wide, essentially
set-once security settings with no natural per-repository owner:

- **CloudTrail** — one trail (`account-baseline`) covering management
  events across all regions, logging to its own dedicated
  `jkandler-cloudtrail-logs` bucket (public access blocked, encrypted,
  logs expire after 365 days). Free from CloudTrail itself; the only
  cost is that bucket's S3 storage, fractions of a cent/month at this
  account's event volume.
- **IAM Access Analyzer** (`account-baseline`, account-scoped) — flags
  any IAM user, role, or S3 bucket reachable from outside the account.
  Zero cost.
- **S3 Block Public Access at the account level**
  (`aws_s3_account_public_access_block`) — a blanket safety net on top
  of whatever each individual bucket's own public-access block already
  does, so a future bucket created without one still can't be made
  public by accident.

Deliberately excludes GuardDuty, AWS Config, and Security Hub: real
ongoing cost, disproportionate to this account's own $10/month budget,
and largely redundant with everything already going through Terraform.

Root account MFA has no Terraform resource and isn't managed here —
check it by hand via IAM → Users (or the account root user's own
security credentials page) in the console.

Applies at the same cadence and trust level as everything else in this
root — root identity only, run alongside a normal `terraform plan`/
`terraform apply` here.

## Decommissioning

The bucket is not configured with `force_destroy`, so Terraform will refuse to
delete it while it contains state or retained object versions. Before any
decommissioning, back up the state and confirm that every dependent Terraform
configuration has been migrated elsewhere. Emptying a versioned bucket requires
deleting all object versions and delete markers, not only the current objects.
