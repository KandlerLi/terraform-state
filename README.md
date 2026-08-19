# Terraform State Bootstrap

This Terraform configuration creates the central S3 bucket used as the remote
state backend by the infrastructure repositories. State locking uses S3 lock
files, so no DynamoDB table is required.

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

## Decommissioning

The bucket is not configured with `force_destroy`, so Terraform will refuse to
delete it while it contains state or retained object versions. Before any
decommissioning, back up the state and confirm that every dependent Terraform
configuration has been migrated elsewhere. Emptying a versioned bucket requires
deleting all object versions and delete markers, not only the current objects.
