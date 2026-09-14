terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "aws_s3_bucket" "terraform_state" {
  bucket = var.state_bucket_name
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

#trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  # Deliberately still AES256, not the shared CMK -- trivy's AWS-0132
  # flags this, but fixing it isn't a narrow change like the CloudTrail
  # bucket's own version of the same finding: every repo's CI role in
  # this whole workspace reads/writes state here via s3:GetObject/
  # PutObject, and SSE-KMS would require every one of them to also gain
  # kms:GenerateDataKey/kms:Decrypt on the shared key or their own
  # terraform plan/apply would start failing account-wide the moment
  # this applies. Suppressed rather than left visibly failing so the
  # required status check (repo-infra's own config.yml) means something
  # -- needs a full audit of every repo's IAM permissions first
  # (PARKED.md) before this can actually be fixed, not something to flip
  # alongside an unrelated KMS-key PR.
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Fixes trivy's AWS-0089 -- self-logging under a distinct prefix, same
# reasoning as cloudtrail_logs' own identical fix in account_baseline.tf.
# Safe/isolated unlike the encryption finding above: access-log delivery
# is a separate write path handled by the S3 log delivery service itself,
# not any of the many IAM roles that read/write this bucket's objects.
resource "aws_s3_bucket_logging" "terraform_state" {
  bucket        = aws_s3_bucket.terraform_state.id
  target_bucket = aws_s3_bucket.terraform_state.id
  target_prefix = "access-logs/"
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
