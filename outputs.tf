output "state_bucket_name" {
  description = "Name of the Terraform state S3 bucket"
  value       = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  description = "ARN of the Terraform state S3 bucket"
  value       = aws_s3_bucket.terraform_state.arn
}

output "aws_region" {
  description = "AWS region containing the Terraform state bucket"
  value       = var.aws_region
}

output "shared_kms_key_arn" {
  description = "ARN of the shared CMK for AWS-managed encryption across this account"
  value       = aws_kms_key.shared.arn
}
