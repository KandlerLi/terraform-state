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

output "logs_kms_key_arn" {
  description = "ARN of the shared CMK for CloudWatch Logs encryption"
  value       = aws_kms_key.logs.arn
}
