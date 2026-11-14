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

output "k3s_oidc_issuer" {
  description = "Public OIDC issuer URL of the k3s cluster, the first --service-account-issuer (ADR 0032)"
  value       = local.k3s_oidc_issuer
}

output "k3s_eso_role_arns" {
  description = "Per namespace, the IAM role its external-secrets ServiceAccount assumes (ADR 0032)"
  value       = { for namespace, role in aws_iam_role.k3s_eso : namespace => role.arn }
}
