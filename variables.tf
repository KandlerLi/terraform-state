variable "aws_region" {
  description = "AWS region in which to create the state bucket"
  type        = string
}

variable "state_bucket_name" {
  description = "Name of the S3 bucket for Terraform state"
  type        = string
}
