terraform {
  required_version = ">= 1.10.0"

  backend "s3" {
    bucket       = "jkandler-terraform-state"
    key          = "terraform-state/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    use_lockfile = true
  }
}