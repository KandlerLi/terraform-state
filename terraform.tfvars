# Non-secret deployment configuration. Both variables here are
# required (no default in variables.tf) -- explicitly listed as an
# exception to this repo's own blanket *.tfvars gitignore rule (see
# .gitignore), since this file holds no secret value itself. This
# root is human-applied only, never CI, so this is also the only
# place either value is set.
aws_region        = "eu-central-1"
state_bucket_name = "jkandler-terraform-state"
