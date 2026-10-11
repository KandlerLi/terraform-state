#!/usr/bin/env bash
# Local plan/apply. Run aws login as root first; this script never sets AWS credentials. See README.

set -euo pipefail

usage() {
  echo "usage: $(basename "$0") plan|apply" >&2
  exit 1
}

[ $# -eq 1 ] || usage
mode="$1"
case "$mode" in
  plan | apply) ;;
  *) usage ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "${script_dir}")"

gpg_fingerprint="6D8B16CB662983A54B4AF1466F0B5C2AB1509600"
export TF_VAR_repo_infra_local_pgp_key="$(gpg --export "${gpg_fingerprint}" | base64)"
export TF_VAR_k3s_bootstrap_local_pgp_key="$(gpg --export "${gpg_fingerprint}" | base64)"
export TF_VAR_home_infra_local_pgp_key="$(gpg --export "${gpg_fingerprint}" | base64)"

cd "${repo_root}"

terraform init -input=false
terraform fmt -check -recursive
terraform validate
# -input=false: fail on a missing variable instead of prompting for it.
terraform plan -input=false

if [ "${mode}" = "apply" ]; then
  # Interactive on purpose: terraform's own confirm prompt is the review step.
  terraform apply -input=false
fi
