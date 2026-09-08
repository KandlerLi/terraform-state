#!/usr/bin/env bash
# Mimics what a real CI pipeline would do for this repo's own apply,
# run locally -- minus AWS credentials. Unlike github/repo-infra's and
# bootstrap/k3s-bootstrap's own scripts/roll-out.sh, this one
# deliberately does NOT set up AWS credentials: this root manages the
# identities used to run the *other* two locally (julian, and now
# repo-infra-local/k3s-bootstrap-local), so it stays applied only as
# root/an admin-equivalent identity via an interactive `aws login`,
# same as ADR 0018's own "neither should flow through an agent session
# or get written anywhere, committed or not" principle already
# establishes for this exact root. Run that yourself first.
#
#   scripts/roll-out.sh plan
#   scripts/roll-out.sh apply
#
# What this script does automate: repo_infra_local_pgp_key and
# k3s_bootstrap_local_pgp_key are required variables with no default
# (deliberately -- see their own descriptions), so Terraform prompts
# for both on *every* apply in this root, even ones that don't touch
# either access key. Both are just a deterministic re-export of this
# workspace's existing GPG public key, safe to recompute every run.

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

cd "${repo_root}"

terraform init -input=false
terraform fmt -check -recursive
terraform validate
# -input=false on plan/apply too, not just init -- see
# github/repo-infra's own roll-out.sh for why (a missing/unexported
# required variable otherwise drops into a confusing interactive
# prompt instead of failing outright). Doesn't affect
# repo_infra_local_pgp_key/k3s_bootstrap_local_pgp_key above -- those
# are always exported by this script itself before this point.
terraform plan -input=false

if [ "${mode}" = "apply" ]; then
  # Interactive on purpose -- terraform's own plan-and-confirm prompt is
  # the review step, not -auto-approve. -input=false doesn't affect
  # that prompt, only variable-value prompts.
  terraform apply -input=false
fi
