#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: verify-deployment.sh ENV_FILE OUTPUT_RECEIPT' >&2
  exit 64
fi

env_file=$1
output=$2
[[ ${env_file} = /* && -f ${env_file} ]] || { echo 'ENV_FILE must be an absolute regular file' >&2; exit 64; }
[[ ${output} = /* && ! -e ${output} ]] || { echo 'OUTPUT_RECEIPT must be an unused absolute path' >&2; exit 64; }

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
state_root=$(sed -n 's/^AMBIT_DAYTONA_STATE_ROOT=//p' "${env_file}")
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || { echo 'invalid state root in ENV_FILE' >&2; exit 64; }
temporary=$(mktemp "${state_root}/evidence/.compose-config.XXXXXX.json")
cleanup() {
  if [[ -e ${temporary} ]]; then
    shred -u -- "${temporary}" >/dev/null 2>&1 || unlink "${temporary}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM
chmod 0600 "${temporary}"

docker compose --env-file "${env_file}" -f "${script_dir}/compose.yaml" config --format json > "${temporary}"
python3 "${script_dir}/verify-compose.py" \
  --compose-config "${temporary}" \
  --compose-source "${script_dir}/compose.yaml" \
  --capacity-lock "${script_dir}/capacity-profile.lock.json" \
  --environment "${env_file}" \
  --dex-config "${state_root}/config/dex.yaml" \
  --output "${output}"
