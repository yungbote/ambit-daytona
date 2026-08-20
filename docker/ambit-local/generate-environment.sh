#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: generate-environment.sh OUTPUT_ENV STATE_ROOT

Required pre-set variables (all images must be immutable @sha256 references):
  AMBIT_DAYTONA_API_IMAGE
  AMBIT_DAYTONA_PROXY_IMAGE
  AMBIT_DAYTONA_RUNNER_IMAGE
  AMBIT_DAYTONA_POSTGRES_IMAGE
  AMBIT_DAYTONA_REDIS_IMAGE
  AMBIT_DAYTONA_REGISTRY_IMAGE
  AMBIT_DAYTONA_MINIO_IMAGE
  AMBIT_DAYTONA_MINIO_MC_IMAGE
  AMBIT_DAYTONA_DEX_IMAGE
  AMBIT_C16B_RUNTIME_OCI_REFERENCE

The output must not already exist. State is created only below an absolute
/home path. Secrets are generated locally and written with mode 0600.
EOF
}

if [[ ${1:-} == --help && $# -eq 1 ]]; then
  usage
  exit 0
fi
if [[ $# -ne 2 ]]; then
  usage >&2
  exit 64
fi

output=$1
state_root=$2
[[ ${output} = /* ]] || { echo "OUTPUT_ENV must be absolute" >&2; exit 64; }
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || {
  echo "STATE_ROOT must be a specific absolute path below /home" >&2
  exit 64
}
[[ ${state_root} != *'/../'* && ${state_root} != */.. && ${state_root} != *'//'* ]] || {
  echo "STATE_ROOT must not contain traversal or empty path components" >&2
  exit 64
}
[[ $(realpath -m -- "${state_root}") == "${state_root}" ]] || {
  echo "STATE_ROOT must not traverse a symlinked or non-canonical path" >&2
  exit 64
}
[[ ! -e ${output} ]] || { echo "OUTPUT_ENV already exists: ${output}" >&2; exit 65; }

required_images=(
  AMBIT_DAYTONA_API_IMAGE
  AMBIT_DAYTONA_PROXY_IMAGE
  AMBIT_DAYTONA_RUNNER_IMAGE
  AMBIT_DAYTONA_POSTGRES_IMAGE
  AMBIT_DAYTONA_REDIS_IMAGE
  AMBIT_DAYTONA_REGISTRY_IMAGE
  AMBIT_DAYTONA_MINIO_IMAGE
  AMBIT_DAYTONA_MINIO_MC_IMAGE
  AMBIT_DAYTONA_DEX_IMAGE
  AMBIT_C16B_RUNTIME_OCI_REFERENCE
)
for variable in "${required_images[@]}"; do
  value=${!variable:-}
  if [[ ! ${value} =~ ^[a-z0-9][a-z0-9.:-]*(/[a-z0-9][a-z0-9._/-]*)+@sha256:[0-9a-f]{64}$ ]]; then
    echo "${variable} must be an exact lowercase image@sha256 reference" >&2
    exit 64
  fi
done

mkdir -p "$(dirname "${output}")" "${state_root}/config"
for directory in outer-docker outer-containerd postgres redis minio registry dex runner-docker runner-log evidence; do
  mkdir -p "${state_root}/${directory}"
  [[ ! -L ${state_root}/${directory} ]] || { echo "state subdirectory is a symlink: ${directory}" >&2; exit 66; }
done
chmod 0700 "${state_root}" "${state_root}/config" "${state_root}/postgres" \
  "${state_root}/redis" "${state_root}/minio" "${state_root}/registry" \
  "${state_root}/dex" "${state_root}/runner-docker" "${state_root}/runner-log" \
  "${state_root}/evidence" "${state_root}/outer-docker" "${state_root}/outer-containerd"

temporary=$(mktemp "$(dirname "${output}")/.ambit-daytona-env.XXXXXX")
cleanup() {
  rm -f -- "${temporary}"
}
trap cleanup EXIT INT TERM
umask 077

random_hex() {
  openssl rand -hex "$1"
}

{
  printf 'AMBIT_DAYTONA_API_IMAGE=%s\n' "${AMBIT_DAYTONA_API_IMAGE}"
  printf 'AMBIT_DAYTONA_PROXY_IMAGE=%s\n' "${AMBIT_DAYTONA_PROXY_IMAGE}"
  printf 'AMBIT_DAYTONA_RUNNER_IMAGE=%s\n' "${AMBIT_DAYTONA_RUNNER_IMAGE}"
  printf 'AMBIT_DAYTONA_POSTGRES_IMAGE=%s\n' "${AMBIT_DAYTONA_POSTGRES_IMAGE}"
  printf 'AMBIT_DAYTONA_REDIS_IMAGE=%s\n' "${AMBIT_DAYTONA_REDIS_IMAGE}"
  printf 'AMBIT_DAYTONA_REGISTRY_IMAGE=%s\n' "${AMBIT_DAYTONA_REGISTRY_IMAGE}"
  printf 'AMBIT_DAYTONA_MINIO_IMAGE=%s\n' "${AMBIT_DAYTONA_MINIO_IMAGE}"
  printf 'AMBIT_DAYTONA_MINIO_MC_IMAGE=%s\n' "${AMBIT_DAYTONA_MINIO_MC_IMAGE}"
  printf 'AMBIT_DAYTONA_DEX_IMAGE=%s\n' "${AMBIT_DAYTONA_DEX_IMAGE}"
  printf 'AMBIT_C16B_RUNTIME_OCI_REFERENCE=%s\n' "${AMBIT_C16B_RUNTIME_OCI_REFERENCE}"
  printf 'AMBIT_DAYTONA_STATE_ROOT=%s\n' "${state_root}"
  printf 'AMBIT_DAYTONA_API_PORT=33000\n'
  printf 'AMBIT_DAYTONA_PROXY_PORT=34000\n'
  printf 'AMBIT_DAYTONA_DEX_PORT=35556\n'
  printf 'AMBIT_DAYTONA_REGISTRY_PORT=36000\n'
  printf 'AMBIT_DAYTONA_ADMIN_API_KEY=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_ENCRYPTION_KEY=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_ENCRYPTION_SALT=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_POSTGRES_PASSWORD=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_REDIS_PASSWORD=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_MINIO_ACCESS_KEY=%s\n' "$(random_hex 16)"
  printf 'AMBIT_DAYTONA_MINIO_SECRET_KEY=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_PROXY_API_KEY=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_RUNNER_API_KEY=%s\n' "$(random_hex 32)"
  printf 'AMBIT_DAYTONA_HEALTH_API_KEY=%s\n' "$(random_hex 32)"
} > "${temporary}"
chmod 0600 "${temporary}"
mv -- "${temporary}" "${output}"

cat > "${state_root}/config/dex.yaml" <<EOF
issuer: http://dex:5556/dex
storage:
  type: sqlite3
  config:
    file: /var/dex/dex.db
web:
  http: 0.0.0.0:5556
  allowedOrigins:
    - http://127.0.0.1:33000
staticClients:
  - id: ambit-daytona-local
    redirectURIs:
      - http://127.0.0.1:33000/dashboard
      - http://127.0.0.1:33000/api/oauth2-redirect.html
      - http://proxy.localhost:34000/callback
    name: Ambit local Daytona
    public: true
enablePasswordDB: false
EOF
chmod 0600 "${state_root}/config/dex.yaml"
trap - EXIT INT TERM

printf 'created %s and isolated state root %s\n' "${output}" "${state_root}"
