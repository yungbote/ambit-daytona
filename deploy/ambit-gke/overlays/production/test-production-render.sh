#!/usr/bin/env bash
# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ambit-daytona-production-test.XXXXXX")"

cleanup() {
  find "$work_dir" -type f -delete
  rmdir "$work_dir"
}
trap cleanup EXIT

for command_name in git grep helm kubectl sed sort; do
  command -v "$command_name" >/dev/null || {
    echo "required production-render test command is unavailable: $command_name" >&2
    exit 1
  }
done

raw_render="$work_dir/raw.yaml"
harbor_render="$work_dir/harbor.yaml"
harbor_post_render="$work_dir/harbor-post.yaml"

kubectl kustomize --load-restrictor LoadRestrictionsNone "$script_dir" > "$raw_render"

[[ "$(grep -Fc 'ambit.sh/source-revision: SOURCE_REVISION_REQUIRED' "$raw_render")" -eq 5 ]]
[[ "$(grep -Fc 'ambit.sh/source-url: https://github.com/yungbote/ambit-daytona' "$raw_render")" -eq 5 ]]
[[ "$(grep -Fc 'ambit.sh/source-revision: 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a' "$raw_render")" -eq 1 ]]
if grep -En 'REQUIRED_|build-required|source-build-required|9cfc0e9a2987b55489052e8b0479f6b33ed83d5a' "$raw_render" >&2; then
  echo 'raw production render contains a stale or unresolved non-provenance input' >&2
  exit 1
fi
if grep -En 'daytona-oss-|daytona-(harbor-)?redis-ca|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|10\.160\.[0-9]+\.[0-9]+|6378' "$raw_render" >&2; then
  echo 'raw production render retains a retired release or managed-Redis contract' >&2
  exit 1
fi

mapfile -t kustomize_images < <(
  sed -nE 's/^[[:space:]-]*image:[[:space:]]*"?([^"[:space:]]+)"?.*$/\1/p' "$raw_render" |
    sort -u
)
[[ "${#kustomize_images[@]}" -ge 1 ]]
for image in "${kustomize_images[@]}"; do
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || {
    echo "mutable Kustomize image: $image" >&2
    exit 1
  }
done

redis_image='docker.io/library/redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf'
[[ "$(grep -Fc "image: $redis_image" "$raw_render")" -eq 2 ]]
[[ "$(grep -Fc 'REDIS_HOST: redis' "$raw_render")" -eq 2 ]]
[[ "$(grep -Fc 'REDIS_TLS: "false"' "$raw_render")" -eq 2 ]]
[[ "$(grep -Fc 'name: daytona-api-secrets' "$raw_render")" -ge 2 ]]
[[ "$(grep -Fc 'name: daytona-harbor-redis' "$raw_render")" -ge 2 ]]

[[ "$(grep -Fc 'networking.gke.io/certmap: ambit-daytona-public' "$raw_render")" -eq 1 ]]
[[ "$(grep -Fc 'value: ambit-daytona-gateway-ip' "$raw_render")" -eq 1 ]]
[[ "$(grep -Fc '*.proxy.daytona.ambit.sh' "$raw_render")" -eq 2 ]]

helm template daytona-harbor "$script_dir/charts/harbor-1.19.2/harbor" \
  --namespace daytona-state \
  --values "$script_dir/harbor-values.yaml" \
  > "$harbor_render"
"$script_dir/harbor-post-renderer.sh" < "$harbor_render" > "$harbor_post_render"

mapfile -t harbor_images < <(
  sed -nE 's/^[[:space:]-]*image:[[:space:]]*"?([^"[:space:]]+)"?.*$/\1/p' "$harbor_post_render" |
    sort -u
)
[[ "${#harbor_images[@]}" -ge 1 ]]
for image in "${harbor_images[@]}"; do
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || {
    echo "mutable Harbor image: $image" >&2
    exit 1
  }
done

grep -Fq 'addr: harbor-redis.daytona-state.svc.cluster.local:6379' "$script_dir/harbor-values.yaml"
grep -Fq 'existingSecret: daytona-harbor-redis' "$script_dir/harbor-values.yaml"
! grep -Fq 'caBundleSecretName' "$script_dir/harbor-values.yaml"

if [[ -f "$repo_root/cloudbuild.ambit.yaml" ]]; then
  grep -Fq '_SOURCE_REVISION: ${COMMIT_SHA}' "$repo_root/cloudbuild.ambit.yaml"
  grep -Fq '_TAG: ${COMMIT_SHA}' "$repo_root/cloudbuild.ambit.yaml"
  [[ "$(grep -Fc -- '--label=org.opencontainers.image.revision=${_SOURCE_REVISION}' "$repo_root/cloudbuild.ambit.yaml")" -eq 4 ]]
  [[ "$(grep -Fc -- '--label=org.opencontainers.image.source=${_SOURCE_URL}' "$repo_root/cloudbuild.ambit.yaml")" -eq 4 ]]
  ! grep -Fq 'daytona-oss-' "$repo_root/cloudbuild.ambit.yaml"
fi
if [[ -f "$repo_root/cloudbuild.minio.yaml" ]]; then
  grep -Fq 'for attempt in 1 2 3' "$repo_root/cloudbuild.minio.yaml"
  grep -Fq 'docker push "$$image"' "$repo_root/cloudbuild.minio.yaml"
  grep -Fq 'sleep 5' "$repo_root/cloudbuild.minio.yaml"
fi

if [[ "${1:-}" == '--live' ]]; then
  admitted_render="$work_dir/admitted.yaml"
  "$script_dir/render-production.sh" > "$admitted_render"
  ! grep -Eq 'REQUIRED_|build-required|source-build-required|SOURCE_REVISION_REQUIRED' "$admitted_render"
fi

echo 'Daytona production render tests passed'
