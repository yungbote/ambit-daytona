#!/usr/bin/env bash
# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(git -C "$script_dir" rev-parse --show-toplevel)"
source_url="https://github.com/yungbote/ambit-daytona"
revision_token="SOURCE_REVISION_REQUIRED"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ambit-daytona-production-render.XXXXXX")"

cleanup() {
  find "$work_dir" -type f -delete
  rmdir "$work_dir"
}
trap cleanup EXIT

for command_name in curl gcloud git jq kubectl; do
  command -v "$command_name" >/dev/null || {
    echo "required production-render command is unavailable: $command_name" >&2
    exit 1
  }
done

raw_render="$work_dir/raw.yaml"
admitted_render="$work_dir/admitted.yaml"

kubectl kustomize --load-restrictor LoadRestrictionsNone "$script_dir" > "$raw_render"

mapfile -t rendered_images < <(
  sed -nE 's/^[[:space:]-]*image:[[:space:]]*"?([^"[:space:]]+)"?.*$/\1/p' "$raw_render" |
    sort -u
)

component_repositories=(
  us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/daytona-api
  us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/daytona-proxy
  us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/daytona-runner
  us-east4-docker.pkg.dev/mwcc-infrastructure/ambit/daytona-ssh-gateway
)

umask 077
registry_token="$(gcloud auth print-access-token)"
[[ -n "$registry_token" ]] || {
  echo 'gcloud returned an empty Artifact Registry access token' >&2
  exit 1
}
curl_config="$work_dir/curl.conf"
printf 'header = "Authorization: Bearer %s"\n' "$registry_token" > "$curl_config"
unset registry_token

inspect_labels() {
  local image="$1"
  local repository="${image%%@*}"
  local repository_path="${repository#us-east4-docker.pkg.dev/}"
  local digest="${image##*@}"
  local manifest_file="$work_dir/manifest-${repository##*/}.json"
  local error_file="$work_dir/image-inspect-error"
  local config_digest

  curl --config "$curl_config" --fail --silent --show-error --location \
    --connect-timeout 5 --max-time 20 --retry 2 --retry-all-errors \
    --header 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json' \
    "https://us-east4-docker.pkg.dev/v2/$repository_path/manifests/$digest" \
    > "$manifest_file" 2>"$error_file" || {
      echo "could not read immutable production manifest: $image" >&2
      sed -n '1,20p' "$error_file" >&2
      return 1
    }

  config_digest="$(jq -er '.config.digest' "$manifest_file")"
  curl --config "$curl_config" --fail --silent --show-error --location \
    --connect-timeout 5 --max-time 20 --retry 2 --retry-all-errors \
    "https://us-east4-docker.pkg.dev/v2/$repository_path/blobs/$config_digest" \
    2>"$error_file" |
    jq -ce '.config.Labels' || {
      echo "could not read OCI labels for production image: $image" >&2
      sed -n '1,20p' "$error_file" >&2
      return 1
    }
}

source_revision=""
for repository in "${component_repositories[@]}"; do
  matches=()
  for image in "${rendered_images[@]}"; do
    if [[ "$image" == "$repository"@sha256:* ]]; then
      matches+=("$image")
    fi
  done

  if [[ "${#matches[@]}" -ne 1 ]]; then
    echo "production render must contain exactly one immutable image for $repository" >&2
    exit 1
  fi

  image="${matches[0]}"
  digest="${image#*@sha256:}"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "production component image is not digest-pinned: $image" >&2
    exit 1
  }

  labels="$(inspect_labels "$image")"
  image_source="$(jq -er '.["org.opencontainers.image.source"]' <<<"$labels")"
  image_revision="$(jq -er '.["org.opencontainers.image.revision"]' <<<"$labels")"

  [[ "$image_source" == "$source_url" ]] || {
    echo "unexpected OCI source for $image: $image_source" >&2
    exit 1
  }
  [[ "$image_revision" =~ ^[0-9a-f]{40}$ ]] || {
    echo "OCI revision is not a full lowercase Git SHA for $image: $image_revision" >&2
    exit 1
  }

  if [[ -z "$source_revision" ]]; then
    source_revision="$image_revision"
  elif [[ "$image_revision" != "$source_revision" ]]; then
    echo "Daytona component images do not share one source revision" >&2
    exit 1
  fi
done

resolved_revision="$(git -C "$repo_root" rev-parse "$source_revision^{commit}" 2>/dev/null || true)"
if [[ -z "$resolved_revision" ]]; then
  # The operational infra repository carries a byte-identical derived copy of
  # this package, not Daytona's Git object database. Prove the public source
  # commit directly when rendering from that copy or from a shallow checkout.
  resolved_revision="$(
    curl --fail --silent --show-error --location \
      --connect-timeout 5 --max-time 20 --retry 2 --retry-all-errors \
      "https://api.github.com/repos/yungbote/ambit-daytona/commits/$source_revision" |
      jq -er '.sha'
  )"
fi
[[ "$resolved_revision" == "$source_revision" ]] || {
  echo "OCI source revision does not resolve to the exact public Git commit" >&2
  exit 1
}

token_count="$(grep -c "$revision_token" "$raw_render" || true)"
[[ "$token_count" -eq 5 ]] || {
  echo "expected five Daytona source-revision template annotations, found $token_count" >&2
  exit 1
}
sed "s/$revision_token/$source_revision/g" "$raw_render" > "$admitted_render"

if grep -En 'REQUIRED_|build-required|source-build-required|SOURCE_REVISION_REQUIRED' "$admitted_render" >&2; then
  echo 'production render contains an unresolved release input' >&2
  exit 1
fi
if grep -En 'daytona-oss-|daytona-(harbor-)?redis-ca|NODE_EXTRA_CA_CERTS|SSL_CERT_FILE|10\.160\.[0-9]+\.[0-9]+|6378' "$admitted_render" >&2; then
  echo 'production render contains a retired image or managed-Redis contract' >&2
  exit 1
fi

for image in "${rendered_images[@]}"; do
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || {
    echo "production render contains a mutable image: $image" >&2
    exit 1
  }
done

[[ "$(grep -Fc "ambit.sh/source-url: $source_url" "$admitted_render")" -eq 5 ]] || {
  echo 'expected five canonical Daytona source URL annotations' >&2
  exit 1
}
[[ "$(grep -Fc "ambit.sh/source-revision: $source_revision" "$admitted_render")" -eq 5 ]] || {
  echo 'Daytona workload annotations do not match admitted OCI provenance' >&2
  exit 1
}

[[ "$(grep -Fc 'networking.gke.io/certmap: ambit-daytona-public' "$admitted_render")" -eq 1 ]] \
  && [[ "$(grep -Fc 'value: ambit-daytona-gateway-ip' "$admitted_render")" -eq 1 ]] \
  && [[ "$(grep -Fc 'protocol: HTTPS' "$admitted_render")" -ge 1 ]] \
  && [[ "$(grep -Fc 'port: 443' "$admitted_render")" -ge 1 ]] \
  && [[ "$(grep -Fc 'proxy.daytona.ambit.sh' "$admitted_render")" -ge 4 ]] \
  && [[ "$(grep -Fc '*.proxy.daytona.ambit.sh' "$admitted_render")" -eq 2 ]] || {
    echo 'production Gateway does not represent proxy apex and deep-wildcard HTTPS/DNS routes' >&2
    exit 1
  }

redis_image='docker.io/library/redis@sha256:ff02b58f971e7d7d156a1267e283fcbbeee91773b6aa36c49dac28ecfe28eadf'
[[ "$(grep -Fc "image: $redis_image" "$admitted_render")" -eq 2 ]] \
  && [[ "$(grep -Fc 'name: redis-data' "$admitted_render")" -eq 1 ]] \
  && [[ "$(grep -Fc 'claimName: redis-data' "$admitted_render")" -eq 1 ]] \
  && [[ "$(grep -Fc 'name: harbor-redis-data' "$admitted_render")" -eq 1 ]] \
  && [[ "$(grep -Fc 'claimName: harbor-redis-data' "$admitted_render")" -eq 1 ]] || {
    echo 'authenticated in-cluster Redis workloads are absent or not immutable' >&2
    exit 1
  }

grep -Fq 'addr: harbor-redis.daytona-state.svc.cluster.local:6379' "$script_dir/harbor-values.yaml" \
  && grep -Fq 'existingSecret: daytona-harbor-redis' "$script_dir/harbor-values.yaml" || {
    echo 'Harbor does not use the authenticated in-cluster Redis contract' >&2
    exit 1
  }

printf 'verified Daytona component provenance at source revision %s\n' "$source_revision" >&2
cat "$admitted_render"
