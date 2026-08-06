#!/usr/bin/env bash
# Copyright 2026 Ambit
# SPDX-License-Identifier: AGPL-3.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
render_dir="$(mktemp -d "${TMPDIR:-/tmp}/ambit-harbor-render.XXXXXX")"
cleanup() {
  find "$render_dir" -type f -delete
  rmdir "$render_dir"
}
trap cleanup EXIT

tee "$render_dir/resources.yaml" >/dev/null
cp "$script_dir/harbor-core-runtime-patch.yaml" "$render_dir/"
cp "$script_dir/harbor-exporter-runtime-patch.yaml" "$render_dir/"
cp "$script_dir/harbor-jobservice-runtime-patch.yaml" "$render_dir/"

printf '%s\n' \
  'apiVersion: kustomize.config.k8s.io/v1beta1' \
  'kind: Kustomization' \
  'resources:' \
  '  - resources.yaml' \
  'patches:' \
  '  - path: harbor-core-runtime-patch.yaml' \
  '  - path: harbor-exporter-runtime-patch.yaml' \
  '  - path: harbor-jobservice-runtime-patch.yaml' \
  > "$render_dir/kustomization.yaml"

kubectl kustomize "$render_dir"
