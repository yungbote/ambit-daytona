#!/usr/bin/env bash
set -euo pipefail

source_root=${1:-/source}
revision=${BUILD_SOURCE_REVISION:-}
tree=${BUILD_SOURCE_TREE:-}
source_set=${BUILD_SOURCE_SET_SHA256:-}

[[ ${revision} =~ ^[0-9a-f]{40}$ ]]
[[ ${tree} =~ ^[0-9a-f]{40}$ ]]
[[ ${source_set} =~ ^[0-9a-f]{64}$ ]]
test "$(sha256sum "${source_root}/source-contracts.sha256" | cut -d ' ' -f 1)" = \
  "${source_set}"
(
  cd "${source_root}"
  sha256sum -c source-contracts.sha256
)
