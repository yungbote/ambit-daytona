#!/usr/bin/env bash
set -euo pipefail

output_root=${1:?empty output directory is required}
pack_root=/opt/ambit/runtime-pack/web-browser
mkdir -p "${output_root}"
"${pack_root}/conformance/runtime-guard.sh" web-browser "${output_root}"
export HOME=${output_root}/home
export XDG_CACHE_HOME=${output_root}/cache
export XDG_CONFIG_HOME=${output_root}/config
export XDG_RUNTIME_DIR=${output_root}/run
mkdir -p "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
chmod 0700 "${XDG_RUNTIME_DIR}"
node "${pack_root}/conformance/verify.mjs" "${output_root}"
rm -rf "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
test -s "${output_root}/conformance-receipt.json"
