#!/usr/bin/env bash
set -euo pipefail

output_root=${1:?empty output directory is required}
pack_root=/opt/ambit/runtime-pack/web-browser
mkdir -p "${output_root}"
"${pack_root}/conformance/runtime-guard.sh" web-browser "${output_root}"
task_tmp=${TMPDIR:?task-private TMPDIR is required}
runtime_root=${task_tmp}/web-conformance-runtime
test ! -e "${runtime_root}"
mkdir -m 0700 "${runtime_root}"
cleanup() {
  rm -rf -- "${runtime_root}"
}
trap cleanup EXIT
export HOME=${runtime_root}/home
export XDG_CACHE_HOME=${runtime_root}/cache
export XDG_CONFIG_HOME=${runtime_root}/config
export XDG_RUNTIME_DIR=${runtime_root}/run
export TMPDIR=${runtime_root}/tmp
mkdir -p "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}" "${TMPDIR}"
chmod 0700 "${XDG_RUNTIME_DIR}"
python3 "${pack_root}/conformance/render-probe.py" \
  --name web-static-html \
  --facet web_application \
  --media-type text/html \
  --source "${pack_root}/conformance/fixtures/static.html" \
  --receipt "${output_root}/web-render-probe.json"
node "${pack_root}/conformance/verify.mjs" "${output_root}"
cleanup
trap - EXIT
test -s "${output_root}/conformance-receipt.json"
test -s "${output_root}/web-render-probe.json"
