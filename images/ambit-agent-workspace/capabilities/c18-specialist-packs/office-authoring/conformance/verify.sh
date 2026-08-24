#!/usr/bin/env bash
set -euo pipefail

output_root=${1:?empty output directory is required}
pack_root=/opt/ambit/runtime-pack/office-authoring
mkdir -p "${output_root}"
"${pack_root}/conformance/runtime-guard.sh" office-authoring "${output_root}"
export HOME=${output_root}/home
export XDG_CACHE_HOME=${output_root}/cache
export XDG_CONFIG_HOME=${output_root}/config
export XDG_RUNTIME_DIR=${output_root}/run
mkdir -p "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
chmod 0700 "${XDG_RUNTIME_DIR}"

python3 "${pack_root}/conformance/verify.py" generate "${output_root}/fixtures"
mkdir -p "${output_root}/rendered"
for source in "${output_root}"/fixtures/*.xlsx "${output_root}"/fixtures/*.pptx; do
  profile=${output_root}/profiles/$(basename "${source}")
  mkdir -p "${profile}"
  soffice --headless --nologo --nodefault --nofirststartwizard \
    -env:UserInstallation="file://${profile}" \
    --convert-to pdf --outdir "${output_root}/rendered" "${source}" >/dev/null
done
for pdf in "${output_root}"/rendered/*.pdf; do
  stem=$(basename "${pdf}" .pdf)
  pdfinfo "${pdf}" > "${output_root}/rendered/${stem}.pdfinfo.txt"
  pdffonts "${pdf}" > "${output_root}/rendered/${stem}.pdffonts.txt"
  pdftotext -layout "${pdf}" "${output_root}/rendered/${stem}.txt"
  pdftoppm -png -r 96 "${pdf}" "${output_root}/rendered/${stem}" >/dev/null 2>&1
done
rm -rf "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}" \
  "${output_root}/profiles"
python3 "${pack_root}/conformance/verify.py" finalize "${output_root}"
test -s "${output_root}/conformance-receipt.json"
