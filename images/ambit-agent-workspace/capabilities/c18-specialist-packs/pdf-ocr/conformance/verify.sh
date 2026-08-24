#!/usr/bin/env bash
set -euo pipefail

output_root=${1:?empty output directory is required}
pack_root=/opt/ambit/runtime-pack/pdf-ocr
mkdir -p "${output_root}"
"${pack_root}/conformance/runtime-guard.sh" pdf-ocr "${output_root}"
export HOME=${output_root}/home
export XDG_CACHE_HOME=${output_root}/cache
export XDG_CONFIG_HOME=${output_root}/config
export XDG_RUNTIME_DIR=${output_root}/run
mkdir -p "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}" \
  "${output_root}/checks"
chmod 0700 "${XDG_RUNTIME_DIR}"

python3 "${pack_root}/conformance/verify.py" generate "${output_root}/fixtures"
unpaper --overwrite "${output_root}/fixtures/scan.pgm" "${output_root}/checks/cleaned.pgm" \
  >/dev/null 2>&1
tesseract "${output_root}/checks/cleaned.pgm" stdout --psm 6 \
  > "${output_root}/checks/ocr.txt" 2>/dev/null
tesseract "${output_root}/checks/cleaned.pgm" "${output_root}/checks/ocr" pdf --psm 6 \
  >/dev/null 2>&1

for pdf in "${output_root}"/fixtures/*.pdf; do
  stem=$(basename "${pdf}" .pdf)
  qpdf --check "${pdf}" > "${output_root}/checks/${stem}.qpdf.txt" 2>&1
  pdfinfo "${pdf}" > "${output_root}/checks/${stem}.pdfinfo.txt"
  pdftotext -layout "${pdf}" "${output_root}/checks/${stem}.txt"
  pdftoppm -f 1 -singlefile -png -r 96 "${pdf}" \
    "${output_root}/checks/${stem}-1" >/dev/null 2>&1
done
qpdf --check "${output_root}/checks/ocr.pdf" > "${output_root}/checks/ocr.qpdf.txt" 2>&1
pdftotext -layout "${output_root}/checks/ocr.pdf" "${output_root}/checks/ocr-pdf.txt"
set +e
pdfsig "${output_root}/fixtures/redacted.pdf" \
  > "${output_root}/checks/signature-inspection.txt" 2>&1
signature_status=$?
set -e
# Poppler 25.03 returns 2 when the inspected PDF has no signature fields. That
# negative result is the expected proof for this pack: signing remains an
# external approved effect, and the runtime fixture must not smuggle a key or
# signature into the image.
test "${signature_status}" = 2
grep -Fi 'does not contain any signatures' \
  "${output_root}/checks/signature-inspection.txt" >/dev/null
exiftool -j "${output_root}/fixtures/metadata-edited.pdf" \
  > "${output_root}/checks/metadata.json"
gs -dPDFA=2 -dBATCH -dNOPAUSE -dSAFER \
  -sColorConversionStrategy=RGB -sDEVICE=pdfwrite -dPDFACompatibilityPolicy=1 \
  -sOutputFile="${output_root}/checks/pdfa.pdf" \
  /usr/share/ghostscript/10.05.1/lib/PDFA_def.ps \
  "${output_root}/fixtures/redacted.pdf" >/dev/null 2>&1
qpdf --check "${output_root}/checks/pdfa.pdf" \
  > "${output_root}/checks/pdfa.qpdf.txt" 2>&1

rm -rf "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
python3 "${pack_root}/conformance/verify.py" finalize "${output_root}"
test -s "${output_root}/conformance-receipt.json"
