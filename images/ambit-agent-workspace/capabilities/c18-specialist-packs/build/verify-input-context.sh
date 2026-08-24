#!/usr/bin/env bash
set -euo pipefail

pack_id=${1:?pack id is required}
source_root=${2:-/source}
input_root=${3:-/inputs}
pack_source=${source_root}/${pack_id}

case "${pack_id}" in
  office-authoring|pdf-ocr|data-research)
    expected_roots=$'debian\npython'
    ;;
  web-browser)
    expected_roots=npm
    ;;
  *)
    echo "unsupported specialist pack: ${pack_id}" >&2
    exit 64
    ;;
esac

test -d "${input_root}"
test ! -L "${input_root}"
find "${input_root}" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
  | LC_ALL=C sort > /tmp/input-roots.actual
printf '%s\n' "${expected_roots}" | LC_ALL=C sort > /tmp/input-roots.expected
cmp /tmp/input-roots.expected /tmp/input-roots.actual
test -z "$(find "${input_root}" -type l -print -quit)"
test -z "$(find "${input_root}" -mindepth 1 ! -type d ! -type f -print -quit)"

verify_roster() {
  local directory=$1
  local manifest=$2
  local prefix=$3
  (
    cd "${input_root}"
    sha256sum -c "${pack_source}/locks/${manifest}"
  )
  cut -d ' ' -f 3 "${pack_source}/locks/${manifest}" \
    | LC_ALL=C sort > /tmp/input-files.expected
  find "${input_root}/${directory}" -maxdepth 1 -type f -printf "${prefix}/%f\n" \
    | LC_ALL=C sort > /tmp/input-files.actual
  cmp /tmp/input-files.expected /tmp/input-files.actual
}

if [[ ${pack_id} == web-browser ]]; then
  verify_roster npm npm-archives.sha256 npm
else
  verify_roster debian debian-archives.sha256 debian
  verify_roster python python-wheels.sha256 python
  python3 -B "${source_root}/certification/wheel_lock.py" verify \
    --wheel-directory "${input_root}/python" \
    --lock "${pack_source}/locks/python-wheels.lock.json"
fi
