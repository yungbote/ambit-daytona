#!/usr/bin/env bash
set -euo pipefail

pack_id=${1:?pack id is required}
source_root=${2:-/source}
input_root=${3:-/inputs}
pack_source=${source_root}/${pack_id}
pack_root=/opt/ambit/runtime-pack/${pack_id}

case "${pack_id}" in
  office-authoring|pdf-ocr|data-research) ;;
  *)
    echo "unsupported Debian/Python specialist pack: ${pack_id}" >&2
    exit 64
    ;;
esac

test "$(python3 --version)" = "Python 3.14.7"
test -d "${input_root}/debian"
test -d "${input_root}/python"
install -d -m 0555 "${pack_root}/locks" "${pack_root}/conformance"
install -m 0444 "${pack_source}/pack.lock.json" "${pack_root}/pack.lock.json"
cp -a "${pack_source}/locks/." "${pack_root}/locks/"
cp -a "${pack_source}/conformance/." "${pack_root}/conformance/"
cp -a "${source_root}/conformance/runtime-guard.sh" "${pack_root}/conformance/"
cp -a "${source_root}/conformance/common.py" "${pack_root}/conformance/"

if [[ ${pack_id} == office-authoring ]]; then
  dpkg -i \
    "${input_root}"/debian/libncursesw6_*.deb \
    "${input_root}"/debian/libproc2-0_*.deb \
    "${input_root}"/debian/procps_*.deb \
    "${input_root}"/debian/libtext-charwidth-perl_*.deb \
    "${input_root}"/debian/libtext-wrapi18n-perl_*.deb \
    "${input_root}"/debian/sensible-utils_*.deb \
    "${input_root}"/debian/ucf_*.deb
  base_debs=()
  for file in "${input_root}"/debian/*.deb; do
    case "$(basename "${file}")" in
      libreoffice-calc-nogui_*|libreoffice-draw-nogui_*|libreoffice-impress-nogui_*) ;;
      *) base_debs+=("${file}") ;;
    esac
  done
  dpkg -i "${base_debs[@]}"
  dpkg -i \
    "${input_root}"/debian/libreoffice-calc-nogui_*.deb \
    "${input_root}"/debian/libreoffice-draw-nogui_*.deb \
    "${input_root}"/debian/libreoffice-impress-nogui_*.deb
else
  dpkg -i "${input_root}"/debian/*.deb
fi

dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}=${Version}\n' \
  | awk '$1 == "ii" {print $2}' | LC_ALL=C sort > /tmp/installed-dpkg.actual
cmp "${pack_root}/locks/installed-dpkg.lock" /tmp/installed-dpkg.actual

python3 -m venv "${pack_root}/python"
"${pack_root}/python/bin/python" -m pip install \
  --no-index --no-deps --only-binary=:all: --require-hashes \
  --find-links="${input_root}/python" \
  -r "${pack_root}/locks/requirements.lock"
"${pack_root}/python/bin/python" -m pip check
"${pack_root}/python/bin/python" - "${pack_root}/locks/requirements.lock" <<'PY'
import importlib.metadata
import pathlib
import re
import sys

lock = pathlib.Path(sys.argv[1])
expected = {}
for line in lock.read_text(encoding="utf-8").splitlines():
    requirement, _, _ = line.partition(" --hash=")
    name, version = requirement.split("==", 1)
    expected[re.sub(r"[-_.]+", "-", name).lower()] = version
actual = {
    re.sub(r"[-_.]+", "-", distribution.metadata["Name"]).lower(): distribution.version
    for distribution in importlib.metadata.distributions()
    if distribution.metadata["Name"]
}
actual.pop("pip", None)
assert actual == expected, (sorted(actual.items()), sorted(expected.items()))
PY

groupadd --gid 1000 daytona
useradd --uid 1000 --gid 1000 --home-dir /workspace --shell /bin/bash daytona
install -d -m 0700 -o daytona -g daytona /workspace

rm -rf \
  /root/.cache \
  /tmp/installed-dpkg.actual \
  /usr/local/lib/python3.14/ensurepip \
  /usr/local/lib/python3.14/site-packages/pip \
  /usr/local/lib/python3.14/site-packages/pip-* \
  "${pack_root}/python/lib/python3.14/site-packages/pip" \
  "${pack_root}"/python/lib/python3.14/site-packages/pip-* \
  /var/cache/apt/* \
  /var/lib/apt/lists/*
rm -f \
  /usr/bin/apk \
  /usr/bin/apt \
  /usr/bin/apt-* \
  /usr/bin/aptitude* \
  /usr/bin/dpkg \
  /usr/bin/dpkg-* \
  /usr/bin/ldd \
  /usr/local/bin/pip \
  /usr/local/bin/pip3 \
  /usr/local/bin/pip3.14 \
  "${pack_root}"/python/bin/pip \
  "${pack_root}"/python/bin/pip3 \
  "${pack_root}"/python/bin/pip3.14 \
  "${pack_root}"/python/bin/easy_install*
find "${pack_root}" -type d -name __pycache__ -prune -exec rm -rf '{}' +
find "${pack_root}" -type d -exec chmod 0555 '{}' +
find "${pack_root}" -type f -exec chmod a-w,go+r '{}' +
find "${pack_root}/conformance" -type f -name '*.sh' -exec chmod 0555 '{}' +

hash -r
for installer in apk apt apt-get dpkg dpkg-deb pip pip3 uv npm npx pnpm yarn corepack conda mamba micromamba; do
  if command -v "${installer}" >/dev/null 2>&1; then
    echo "runtime installer survived image construction: ${installer}" >&2
    exit 1
  fi
done
python3 - <<'PY'
import importlib.util

assert importlib.util.find_spec("pip") is None
assert importlib.util.find_spec("ensurepip") is None
PY
