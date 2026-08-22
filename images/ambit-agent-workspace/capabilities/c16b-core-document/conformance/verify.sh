#!/usr/bin/env bash
set -euo pipefail

output_root="${1:-/workspace/c16b-conformance}"
pack_root=/opt/ambit/runtime-pack/core-document
source_root="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
helper_source_root="${3:?backend helper source root is required}"

mkdir -p "${output_root}"
if find "${output_root}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "conformance output must be an empty directory: ${output_root}" >&2
  exit 1
fi
if [[ $(id -u) != "1000" || $(id -un) != "daytona" ]]; then
  echo "runtime-user-gate: expected uid 1000 user daytona" >&2
  exit 91
fi
if [[ -S /var/run/docker.sock ]]; then
  echo "host-socket-gate: /var/run/docker.sock is forbidden" >&2
  exit 92
fi
export HOME="${output_root}/home"
export XDG_CACHE_HOME="${output_root}/cache"
export XDG_CONFIG_HOME="${output_root}/config"
export XDG_RUNTIME_DIR="${output_root}/run"
mkdir -p "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
chmod 0700 "${XDG_RUNTIME_DIR}"

test ! -w "${pack_root}"
test "$(python3 -c 'import locale; print(locale.getpreferredencoding(False))')" = "UTF-8"
test "${LANG}" = "C.UTF-8"
test "${LC_ALL}" = "C.UTF-8"
if env | cut -d= -f1 | grep -Eiq '(api[_-]?key|password|private[_-]?key|secret|token)'; then
  echo "secret-shaped environment variable reached the runtime" >&2
  exit 1
fi

test "$(python3 --version)" = "Python 3.14.7"
bash --version | grep -F 'GNU bash, version 5.3' >/dev/null
sha256sum --version | grep -F 'coreutils) 9.11' >/dev/null
find --version | grep -F 'find (GNU findutils) 4.11.0' >/dev/null
diff --version | grep -F 'diff (GNU diffutils) 3.12' >/dev/null
file --version | grep -F 'file-5.48' >/dev/null
awk --version | grep -F 'GNU Awk 5.4.1' >/dev/null
grep --version | grep -F 'grep (GNU grep) 3.12' >/dev/null
ps --version | grep -F 'procps-ng 4.0.7' >/dev/null
sed --version | grep -F 'sed (GNU sed) 4.10' >/dev/null
test "$(command -v ambit-atomic-materialize)" = "${pack_root}/bin/ambit-atomic-materialize"

python3 - "${pack_root}" "${output_root}/python-runtime-receipt.json" "${helper_source_root}" "${source_root}" <<'PY'
import hashlib
import importlib.metadata
import importlib.util
import json
import pathlib
import stat
import sys

from lxml import etree

pack_root = pathlib.Path(sys.argv[1])
receipt_path = pathlib.Path(sys.argv[2])
helper_source_root = pathlib.Path(sys.argv[3])
pack_source_root = pathlib.Path(sys.argv[4])
lock = json.loads((helper_source_root / "materializer.lock.json").read_text())
toolchain = json.loads((pack_source_root / "toolchain-manifest.json").read_text())
helper = pack_root / "bin" / "ambit-atomic-materialize"
helper_metadata = helper.lstat()
assert stat.S_ISREG(helper_metadata.st_mode) and not helper.is_symlink()
assert stat.S_IMODE(helper_metadata.st_mode) == 0o555
assert helper_metadata.st_uid == 0 and helper_metadata.st_gid == 0
assert helper_metadata.st_nlink == 1
assert hashlib.sha256(helper.read_bytes()).hexdigest() == lock["binary"]["sha256"]
materializer = toolchain["atomicMaterializer"]
assert materializer["binarySha256"] == lock["binary"]["sha256"]
assert materializer["protocolDigest"] == lock["protocol"]["digest"]
assert materializer["treeProtocolDigest"] == lock["protocol"]["treeDigest"]
versions = {
    name: importlib.metadata.version(name)
    for name in ("cobble", "lxml", "mammoth", "python-docx", "typing-extensions")
}
assert versions == {
    "cobble": "0.1.4",
    "lxml": "6.1.2",
    "mammoth": "1.12.1",
    "python-docx": "1.2.0",
    "typing-extensions": "4.16.0",
}
for installer in ("pip", "setuptools", "uv"):
    assert importlib.util.find_spec(installer) is None, installer
receipt_path.write_text(
    json.dumps(
        {
            "schema": "ambit.runtime-pack-python-runtime/v1",
            "outcome": "passed",
            "packages": versions,
            "lxmlRuntime": {
                "lxml": list(etree.LXML_VERSION),
                "libxml": list(etree.LIBXML_VERSION),
                "libxslt": list(etree.LIBXSLT_VERSION),
            },
            "runtimeInstallers": "absent",
            "helperSha256": lock["binary"]["sha256"],
            "helperProtocolDigest": materializer["protocolDigest"],
            "helperTreeProtocolDigest": materializer["treeProtocolDigest"],
            "helperIdentity": {
                "mode": "0555",
                "uid": helper_metadata.st_uid,
                "gid": helper_metadata.st_gid,
                "linkCount": helper_metadata.st_nlink,
            },
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
PY

awk '/^P:/ { package=substr($0,3) } /^V:/ { print package "=" substr($0,3) }' \
  /lib/apk/db/installed | LC_ALL=C sort > "${output_root}/apk-packages.actual.lock"
cmp "${source_root}/apk-packages.lock" "${output_root}/apk-packages.actual.lock"

absent_commands=(
  apk pip pip3 uv node npm npx pyright tsc ts-node typescript-language-server
  libreoffice soffice qpdf pdfinfo pdftotext pdftoppm gs tesseract pandoc chromium
  ffmpeg magick convert dot gcc cc g++ go rustc cargo ldd
)
for absent in "${absent_commands[@]}"; do
  if command -v "${absent}" >/dev/null 2>&1; then
    echo "unadmitted build, installer, or specialist command leaked into runtime: ${absent}" >&2
    exit 1
  fi
done
printf '%s\n' "${absent_commands[@]}" | LC_ALL=C sort > "${output_root}/absent-commands.txt"
test ! -d /usr/lib/python3.14/ensurepip
test ! -d /usr/share/python-wheels
test ! -d /var/lib/db/sbom
test ! -e /var/cache/ldconfig
test -z "$(find /usr /opt/ambit/runtime-pack/core-document -type f -iname '*pip*.whl' -print -quit 2>/dev/null)"

python3 - <<'PY'
import importlib.util

for name in (
    "duckdb",
    "openpyxl",
    "pikepdf",
    "playwright",
    "polars",
    "pptx",
    "pyarrow",
    "reportlab",
):
    assert importlib.util.find_spec(name) is None, name
PY

python3 "${source_root}/conformance/materializer_conformance.py" "${output_root}"
python3 "${source_root}/conformance/artifact_conformance.py" "${output_root}"

if python3 - <<'PY'
import socket

try:
    socket.create_connection(("93.184.216.34", 443), timeout=2)
except OSError:
    raise SystemExit(1)
PY
then
  echo "network-none runtime unexpectedly reached public egress" >&2
  exit 1
fi

rm -rf "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
python3 "${source_root}/conformance/finalize_receipt.py" "${output_root}"
test -s "${output_root}/conformance-receipt.json"
