#!/usr/bin/env bash
set -euo pipefail

test "$(id -u)" -eq 0
component="$(cd -- "$(dirname -- "$0")" && pwd)"
lock="$component/file-tools.lock.json"
lineage=/opt/ambit/runtime-base/workspace/lineage/file-tools
tool_root=/opt/ambit/file-tools

mapfile -t packages < <(jq -r '.debianPackages | to_entries[] | .key + "=" + .value' "$lock")
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"

venv="$(jq -r '.python.venv' "$lock")"
requirements="$(jq -r '.python.requirements' "$lock")"
expected="$(jq -r '.python.requirementsSha256' "$lock")"
printf '%s  %s\n' "$expected" "$component/$requirements" | sha256sum -c -
/usr/bin/python3.13 -m venv "$venv"
"$venv/bin/python" -m pip --isolated install --only-binary=:all: \
  --no-deps --require-hashes -r "$component/$requirements"
"$venv/bin/python" -m pip check
ln -s "$venv/bin/markitdown" /usr/local/bin/markitdown
ln -s "$venv/bin/magika" /usr/local/bin/magika

install -d -m 0755 "$tool_root/tika" "$lineage"
python3 - "$lock" "$tool_root/tika" <<'PY'
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import urllib.request
import zipfile

artifact = json.loads(Path(sys.argv[1]).read_text())['artifacts']['tika']
destination = Path(sys.argv[2])
with tempfile.TemporaryFile() as archive:
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(artifact['url'], timeout=60) as response:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > artifact['bytes']:
                raise RuntimeError('Tika archive exceeds its pinned size')
            digest.update(chunk)
            archive.write(chunk)
    if size != artifact['bytes'] or digest.hexdigest() != artifact['sha256']:
        raise RuntimeError('Tika archive does not match its locked bytes')
    archive.seek(0)
    with zipfile.ZipFile(archive) as distribution:
        for entry in distribution.infolist():
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or '..' in path.parts or stat.S_ISLNK(entry.external_attr >> 16):
                raise RuntimeError('Tika archive contains an unsafe path')
        distribution.extractall(destination)
PY
install -m 0444 "$lock" "$lineage/file-tools.lock.json"
install -m 0444 "$component/$requirements" "$lineage/$requirements"
install -m 0444 "$component/tika-config.json" "$lineage/tika-config.json"
install -m 0755 "$component/tika" /usr/local/bin/tika
install -m 0755 "$component/tesseract" /usr/local/bin/tesseract
dpkg-query -W -f='${Package}\t${Version}\n' | LC_ALL=C sort > "$lineage/installed-dpkg.lock"
rm -rf /var/lib/apt/lists/* /root/.cache/pip
