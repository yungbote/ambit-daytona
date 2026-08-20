#!/usr/bin/env bash
set -euo pipefail

output_root="${1:-/workspace/c16b-conformance}"
pack_root=/opt/ambit/runtime-pack/core-document

mkdir -p "${output_root}"
if find "${output_root}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "conformance output must be an empty directory: ${output_root}" >&2
  exit 1
fi
export HOME="${output_root}/home"
export XDG_CACHE_HOME="${output_root}/cache"
export XDG_CONFIG_HOME="${output_root}/config"
export XDG_RUNTIME_DIR="${output_root}/run"
mkdir -p "${HOME}" "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_RUNTIME_DIR}"
chmod 0700 "${XDG_RUNTIME_DIR}"

test "$(id -u)" = "1000"
test "$(id -un)" = "daytona"
test ! -S /var/run/docker.sock
test ! -w "${pack_root}"
test "$(locale charmap)" = "UTF-8"
test "${LANG}" = "C.UTF-8"
test "${LC_ALL}" = "C.UTF-8"
if env | cut -d= -f1 | grep -Eiq '(api[_-]?key|password|private[_-]?key|secret|token)'; then
  echo "secret-shaped environment variable reached the runtime" >&2
  exit 1
fi
if sudo -n true >/dev/null 2>&1; then
  echo "runtime user unexpectedly retained sudo authority" >&2
  exit 1
fi

test "$(python3 --version)" = "Python 3.11.14"
test "$(node --version)" = "v20.19.2"
test "$(npm --version)" = "10.8.2"
test "$(npx --version)" = "10.8.2"
test "$(npm config get ignore-scripts)" = "true"
test "$(pyright --version)" = "pyright 1.1.413"
test "$(typescript-language-server --version)" = "5.1.3"
test "$(ts-node --version)" = "v10.9.2"
test "$(tsc --version)" = "Version 5.9.3"
test "$(uv --version)" = "uv 0.9.26"
chromium --version | grep -F 'Chromium 151.0.7922.137' >/dev/null
libreoffice --version | grep -F 'LibreOffice 25.2.3.2' >/dev/null
pandoc --version | grep -F 'pandoc 3.1.11.1' >/dev/null
git lfs version | grep -F 'git-lfs/3.6.1' >/dev/null
file --version | grep -F 'file-5.46' >/dev/null
wget --version | grep -F 'GNU Wget 1.25.0' >/dev/null
ssh -V 2>&1 | grep -F 'OpenSSH_10.0p2' >/dev/null
test "$(command -v scp)" = "/usr/bin/scp"
7z i | grep -F '7-Zip 25.01' >/dev/null
unzip -v | grep -F 'UnZip 6.00' >/dev/null
zip -v | grep -F 'Zip 3.0' >/dev/null
test "$(printf '%s\n' '{"value":42}' | yq -r '.value')" = "42"

while IFS= read -r expected; do
  package="${expected%%=*}"
  version="$(dpkg-query -W -f='${Version}' "${package}")"
  test "${package}=${version}" = "${expected}"
done < "${pack_root}/apt-packages.lock"

while IFS= read -r expected; do
  package="${expected%%=*}"
  version="$(dpkg-query -W -f='${Version}' "${package}")"
  test "${package}=${version}" = "${expected}"
done < "${pack_root}/dpkg-packages.lock"

python3 -m pip check

malicious_python="${output_root}/malicious-python"
mkdir -p "${malicious_python}"
printf '%s\n' \
  'from pathlib import Path' \
  'from setuptools import setup' \
  "Path('${output_root}/PYTHON_INSTALL_SCRIPT_EXECUTED').write_text('unsafe')" \
  "setup(name='ambit-malicious-install-fixture', version='1.0.0')" \
  > "${malicious_python}/setup.py"
if python3 -m pip install "${malicious_python}" >"${output_root}/pip-policy.log" 2>&1; then
  echo "unlocked Python source installation unexpectedly succeeded" >&2
  exit 1
fi
test ! -e "${output_root}/PYTHON_INSTALL_SCRIPT_EXECUTED"

malicious_node="${output_root}/malicious-node"
node_target="${output_root}/node-policy-target"
mkdir -p "${malicious_node}" "${node_target}"
printf '%s\n' \
  '{' \
  '  "name": "ambit-malicious-install-fixture",' \
  '  "version": "1.0.0",' \
  "  \"scripts\": {\"preinstall\": \"touch ${output_root}/NODE_INSTALL_SCRIPT_EXECUTED\"}" \
  '}' > "${malicious_node}/package.json"
npm install --offline --no-audit --no-fund \
  --cache "${XDG_CACHE_HOME}/npm" \
  --prefix "${node_target}" \
  "${malicious_node}" >"${output_root}/npm-policy.log" 2>&1
test ! -e "${output_root}/NODE_INSTALL_SCRIPT_EXECUTED"

code_probe="${output_root}/code-intelligence"
mkdir -p "${code_probe}"
printf '%s\n' \
  'def add(left: int, right: int) -> int:' \
  '    return left + right' \
  '' \
  'result: int = add(20, 22)' > "${code_probe}/typed_probe.py"
pyright --outputjson "${code_probe}/typed_probe.py" > "${output_root}/pyright-receipt.json"
test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"]["errorCount"])' "${output_root}/pyright-receipt.json")" = "0"
printf '%s\n' \
  'const add = (left: number, right: number): number => left + right;' \
  'const result: number = add(20, 22);' \
  'if (result !== 42) throw new Error("unexpected result");' \
  'console.log(result);' > "${code_probe}/typed-probe.ts"
tsc --noEmit --strict --skipLibCheck "${code_probe}/typed-probe.ts" \
  > "${output_root}/typescript-receipt.log" 2>&1
npx --no-install ts-node -T --ignore-diagnostics 5107 \
  -O '{"module":"CommonJS"}' "${code_probe}/typed-probe.ts" \
  > "${output_root}/typescript-execution-receipt.log" 2>&1
test "$(cat "${output_root}/typescript-execution-receipt.log")" = "42"

python3 "${pack_root}/conformance/artifact_conformance.py" "${output_root}"

python3 -m http.server 8123 --bind 127.0.0.1 --directory "${output_root}/web" >"${output_root}/http.log" 2>&1 &
server_pid=$!
cleanup_server() {
  kill "${server_pid}" >/dev/null 2>&1 || true
  wait "${server_pid}" >/dev/null 2>&1 || true
}
trap cleanup_server EXIT
for _ in $(seq 1 50); do
  if curl --fail --silent http://127.0.0.1:8123/ >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --fail --silent --show-error http://127.0.0.1:8123/ >/dev/null
node "${pack_root}/conformance/web_conformance.cjs" "${output_root}" http://127.0.0.1:8123/
cleanup_server
trap - EXIT

if python3 -m pip install --disable-pip-version-check ambit-package-that-does-not-exist >/dev/null 2>&1; then
  echo "offline Python package acquisition unexpectedly succeeded" >&2
  exit 1
fi
if curl --connect-timeout 2 --max-time 3 --silent https://example.com >/dev/null 2>&1; then
  echo "network-none runtime unexpectedly reached public egress" >&2
  exit 1
fi

rm -rf \
  "${HOME}" \
  "${XDG_CACHE_HOME}" \
  "${XDG_CONFIG_HOME}" \
  "${XDG_RUNTIME_DIR}" \
  "${malicious_python}" \
  "${malicious_node}" \
  "${node_target}" \
  "${code_probe}" \
  "${output_root}"/lo-profile-*

python3 "${pack_root}/conformance/finalize_receipt.py" "${output_root}"
test -s "${output_root}/conformance-receipt.json"
