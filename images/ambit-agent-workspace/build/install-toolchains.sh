#!/usr/bin/env bash
# Installs the exact toolchain roster named by locks/toolchains.lock.json into
# the admitted Ambit agent-workspace image. Runs once, as root, inside the
# image build. Every input is an exact Debian package version resolved by apt
# from the base image's own Debian sources, an upstream archive pinned by URL
# and checksum in the lock, a hash-pinned Python requirement set installed with
# --require-hashes, or an npm package-lock installed with `npm ci`. The two
# sidecar lock files are themselves pinned by sha256 in toolchains.lock.json.
# Nothing here is a runtime installer: the script is bind-mounted into the
# build and never enters the image.
set -euo pipefail

LOCK="${1:?usage: install-toolchains.sh /path/to/toolchains.lock.json}"
LINEAGE=/opt/ambit/runtime-base/workspace/lineage
RUNTIME_USER=daytona
export DEBIAN_FRONTEND=noninteractive

lock() {
  # lock <python expression over `lock`>
  python3 - "$LOCK" "$1" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
value = eval(sys.argv[2], {"lock": lock})
if isinstance(value, (list, tuple)):
    print("\n".join(str(item) for item in value))
elif isinstance(value, dict):
    print("\n".join(f"{key}\t{val}" for key, val in value.items()))
else:
    print(value)
PY
}

verify_checksum() {
  # verify_checksum <file> <sha256|sha512> <digest>
  local file="$1" algorithm="$2" digest="$3"
  echo "${digest}  ${file}" | "${algorithm}sum" -c - >/dev/null
}

fetch() {
  # fetch <url> <destination> — bounded, no redirects to other hosts.
  curl --fail --silent --show-error --location --proto '=https' --max-redirs 5 \
    --retry 3 --retry-delay 5 --connect-timeout 30 --max-time 1800 \
    --output "$2" "$1"
}

test "$(id -u)" = 0
test -n "$(lock 'lock["schema"]' | grep -F 'ambit.agent-workspace-toolchains-lock/v2')"

# --- base invariants ---------------------------------------------------------
# The base image's Python and Node are part of the admitted contract and must
# not move. Fail the build before changing anything if they already differ.
BASE_PYTHON="$(lock 'lock["base"]["invariants"]["python3Path"]')"
test "$("${BASE_PYTHON}" --version)" = "$(lock 'lock["base"]["invariants"]["python3"]')"
test "$(command -v python3)" = "${BASE_PYTHON}"
test "$(node --version)" = "$(lock 'lock["base"]["invariants"]["node"]')"
id "${RUNTIME_USER}" >/dev/null

# --- Debian packages, exact versions ------------------------------------------
mapfile -t PINS < <(lock 'lock["debian"]["packages"]' | awk -F'\t' '{ print $1 "=" $2 }')
test "${#PINS[@]}" -gt 0
apt-get update
apt-get install -y --no-install-recommends "${PINS[@]}"
# Every pin is installed at exactly its locked version.
while IFS=$'\t' read -r package version; do
  installed="$(dpkg-query -W -f='${Version}' "${package}")"
  test "${installed}" = "${version}" || {
    echo "install-toolchains: ${package} resolved to ${installed}, lock says ${version}" >&2
    exit 1
  }
done < <(lock 'lock["debian"]["packages"]')

# --- upstream archives, exact checksums ---------------------------------------
DOWNLOADS="$(mktemp -d)"
ARCHIVE_COUNT="$(lock 'len(lock["archives"])')"
for ((index = 0; index < ARCHIVE_COUNT; index++)); do
  entry="lock[\"archives\"][${index}]"
  name="$(lock "${entry}[\"name\"]")"
  kind="$(lock "${entry}[\"kind\"]")"
  version="$(lock "${entry}[\"version\"]")"
  url="$(lock "${entry}[\"url\"]")"
  file="${DOWNLOADS}/${name}"
  echo "install-toolchains: ${name} ${version}"
  fetch "${url}" "${file}"
  if [ "$(lock "\"sha256\" in ${entry}")" = "True" ]; then
    verify_checksum "${file}" sha256 "$(lock "${entry}[\"sha256\"]")"
  else
    verify_checksum "${file}" sha512 "$(lock "${entry}[\"sha512\"]")"
  fi
  case "${kind}" in
    go)
      root="$(lock "${entry}[\"installRoot\"]")"
      test ! -e "${root}"
      tar -C "$(dirname "${root}")" -xzf "${file}"
      test "$("${root}/bin/go" env GOVERSION)" = "go${version}"
      ;;
    rustup-init)
      export RUSTUP_HOME CARGO_HOME
      RUSTUP_HOME="$(lock "${entry}[\"rustupHome\"]")"
      CARGO_HOME="$(lock "${entry}[\"cargoHome\"]")"
      toolchain="$(lock "${entry}[\"toolchain\"]")"
      profile="$(lock "${entry}[\"profile\"]")"
      mapfile -t components < <(lock "${entry}[\"components\"]")
      component_args=()
      for component in "${components[@]}"; do component_args+=(--component "${component}"); done
      chmod 0755 "${file}"
      # rustup fetches the pinned toolchain itself and checks every component
      # against the channel manifest hashes; the version pin is the lock's
      # authority, the component bytes are rustup's.
      "${file}" -y --no-modify-path --profile "${profile}" \
        --default-toolchain "${toolchain}" "${component_args[@]}"
      test "$("${CARGO_HOME}/bin/rustc" --version | awk '{ print $2 }')" = "${toolchain}"
      test "$("${CARGO_HOME}/bin/cargo" --version | awk '{ print $2 }')" = "${toolchain}"
      # Rust is the one toolchain whose home must stay writable by the runtime
      # user: `rustup component add`, `rustup target add`, and `cargo install`
      # write there. Every other toolchain root stays root-owned.
      chown -R "${RUNTIME_USER}:${RUNTIME_USER}" "${RUSTUP_HOME}" "${CARGO_HOME}"
      ;;
    maven)
      root="$(lock "${entry}[\"installRoot\"]")"
      test ! -e "${root}"
      mkdir -p "${root}"
      tar -C "${root}" --strip-components=1 -xzf "${file}"
      ln -s "${root}/bin/mvn" /usr/local/bin/mvn
      test "$(mvn -v 2>/dev/null | head -1 | awk '{ print $3 }')" = "${version}"
      ;;
    gradle)
      root="$(lock "${entry}[\"installRoot\"]")"
      test ! -e "${root}"
      unzip -q "${file}" -d "${DOWNLOADS}/gradle-unpack"
      mv "${DOWNLOADS}/gradle-unpack/gradle-${version}" "${root}"
      ln -s "${root}/bin/gradle" /usr/local/bin/gradle
      test "$(gradle --version 2>/dev/null | awk '/^Gradle / { print $2 }')" = "${version}"
      ;;
    dotnet-sdk)
      root="$(lock "${entry}[\"installRoot\"]")"
      test ! -e "${root}"
      mkdir -p "${root}"
      tar -C "${root}" -xzf "${file}"
      ln -s "${root}/dotnet" /usr/local/bin/dotnet
      test "$(DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 dotnet --version)" = "${version}"
      ;;
    composer)
      path="$(lock "${entry}[\"installPath\"]")"
      test ! -e "${path}"
      install -m 0755 -o root -g root "${file}" "${path}"
      test "$(composer --version --no-ansi 2>/dev/null | awk '{ print $3 }')" = "${version}"
      ;;
    *)
      echo "install-toolchains: unknown archive kind ${kind}" >&2
      exit 1
      ;;
  esac
done
rm -rf "${DOWNLOADS}"

# --- Python: the workspace interpreter ---------------------------------------
# A venv on the Debian 3.13 interpreter, owned by the runtime user and put in
# front of the base image's 3.11 on PATH, is what `python3`/`pip` mean inside a
# run. Its contents are a fully hashed, transitively pinned requirement set:
# --require-hashes makes the installed bytes, not just the versions, exact.
PY_INTERPRETER="$(lock 'lock["python"]["interpreter"]')"
test "$("${PY_INTERPRETER}" --version)" = "$(lock 'lock["python"]["interpreterVersion"]')"
PY_REQUIREMENTS="$(dirname "${LOCK}")/$(lock 'lock["python"]["requirements"]')"
verify_checksum "${PY_REQUIREMENTS}" sha256 "$(lock 'lock["python"]["requirementsSha256"]')"
PY_VENV="$(lock 'lock["python"]["venv"]')"
test ! -e "${PY_VENV}"
install -d -m 0755 "$(dirname "${PY_VENV}")"
"${PY_INTERPRETER}" -m venv "${PY_VENV}"
"${PY_VENV}/bin/pip" install --no-input --disable-pip-version-check --no-cache-dir \
  --require-hashes --requirement "${PY_REQUIREMENTS}"
"${PY_VENV}/bin/pip" check
# Every module the lock promises must import in the installed environment.
mapfile -t PY_IMPORTS < <(lock 'lock["python"]["imports"]')
test "${#PY_IMPORTS[@]}" -gt 0
"${PY_VENV}/bin/python" -c "import sys; [__import__(m) for m in sys.argv[1:]]" "${PY_IMPORTS[@]}"
# The runtime user owns the venv so `pip install` during a run needs no root.
chown -R "${RUNTIME_USER}:${RUNTIME_USER}" "${PY_VENV}"

# --- Node: the workspace CLI toolchain ----------------------------------------
# `npm ci` against a committed package-lock: exact versions, integrity hashes
# checked by npm itself. NODE_PATH (image ENV) makes these resolvable from any
# working directory, the same way the venv is.
NODE_ROOT="$(lock 'lock["node"]["root"]')"
NODE_MANIFEST="$(dirname "${LOCK}")/$(lock 'lock["node"]["manifest"]')"
NODE_LOCKFILE="$(dirname "${LOCK}")/$(lock 'lock["node"]["lockfile"]')"
verify_checksum "${NODE_MANIFEST}" sha256 "$(lock 'lock["node"]["manifestSha256"]')"
verify_checksum "${NODE_LOCKFILE}" sha256 "$(lock 'lock["node"]["lockfileSha256"]')"
test ! -e "${NODE_ROOT}"
install -d -m 0755 "${NODE_ROOT}"
install -m 0644 "${NODE_MANIFEST}" "${NODE_ROOT}/package.json"
install -m 0644 "${NODE_LOCKFILE}" "${NODE_ROOT}/package-lock.json"
( cd "${NODE_ROOT}" && HOME=/tmp npm_config_cache=/tmp/npm-cache \
    npm ci --omit=dev --no-audit --no-fund )
while IFS=$'\t' read -r package version; do
  installed="$(node -p "require('${NODE_ROOT}/node_modules/${package}/package.json').version" 2>/dev/null || echo missing)"
  test "${installed}" = "${version}" || {
    echo "install-toolchains: node ${package} resolved to ${installed}, lock says ${version}" >&2
    exit 1
  }
done < <(lock 'lock["node"]["packages"]')
while read -r binary; do
  test -x "${NODE_ROOT}/node_modules/.bin/${binary}" || {
    echo "install-toolchains: node bin ${binary} missing" >&2
    exit 1
  }
done < <(lock 'lock["node"]["bins"]')
chown -R "${RUNTIME_USER}:${RUNTIME_USER}" "${NODE_ROOT}"

# --- Debian name reconciliation -------------------------------------------------
# Debian ships fd as `fdfind` to avoid a name clash with an unrelated package.
# Agents (and every fd tutorial) say `fd`; publish it under the expected name.
test -x /usr/bin/fdfind
ln -s /usr/bin/fdfind /usr/local/bin/fd

# --- login-shell parity ---------------------------------------------------------
# Daytona exec inherits the image ENV. Login shells (ssh through the gateway)
# reset PATH from /etc/profile, which already loses the base image's Node.
# Publish the same toolchain environment there so both entry points agree.
install -d -m 0755 /etc/profile.d
cat > /etc/profile.d/ambit-agent-workspace.sh <<'EOF'
# Ambit agent workspace toolchains (mirrors the image ENV for login shells).
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export DOTNET_ROOT=/usr/share/dotnet
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
export VIRTUAL_ENV=/opt/ambit/python
export NODE_PATH=/opt/ambit/node/node_modules
export PATH="/opt/ambit/python/bin:/opt/ambit/node/node_modules/.bin:/usr/local/cargo/bin:/usr/local/go/bin:/usr/local/nvm/versions/node/v22.14.0/bin:/usr/local/sbin:/usr/local/bin:${PATH}"
EOF
chmod 0644 /etc/profile.d/ambit-agent-workspace.sh

# --- lineage receipt -------------------------------------------------------------
# The image carries the exact lock it was built from and the resulting full
# dpkg roster, the same way the certified core carries its base roster.
install -d -m 0755 "${LINEAGE}"
install -m 0444 -o root -g root "${LOCK}" "${LINEAGE}/toolchains.lock.json"
install -m 0444 -o root -g root "${PY_REQUIREMENTS}" "${LINEAGE}/$(lock 'lock["python"]["requirements"]')"
install -m 0444 -o root -g root "${NODE_MANIFEST}" "${LINEAGE}/$(lock 'lock["node"]["manifest"]')"
install -m 0444 -o root -g root "${NODE_LOCKFILE}" "${LINEAGE}/$(lock 'lock["node"]["lockfile"]')"
dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort > "${LINEAGE}/installed-dpkg.lock"
chmod 0444 "${LINEAGE}/installed-dpkg.lock"

# --- cleanup ----------------------------------------------------------------------
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/log/apt/* /var/log/dpkg.log \
  /root/.cache /root/.npm /root/.wget-hsts /tmp/npm-cache /tmp/* /var/tmp/*
