#!/usr/bin/env bash
# Installs the exact toolchain roster named by locks/toolchains.lock.json into
# the admitted Ambit agent-workspace image. Runs once, as root, inside the
# image build. Every input is either an exact Debian package version resolved
# by apt from the base image's own Debian sources, or an upstream archive
# pinned by URL and checksum in the lock. Nothing here is a runtime installer:
# the script is bind-mounted into the build and never enters the image.
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
test -n "$(lock 'lock["schema"]' | grep -F 'ambit.agent-workspace-toolchains-lock/v1')"

# --- base invariants ---------------------------------------------------------
# The base image's Python and Node are part of the admitted contract and must
# not move. Fail the build before changing anything if they already differ.
test "$(python3 --version)" = "$(lock 'lock["base"]["invariants"]["python3"]')"
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
export PATH="/usr/local/cargo/bin:/usr/local/go/bin:/usr/local/nvm/versions/node/v22.14.0/bin:/usr/local/sbin:/usr/local/bin:${PATH}"
EOF
chmod 0644 /etc/profile.d/ambit-agent-workspace.sh

# --- lineage receipt -------------------------------------------------------------
# The image carries the exact lock it was built from and the resulting full
# dpkg roster, the same way the certified core carries its base roster.
install -d -m 0755 "${LINEAGE}"
install -m 0444 -o root -g root "${LOCK}" "${LINEAGE}/toolchains.lock.json"
dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort > "${LINEAGE}/installed-dpkg.lock"
chmod 0444 "${LINEAGE}/installed-dpkg.lock"

# --- cleanup ----------------------------------------------------------------------
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb /var/log/apt/* /var/log/dpkg.log \
  /root/.cache /root/.npm /root/.wget-hsts /tmp/* /var/tmp/*
