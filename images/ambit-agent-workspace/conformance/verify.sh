#!/usr/bin/env bash
# Conformance probe for a built Ambit agent-workspace image. Runs inside the
# image as the runtime user with networking disabled:
#
#   docker run --rm --network none \
#     -v "$PWD/images/ambit-agent-workspace/locks:/source-locks:ro" \
#     -v "$PWD/images/ambit-agent-workspace/conformance/verify.sh:/verify.sh:ro" \
#     --entrypoint bash IMAGE /verify.sh
#
# It proves the image was built from the checked-in lock, that every locked
# toolchain is present at its exact version, that the base Python/Node did not
# move, and that the /workspace contract holds. It prints the human-readable
# version roster last so the same run doubles as the release evidence.
set -euo pipefail

LINEAGE=/opt/ambit/runtime-base/workspace/lineage
IMAGE_LOCK="${LINEAGE}/toolchains.lock.json"
SOURCE_LOCKS="${SOURCE_LOCKS:-/source-locks}"
failures=0

fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
ok() { echo "ok: $*"; }

lock() {
  python3 - "$IMAGE_LOCK" "$1" <<'PY'
import json, sys
lock = json.load(open(sys.argv[1]))
value = eval(sys.argv[2], {"lock": lock})
if isinstance(value, dict):
    print("\n".join(f"{key}\t{val}" for key, val in value.items()))
elif isinstance(value, (list, tuple)):
    print("\n".join(str(item) for item in value))
else:
    print(value)
PY
}

# --- the image was built from this exact source lock -------------------------
test -r "$IMAGE_LOCK" || { echo "FAIL: image carries no lineage lock at $IMAGE_LOCK" >&2; exit 1; }
if [ -r "${SOURCE_LOCKS}/toolchains.lock.json" ]; then
  if cmp -s "${SOURCE_LOCKS}/toolchains.lock.json" "$IMAGE_LOCK"; then
    ok "image lineage lock equals source locks/toolchains.lock.json"
  else
    fail "image lineage lock differs from source locks/toolchains.lock.json"
  fi
else
  echo "note: no source lock mounted at ${SOURCE_LOCKS}; skipping source equality"
fi
if [ -r "${SOURCE_LOCKS}/installed-dpkg.lock" ]; then
  if cmp -s "${SOURCE_LOCKS}/installed-dpkg.lock" "${LINEAGE}/installed-dpkg.lock"; then
    ok "installed dpkg roster equals source locks/installed-dpkg.lock"
  else
    fail "installed dpkg roster drifted from source locks/installed-dpkg.lock"
    diff "${SOURCE_LOCKS}/installed-dpkg.lock" "${LINEAGE}/installed-dpkg.lock" >&2 || true
  fi
else
  echo "note: no source dpkg roster mounted; skipping roster equality"
fi

# --- runtime user and workspace contract ---------------------------------------
[ "$(whoami)" = "$(lock 'lock["base"]["invariants"]["user"]')" ] && ok "runtime user $(whoami)" || fail "runtime user is $(whoami)"
workspace="$(lock 'lock["base"]["invariants"]["workspace"]')"
[ -d "$workspace" ] && [ -w "$workspace" ] && ok "$workspace writable" || fail "$workspace is not a writable directory"
[ "$PWD" = "$workspace" ] && ok "working directory $workspace" || fail "working directory is $PWD"

# --- base invariants must not move ---------------------------------------------
[ "$(python3 --version)" = "$(lock 'lock["base"]["invariants"]["python3"]')" ] && ok "$(python3 --version)" || fail "python3 is $(python3 --version)"
[ "$(node --version)" = "$(lock 'lock["base"]["invariants"]["node"]')" ] && ok "node $(node --version)" || fail "node is $(node --version)"

# --- every Debian pin at its exact version ---------------------------------------
while IFS=$'\t' read -r package version; do
  installed="$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || echo missing)"
  [ "$installed" = "$version" ] && ok "$package=$version" || fail "$package is $installed, lock says $version"
done < <(lock 'lock["debian"]["packages"]')

# --- every archive toolchain at its exact version ----------------------------------
expect() { # expect <label> <observed> <expected>
  [ "$2" = "$3" ] && ok "$1 $2" || fail "$1 is '$2', lock says '$3'"
}
count="$(lock 'len(lock["archives"])')"
for ((index = 0; index < count; index++)); do
  entry="lock[\"archives\"][${index}]"
  kind="$(lock "${entry}[\"kind\"]")"
  version="$(lock "${entry}[\"version\"]")"
  case "$kind" in
    go)          expect go "$(go env GOVERSION)" "go${version}" ;;
    rustup-init) toolchain="$(lock "${entry}[\"toolchain\"]")"
                 expect rustc "$(rustc --version | awk '{ print $2 }')" "$toolchain"
                 expect cargo "$(cargo --version | awk '{ print $2 }')" "$toolchain"
                 expect rustup "$(rustup --version 2>/dev/null | head -1 | awk '{ print $2 }')" "$version"
                 while read -r component; do
                   rustup component list --installed 2>/dev/null | grep -q "^${component}" && ok "rust component $component" || fail "rust component $component missing"
                 done < <(lock "${entry}[\"components\"]")
                 [ -w "$(lock "${entry}[\"cargoHome\"]")" ] && ok "CARGO_HOME writable by runtime user" || fail "CARGO_HOME not writable" ;;
    maven)       expect maven "$(mvn -v 2>/dev/null | head -1 | awk '{ print $3 }')" "$version" ;;
    gradle)      expect gradle "$(gradle --version 2>/dev/null | awk '/^Gradle / { print $2 }')" "$version" ;;
    dotnet-sdk)  expect dotnet "$(dotnet --version)" "$version" ;;
    composer)    expect composer "$(composer --version --no-ansi 2>/dev/null | awk '{ print $3 }')" "$version" ;;
    *)           fail "unknown archive kind $kind" ;;
  esac
done

# --- tools the roster promises must actually resolve on PATH ---------------------
for tool in gcc g++ clang make cmake pkg-config jq rg curl git unzip zip sqlite3 java javac mvn gradle dotnet ruby gem bundle php composer go gofmt rustc cargo python3 pip node npm; do
  command -v "$tool" >/dev/null && ok "on PATH: $tool" || fail "not on PATH: $tool"
done
[ "$(java -version 2>&1 | head -1 | grep -c '^openjdk version "21\.')" = 1 ] && ok "java is OpenJDK 21" || fail "java is not OpenJDK 21"
[ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ] && ok "JAVA_HOME=${JAVA_HOME}" || fail "JAVA_HOME unset or wrong"

# --- release evidence roster ---------------------------------------------------------
echo
echo "=== version roster ==="
go version
rustc --version
cargo --version
java -version 2>&1 | head -1
mvn -v 2>/dev/null | head -1
gradle -v 2>/dev/null | grep Gradle
dotnet --version
ruby -v
bundle -v
php -v | head -1
composer --version --no-ansi 2>/dev/null
clang --version | head -1
gcc --version | head -1
cmake --version | head -1
make --version | head -1
pkg-config --version
jq --version
rg --version | head -1
git --version
sqlite3 --version | awk '{ print "sqlite3 " $1 }'
python3 --version
node --version
whoami
test -w /workspace && echo workspace-writable

echo
if [ "$failures" -ne 0 ]; then
  echo "conformance: FAILED (${failures} failure(s))" >&2
  exit 1
fi
echo "conformance: passed"
