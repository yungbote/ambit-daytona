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
PY_REQUIREMENTS_NAME="$(lock 'lock["python"]["requirements"]')"
NODE_MANIFEST_NAME="$(lock 'lock["node"]["manifest"]')"
NODE_LOCKFILE_NAME="$(lock 'lock["node"]["lockfile"]')"
for name in toolchains.lock.json "$PY_REQUIREMENTS_NAME" "$NODE_MANIFEST_NAME" "$NODE_LOCKFILE_NAME"; do
  [ -r "${LINEAGE}/${name}" ] || { fail "image carries no lineage copy of ${name}"; continue; }
  if [ -r "${SOURCE_LOCKS}/${name}" ]; then
    if cmp -s "${SOURCE_LOCKS}/${name}" "${LINEAGE}/${name}"; then
      ok "image lineage copy equals source locks/${name}"
    else
      fail "image lineage copy differs from source locks/${name}"
    fi
  else
    echo "note: no source locks/${name} mounted at ${SOURCE_LOCKS}; skipping source equality"
  fi
done
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
base_python="$(lock 'lock["base"]["invariants"]["python3Path"]')"
[ "$("$base_python" --version)" = "$(lock 'lock["base"]["invariants"]["python3"]')" ] \
  && ok "base interpreter ${base_python} $("$base_python" --version)" \
  || fail "base interpreter ${base_python} is $("$base_python" --version 2>&1)"
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

# --- the Ambit Python environment ------------------------------------------------
py_venv="$(lock 'lock["python"]["venv"]')"
[ "$(command -v python3)" = "${py_venv}/bin/python3" ] && ok "python3 is the Ambit venv" || fail "python3 is $(command -v python3), expected ${py_venv}/bin/python3"
[ "$(command -v pip)" = "${py_venv}/bin/pip" ] && ok "pip is the Ambit venv" || fail "pip is $(command -v pip), expected ${py_venv}/bin/pip"
[ "$(python3 --version)" = "$(lock 'lock["python"]["interpreterVersion"]')" ] && ok "workspace $(python3 --version)" || fail "workspace python3 is $(python3 --version)"
[ -w "${py_venv}/lib" ] && ok "venv writable by runtime user" || fail "venv not writable by runtime user"

# Every distribution the requirement lock pins is installed at exactly that
# version, and nothing outside the lock is installed alongside it.
if python3 - "${LINEAGE}/${PY_REQUIREMENTS_NAME}" <<'PYEOF'
import re, sys
from importlib.metadata import distributions

def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()

pinned = {}
for line in open(sys.argv[1], encoding="utf-8"):
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", line)
    if match:
        pinned[norm(match.group(1))] = match.group(2)
installed = {norm(dist.metadata["Name"]): dist.version for dist in distributions()}
# venv bootstrap distributions are not part of the requirement set
bootstrap = {"pip", "setuptools", "wheel"}
problems = []
for name, version in sorted(pinned.items()):
    if installed.get(name) != version:
        problems.append(f"{name}: installed {installed.get(name, 'missing')}, lock says {version}")
for name in sorted(set(installed) - set(pinned) - bootstrap):
    problems.append(f"{name}=={installed[name]} installed but not in the lock")
if problems:
    print("\n".join(problems), file=sys.stderr)
    raise SystemExit(1)
print(len(pinned))
PYEOF
then
  ok "python distributions equal the pinned requirement set"
else
  fail "python distributions drifted from the pinned requirement set"
fi

# Every module the lock promises imports.
mapfile -t py_imports < <(lock 'lock["python"]["imports"]')
[ "${#py_imports[@]}" -gt 0 ] || fail "lock names no python imports"
for module in "${py_imports[@]}"; do
  python3 -c "import sys; __import__(sys.argv[1])" "$module" 2>/dev/null && ok "python import: $module" || fail "python import failed: $module"
done

# --- the Ambit Node toolchain ----------------------------------------------------
node_root="$(lock 'lock["node"]["root"]')"
while IFS=$'\t' read -r package version; do
  installed="$(node -p "require('${node_root}/node_modules/${package}/package.json').version" 2>/dev/null || echo missing)"
  [ "$installed" = "$version" ] && ok "node ${package}@${version}" || fail "node ${package} is ${installed}, lock says ${version}"
done < <(lock 'lock["node"]["packages"]')
while read -r binary; do
  resolved="$(command -v "$binary" || echo missing)"
  case "$resolved" in
    "${node_root}/node_modules/.bin/${binary}") ok "on PATH from the Ambit node root: ${binary}" ;;
    *) fail "${binary} resolves to ${resolved}, expected ${node_root}/node_modules/.bin/${binary}" ;;
  esac
done < <(lock 'lock["node"]["bins"]')
node -e "require('typescript')" 2>/dev/null && ok "NODE_PATH resolves the Ambit node toolchain" || fail "require('typescript') fails; NODE_PATH is '${NODE_PATH:-unset}'"

# --- tools the roster promises must actually resolve on PATH ---------------------
for tool in gcc g++ clang make cmake pkg-config jq rg fd fdfind curl git unzip zip 7z sqlite3 \
            java javac mvn gradle dotnet ruby gem bundle php composer go gofmt rustc cargo \
            python3 pip node npm \
            pdftotext pdftoppm pdfinfo qpdf gs convert magick ffmpeg ffprobe pandoc \
            tesseract dot soffice libreoffice exiftool file; do
  command -v "$tool" >/dev/null && ok "on PATH: $tool" || fail "not on PATH: $tool"
done
[ "$(java -version 2>&1 | head -1 | grep -c '^openjdk version "21\.')" = 1 ] && ok "java is OpenJDK 21" || fail "java is not OpenJDK 21"
[ -n "${JAVA_HOME:-}" ] && [ -x "${JAVA_HOME}/bin/java" ] && ok "JAVA_HOME=${JAVA_HOME}" || fail "JAVA_HOME unset or wrong"

# --- the document/media tools must run, not merely resolve -------------------------
probe() { # probe <label> <command...>
  if "${@:2}" >/dev/null 2>&1; then ok "runs: $1"; else fail "does not run: $1"; fi
}
probe pdftotext pdftotext -v
probe pdftoppm pdftoppm -v
probe qpdf qpdf --version
probe ghostscript gs --version
probe imagemagick convert -version
probe ffmpeg ffmpeg -version
probe pandoc pandoc --version
probe tesseract tesseract --version
probe graphviz dot -V
probe exiftool exiftool -ver
probe 7z 7z i
probe fd fd --version
probe file file --version
probe libreoffice timeout 180 soffice --headless --version

# One real round trip through the document stack: reportlab writes a PDF,
# poppler reads the text back, and LibreOffice converts a spreadsheet headless.
probe_dir="$(mktemp -d)"
if python3 - "$probe_dir" <<'PYEOF' >/dev/null 2>&1 && [ "$(pdftotext "${probe_dir}/probe.pdf" - 2>/dev/null | tr -d '[:space:]')" = "ambit-workspace" ]
import sys
from reportlab.pdfgen.canvas import Canvas
canvas = Canvas(f"{sys.argv[1]}/probe.pdf")
canvas.drawString(72, 720, "ambit-workspace")
canvas.save()
PYEOF
then ok "reportlab -> pdftotext round trip"; else fail "reportlab -> pdftotext round trip"; fi
printf 'a,b\n1,2\n' > "${probe_dir}/probe.csv"
if timeout 180 soffice --headless --convert-to xlsx --outdir "${probe_dir}" "${probe_dir}/probe.csv" >/dev/null 2>&1 \
   && python3 -c "import sys, openpyxl; sys.exit(0 if openpyxl.load_workbook(sys.argv[1]).active['A1'].value == 'a' else 1)" "${probe_dir}/probe.xlsx"; then
  ok "soffice --headless --convert-to -> openpyxl round trip"
else
  fail "soffice --headless --convert-to -> openpyxl round trip"
fi
rm -rf "$probe_dir"

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
python3 -c "import numpy, pandas, polars, scipy, sklearn; print('numpy ' + numpy.__version__, 'pandas ' + pandas.__version__, 'polars ' + polars.__version__, 'scipy ' + scipy.__version__, 'scikit-learn ' + sklearn.__version__)"
node --version
tsc --version
prettier --version
eslint --version
esbuild --version
pnpm --version
yarn --version
pdftotext -v 2>&1 | head -1
pandoc --version | head -1
tesseract --version 2>&1 | head -1
ffmpeg -version | head -1
convert -version | head -1
soffice --headless --version 2>&1 | head -1
gs --version | sed 's/^/ghostscript /'
qpdf --version | head -1
exiftool -ver | sed 's/^/exiftool /'
dot -V 2>&1 | head -1
7z i 2>/dev/null | awk 'NR == 2'
fd --version
whoami
test -w /workspace && echo workspace-writable

echo
if [ "$failures" -ne 0 ]; then
  echo "conformance: FAILED (${failures} failure(s))" >&2
  exit 1
fi
echo "conformance: passed"
