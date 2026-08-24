#!/usr/bin/env bash
set -euo pipefail

source_root=${1:-/source}
input_root=${2:-/inputs}
pack_source=${source_root}/web-browser
pack_root=/opt/ambit/runtime-pack/web-browser

test "$(node --version)" = "v24.18.1"
install -d -m 0555 \
  "${pack_root}/locks" \
  "${pack_root}/bin" \
  "${pack_root}/conformance" \
  "${pack_root}/protocol" \
  "${pack_root}/runtime" \
  "${pack_root}/node_modules/playwright-core" \
  "${pack_root}/node_modules/axe-core" \
  "${pack_root}/licenses"
install -m 0444 "${pack_source}/pack.lock.json" "${pack_root}/pack.lock.json"
install -m 0444 "${pack_source}/executor.lock.json" "${pack_root}/executor.lock.json"
cp -a "${pack_source}/locks/." "${pack_root}/locks/"
cp -a "${pack_source}/conformance/." "${pack_root}/conformance/"
cp -a "${pack_source}/runtime/." "${pack_root}/runtime/"
cp -a "${source_root}/protocol/." "${pack_root}/protocol/"
cp -a "${source_root}/conformance/runtime-guard.sh" "${pack_root}/conformance/"
cp -a "${source_root}/conformance/render-probe.py" "${pack_root}/conformance/"
install -m 0555 "${source_root}/protocol/render_cli.py" \
  "${pack_root}/bin/ambit-specialist-render"
tar -xzf "${input_root}/npm/playwright-core-1.62.1.tgz" \
  -C "${pack_root}/node_modules/playwright-core" --strip-components=1
tar -xzf "${input_root}/npm/axe-core-4.13.0.tgz" \
  -C "${pack_root}/node_modules/axe-core" --strip-components=1
install -m 0444 "${pack_root}/node_modules/playwright-core/LICENSE" \
  "${pack_root}/licenses/PLAYWRIGHT-LICENSE"
install -m 0444 "${pack_root}/node_modules/playwright-core/NOTICE" \
  "${pack_root}/licenses/PLAYWRIGHT-NOTICE"
install -m 0444 "${pack_root}/node_modules/playwright-core/ThirdPartyNotices.txt" \
  "${pack_root}/licenses/PLAYWRIGHT-THIRD-PARTY-NOTICES"
install -m 0444 "${pack_root}/node_modules/axe-core/LICENSE" \
  "${pack_root}/licenses/AXE-CORE-LICENSE"
install -m 0444 "${pack_root}/node_modules/axe-core/LICENSE-3RD-PARTY.txt" \
  "${pack_root}/licenses/AXE-CORE-THIRD-PARTY-LICENSES"

echo '45873d00a0dd243596deb4aa23b2493b3d1f0671921bf2538ea431d7380220eb  /opt/ambit/runtime-pack/web-browser/licenses/PLAYWRIGHT-LICENSE' | sha256sum -c -
echo '6d602191187b35b9b01d2cffa01c8469c2c8d9de8a96f1bf868e0f264f51c81d  /opt/ambit/runtime-pack/web-browser/licenses/PLAYWRIGHT-NOTICE' | sha256sum -c -
echo 'a549d329bad8806fe279f0ecae0fc0270dec7e7c2dc8ec10f90e394f7c32b144  /opt/ambit/runtime-pack/web-browser/licenses/PLAYWRIGHT-THIRD-PARTY-NOTICES' | sha256sum -c -
echo 'af175b9d96ee93c21a036152e1b905b0b95304d4ae8c2c921c7609100ba8df7e  /opt/ambit/runtime-pack/web-browser/licenses/AXE-CORE-LICENSE' | sha256sum -c -
echo '4f8563870d0fca38bbc3e00b6f670cb7fa9f380ba9f26a7f7d1184a6b18b1653  /opt/ambit/runtime-pack/web-browser/licenses/AXE-CORE-THIRD-PARTY-LICENSES' | sha256sum -c -

node - "${pack_root}" <<'JS'
const path = require('node:path');
const root = process.argv[2];
const playwright = require(path.join(root, 'node_modules/playwright-core/package.json'));
const axe = require(path.join(root, 'node_modules/axe-core/package.json'));
if (playwright.name !== 'playwright-core' || playwright.version !== '1.62.1') throw new Error('playwright-core mismatch');
if (axe.name !== 'axe-core' || axe.version !== '4.13.0') throw new Error('axe-core mismatch');
JS

dpkg-query -W -f='${binary:Package}=${Version}\n' | LC_ALL=C sort \
  > /tmp/base-installed-dpkg.actual
cmp "${pack_root}/locks/base-installed-dpkg.lock" /tmp/base-installed-dpkg.actual
dpkg-query -W -f='${binary:Package}\n' \
  | grep -E '^(apt|dpkg|libapt-pkg)' \
  | xargs -r dpkg-query -L \
  | LC_ALL=C sort -u > /tmp/package-manager-files
fc-list : family style file | LC_ALL=C sort > /tmp/fontconfig-roster.actual
cmp "${pack_root}/locks/fontconfig-roster.lock" /tmp/fontconfig-roster.actual
test "$(/ms-playwright/chromium-1234/chrome-linux64/chrome --version)" = \
  "Google Chrome for Testing 151.0.7922.34 "
test "$(/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell --version)" = \
  "Google Chrome for Testing 151.0.7922.34"
test "$(/ms-playwright/firefox-1538/firefox/firefox --version 2>/dev/null)" = \
  "Mozilla Firefox 153.0"
test -x /ms-playwright/webkit-2336/pw_run.sh
test -x /ms-playwright/ffmpeg-1011/ffmpeg-linux

if id pwuser >/dev/null 2>&1; then
  userdel --remove pwuser
fi
groupmod --new-name daytona ubuntu
usermod --login daytona --home /workspace --move-home ubuntu
usermod --groups '' daytona
install -d -m 0700 -o daytona -g daytona /workspace
test "$(id -G daytona)" = 1000
test "$(id -Gn daytona)" = daytona

rm -rf \
  /etc/apt \
  /etc/dpkg \
  /home/pwuser \
  /root/.cache \
  /tmp/base-installed-dpkg.actual \
  /tmp/fontconfig-roster.actual \
      /usr/lib/node_modules/corepack \
      /usr/lib/node_modules/npm \
      /usr/lib/node_modules/yarn \
  /usr/lib/apt \
  /usr/lib/dpkg \
  /usr/libexec/dpkg \
  /usr/share/apt \
  /usr/share/dpkg \
  /var/cache/apt \
  /var/cache/debconf \
  /var/cache/fontconfig \
  /var/cache/ldconfig \
  /var/lib/apt \
  /var/lib/debconf \
  /var/lib/dpkg \
  /var/log/apt \
  /var/log/alternatives.log \
  /var/log/dpkg.log
rm -f \
  /etc/hostname \
  /usr/bin/apk \
  /usr/bin/apt \
  /usr/bin/apt-* \
  /usr/bin/aptitude* \
  /usr/bin/corepack \
  /usr/bin/dpkg \
  /usr/bin/dpkg-* \
  /usr/bin/debconf-apt-progress \
  /usr/bin/ldd \
  /usr/bin/npm \
  /usr/bin/npx \
  /usr/bin/pnpm \
  /usr/bin/yarn \
  /usr/local/bin/npm \
  /usr/local/bin/npx \
  /usr/local/bin/pnpm \
  /usr/local/bin/yarn
while IFS= read -r path; do
  if [[ -L ${path} || -f ${path} ]]; then
    rm -f -- "${path}"
  fi
done < /tmp/package-manager-files
rm -f /tmp/package-manager-files
find "${pack_root}" -type d -exec chmod 0555 '{}' +
find "${pack_root}" -type f -exec chmod a-w,go+r '{}' +
find "${pack_root}/conformance" -type f -name '*.sh' -exec chmod 0555 '{}' +
chmod 0555 "${pack_root}/bin/ambit-specialist-render"

hash -r
for installer in apk apt apt-get dpkg dpkg-deb pip pip3 uv npm npx pnpm yarn corepack conda mamba micromamba; do
  if command -v "${installer}" >/dev/null 2>&1; then
    echo "runtime installer survived image construction: ${installer}" >&2
    exit 1
  fi
done
