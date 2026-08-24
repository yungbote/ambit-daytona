#!/bin/sh
set -eu

helper=/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize

test "$(id -u)" = 1000
test "$(id -g)" = 1000
test "$(id -un)" = daytona
test "$HOME" = /workspace
test "$LANG" = C.UTF-8
test "$LC_ALL" = C.UTF-8
test "$TZ" = UTC
test -x /bin/sh
test -x /bin/bash
test -x "$helper"
test "$(sha256sum "$helper" | cut -d ' ' -f 1)" = 8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5
test "$(stat -c '%a:%u:%g:%h' "$helper")" = 555:0:0:1
test -r /usr/share/licenses/ambit-atomic-materialize/ATOMIC-MATERIALIZER-LICENSE.md
test -r /usr/share/licenses/ambit-atomic-materialize/atomic-materializer-license.lock.json
test -z "$(find /workspace -mindepth 1 -print -quit)"

for command in apt apt-get dpkg dpkg-query pip pip3 python python3 node npm npx \
  libreoffice soffice chromium playwright; do
  if command -v "$command" >/dev/null 2>&1; then
    echo "unexpected runtime command: $command" >&2
    exit 1
  fi
done

for path in /etc/apt /etc/dpkg /usr/lib/apt /usr/lib/dpkg /var/lib/apt \
  /var/lib/dpkg /var/cache/apt; do
  test ! -e "$path"
done

printf '%s\n' \
  '{"capabilities":["ambit.runtime/command.execute@1","ambit.runtime/filesystem.read-write@1"],"helperSha256":"sha256:8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5","networkAuthority":"external-required-none","outcome":"passed","privilege":"non-root","schema":"ambit.runtime-core-base-conformance/v1"}'
