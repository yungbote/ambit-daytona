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
awk '$1 == "CapEff:" { exit $2 == "0000000000000000" ? 0 : 1 }' /proc/self/status
awk '$1 == "NoNewPrivs:" { exit $2 == "1" ? 0 : 1 }' /proc/self/status
test "$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)" = lo
test -x /bin/sh
test -x /bin/bash
test -x "$helper"
test "$(sha256sum "$helper" | cut -d ' ' -f 1)" = 8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5
test "$(stat -c '%a:%u:%g:%h' "$helper")" = 555:0:0:1
test -r /usr/share/licenses/ambit-atomic-materialize/ATOMIC-MATERIALIZER-LICENSE.md
test -r /usr/share/licenses/ambit-atomic-materialize/atomic-materializer-license.lock.json
test -z "$(find /workspace -mindepth 1 -print -quit)"

if touch /tmp/ambit-core-rootfs-write-probe 2>/dev/null; then
  echo "runtime root filesystem is writable" >&2
  rm -f /tmp/ambit-core-rootfs-write-probe
  exit 1
fi

for socket in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock \
  /run/k3s/containerd/containerd.sock /var/run/crio/crio.sock; do
  test ! -e "$socket"
done

if env | cut -d= -f1 | grep -Eiq \
  '(^|_)(TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|PRIVATE_KEY)($|_)'; then
  echo "secret-shaped environment name reached the core runtime" >&2
  exit 1
fi

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
  '{"capabilities":["ambit.runtime/command.execute@1","ambit.runtime/filesystem.read-write@1"],"helperSha256":"sha256:8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5","hostSockets":"absent","linuxCapabilities":"none","network":"loopback-only","noNewPrivileges":true,"outcome":"passed","privilege":"non-root","rootFilesystem":"read-only","schema":"ambit.runtime-core-base-conformance/v1","secretEnvironmentNames":[]}'
