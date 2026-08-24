#!/usr/bin/env bash
set -euo pipefail

pack_id=${1:?pack id is required}
output_root=${2:?output root is required}
pack_root=/opt/ambit/runtime-pack/${pack_id}

case "${pack_id}" in
  office-authoring|pdf-ocr|data-research|web-browser) ;;
  *)
    echo "unsupported specialist pack: ${pack_id}" >&2
    exit 64
    ;;
esac

test "$(id -u)" = 1000
test "$(id -g)" = 1000
test "$(id -un)" = daytona
test "$(id -G)" = 1000
test "$(id -Gn)" = daytona
test -d "${pack_root}"
test ! -w "${pack_root}"
test -d "${output_root}"
test -w "${output_root}"
test -z "$(find "${output_root}" -mindepth 1 -maxdepth 1 -print -quit)"

cap_eff=$(awk '$1 == "CapEff:" {print $2}' /proc/self/status)
no_new_privileges=$(awk '$1 == "NoNewPrivs:" {print $2}' /proc/self/status)
seccomp_mode=$(awk '$1 == "Seccomp:" {print $2}' /proc/self/status)
test "${cap_eff}" = 0000000000000000
test "${no_new_privileges}" = 1
test "${seccomp_mode}" = 2

if touch /ambit-c18-root-write-probe 2>/dev/null; then
  rm -f /ambit-c18-root-write-probe
  echo "runtime root filesystem is writable" >&2
  exit 1
fi

for socket in \
  /run/containerd/containerd.sock \
  /run/k3s/containerd/containerd.sock \
  /run/podman/podman.sock \
  /var/run/crio/crio.sock \
  /var/run/docker.sock \
  /var/run/podman/podman.sock; do
  test ! -e "${socket}"
done

for state_path in \
  /etc/apt /etc/dpkg /usr/lib/apt /usr/lib/dpkg /usr/libexec/dpkg \
  /usr/share/apt /usr/share/dpkg /var/lib/apt /var/lib/dpkg; do
  test ! -e "${state_path}"
done

for installer in \
  apk apt apt-get conda corepack dpkg dpkg-deb mamba micromamba npm npx pip pip3 pnpm uv yarn; do
  if command -v "${installer}" >/dev/null 2>&1; then
    echo "runtime installer is present: ${installer}" >&2
    exit 1
  fi
done

if env | cut -d= -f1 | grep -Eiq '(api[_-]?key|password|private[_-]?key|secret|token)'; then
  echo "secret-shaped environment variable reached runtime conformance" >&2
  exit 1
fi

if timeout 2 bash -c 'exec 3<>/dev/tcp/93.184.216.34/443' 2>/dev/null; then
  echo "network-none conformance reached public egress" >&2
  exit 1
fi

{
  printf 'cap_eff\t%s\n' "${cap_eff}"
  printf 'gid\t%s\n' "$(id -g)"
  printf 'network\tnone\n'
  printf 'no_new_privileges\t%s\n' "${no_new_privileges}"
  printf 'pack\t%s\n' "${pack_id}"
  printf 'root_filesystem\tread_only\n'
  printf 'supplementary_groups\tnone\n'
  printf 'runtime_installers\tabsent\n'
  printf 'seccomp_mode\t%s\n' "${seccomp_mode}"
  printf 'uid\t%s\n' "$(id -u)"
  printf 'user\t%s\n' "$(id -un)"
} > "${output_root}/runtime-guard.tsv"
