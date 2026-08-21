#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: prepare-runner-storage.sh STATE_ROOT' >&2
  exit 64
fi

state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || {
  echo 'STATE_ROOT must be a specific path below /home' >&2
  exit 64
}
[[ $(realpath -e -- "${state_root}") == "${state_root}" ]] || {
  echo 'STATE_ROOT must be an existing canonical non-symlink path' >&2
  exit 64
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
verifier=${script_dir}/verify-runner-storage.py
capacity_root=${state_root}/capacity
target=${state_root}/runner-docker
image=${capacity_root}/runner-docker.xfs
receipt=${state_root}/evidence/runner-docker-storage.json
image_bytes=64424509440

for command_name in blkid chmod find findmnt install losetup mkfs.xfs mktemp mountpoint mv python3 realpath stat sudo xfs_info; do
  command -v "${command_name}" >/dev/null || {
    echo "required runner-storage command is absent: ${command_name}" >&2
    exit 66
  }
done
[[ -f ${verifier} ]] || { echo 'runner storage verifier is absent' >&2; exit 66; }
[[ -d ${target} && ! -L ${target} ]] || { echo 'runner storage target is invalid' >&2; exit 66; }
[[ $(realpath -e -- "${target}") == "${target}" ]] || { echo 'runner storage target is non-canonical' >&2; exit 66; }
[[ -z $(find "${target}" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
  echo 'runner storage target must be empty before mounting' >&2
  exit 66
}
[[ ! -e ${receipt} ]] || { echo 'runner storage receipt already exists' >&2; exit 65; }
if mountpoint -q -- "${target}"; then
  echo 'runner storage target is already mounted without its receipt' >&2
  exit 65
fi

if [[ ! -e ${capacity_root} ]]; then
  install -d -m 0700 -- "${capacity_root}"
fi
[[ -d ${capacity_root} && ! -L ${capacity_root} ]] || { echo 'runner capacity root is invalid' >&2; exit 66; }
[[ $(realpath -e -- "${capacity_root}") == "${capacity_root}" ]] || { echo 'runner capacity root is non-canonical' >&2; exit 66; }
[[ ! -e ${image} ]] || { echo 'runner storage image already exists' >&2; exit 65; }

umask 077
python3 - "${image}" "${image_bytes}" <<'PY'
import os
import sys

path = sys.argv[1]
size = int(sys.argv[2])
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    os.ftruncate(fd, size)
    os.fsync(fd)
finally:
    os.close(fd)
PY
[[ -f ${image} && ! -L ${image} ]] || { echo 'runner storage image creation failed' >&2; exit 66; }
[[ $(stat -c '%s' -- "${image}") == "${image_bytes}" ]] || { echo 'runner storage image size differs' >&2; exit 66; }
[[ $(stat -c '%a' -- "${image}") == 600 ]] || { echo 'runner storage image mode differs' >&2; exit 66; }

sudo -n mkfs.xfs -q -m crc=1,finobt=1 -n ftype=1 -- "${image}"
loop_device=$(sudo -n losetup --find --show --nooverlap "${image}")
[[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]] || { echo 'runner storage loop device is invalid' >&2; exit 66; }
mounted=false
cleanup_failed_mount() {
  if [[ ${mounted} == true ]] && mountpoint -q -- "${target}"; then
    sudo -n umount -- "${target}" >/dev/null 2>&1 || true
  fi
  sudo -n losetup --detach "${loop_device}" >/dev/null 2>&1 || true
}
trap cleanup_failed_mount EXIT INT TERM
sudo -n mount -t xfs -o pquota,nosuid,nodev -- "${loop_device}" "${target}"
mounted=true

temporary=$(mktemp "${state_root}/evidence/.runner-storage.XXXXXX.json")
python3 "${verifier}" "${state_root}" > "${temporary}"
chmod 0600 "${temporary}"
mv -- "${temporary}" "${receipt}"
trap - EXIT INT TERM
printf '%s\n' "${receipt}"
