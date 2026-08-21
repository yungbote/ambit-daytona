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
evidence_root=${state_root}/evidence
receipt=${evidence_root}/runner-docker-storage.json
image_bytes=64424509440

for command_name in blkid chmod find findmnt install jq losetup mkfs.xfs mktemp mountpoint mv python3 realpath stat sudo xfs_info; do
  command -v "${command_name}" >/dev/null || {
    echo "required runner-storage command is absent: ${command_name}" >&2
    exit 66
  }
done
[[ -f ${verifier} ]] || { echo 'runner storage verifier is absent' >&2; exit 66; }
for directory in "${target}" "${evidence_root}"; do
  [[ -d ${directory} && ! -L ${directory} ]] || { echo "runner storage directory is invalid: ${directory}" >&2; exit 66; }
  [[ $(realpath -e -- "${directory}") == "${directory}" ]] || { echo "runner storage directory is non-canonical: ${directory}" >&2; exit 66; }
done
[[ -z $(find "${target}" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
  echo 'runner storage target must be empty below its mount' >&2
  exit 66
}
target_device=$(stat -c '%d' -- "${target}")
target_inode=$(stat -c '%i' -- "${target}")

loop_device=
mounted=false
image_created=false
capacity_created=false
temporary=
cleanup_failed_prepare() {
  set +e
  local cleanup_safe=true
  if [[ -n ${temporary} && -e ${temporary} ]]; then
    unlink -- "${temporary}"
  fi
  if [[ ${mounted} == true && -n ${loop_device} ]] &&
    [[ -n $(findmnt -rn -S "${loop_device}" -o TARGET 2>/dev/null) ]]; then
    sudo -n umount -- "${loop_device}" || cleanup_safe=false
  fi
  if [[ -n ${loop_device} ]]; then
    if [[ -z $(findmnt -rn -S "${loop_device}" -o TARGET 2>/dev/null) ]]; then
      sudo -n losetup --detach "${loop_device}" >/dev/null 2>&1 || cleanup_safe=false
    else
      cleanup_safe=false
    fi
  fi
  # A published receipt makes the exact image/UUID recoverable after INT,
  # TERM, or reboot. Never turn that state into receipt-without-image.
  if [[ -f ${receipt} && ! -L ${receipt} ]]; then
    cleanup_safe=false
  fi
  if [[ ${cleanup_safe} == true && ${image_created} == true && -f ${image} && ! -L ${image} ]]; then
    sudo -n unlink -- "${image}" || cleanup_safe=false
  fi
  if [[ ${cleanup_safe} == true && ${capacity_created} == true && -d ${capacity_root} && ! -L ${capacity_root} ]]; then
    sudo -n rmdir --ignore-fail-on-non-empty -- "${capacity_root}"
  fi
}
trap cleanup_failed_prepare EXIT INT TERM

write_current_receipt() {
  local current expected_uuid
  current=$(python3 "${verifier}" "${state_root}")
  if [[ -f ${receipt} ]]; then
    expected_uuid=$(jq -er '.filesystem.uuid' "${receipt}")
    [[ $(jq -er '.filesystem.uuid' <<<"${current}") == "${expected_uuid}" ]] || {
      echo 'runner storage filesystem UUID changed across recovery' >&2
      return 66
    }
  fi
  temporary=$(mktemp "${evidence_root}/.runner-storage.XXXXXX.json")
  printf '%s\n' "${current}" > "${temporary}"
  chmod 0600 "${temporary}"
  mv -- "${temporary}" "${receipt}"
  temporary=
}

if [[ -e ${image} || -e ${receipt} ]]; then
  [[ -f ${image} && ! -L ${image} && -f ${receipt} && ! -L ${receipt} ]] || {
    echo 'runner storage is incomplete; run remove-runner-storage.sh before retrying' >&2
    exit 65
  }
  [[ $(stat -c '%s' -- "${image}") == "${image_bytes}" ]] || { echo 'runner storage image size differs' >&2; exit 66; }
  [[ $(stat -c '%a' -- "${image}") == 600 ]] || { echo 'runner storage image mode differs' >&2; exit 66; }
  [[ $(stat -c '%u' -- "${image}") == 0 ]] || { echo 'runner storage image owner differs' >&2; exit 66; }
  [[ $(jq -er '.image.path' "${receipt}") == "${image}" ]] || { echo 'runner storage receipt image path differs' >&2; exit 66; }
  [[ $(jq -er '.image.device' "${receipt}") == "$(stat -c '%d' -- "${image}")" ]] || { echo 'runner storage receipt image device differs' >&2; exit 66; }
  [[ $(jq -er '.image.inode' "${receipt}") == "$(stat -c '%i' -- "${image}")" ]] || { echo 'runner storage receipt image inode differs' >&2; exit 66; }
  if mountpoint -q -- "${target}"; then
    write_current_receipt
    trap - EXIT INT TERM
    printf '%s\n' "${receipt}"
    exit 0
  fi
  associated_output=$(sudo -n losetup --noheadings --output NAME --associated "${image}")
  associated=()
  if [[ -n ${associated_output} ]]; then
    mapfile -t associated < <(sed '/^$/d' <<<"${associated_output}")
  fi
  [[ ${#associated[@]} -le 1 ]] || { echo 'runner storage image has multiple loop devices' >&2; exit 66; }
  if [[ ${#associated[@]} -eq 1 ]]; then
    loop_device=${associated[0]//[[:space:]]/}
    [[ -z $(findmnt -rn -S "${loop_device}" -o TARGET) ]] || {
      echo 'runner storage loop is mounted at an unexpected target' >&2
      exit 66
    }
  else
    loop_device=$(sudo -n losetup --find --show --nooverlap "${image}")
  fi
  [[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]] || { echo 'runner storage loop device is invalid' >&2; exit 66; }
  [[ $(sudo -n blkid -s TYPE -o value "${loop_device}") == xfs ]] || { echo 'runner storage image is not XFS' >&2; exit 66; }
  [[ $(sudo -n blkid -s UUID -o value "${loop_device}") == "$(jq -er '.filesystem.uuid' "${receipt}")" ]] || {
    echo 'runner storage filesystem UUID differs from its receipt' >&2
    exit 66
  }
  exec {target_fd}<"${target}"
  target_handle=/proc/$$/fd/${target_fd}
  [[ $(stat -c '%d:%i' -- "${target_handle}") == "${target_device}:${target_inode}" ]] || {
    echo 'runner storage target changed before mount' >&2
    exit 66
  }
  sudo -n mount -t xfs -o pquota,nosuid,nodev -- "${loop_device}" "${target_handle}"
  mounted=true
  write_current_receipt
  trap - EXIT INT TERM
  printf '%s\n' "${receipt}"
  exit 0
fi

if [[ ! -e ${capacity_root} ]]; then
  install -d -m 0700 -- "${capacity_root}"
  capacity_created=true
fi
[[ -d ${capacity_root} && ! -L ${capacity_root} ]] || { echo 'runner capacity root is invalid' >&2; exit 66; }
[[ $(realpath -e -- "${capacity_root}") == "${capacity_root}" ]] || { echo 'runner capacity root is non-canonical' >&2; exit 66; }

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
image_created=true
[[ -f ${image} && ! -L ${image} ]] || { echo 'runner storage image creation failed' >&2; exit 66; }
[[ $(stat -c '%s' -- "${image}") == "${image_bytes}" ]] || { echo 'runner storage image size differs' >&2; exit 66; }
[[ $(stat -c '%a' -- "${image}") == 600 ]] || { echo 'runner storage image mode differs' >&2; exit 66; }

exec {capacity_fd}<"${capacity_root}"
exec {image_fd}<>"${image}"
capacity_handle=/proc/$$/fd/${capacity_fd}
image_handle=/proc/$$/fd/${image_fd}
[[ $(stat -c '%d:%i' -- "${capacity_handle}") == "$(stat -c '%d:%i' -- "${capacity_root}")" ]] || {
  echo 'runner capacity root changed before ownership transfer' >&2
  exit 66
}
[[ $(stat -c '%d:%i' -- "${image_handle}") == "$(stat -c '%d:%i' -- "${image}")" ]] || {
  echo 'runner storage image changed before ownership transfer' >&2
  exit 66
}
sudo -n chown root:root -- "${capacity_handle}" "${image_handle}"
sudo -n chmod 0711 -- "${capacity_handle}"
sudo -n chmod 0600 -- "${image_handle}"

sudo -n mkfs.xfs -q -m crc=1,finobt=1 -n ftype=1 -- "${image_handle}"
loop_device=$(sudo -n losetup --find --show --nooverlap "${image_handle}")
[[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]] || { echo 'runner storage loop device is invalid' >&2; exit 66; }
exec {target_fd}<"${target}"
target_handle=/proc/$$/fd/${target_fd}
[[ $(stat -c '%d:%i' -- "${target_handle}") == "${target_device}:${target_inode}" ]] || {
  echo 'runner storage target changed before mount' >&2
  exit 66
}
sudo -n mount -t xfs -o pquota,nosuid,nodev -- "${loop_device}" "${target_handle}"
mounted=true
write_current_receipt
image_created=false
capacity_created=false
trap - EXIT INT TERM
printf '%s\n' "${receipt}"
