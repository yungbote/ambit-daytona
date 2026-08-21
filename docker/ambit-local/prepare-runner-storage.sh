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

for command_name in blkid chmod find findmnt flock install jq losetup mkfs.xfs mktemp mv python3 realpath stat sudo xfs_info; do
  command -v "${command_name}" >/dev/null || {
    echo "required runner-storage command is absent: ${command_name}" >&2
    exit 66
  }
done
[[ -f ${verifier} ]] || { echo 'runner storage verifier is absent' >&2; exit 66; }

exec {lifecycle_fd}<"${state_root}"
lifecycle_handle=/proc/$$/fd/${lifecycle_fd}
lifecycle_identity=$(stat -Lc '%d:%i' -- "${lifecycle_handle}")
[[ $(stat -c '%d:%i' -- "${state_root}") == "${lifecycle_identity}" ]] || {
  echo 'runner storage state root changed before lifecycle lock' >&2
  exit 66
}
flock -x "${lifecycle_fd}"
[[ $(stat -c '%d:%i' -- "${state_root}") == "${lifecycle_identity}" ]] || {
  echo 'runner storage state root changed while acquiring lifecycle lock' >&2
  exit 66
}

require_same_object() {
  local handle_identity path_identity
  handle_identity=$(stat -Lc '%d:%i' -- "$1") || return 66
  path_identity=$(stat -c '%d:%i' -- "$2") || return 66
  [[ ${handle_identity} == "${path_identity}" ]]
}

for directory in "${target}" "${evidence_root}"; do
  [[ -d ${directory} && ! -L ${directory} ]] || { echo "runner storage directory is invalid: ${directory}" >&2; exit 66; }
  [[ $(realpath -e -- "${directory}") == "${directory}" ]] || { echo "runner storage directory is non-canonical: ${directory}" >&2; exit 66; }
done

loop_device=
mounted=false
image_created=false
capacity_created=false
temporary=
image_fd=
image_handle=
cleanup_failed_prepare() {
  set +e
  local cleanup_safe=true image_handle_identity image_path_identity
  if [[ -n ${temporary} && -e ${temporary} ]]; then
    unlink -- "${temporary}"
  fi
  if [[ ${mounted} == true && -n ${loop_device} ]]; then
    if collect_mount_table && select_loop_mount_targets "${loop_device}" &&
      [[ ${#loop_mount_targets[@]} -eq 1 && ${loop_mount_targets[0]} == "${target}" ]]; then
      sudo -n umount -- "${target}" || cleanup_safe=false
    else
      cleanup_safe=false
    fi
  fi
  if [[ -n ${loop_device} ]]; then
    if collect_mount_table && select_loop_mount_targets "${loop_device}" && [[ ${#loop_mount_targets[@]} -eq 0 ]]; then
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
  if [[ ${cleanup_safe} == true && ${image_created} == true ]]; then
    if [[ -n ${image_handle} && -e ${image_handle} && -f ${image} && ! -L ${image} ]] &&
      image_handle_identity=$(stat -Lc '%d:%i' -- "${image_handle}") &&
      image_path_identity=$(stat -c '%d:%i' -- "${image}") &&
      [[ ${image_path_identity} == "${image_handle_identity}" ]]; then
      sudo -n unlink -- "${image}" || cleanup_safe=false
    else
      cleanup_safe=false
    fi
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

mount_table=
loop_mount_targets=()
target_mount_sources=()
collect_mount_table() {
  mount_table=$(findmnt --json --list -o SOURCE,MAJ:MIN,TARGET) || {
    echo 'runner storage global mount observation failed' >&2
    return 66
  }
  jq -e '
    (.filesystems | type == "array") and
    all(.filesystems[];
      (.source | type == "string") and
      (."maj:min" | type == "string") and
      (.target | type == "string"))
  ' <<<"${mount_table}" >/dev/null || {
    echo 'runner storage global mount observation is invalid' >&2
    return 66
  }
}

select_loop_mount_targets() {
  local device_number targets_json
  loop_mount_targets=()
  device_number=$(stat -c '%Hr:%Lr' -- "$1") || return 66
  targets_json=$(jq -ce --arg deviceNumber "${device_number}" '
    [.filesystems[] | select(."maj:min" == $deviceNumber) | .target]
  ' <<<"${mount_table}") || return 66
  mapfile -t loop_mount_targets < <(jq -r '.[]' <<<"${targets_json}")
}

select_target_mount_sources() {
  local sources_json
  target_mount_sources=()
  sources_json=$(jq -ce --arg target "$1" '
    [.filesystems[] | select(.target == $target) | .source]
  ' <<<"${mount_table}") || return 66
  mapfile -t target_mount_sources < <(jq -r '.[]' <<<"${sources_json}")
}

target_device=
target_inode=
prove_unmounted_empty_target() {
  local first_entry
  collect_mount_table
  select_target_mount_sources "${target}"
  [[ ${#target_mount_sources[@]} -eq 0 ]] || {
    echo 'runner storage target is mounted without a complete storage identity' >&2
    return 66
  }
  first_entry=$(find "${target}" -mindepth 1 -maxdepth 1 -print -quit) || {
    echo 'runner storage target contents could not be observed' >&2
    return 66
  }
  [[ -z ${first_entry} ]] || {
    echo 'runner storage target must be empty below its mount' >&2
    return 66
  }
  target_device=$(stat -c '%d' -- "${target}")
  target_inode=$(stat -c '%i' -- "${target}")
}

if [[ -e ${image} || -L ${image} || -e ${receipt} || -L ${receipt} ]]; then
  [[ -d ${capacity_root} && ! -L ${capacity_root} ]] || { echo 'runner capacity root is invalid' >&2; exit 66; }
  [[ $(stat -c '%u' -- "${capacity_root}") == 0 ]] || { echo 'runner capacity root owner differs' >&2; exit 66; }
  [[ $(stat -c '%a' -- "${capacity_root}") == 711 ]] || { echo 'runner capacity root mode differs' >&2; exit 66; }
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
  collect_mount_table
  select_target_mount_sources "${target}"
  if [[ ${#target_mount_sources[@]} -gt 0 ]]; then
    [[ ${#target_mount_sources[@]} -eq 1 ]] || {
      echo 'runner storage target has multiple global mounts' >&2
      exit 66
    }
    write_current_receipt
    trap - EXIT INT TERM
    printf '%s\n' "${receipt}"
    exit 0
  fi
  prove_unmounted_empty_target
  associated_output=$(sudo -n losetup --noheadings --output NAME --associated "${image}")
  associated=()
  if [[ -n ${associated_output} ]]; then
    mapfile -t associated < <(sed '/^$/d' <<<"${associated_output}")
  fi
  [[ ${#associated[@]} -le 1 ]] || { echo 'runner storage image has multiple loop devices' >&2; exit 66; }
  if [[ ${#associated[@]} -eq 1 ]]; then
    loop_device=${associated[0]//[[:space:]]/}
    collect_mount_table
    select_loop_mount_targets "${loop_device}"
    [[ ${#loop_mount_targets[@]} -eq 0 ]] || {
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
  [[ $(stat -Lc '%d:%i' -- "${target_handle}") == "${target_device}:${target_inode}" ]] || {
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

prove_unmounted_empty_target

if [[ ! -e ${capacity_root} ]]; then
  install -d -m 0700 -- "${capacity_root}"
  capacity_created=true
fi
[[ -d ${capacity_root} && ! -L ${capacity_root} ]] || { echo 'runner capacity root is invalid' >&2; exit 66; }
[[ $(realpath -e -- "${capacity_root}") == "${capacity_root}" ]] || { echo 'runner capacity root is non-canonical' >&2; exit 66; }

exec {capacity_fd}<"${capacity_root}"
capacity_handle=/proc/$$/fd/${capacity_fd}
require_same_object "${capacity_handle}" "${capacity_root}" || {
  echo 'runner capacity root changed before image creation' >&2
  exit 66
}

umask 077
set -C
if ! exec {image_fd}>"${image}"; then
  set +C
  echo 'runner storage image already exists or could not be created safely' >&2
  exit 66
fi
set +C
image_created=true
image_handle=/proc/$$/fd/${image_fd}
python3 - "${image_handle}" "${image_bytes}" <<'PY'
import os
import sys

path = sys.argv[1]
size = int(sys.argv[2])
fd = os.open(path, os.O_WRONLY)
try:
    os.ftruncate(fd, size)
    os.fsync(fd)
finally:
    os.close(fd)
PY
[[ -f ${image} && ! -L ${image} ]] || { echo 'runner storage image creation failed' >&2; exit 66; }
require_same_object "${image_handle}" "${image}" || {
  echo 'runner storage image path changed after creation' >&2
  exit 66
}
[[ $(stat -Lc '%s' -- "${image_handle}") == "${image_bytes}" ]] || { echo 'runner storage image size differs' >&2; exit 66; }
[[ $(stat -Lc '%a' -- "${image_handle}") == 600 ]] || { echo 'runner storage image mode differs' >&2; exit 66; }
require_same_object "${capacity_handle}" "${capacity_root}" || {
  echo 'runner capacity root changed before ownership transfer' >&2
  exit 66
}
sudo -n chown root:root -- "${capacity_handle}" "${image_handle}"
sudo -n chmod 0711 -- "${capacity_handle}"
sudo -n chmod 0600 -- "${image_handle}"
[[ $(stat -Lc '%u:%a' -- "${capacity_handle}") == 0:711 ]] || { echo 'runner capacity root ownership transfer failed' >&2; exit 66; }
[[ $(stat -Lc '%u:%a' -- "${image_handle}") == 0:600 ]] || { echo 'runner storage image ownership transfer failed' >&2; exit 66; }
require_same_object "${image_handle}" "${image}" || {
  echo 'runner storage image path changed during ownership transfer' >&2
  exit 66
}

sudo -n mkfs.xfs -q -m crc=1,finobt=1 -n ftype=1 -- "${image_handle}"
loop_device=$(sudo -n losetup --find --show --nooverlap "${image_handle}")
[[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]] || { echo 'runner storage loop device is invalid' >&2; exit 66; }
exec {target_fd}<"${target}"
target_handle=/proc/$$/fd/${target_fd}
[[ $(stat -Lc '%d:%i' -- "${target_handle}") == "${target_device}:${target_inode}" ]] || {
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
