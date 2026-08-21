#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: remove-runner-storage.sh STATE_ROOT' >&2
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
target=${state_root}/runner-docker
capacity_root=${state_root}/capacity
image=${capacity_root}/runner-docker.xfs
evidence_root=${state_root}/evidence
receipt=${evidence_root}/runner-docker-storage.json
image_bytes=64424509440
[[ -f ${verifier} && -f ${image} && ! -L ${image} ]] || {
  echo 'runner storage verifier or image is absent' >&2
  exit 66
}
for directory in "${target}" "${capacity_root}" "${evidence_root}"; do
  [[ -d ${directory} && ! -L ${directory} ]] || { echo "runner storage directory is invalid: ${directory}" >&2; exit 66; }
  [[ $(realpath -e -- "${directory}") == "${directory}" ]] || { echo "runner storage directory is non-canonical: ${directory}" >&2; exit 66; }
done
[[ $(stat -c '%s' -- "${image}") == "${image_bytes}" ]] || { echo 'runner storage image size differs' >&2; exit 66; }
[[ $(stat -c '%a' -- "${image}") == 600 ]] || { echo 'runner storage image mode differs' >&2; exit 66; }
[[ $(stat -c '%u' -- "${image}") == "$(id -u)" ]] || { echo 'runner storage image owner differs' >&2; exit 66; }
if [[ -e ${receipt} ]]; then
  [[ -f ${receipt} && ! -L ${receipt} ]] || { echo 'runner storage receipt is invalid' >&2; exit 66; }
  [[ $(jq -er '.image.path' "${receipt}") == "${image}" ]] || { echo 'runner storage receipt image path differs' >&2; exit 66; }
  [[ $(jq -er '.image.device' "${receipt}") == "$(stat -c '%d' -- "${image}")" ]] || { echo 'runner storage receipt image device differs' >&2; exit 66; }
  [[ $(jq -er '.image.inode' "${receipt}") == "$(stat -c '%i' -- "${image}")" ]] || { echo 'runner storage receipt image inode differs' >&2; exit 66; }
fi

mapfile -t associated < <(sudo -n losetup --noheadings --output NAME --associated "${image}" | sed '/^$/d')
[[ ${#associated[@]} -le 1 ]] || { echo 'runner storage image has multiple loop devices' >&2; exit 66; }
loop_device=
if [[ ${#associated[@]} -eq 1 ]]; then
  loop_device=${associated[0]//[[:space:]]/}
fi

if mountpoint -q -- "${target}"; then
  [[ -n ${loop_device} ]] || { echo 'runner storage mount lacks its loop device' >&2; exit 66; }
  current=$(python3 "${verifier}" "${state_root}")
  if [[ -f ${receipt} ]]; then
    [[ $(jq -S -c . "${receipt}") == $(jq -S -c . <<<"${current}") ]] || {
      echo 'runner storage receipt differs from the live mount' >&2
      exit 66
    }
  fi
  mapfile -t mounts < <(findmnt -rn -R "${target}" -o TARGET)
  [[ ${#mounts[@]} -eq 1 && ${mounts[0]} == "${target}" ]] || {
    echo 'runner storage has nested or foreign mounts' >&2
    exit 66
  }
  sudo -n umount -- "${target}"
fi

if [[ -n ${loop_device} ]]; then
  [[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]] || { echo 'runner storage loop device is invalid' >&2; exit 66; }
  [[ -z $(findmnt -rn -S "${loop_device}" -o TARGET) ]] || {
    echo 'runner storage loop remains mounted at a foreign target' >&2
    exit 66
  }
  if [[ -f ${receipt} ]]; then
    [[ $(sudo -n blkid -s UUID -o value "${loop_device}") == "$(jq -er '.filesystem.uuid' "${receipt}")" ]] || {
      echo 'runner storage filesystem UUID differs from its receipt' >&2
      exit 66
    }
  fi
  sudo -n losetup --detach "${loop_device}"
fi

! mountpoint -q -- "${target}" || { echo 'runner storage target remained mounted' >&2; exit 66; }
[[ -z $(sudo -n losetup --associated "${image}") ]] || { echo 'runner storage loop remained attached' >&2; exit 66; }
if [[ -f ${receipt} && ! -L ${receipt} ]]; then
  unlink -- "${receipt}"
fi
unlink -- "${image}"
rmdir --ignore-fail-on-non-empty -- "${capacity_root}"
printf '%s\n' "removed ${target} mount, ${loop_device:-no-loop}, ${image}, and ${receipt}"
