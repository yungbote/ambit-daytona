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
receipt=${state_root}/evidence/runner-docker-storage.json
[[ -f ${verifier} && -f ${receipt} && -f ${image} && ! -L ${image} ]] || {
  echo 'runner storage verifier, receipt, or image is absent' >&2
  exit 66
}
[[ -d ${target} && ! -L ${target} ]] || { echo 'runner storage target is invalid' >&2; exit 66; }

current=$(python3 "${verifier}" "${state_root}")
[[ $(jq -S -c . "${receipt}") == $(jq -S -c . <<<"${current}") ]] || {
  echo 'runner storage receipt differs from the live mount' >&2
  exit 66
}
loop_device=$(jq -er '.filesystem.loopDevice' "${receipt}")
image_device=$(jq -er '.image.device' "${receipt}")
image_inode=$(jq -er '.image.inode' "${receipt}")
[[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]] || { echo 'runner storage loop device is invalid' >&2; exit 66; }
[[ $(stat -c '%d' -- "${image}") == "${image_device}" ]] || { echo 'runner storage image device changed' >&2; exit 66; }
[[ $(stat -c '%i' -- "${image}") == "${image_inode}" ]] || { echo 'runner storage image inode changed' >&2; exit 66; }
mapfile -t mounts < <(findmnt -rn -R "${target}" -o TARGET)
[[ ${#mounts[@]} -eq 1 && ${mounts[0]} == "${target}" ]] || {
  echo 'runner storage has nested or foreign mounts' >&2
  exit 66
}

sudo -n umount -- "${target}"
sudo -n losetup --detach "${loop_device}"
! mountpoint -q -- "${target}" || { echo 'runner storage target remained mounted' >&2; exit 66; }
[[ -z $(sudo -n losetup --associated "${image}") ]] || { echo 'runner storage loop remained attached' >&2; exit 66; }
unlink -- "${receipt}"
unlink -- "${image}"
rmdir --ignore-fail-on-non-empty -- "${capacity_root}"
printf '%s\n' "removed ${target} mount, ${loop_device}, ${image}, and ${receipt}"
