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
for command_name in blkid findmnt flock id jq losetup python3 realpath stat sudo; do
  command -v "${command_name}" >/dev/null || {
    echo "required runner-storage command is absent: ${command_name}" >&2
    exit 66
  }
done
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

[[ -f ${verifier} && -f ${image} && ! -L ${image} ]] || {
  echo 'runner storage verifier or image is absent' >&2
  exit 66
}

for directory in "${target}" "${capacity_root}" "${evidence_root}"; do
  [[ -d ${directory} && ! -L ${directory} ]] || { echo "runner storage directory is invalid: ${directory}" >&2; exit 66; }
  [[ $(realpath -e -- "${directory}") == "${directory}" ]] || { echo "runner storage directory is non-canonical: ${directory}" >&2; exit 66; }
done
[[ $(stat -c '%s' -- "${image}") == "${image_bytes}" ]] || { echo 'runner storage image size differs' >&2; exit 66; }
current_uid=$(id -u)
capacity_owner=$(stat -c '%u' -- "${capacity_root}")
capacity_mode=$(stat -c '%a' -- "${capacity_root}")
image_owner=$(stat -c '%u' -- "${image}")
image_mode=$(stat -c '%a' -- "${image}")
state_root_device=$(stat -c '%d' -- "${state_root}")
[[ $(stat -c '%d' -- "${capacity_root}") == "${state_root_device}" && $(stat -c '%d' -- "${image}") == "${state_root_device}" ]] || {
  echo 'runner storage incomplete state is on a foreign backing filesystem' >&2
  exit 66
}
published_identity=false
if [[ ${capacity_owner}:${capacity_mode}:${image_owner}:${image_mode} == 0:711:0:600 ]]; then
  published_identity=true
elif [[ ! -e ${receipt} && ! -L ${receipt} && ${capacity_mode}:${image_mode} == 700:600 ]] &&
  [[ ${capacity_owner} == "${current_uid}" || ${capacity_owner} == 0 ]] &&
  [[ ${image_owner} == "${current_uid}" || ${image_owner} == 0 ]]; then
  # A kill can interrupt the two-object ownership transfer. The complete
  # pre-publication class therefore admits either task-user or root ownership,
  # but only with the exact 0700/0600 modes and no receipt, loop, or mount.
  published_identity=false
else
  echo 'runner storage image or capacity-root ownership differs' >&2
  exit 66
fi
if [[ -e ${receipt} || -L ${receipt} ]]; then
  [[ ${published_identity} == true ]] || { echo 'runner storage receipt exists before identity publication' >&2; exit 66; }
  [[ -f ${receipt} && ! -L ${receipt} ]] || { echo 'runner storage receipt is invalid' >&2; exit 66; }
  [[ $(jq -er '.image.path' "${receipt}") == "${image}" ]] || { echo 'runner storage receipt image path differs' >&2; exit 66; }
  [[ $(jq -er '.image.device' "${receipt}") == "$(stat -c '%d' -- "${image}")" ]] || { echo 'runner storage receipt image device differs' >&2; exit 66; }
  [[ $(jq -er '.image.inode' "${receipt}") == "$(stat -c '%i' -- "${image}")" ]] || { echo 'runner storage receipt image inode differs' >&2; exit 66; }
fi

associated_output=$(sudo -n losetup --noheadings --output NAME --associated "${image}")
associated=()
if [[ -n ${associated_output} ]]; then
  mapfile -t associated < <(sed '/^$/d' <<<"${associated_output}")
fi
[[ ${#associated[@]} -le 1 ]] || { echo 'runner storage image has multiple loop devices' >&2; exit 66; }
loop_device=
if [[ ${#associated[@]} -eq 1 ]]; then
  loop_device=${associated[0]//[[:space:]]/}
fi

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

collect_mount_table
select_target_mount_sources "${target}"
if [[ ${published_identity} == false ]]; then
  [[ ${#associated[@]} -eq 0 && ${#target_mount_sources[@]} -eq 0 ]] || {
    echo 'runner storage unpublished image unexpectedly reached a loop or mount' >&2
    exit 66
  }
fi
if [[ ${#target_mount_sources[@]} -gt 0 ]]; then
  [[ ${#target_mount_sources[@]} -eq 1 ]] || {
    echo 'runner storage target has multiple global mounts' >&2
    exit 66
  }
  [[ -n ${loop_device} ]] || { echo 'runner storage mount lacks its loop device' >&2; exit 66; }
  current=$(python3 "${verifier}" "${state_root}")
  if [[ -f ${receipt} ]]; then
    stable_filter='{schema,stateRoot,mountTarget,image:{path:.image.path,logicalBytes:.image.logicalBytes,device:.image.device,inode:.image.inode,ownerUid:.image.ownerUid,mode:.image.mode},filesystem:{type:.filesystem.type,uuid:.filesystem.uuid,mountOptions:.filesystem.mountOptions,totalBytes:.filesystem.totalBytes,features:.filesystem.features},backingFilesystem:{device:.backingFilesystem.device,totalBytes:.backingFilesystem.totalBytes,allocationDisposition:.backingFilesystem.allocationDisposition,minimumFreeBytes:.backingFilesystem.minimumFreeBytes},sandboxDiskPolicy}'
    [[ $(jq -S -c "${stable_filter}" "${receipt}") == $(jq -S -c "${stable_filter}" <<<"${current}") ]] || {
      echo 'runner storage stable receipt identity differs from the live mount' >&2
      exit 66
    }
  fi
  mount_tree=$(findmnt -rn -R "${target}" -o TARGET) || {
    echo 'runner storage mount tree observation failed' >&2
    exit 66
  }
  mapfile -t mounts <<<"${mount_tree}"
  [[ ${#mounts[@]} -eq 1 && ${mounts[0]} == "${target}" ]] || {
    echo 'runner storage has nested or foreign mounts' >&2
    exit 66
  }
  sudo -n umount -- "${target}"
fi

if [[ -n ${loop_device} ]]; then
  [[ ${loop_device} =~ ^/dev/loop[0-9]+$ ]] || { echo 'runner storage loop device is invalid' >&2; exit 66; }
  collect_mount_table
  select_loop_mount_targets "${loop_device}"
  [[ ${#loop_mount_targets[@]} -eq 0 ]] || {
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

collect_mount_table
select_target_mount_sources "${target}"
[[ ${#target_mount_sources[@]} -eq 0 ]] || { echo 'runner storage target remained mounted' >&2; exit 66; }
remaining_loops=$(sudo -n losetup --associated "${image}")
[[ -z ${remaining_loops} ]] || { echo 'runner storage loop remained attached' >&2; exit 66; }
if [[ -f ${receipt} && ! -L ${receipt} ]]; then
  unlink -- "${receipt}"
fi
sudo -n unlink -- "${image}"
sudo -n rmdir --ignore-fail-on-non-empty -- "${capacity_root}"
printf '%s\n' "removed ${target} mount, ${loop_device:-no-loop}, ${image}, and ${receipt}"
