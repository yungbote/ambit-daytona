#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: stop-isolated-docker.sh STATE_ROOT' >&2
  exit 64
fi
state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || { echo 'invalid STATE_ROOT' >&2; exit 64; }
[[ $(realpath -e -- "${state_root}") == "${state_root}" ]] || { echo 'STATE_ROOT is not canonical' >&2; exit 64; }

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
runtime_root_tool=${script_dir}/isolated_runtime_root.py
process_identity_tool=${script_dir}/isolated_process_identity.py
receipt=${state_root}/evidence/outer-docker-receipt.json

runtime_id=$(printf '%s' "${state_root}" | sha256sum | cut -c1-12)
runtime_root=/tmp/ambit-c16b-docker-${runtime_id}
socket=${runtime_root}/docker.sock
pidfile=${runtime_root}/docker.pid
containerd_socket=${runtime_root}/containerd.sock
containerd_pidfile=${state_root}/config/outer-containerd.pid
containerd_config=${state_root}/config/outer-containerd.toml
config=${state_root}/config/outer-docker.json
[[ -f ${runtime_root_tool} && -f ${process_identity_tool} && -f ${receipt} && -d ${runtime_root} && ! -L ${runtime_root} && -f ${pidfile} && -f ${containerd_pidfile} && -f ${containerd_config} && -f ${config} ]] || {
  echo 'isolated Docker runtime identity is incomplete' >&2
  exit 65
}
runtime_identity=$(jq -c -e '.runtimeRootIdentity' "${receipt}")
python3 "${runtime_root_tool}" verify "${runtime_root}" --expected "${runtime_identity}" >/dev/null || {
  echo 'isolated Docker runtime root identity changed' >&2
  exit 65
}

process_identity() {
  local pid=$1
  local executable=$2
  local required=$3
  local executable_path
  executable_path=$(readlink -e -- "$(command -v "${executable}")") || return 1
  sudo -n python3 "${process_identity_tool}" "${pid}" "${executable_path}" "${required}"
}
stop_exact() {
  local pid=$1
  local executable=$2
  local required=$3
  local expected_identity=$4
  local observed_identity
  observed_identity=$(process_identity "${pid}" "${executable}" "${required}") || {
    echo "pid does not identify task-owned ${executable}" >&2
    exit 66
  }
  [[ ${observed_identity} == "${expected_identity}" ]] || {
    echo "${executable} process identity changed after startup" >&2
    exit 66
  }
  sudo -n kill -TERM "${pid}"
  for _ in $(seq 1 120); do
    [[ ! -e /proc/${pid} ]] && return
    sleep 0.25
  done
  echo "${executable} did not stop within 30 seconds" >&2
  exit 67
}
unmount_task_netns() {
  local netns_root=${runtime_root}/docker-exec/netns
  [[ -d ${netns_root} ]] || return 0
  local -a targets=()
  mapfile -t targets < <(findmnt -R -n -o TARGET "${netns_root}" 2>/dev/null | sort -r)
  local target filesystem
  for target in "${targets[@]}"; do
    [[ ${target} =~ ^${netns_root}/[A-Za-z0-9._-]+$ ]] || return 1
    [[ $(findmnt -T "${target}" -n -o TARGET) == "${target}" ]] || return 1
    filesystem=$(findmnt -T "${target}" -n -o FSTYPE)
    [[ ${filesystem} == nsfs ]] || return 1
    sudo -n umount -- "${target}" || return 1
  done
}

docker_pid=$(<"${pidfile}")
containerd_pid=$(<"${containerd_pidfile}")
docker_process_identity=$(jq -cS -e '.dockerProcessIdentity' "${receipt}")
containerd_process_identity=$(jq -cS -e '.containerd.processIdentity' "${receipt}")
stop_exact "${docker_pid}" dockerd "${config}" "${docker_process_identity}"
[[ ! -S ${socket} ]] || { echo 'isolated Docker socket remained after stop' >&2; exit 67; }
stop_exact "${containerd_pid}" containerd "${containerd_config}" "${containerd_process_identity}"
[[ ! -S ${containerd_socket} ]] || { echo 'dedicated containerd socket remained after stop' >&2; exit 67; }
unmount_task_netns || { echo 'task-owned Docker network namespace mount could not be removed' >&2; exit 67; }
unlink "${containerd_pidfile}"
python3 "${runtime_root_tool}" verify "${runtime_root}" --expected "${runtime_identity}" >/dev/null
sudo -n find "${runtime_root}" -depth -delete
[[ ! -e ${runtime_root} ]] || { echo 'isolated runtime root remained after stop' >&2; exit 67; }
printf 'stopped task-owned Docker/containerd; recoverable data remains at %s and %s\n' \
  "${state_root}/outer-docker" "${state_root}/outer-containerd"
