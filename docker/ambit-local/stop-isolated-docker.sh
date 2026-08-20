#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: stop-isolated-docker.sh STATE_ROOT' >&2
  exit 64
fi
state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || { echo 'invalid STATE_ROOT' >&2; exit 64; }
[[ $(realpath -e -- "${state_root}") == "${state_root}" ]] || { echo 'STATE_ROOT is not canonical' >&2; exit 64; }

runtime_id=$(printf '%s' "${state_root}" | sha256sum | cut -c1-12)
runtime_root=/tmp/ambit-c16b-docker-${runtime_id}
socket=${runtime_root}/docker.sock
pidfile=${runtime_root}/docker.pid
containerd_socket=${runtime_root}/containerd.sock
containerd_pidfile=${state_root}/config/outer-containerd.pid
containerd_config=${state_root}/config/outer-containerd.toml
config=${state_root}/config/outer-docker.json
[[ -d ${runtime_root} && ! -L ${runtime_root} && -f ${pidfile} && -f ${containerd_pidfile} && -f ${containerd_config} && -f ${config} ]] || {
  echo 'isolated Docker runtime identity is incomplete' >&2
  exit 65
}

safe_process() {
  local pid=$1
  local executable=$2
  local required=$3
  [[ ${pid} =~ ^[1-9][0-9]*$ && -r /proc/${pid}/cmdline ]] || return 1
  local command_line
  command_line=$(tr '\0' ' ' < "/proc/${pid}/cmdline")
  [[ ${command_line} == *"${executable}"* && ${command_line} == *"${required}"* ]]
}
stop_exact() {
  local pid=$1
  local executable=$2
  local required=$3
  safe_process "${pid}" "${executable}" "${required}" || {
    echo "pid does not identify task-owned ${executable}" >&2
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

docker_pid=$(<"${pidfile}")
containerd_pid=$(<"${containerd_pidfile}")
stop_exact "${docker_pid}" dockerd "${config}"
[[ ! -S ${socket} ]] || { echo 'isolated Docker socket remained after stop' >&2; exit 67; }
stop_exact "${containerd_pid}" containerd "${containerd_config}"
[[ ! -S ${containerd_socket} ]] || { echo 'dedicated containerd socket remained after stop' >&2; exit 67; }
unlink "${containerd_pidfile}"
sudo -n find "${runtime_root}" -depth -delete
[[ ! -e ${runtime_root} ]] || { echo 'isolated runtime root remained after stop' >&2; exit 67; }
printf 'stopped task-owned Docker/containerd; recoverable data remains at %s and %s\n' \
  "${state_root}/outer-docker" "${state_root}/outer-containerd"
