#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: stop-isolated-docker.sh STATE_ROOT' >&2
  exit 64
fi
state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || { echo 'invalid STATE_ROOT' >&2; exit 64; }
[[ $(realpath -e -- "${state_root}") == "${state_root}" ]] || { echo 'STATE_ROOT is not canonical' >&2; exit 64; }

pidfile=${state_root}/outer-docker.pid
socket=${state_root}/outer-docker.sock
config=${state_root}/config/outer-docker.json
[[ -f ${pidfile} && -f ${config} ]] || { echo 'isolated Docker pid/config is absent' >&2; exit 65; }
pid=$(<"${pidfile}")
[[ ${pid} =~ ^[1-9][0-9]*$ && -r /proc/${pid}/cmdline ]] || { echo 'isolated Docker pid is not live' >&2; exit 65; }
cmdline=$(tr '\0' ' ' < "/proc/${pid}/cmdline")
[[ ${cmdline} == *dockerd* && ${cmdline} == *"${config}"* ]] || {
  echo 'pidfile does not identify this task-owned Docker daemon' >&2
  exit 66
}
sudo -n kill -TERM "${pid}"
for _ in $(seq 1 120); do
  [[ ! -e /proc/${pid} ]] && break
  sleep 0.25
done
[[ ! -e /proc/${pid} ]] || { echo 'isolated Docker did not stop within 30 seconds' >&2; exit 67; }
[[ ! -S ${socket} ]] || { echo 'isolated Docker socket remained after stop' >&2; exit 67; }
printf 'stopped task-owned isolated Docker daemon pid %s; data remains recoverable at %s\n' "${pid}" "${state_root}/outer-docker"
