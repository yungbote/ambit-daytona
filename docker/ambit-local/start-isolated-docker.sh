#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: start-isolated-docker.sh STATE_ROOT' >&2
  exit 64
fi

state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || {
  echo 'STATE_ROOT must be a specific absolute path below /home' >&2
  exit 64
}
[[ $(realpath -e -- "${state_root}") == "${state_root}" ]] || {
  echo 'STATE_ROOT must be an existing canonical non-symlink path' >&2
  exit 64
}

runtime_id=$(printf '%s' "${state_root}" | sha256sum | cut -c1-12)
runtime_root=/tmp/ambit-c16b-docker-${runtime_id}
data_root=${state_root}/outer-docker
containerd_root=${state_root}/outer-containerd
exec_root=${runtime_root}/docker-exec
socket=${runtime_root}/docker.sock
pidfile=${runtime_root}/docker.pid
containerd_state=${runtime_root}/containerd-state
containerd_socket=${runtime_root}/containerd.sock
containerd_pidfile=${state_root}/config/outer-containerd.pid
containerd_config=${state_root}/config/outer-containerd.toml
docker_log=${state_root}/evidence/outer-docker.log
containerd_log=${state_root}/evidence/outer-containerd.log
config=${state_root}/config/outer-docker.json

for directory in "${data_root}" "${containerd_root}" "${state_root}/config" "${state_root}/evidence"; do
  [[ -d ${directory} && ! -L ${directory} ]] || {
    echo "isolated runtime directory is invalid: ${directory}" >&2
    exit 66
  }
done
[[ ! -e ${runtime_root} ]] || { echo "isolated runtime root already exists: ${runtime_root}" >&2; exit 65; }
[[ ! -e ${containerd_pidfile} && ! -e ${containerd_config} && ! -e ${config} ]] || {
  echo 'isolated daemon pid/config already exists' >&2
  exit 65
}
[[ ! -e ${docker_log} && ! -e ${containerd_log} ]] || {
  echo 'isolated daemon log already exists' >&2
  exit 65
}
command -v containerd >/dev/null
command -v dockerd >/dev/null
sudo -n true

python3 - <<'PY'
import ipaddress
import json
import subprocess

reserved = ipaddress.ip_network("172.30.0.0/16")
routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show"], text=True))
for route in routes:
    destination = route.get("dst")
    if not destination or destination == "default":
        continue
    try:
        observed = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        continue
    if observed.overlaps(reserved):
        raise SystemExit(f"isolated Docker address pool overlaps host route {observed}")
PY

mkdir -p "${exec_root}" "${containerd_state}"
chmod 0700 "${runtime_root}" "${exec_root}" "${containerd_state}"
umask 077
cat > "${config}" <<EOF
{
  "data-root": "${data_root}",
  "exec-root": "${exec_root}",
  "pidfile": "${pidfile}",
  "hosts": ["unix://${socket}"],
  "group": "docker",
  "containerd": "${containerd_socket}",
  "containerd-namespace": "ambit-c16b",
  "containerd-plugins-namespace": "ambit-c16b-plugins",
  "bridge": "none",
  "default-address-pools": [
    {"base": "172.30.0.0/16", "size": 24}
  ],
  "iptables": false,
  "ip6tables": false,
  "ip-forward": false,
  "ip-masq": false,
  "userland-proxy": true,
  "live-restore": false,
  "storage-driver": "overlay2",
  "log-driver": "local",
  "log-opts": {"max-size": "50m", "max-file": "3"}
}
EOF
chmod 0600 "${config}"
cat > "${containerd_config}" <<EOF
version = 3
root = '${containerd_root}'
state = '${containerd_state}'
temp = '${runtime_root}/containerd-temp'
disabled_plugins = [
  'io.containerd.cri.v1.images',
  'io.containerd.cri.v1.runtime',
  'io.containerd.nri.v1.nri',
]
required_plugins = []
imports = []

[grpc]
  address = '${containerd_socket}'
  uid = 0
  gid = 0
EOF
chmod 0600 "${containerd_config}"

containerd_pid=
docker_pid=
runtime_started=false
safe_process() {
  local pid=$1
  local executable=$2
  local required=$3
  [[ ${pid} =~ ^[1-9][0-9]*$ && -r /proc/${pid}/cmdline ]] || return 1
  local command_line
  command_line=$(tr '\0' ' ' < "/proc/${pid}/cmdline")
  [[ ${command_line} == *"${executable}"* && ${command_line} == *"${required}"* ]]
}
terminate_exact() {
  local pid=$1
  local executable=$2
  local required=$3
  if safe_process "${pid}" "${executable}" "${required}"; then
    sudo -n kill -TERM "${pid}" >/dev/null 2>&1 || true
    for _ in $(seq 1 80); do
      [[ ! -e /proc/${pid} ]] && break
      sleep 0.25
    done
  fi
}
startup_cleanup() {
  if [[ -n ${docker_pid} ]]; then
    terminate_exact "${docker_pid}" dockerd "${config}"
  elif [[ -f ${pidfile} ]]; then
    terminate_exact "$(<"${pidfile}")" dockerd "${config}"
  fi
  if [[ -n ${containerd_pid} ]]; then
    terminate_exact "${containerd_pid}" containerd "${containerd_config}"
  elif [[ -f ${containerd_pidfile} ]]; then
    terminate_exact "$(<"${containerd_pidfile}")" containerd "${containerd_config}"
  fi
  sudo -n find "${runtime_root}" -depth -delete >/dev/null 2>&1 || true
  unlink "${containerd_pidfile}" >/dev/null 2>&1 || true
}
trap 'if [[ ${runtime_started} != true ]]; then startup_cleanup; fi' EXIT INT TERM

sudo -n containerd --config "${containerd_config}" --log-level info > "${containerd_log}" 2>&1 &
containerd_pid=$!
printf '%s\n' "${containerd_pid}" > "${containerd_pidfile}"
for _ in $(seq 1 120); do
  [[ -S ${containerd_socket} ]] && break
  safe_process "${containerd_pid}" containerd "${containerd_config}" || {
    echo 'dedicated containerd exited during startup' >&2
    exit 68
  }
  sleep 0.25
done
[[ -S ${containerd_socket} ]] || { echo 'dedicated containerd socket was not created' >&2; exit 68; }

sudo -n dockerd --config-file "${config}" > "${docker_log}" 2>&1 &
docker_pid=$!
for _ in $(seq 1 240); do
  if [[ -S ${socket} ]] && DOCKER_HOST="unix://${socket}" docker info >/dev/null 2>&1; then
    break
  fi
  safe_process "${docker_pid}" dockerd "${config}" || {
    echo 'isolated Docker daemon exited during startup' >&2
    exit 68
  }
  sleep 0.25
done
[[ -S ${socket} && -f ${pidfile} ]] || { echo 'isolated Docker socket/pidfile was not created' >&2; exit 68; }
docker_pid=$(<"${pidfile}")
safe_process "${docker_pid}" dockerd "${config}" || { echo 'Docker pidfile does not identify this daemon' >&2; exit 68; }
docker_root=$(DOCKER_HOST="unix://${socket}" docker info --format '{{.DockerRootDir}}')
[[ ${docker_root} == "${data_root}" ]] || { echo 'isolated Docker reported the wrong data root' >&2; exit 68; }
docker_server_id=$(DOCKER_HOST="unix://${socket}" docker info --format '{{.ID}}')
[[ ${docker_server_id} =~ ^[0-9a-f-]{36}$ ]] || { echo 'isolated Docker server ID is invalid' >&2; exit 68; }

jq -n -S \
  --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg runtimeRoot "${runtime_root}" \
  --arg socket "${socket}" \
  --arg dataRoot "${data_root}" \
  --arg execRoot "${exec_root}" \
  --arg containerdAddress "${containerd_socket}" \
  --arg containerdRoot "${containerd_root}" \
  --arg containerdVersion "$(containerd --version)" \
  --arg containerdConfigSha256 "$(sha256sum "${containerd_config}" | cut -d' ' -f1)" \
  --arg serverId "${docker_server_id}" \
  --arg serverVersion "$(DOCKER_HOST="unix://${socket}" docker version --format '{{.Server.Version}}')" \
  --arg configSha256 "$(sha256sum "${config}" | cut -d' ' -f1)" \
  --argjson dockerPid "${docker_pid}" \
  --argjson containerdPid "${containerd_pid}" \
  '{
    schema:"ambit.local-daytona-isolated-docker/v2",
    outcome:"passed",
    observedAt:$observedAt,
    runtimeRoot:$runtimeRoot,
    socket:$socket,
    dataRoot:$dataRoot,
    execRoot:$execRoot,
    containerd:{address:$containerdAddress,root:$containerdRoot,version:$containerdVersion,pid:$containerdPid,configSha256:$containerdConfigSha256},
    network:{defaultBridge:"disabled",addressPool:"172.30.0.0/16",hostFirewallMutation:false},
    serverId:$serverId,
    serverVersion:$serverVersion,
    dockerPid:$dockerPid,
    configSha256:$configSha256
  }' > "${state_root}/evidence/outer-docker-receipt.json"

runtime_started=true
trap - EXIT INT TERM
printf 'export DOCKER_HOST=unix://%s\n' "${socket}"
