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

data_root=${state_root}/outer-docker
exec_root=${state_root}/outer-docker-exec
socket=${state_root}/outer-docker.sock
pidfile=${state_root}/outer-docker.pid
log=${state_root}/evidence/outer-docker.log
config=${state_root}/config/outer-docker.json
bridge=ambitc16b0

[[ -d ${data_root} && ! -L ${data_root} ]] || { echo 'outer Docker data root is invalid' >&2; exit 66; }
[[ ! -e ${socket} && ! -e ${pidfile} ]] || { echo 'isolated Docker daemon already has a socket or pidfile' >&2; exit 65; }
[[ ! -e ${config} ]] || { echo 'isolated Docker config already exists' >&2; exit 65; }
[[ ! -e ${log} ]] || { echo 'isolated Docker log already exists' >&2; exit 65; }
command -v dockerd >/dev/null
sudo -n true

if ip link show "${bridge}" >/dev/null 2>&1; then
  echo "network bridge already exists: ${bridge}" >&2
  exit 67
fi
python3 - <<'PY'
import ipaddress
import json
import subprocess

reserved = [ipaddress.ip_network("172.29.240.0/24"), ipaddress.ip_network("172.30.0.0/16")]
routes = json.loads(subprocess.check_output(["ip", "-j", "route", "show"], text=True))
for route in routes:
    destination = route.get("dst")
    if not destination or destination == "default":
        continue
    try:
        observed = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        continue
    if any(observed.overlaps(candidate) for candidate in reserved):
        raise SystemExit(f"isolated Docker network overlaps host route {observed}")
PY

mkdir -p "${exec_root}"
chmod 0700 "${exec_root}"
umask 077
cat > "${config}" <<EOF
{
  "data-root": "${data_root}",
  "exec-root": "${exec_root}",
  "pidfile": "${pidfile}",
  "hosts": ["unix://${socket}"],
  "group": "docker",
  "bridge": "${bridge}",
  "bip": "172.29.240.1/24",
  "default-address-pools": [
    {"base": "172.30.0.0/16", "size": 24}
  ],
  "iptables": true,
  "ip-forward": true,
  "ip-masq": true,
  "userland-proxy": false,
  "live-restore": false,
  "storage-driver": "overlay2",
  "log-driver": "local",
  "log-opts": {"max-size": "50m", "max-file": "3"}
}
EOF
chmod 0600 "${config}"

sudo -n dockerd --config-file "${config}" > "${log}" 2>&1 &
launcher_pid=$!
for _ in $(seq 1 240); do
  if [[ -S ${socket} ]] && DOCKER_HOST="unix://${socket}" docker info >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "${launcher_pid}" >/dev/null 2>&1; then
    echo 'isolated Docker daemon exited during startup' >&2
    exit 68
  fi
  sleep 0.25
done
[[ -S ${socket} ]] || { echo 'isolated Docker socket was not created' >&2; exit 68; }
docker_root=$(DOCKER_HOST="unix://${socket}" docker info --format '{{.DockerRootDir}}')
[[ ${docker_root} == "${data_root}" ]] || { echo 'isolated Docker reported the wrong data root' >&2; exit 68; }

jq -n -S \
  --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg socket "${socket}" \
  --arg dataRoot "${data_root}" \
  --arg execRoot "${exec_root}" \
  --arg bridge "${bridge}" \
  --arg serverVersion "$(DOCKER_HOST="unix://${socket}" docker version --format '{{.Server.Version}}')" \
  --arg configSha256 "$(sha256sum "${config}" | cut -d' ' -f1)" \
  '{
    schema:"ambit.local-daytona-isolated-docker/v1",
    outcome:"passed",
    observedAt:$observedAt,
    socket:$socket,
    dataRoot:$dataRoot,
    execRoot:$execRoot,
    bridge:{name:$bridge,bip:"172.29.240.1/24",addressPool:"172.30.0.0/16"},
    serverVersion:$serverVersion,
    configSha256:$configSha256
  }' > "${state_root}/evidence/outer-docker-receipt.json"

printf 'export DOCKER_HOST=unix://%s\n' "${socket}"
