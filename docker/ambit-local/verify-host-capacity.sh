#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: DOCKER_HOST=unix://... verify-host-capacity.sh STATE_ROOT OUTPUT_RECEIPT' >&2
  exit 64
fi

state_root=$1
output=$2
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || {
  echo 'STATE_ROOT must be a specific path below /home' >&2
  exit 64
}
[[ ${state_root} != *'/../'* && ${state_root} != */.. && ${state_root} != *'//'* ]] || {
  echo 'STATE_ROOT must not contain traversal or empty path components' >&2
  exit 64
}
[[ $(realpath -e -- "${state_root}") == "${state_root}" ]] || {
  echo 'STATE_ROOT must be an existing canonical non-symlink path' >&2
  exit 64
}
[[ ${output} = /* && ! -e ${output} ]] || { echo 'OUTPUT_RECEIPT must be an unused absolute path' >&2; exit 64; }

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
runtime_root_tool=${script_dir}/isolated_runtime_root.py
process_identity_tool=${script_dir}/isolated_process_identity.py
[[ -f ${runtime_root_tool} && -f ${process_identity_tool} ]] || {
  echo 'isolated runtime identity verifier is absent' >&2
  exit 66
}

runtime_id=$(printf '%s' "${state_root}" | sha256sum | cut -c1-12)
runtime_root=/tmp/ambit-c16b-docker-${runtime_id}
expected_socket=${runtime_root}/docker.sock
expected_docker_host=unix://${expected_socket}
isolated_receipt=${state_root}/evidence/outer-docker-receipt.json
config=${state_root}/config/outer-docker.json
containerd_config=${state_root}/config/outer-containerd.toml
expected_data_root=${state_root}/outer-docker
expected_containerd_root=${state_root}/outer-containerd
[[ ${DOCKER_HOST:-} == "${expected_docker_host}" ]] || {
  echo "DOCKER_HOST must name the task-owned socket: ${expected_docker_host}" >&2
  exit 66
}
[[ -z ${DOCKER_CONTEXT:-} ]] || { echo 'DOCKER_CONTEXT must be unset' >&2; exit 66; }
[[ -S ${expected_socket} && -f ${isolated_receipt} && -f ${config} && -f ${containerd_config} ]] || {
  echo 'task-owned Docker socket/config/receipt is incomplete' >&2
  exit 66
}

config_sha256=$(sha256sum "${config}" | cut -d' ' -f1)
containerd_config_sha256=$(sha256sum "${containerd_config}" | cut -d' ' -f1)
runtime_root_identity=$(jq -c -e '.runtimeRootIdentity' "${isolated_receipt}")
python3 "${runtime_root_tool}" verify "${runtime_root}" --expected "${runtime_root_identity}" >/dev/null || {
  echo 'live Docker runtime root differs from its task-owned startup receipt' >&2
  exit 66
}
docker_root=$(docker info --format '{{.DockerRootDir}}')
docker_server_id=$(docker info --format '{{.ID}}')
docker_server_version=$(docker version --format '{{.Server.Version}}')
docker_pid=$(jq -er '.dockerPid' "${isolated_receipt}")
containerd_pid=$(jq -er '.containerd.pid' "${isolated_receipt}")
docker_executable=$(readlink -e -- "$(command -v dockerd)")
containerd_executable=$(readlink -e -- "$(command -v containerd)")
docker_process_identity=$(sudo -n python3 "${process_identity_tool}" "${docker_pid}" "${docker_executable}" "${config}")
containerd_process_identity=$(sudo -n python3 "${process_identity_tool}" "${containerd_pid}" "${containerd_executable}" "${containerd_config}")
jq -e \
  --arg runtimeRoot "${runtime_root}" \
  --argjson runtimeRootIdentity "${runtime_root_identity}" \
  --arg socket "${expected_socket}" \
  --arg dataRoot "${expected_data_root}" \
  --arg containerdRoot "${expected_containerd_root}" \
  --arg serverId "${docker_server_id}" \
  --arg serverVersion "${docker_server_version}" \
  --arg configSha256 "${config_sha256}" \
  --arg containerdConfigSha256 "${containerd_config_sha256}" \
  --argjson containerdProcessIdentity "${containerd_process_identity}" \
  --argjson dockerProcessIdentity "${docker_process_identity}" '
    .schema == "ambit.local-daytona-isolated-docker/v3" and
    .outcome == "passed" and
    .runtimeRoot == $runtimeRoot and
    .runtimeRootIdentity == $runtimeRootIdentity and
    .socket == $socket and
    .dataRoot == $dataRoot and
    .containerd.root == $containerdRoot and
    .containerd.address == ($runtimeRoot + "/containerd.sock") and
    .containerd.configSha256 == $containerdConfigSha256 and
    .containerd.processIdentity == $containerdProcessIdentity and
    .network == {addressPool:"172.30.0.0/16",defaultBridge:"disabled",hostFirewallMutation:false} and
    .serverId == $serverId and
    .serverVersion == $serverVersion and
    .dockerProcessIdentity == $dockerProcessIdentity and
    .configSha256 == $configSha256
  ' "${isolated_receipt}" >/dev/null || {
    echo 'live Docker identity differs from its task-owned startup receipt' >&2
    exit 66
  }
[[ ${docker_root} == "${expected_data_root}" ]] || { echo 'live Docker data root differs' >&2; exit 66; }

cpu_count=$(nproc)
memory_available_kib=$(awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo)
storage_available_bytes=$(df -PB1 "${state_root}" | awk 'NR == 2 { print $4 }')
storage_filesystem=$(df -P "${state_root}" | awk 'NR == 2 { print $1 }')
required_cpu=4
required_memory=8589934592
required_storage=42949672960
headroom_cpu=2
headroom_memory=4294967296
headroom_storage=21474836480
minimum_cpu=$((required_cpu + headroom_cpu))
minimum_memory=$((required_memory + headroom_memory))
minimum_storage=$((required_storage + headroom_storage))
memory_available_bytes=$((memory_available_kib * 1024))

outcome=passed
reasons=()
(( cpu_count >= minimum_cpu )) || { outcome=failed; reasons+=(cpu_below_aggregate_plus_headroom); }
(( memory_available_bytes >= minimum_memory )) || { outcome=failed; reasons+=(memory_below_aggregate_plus_headroom); }
(( storage_available_bytes >= minimum_storage )) || { outcome=failed; reasons+=(storage_below_aggregate_plus_headroom); }
[[ ${docker_root} == /home/* ]] || { outcome=failed; reasons+=(docker_root_not_under_home); }
[[ ${docker_root} == "${state_root}"/* ]] || { outcome=failed; reasons+=(docker_root_outside_state_root); }

reasons_json=$(printf '%s\n' "${reasons[@]:-}" | sed '/^$/d' | jq -R . | jq -s .)
mkdir -p "$(dirname "${output}")"
jq -n -S \
  --arg outcome "${outcome}" \
  --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg stateRoot "${state_root}" \
  --arg dockerHost "${expected_docker_host}" \
  --arg dockerRoot "${docker_root}" \
  --arg dockerServerId "${docker_server_id}" \
  --arg storageFilesystem "${storage_filesystem}" \
  --arg isolatedReceiptSha256 "$(sha256sum "${isolated_receipt}" | cut -d' ' -f1)" \
  --arg configSha256 "${config_sha256}" \
  --arg containerdConfigSha256 "${containerd_config_sha256}" \
  --argjson cpu "${cpu_count}" \
  --argjson memory "${memory_available_bytes}" \
  --argjson storage "${storage_available_bytes}" \
  --argjson reasons "${reasons_json}" \
  --argjson dockerProcessIdentity "${docker_process_identity}" \
  --argjson containerdProcessIdentity "${containerd_process_identity}" \
  '{
    schema:"ambit.local-daytona-host-capacity-headroom/v3",
    outcome:$outcome,
    observedAt:$observedAt,
    capacityProfile:{
      ref:"ambit.workspace-provider-capacity/local-daytona@1",
      digest:"sha256:9326b853b19bb4c1e0704f676751fec9269832be45fe3610b61f8644256e6cfe",
      aggregate:{cpuCores:4,memoryBytes:8589934592,diskBytes:42949672960,gpuCount:0},
      requiredHeadroom:{cpuCores:2,memoryBytes:4294967296,diskBytes:21474836480,gpuCount:0},
      minimumObserved:{cpuCores:6,memoryBytes:12884901888,diskBytes:64424509440,gpuCount:0}
    },
    providerOuterCeiling:{cpuCores:5.8,memoryBytes:12616466432,diskReservationBytes:64424509440},
    isolatedDaemon:{dockerHost:$dockerHost,dockerRoot:$dockerRoot,serverId:$dockerServerId,startupReceiptSha256:$isolatedReceiptSha256,configSha256:$configSha256,containerdConfigSha256:$containerdConfigSha256,processes:{dockerd:$dockerProcessIdentity,containerd:$containerdProcessIdentity}},
    observed:{cpuCores:$cpu,memoryAvailableBytes:$memory,storageAvailableBytes:$storage,storageFilesystem:$storageFilesystem,stateRoot:$stateRoot},
    reasons:$reasons
  }' > "${output}"

[[ ${outcome} == passed ]]
