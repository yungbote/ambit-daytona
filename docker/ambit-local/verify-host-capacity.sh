#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: verify-host-capacity.sh STATE_ROOT OUTPUT_RECEIPT' >&2
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
[[ ${output} = /* ]] || { echo 'OUTPUT_RECEIPT must be absolute' >&2; exit 64; }
[[ ! -e ${output} ]] || { echo "OUTPUT_RECEIPT already exists: ${output}" >&2; exit 65; }
[[ -d ${state_root} ]] || { echo "STATE_ROOT does not exist: ${state_root}" >&2; exit 66; }

cpu_count=$(nproc)
memory_available_kib=$(awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo)
storage_available_bytes=$(df -PB1 "${state_root}" | awk 'NR == 2 { print $4 }')
storage_filesystem=$(df -P "${state_root}" | awk 'NR == 2 { print $1 }')
docker_root=$(docker info --format '{{.DockerRootDir}}')

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
[[ ${state_root} == "${docker_root}"/* || ${docker_root} == "${state_root}"/* ]] || {
  outcome=failed
  reasons+=(state_root_and_docker_root_not_same_qualified_tree)
}

reasons_json=$(printf '%s\n' "${reasons[@]:-}" | sed '/^$/d' | jq -R . | jq -s .)
mkdir -p "$(dirname "${output}")"
jq -n -S \
  --arg outcome "${outcome}" \
  --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg stateRoot "${state_root}" \
  --arg dockerRoot "${docker_root}" \
  --arg storageFilesystem "${storage_filesystem}" \
  --argjson cpu "${cpu_count}" \
  --argjson memory "${memory_available_bytes}" \
  --argjson storage "${storage_available_bytes}" \
  --argjson reasons "${reasons_json}" \
  '{
    schema:"ambit.local-daytona-host-capacity-headroom/v1",
    outcome:$outcome,
    observedAt:$observedAt,
    capacityProfile:{
      ref:"ambit.workspace-provider-capacity/local-daytona@1",
      digest:"sha256:9326b853b19bb4c1e0704f676751fec9269832be45fe3610b61f8644256e6cfe",
      aggregate:{cpuCores:4,memoryBytes:8589934592,diskBytes:42949672960,gpuCount:0},
      requiredHeadroom:{cpuCores:2,memoryBytes:4294967296,diskBytes:21474836480,gpuCount:0},
      minimumObserved:{cpuCores:6,memoryBytes:12884901888,diskBytes:64424509440,gpuCount:0}
    },
    observed:{
      cpuCores:$cpu,
      memoryAvailableBytes:$memory,
      storageAvailableBytes:$storage,
      storageFilesystem:$storageFilesystem,
      stateRoot:$stateRoot,
      dockerRoot:$dockerRoot
    },
    reasons:$reasons
  }' > "${output}"

[[ ${outcome} == passed ]]
