#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'Usage: DOCKER_HOST=unix://... verify-host-capacity.sh STATE_ROOT OUTPUT_RECEIPT' >&2
  exit 64
fi

state_root=$1
output=$2
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || { echo 'invalid STATE_ROOT' >&2; exit 64; }
[[ $(/usr/bin/realpath -e -- "${state_root}") == "${state_root}" ]] || { echo 'STATE_ROOT is not canonical' >&2; exit 64; }
[[ ${output} = /* && ! -e ${output} && ! -L ${output} ]] || { echo 'OUTPUT_RECEIPT must be an unused absolute path' >&2; exit 64; }

caller_uid=$(/usr/bin/id -u)
caller_gid=$(/usr/bin/id -g)
[[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${state_root}") == "${caller_uid}:${caller_gid}:700:directory" ]] || {
  echo 'STATE_ROOT authority differs' >&2
  exit 66
}
evidence_root=${state_root}/evidence
[[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${evidence_root}") == "${caller_uid}:${caller_gid}:700:directory" ]] || {
  echo 'evidence-root authority differs' >&2
  exit 66
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
process_identity=${script_dir}/isolated_process_identity.py
process_identity_sha256=28ea7928529c55596174496fee625066fa05bfb0d8f6a077991aed715c1c1b15
[[ $(/usr/bin/sha256sum "${process_identity}" | /usr/bin/cut -d' ' -f1) == "${process_identity_sha256}" ]] || {
  echo 'process identity source digest differs' >&2
  exit 66
}
for executable in /usr/bin/env /usr/bin/nsenter /usr/bin/python3 /usr/bin/sudo; do
  [[ $(/usr/bin/stat -Lc '%u:%g:%F' -- "${executable}") == '0:0:regular file' ]] || {
    echo "host gate executable authority differs: ${executable}" >&2
    exit 66
  }
  executable_mode=$(/usr/bin/stat -Lc '%a' -- "${executable}")
  (( (8#${executable_mode} & 8#022) == 0 )) || {
    echo "host gate executable is writable: ${executable}" >&2
    exit 66
  }
done

read -r -d '' pinned_loader <<'PY' || true
import hashlib
import hmac
import os
import stat
import sys

path, expected, *arguments = sys.argv[1:]
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    identity = os.fstat(descriptor)
    if not stat.S_ISREG(identity.st_mode) or not 0 < identity.st_size <= 2 * 1024 * 1024:
        raise SystemExit("pinned Python source identity is invalid")
    source = bytearray()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        source.extend(block)
finally:
    os.close(descriptor)
if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), expected):
    raise SystemExit("pinned Python source digest differs")
sys.argv = [path, *arguments]
globals()["__file__"] = path
globals()["__package__"] = None
exec(compile(source, path, "exec"), globals(), globals())
PY

runtime_id=$(printf '%s' "${state_root}" | /usr/bin/sha256sum | /usr/bin/cut -c1-12)
runtime_root=/run/ambit-c16b-docker-${runtime_id}
control=${evidence_root}/outer-docker-control.json
start=${evidence_root}/outer-docker-receipt.json
projection=${evidence_root}/runner-docker-storage.json
for receipt in "${control}" "${start}" "${projection}"; do
  [[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${receipt}") == "${caller_uid}:${caller_gid}:600:regular file" ]] || {
    echo "required receipt authority differs: ${receipt}" >&2
    exit 66
  }
done

/usr/bin/jq -e \
  --arg stateRoot "${state_root}" --arg runtimeRoot "${runtime_root}" \
  --arg processSha "${process_identity_sha256}" '
    .schema == "ambit.local-daytona-isolated-docker-control/v1" and
    .outcome == "active" and .stateRoot == $stateRoot and .runtimeRoot == $runtimeRoot and
    .processIdentitySourceSha256 == $processSha and
    (.mountNamespace | keys | sort) == ["device","inode"] and
    (.supervisorProcessIdentity | keys | sort) == [
      "argumentsSha256","executable","mountNamespace","parentPid","pid","procInode","startTimeTicks"
    ] and
    .supervisorProcessIdentity.mountNamespace == .mountNamespace
  ' "${control}" >/dev/null || { echo 'active supervisor control receipt is invalid' >&2; exit 66; }

/usr/bin/jq -e \
  --arg stateRoot "${state_root}" --arg runtimeRoot "${runtime_root}" \
  --argjson control "$(/usr/bin/jq -cS . "${control}")" '
    .schema == "ambit.local-daytona-isolated-docker/v4" and .outcome == "passed" and
    .stateRoot == $stateRoot and .runtimeRoot == $runtimeRoot and
    .mountNamespace == $control.mountNamespace and
    .supervisorProcessIdentity == $control.supervisorProcessIdentity and
    .storageLifecycleSourceSha256 == $control.storageLifecycleSourceSha256 and
    .processIdentitySourceSha256 == $control.processIdentitySourceSha256 and
    .storage.lifecycleSchema == "ambit.local-daytona-runner-storage-operation/v2" and
    .storage.receiptSchema == "ambit.local-daytona-runner-storage/v2" and
    .storage.authorityRoot == "/home/.ambit-c16b-runner-storage" and
    .storage.target == "/home/.ambit-c16b-runner-storage/runner-docker" and
    .storage.mountNamespace == .mountNamespace and
    (.storage.projectionDigest | test("^[0-9a-f]{64}$"))
  ' "${start}" >/dev/null || { echo 'v4 isolated runtime start receipt is invalid' >&2; exit 66; }

namespace=$(/usr/bin/jq -cS '.mountNamespace' "${control}")
supervisor_pid=$(/usr/bin/jq -er '.supervisorProcessIdentity.pid' "${control}")
storage_sha=$(/usr/bin/jq -er '.storageLifecycleSourceSha256' "${control}")
snapshot_helper=${runtime_root}/runner-storage-lifecycle.py
[[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${snapshot_helper}") == '0:0:400:regular file' ]] || {
  echo 'runtime storage helper snapshot authority differs' >&2
  exit 66
}
[[ $(/usr/bin/sha256sum "${snapshot_helper}" | /usr/bin/cut -d' ' -f1) == "${storage_sha}" ]] || {
  echo 'runtime storage helper snapshot digest differs' >&2
  exit 66
}

verify_process() {
  local expected=$1 executable=$2 pid parent arguments namespace_value observed
  pid=$(/usr/bin/jq -er '.pid' <<<"${expected}")
  parent=$(/usr/bin/jq -er '.parentPid' <<<"${expected}")
  arguments=$(/usr/bin/jq -er '.argumentsSha256' <<<"${expected}")
  namespace_value=$(/usr/bin/jq -cS '.mountNamespace' <<<"${expected}")
  observed=$(
    /usr/bin/sudo -n /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
      /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
      "${process_identity}" "${process_identity_sha256}" verify-digest \
      "${pid}" "${executable}" 0 "${arguments}" \
      --parent-pid "${parent}" --mount-namespace "${namespace_value}"
  )
  [[ $(/usr/bin/jq -cS . <<<"${observed}") == "${expected}" ]] || {
    echo "live process identity differs: ${executable}" >&2
    return 66
  }
}

supervisor_identity=$(/usr/bin/jq -cS '.supervisorProcessIdentity' "${start}")
containerd_identity=$(/usr/bin/jq -cS '.containerd.processIdentity' "${start}")
docker_identity=$(/usr/bin/jq -cS '.dockerProcessIdentity' "${start}")
verify_process "${supervisor_identity}" /usr/bin/python3
verify_process "${containerd_identity}" /usr/bin/containerd
verify_process "${docker_identity}" /usr/bin/dockerd
[[ $(/usr/bin/jq -cS '.mountNamespace' <<<"${containerd_identity}") == "${namespace}" &&
   $(/usr/bin/jq -cS '.mountNamespace' <<<"${docker_identity}") == "${namespace}" ]] || {
  echo 'daemon mount namespace differs from supervisor' >&2
  exit 66
}
[[ $(/usr/bin/jq -er '.parentPid' <<<"${containerd_identity}") == "${supervisor_pid}" &&
   $(/usr/bin/jq -er '.parentPid' <<<"${docker_identity}") == "${supervisor_pid}" ]] || {
  echo 'daemon parent differs from supervisor' >&2
  exit 66
}

namespace_device=$(/usr/bin/jq -er '.device' <<<"${namespace}")
namespace_inode=$(/usr/bin/jq -er '.inode' <<<"${namespace}")
storage_operation=$(
  /usr/bin/sudo -n /usr/bin/nsenter --mount="/proc/${supervisor_pid}/ns/mnt" -- \
    /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${snapshot_helper}" "${storage_sha}" observe-private \
    "${state_root}" "${caller_uid}" "${caller_gid}" \
    "${namespace_device}" "${namespace_inode}"
)

verify_process "${supervisor_identity}" /usr/bin/python3
verify_process "${containerd_identity}" /usr/bin/containerd
verify_process "${docker_identity}" /usr/bin/dockerd

/usr/bin/jq -e \
  --arg digest "$(/usr/bin/jq -er '.storage.projectionDigest' "${start}")" \
  --argjson namespace "${namespace}" '
    .schema == "ambit.local-daytona-runner-storage-operation/v2" and
    .outcome == "observed" and
    .mountNamespace == (($namespace.device|tostring) + ":" + ($namespace.inode|tostring)) and
    .authorityRoot == "/home/.ambit-c16b-runner-storage" and
    .mountTarget == "/home/.ambit-c16b-runner-storage/runner-docker" and
    .authorityReceiptSha256 == $digest and
    .receipt.schema == "ambit.local-daytona-runner-storage/v2" and
    .receipt.lifecycleState == "attached" and .receipt.mountNamespace == $namespace
  ' <<<"${storage_operation}" >/dev/null || { echo 'private namespace storage observation is invalid' >&2; exit 66; }

/usr/bin/jq -e \
  --arg digest "$(/usr/bin/jq -er '.authorityReceiptSha256' <<<"${storage_operation}")" '
    .schema == "ambit.local-daytona-runner-storage-projection/v1" and
    .authorityReceiptSha256 == $digest and .receipt.schema == "ambit.local-daytona-runner-storage/v2"
  ' "${projection}" >/dev/null || { echo 'user storage projection differs from root authority' >&2; exit 66; }
projection_receipt_sha256=$(/usr/bin/jq -cS '.receipt' "${projection}" | /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1)
[[ ${projection_receipt_sha256} == "$(/usr/bin/jq -er '.authorityReceiptSha256' <<<"${storage_operation}")" ]] || {
  echo 'user storage projection payload digest differs from root authority' >&2
  exit 66
}

[[ ${DOCKER_HOST:-} == "unix://$(/usr/bin/jq -er '.socket' "${start}")" ]] || {
  echo 'DOCKER_HOST differs from v4 start receipt' >&2
  exit 66
}
[[ -z ${DOCKER_CONTEXT:-} ]] || { echo 'DOCKER_CONTEXT must be unset' >&2; exit 66; }
docker_root=$(/usr/bin/docker info --format '{{.DockerRootDir}}')
docker_server_id=$(/usr/bin/docker info --format '{{.ID}}')
[[ ${docker_root} == "$(/usr/bin/jq -er '.dataRoot' "${start}")" ]] || { echo 'live Docker data root differs' >&2; exit 66; }
[[ ${docker_server_id} == "$(/usr/bin/jq -er '.serverId' "${start}")" ]] || { echo 'live Docker server identity differs' >&2; exit 66; }

cpu_count=$(nproc)
memory_available_kib=$(awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo)
memory_available_bytes=$((memory_available_kib * 1024))
storage_available_bytes=$(/usr/bin/jq -er '.receipt.backingFilesystem.freeBytes' <<<"${storage_operation}")
runner_total=$(/usr/bin/jq -er '.receipt.filesystem.totalBytes' <<<"${storage_operation}")
runner_free=$(/usr/bin/jq -er '.receipt.filesystem.freeBytes' <<<"${storage_operation}")
minimum_cpu=6
minimum_memory=12884901888
minimum_storage=64424509440
required_runner_storage=42949672960
outcome=passed
reasons=()
(( cpu_count >= minimum_cpu )) || { outcome=failed; reasons+=(cpu_below_aggregate_plus_headroom); }
(( memory_available_bytes >= minimum_memory )) || { outcome=failed; reasons+=(memory_below_aggregate_plus_headroom); }
(( storage_available_bytes >= minimum_storage )) || { outcome=failed; reasons+=(storage_below_aggregate_plus_headroom); }
(( runner_total >= required_runner_storage )) || { outcome=failed; reasons+=(runner_storage_below_aggregate_capacity); }
(( runner_free >= required_runner_storage )) || { outcome=failed; reasons+=(runner_storage_below_aggregate_free_space); }
reasons_json=$(printf '%s\n' "${reasons[@]:-}" | sed '/^$/d' | jq -R . | jq -s .)

temporary=$(mktemp "$(dirname "${output}")/.host-capacity.XXXXXX")
cleanup_output() {
  trap - EXIT INT TERM
  unlink -- "${temporary}" 2>/dev/null || true
}
trap cleanup_output EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/jq -n -S \
  --arg outcome "${outcome}" --arg observedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg stateRoot "${state_root}" --arg dockerHost "${DOCKER_HOST}" \
  --arg dockerRoot "${docker_root}" --arg dockerServerId "${docker_server_id}" \
  --arg startReceiptSha256 "$(/usr/bin/sha256sum "${start}" | /usr/bin/cut -d' ' -f1)" \
  --arg controlReceiptSha256 "$(/usr/bin/sha256sum "${control}" | /usr/bin/cut -d' ' -f1)" \
  --arg projectionSha256 "$(/usr/bin/sha256sum "${projection}" | /usr/bin/cut -d' ' -f1)" \
  --argjson cpu "${cpu_count}" --argjson memory "${memory_available_bytes}" \
  --argjson storage "${storage_available_bytes}" --argjson reasons "${reasons_json}" \
  --argjson namespace "${namespace}" --argjson supervisor "${supervisor_identity}" \
  --argjson containerd "${containerd_identity}" --argjson dockerd "${docker_identity}" \
  --argjson runnerStorage "$(/usr/bin/jq -cS '.receipt' <<<"${storage_operation}")" '
  {
    schema:"ambit.local-daytona-host-capacity-headroom/v4",
    outcome:$outcome,
    observedAt:$observedAt,
    capacityProfile:{
      ref:"ambit.workspace-provider-capacity/local-daytona@1",
      digest:"sha256:9326b853b19bb4c1e0704f676751fec9269832be45fe3610b61f8644256e6cfe",
      aggregate:{cpuCores:4,memoryBytes:8589934592,diskBytes:42949672960,gpuCount:0},
      requiredHeadroom:{cpuCores:2,memoryBytes:4294967296,diskBytes:21474836480,gpuCount:0},
      minimumObserved:{cpuCores:6,memoryBytes:12884901888,diskBytes:64424509440,gpuCount:0}
    },
    isolatedDaemon:{
      dockerHost:$dockerHost,dockerRoot:$dockerRoot,serverId:$dockerServerId,
      mountNamespace:$namespace,supervisor:$supervisor,containerd:$containerd,dockerd:$dockerd,
      startReceiptSha256:$startReceiptSha256,controlReceiptSha256:$controlReceiptSha256
    },
    runnerStorage:$runnerStorage,
    runnerStorageProjectionSha256:$projectionSha256,
    observed:{cpuCores:$cpu,memoryAvailableBytes:$memory,storageAvailableBytes:$storage,stateRoot:$stateRoot},
    reasons:$reasons
  }' >"${temporary}"
chmod 0600 "${temporary}"
mv -- "${temporary}" "${output}"
trap - EXIT INT TERM
[[ ${outcome} == passed ]]
