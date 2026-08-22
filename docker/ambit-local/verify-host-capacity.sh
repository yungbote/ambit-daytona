#!/usr/bin/bash -p
set -euo pipefail

umask 077
unset BASH_ENV ENV CDPATH GLOBIGNORE LD_LIBRARY_PATH LD_PRELOAD PYTHONHOME PYTHONPATH
PATH=/usr/bin:/bin
LC_ALL=C.UTF-8
LANG=C.UTF-8
IFS=$' \t\n'
export PATH LC_ALL LANG
readonly PATH LC_ALL LANG IFS

trusted_tool_directories=(/ /bin /usr /usr/bin)
for directory in "${trusted_tool_directories[@]}"; do
  directory_identity=$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${directory}")
  [[ ${directory_identity} == 0:0:*:directory ]] || {
    echo "host gate tool directory authority differs: ${directory}" >&2
    exit 66
  }
  directory_mode=${directory_identity#0:0:}
  directory_mode=${directory_mode%%:*}
  (( (8#${directory_mode} & 8#022) == 0 )) || {
    echo "host gate tool directory is writable: ${directory}" >&2
    exit 66
  }
done

trusted_executables=(
  /usr/bin/awk
  /usr/bin/bash
  /usr/bin/chmod
  /usr/bin/containerd
  /usr/bin/date
  /usr/bin/dirname
  /usr/bin/docker
  /usr/bin/dockerd
  /usr/bin/env
  /usr/bin/id
  /usr/bin/jq
  /usr/bin/mktemp
  /usr/bin/mv
  /usr/bin/nproc
  /usr/bin/nsenter
  /usr/bin/python3
  /usr/bin/realpath
  /usr/bin/sed
  /usr/bin/sha256sum
  /usr/bin/stat
  /usr/bin/sudo
  /usr/bin/unlink
)
for executable in "${trusted_executables[@]}"; do
  executable_identity=$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${executable}")
  [[ ${executable_identity} == 0:0:*:'regular file' ]] || {
    echo "host gate executable authority differs: ${executable}" >&2
    exit 66
  }
  executable_mode=${executable_identity#0:0:}
  executable_mode=${executable_mode%%:*}
  (( (8#${executable_mode} & 8#022) == 0 && (8#${executable_mode} & 8#111) != 0 )) || {
    echo "host gate executable mode is unsafe: ${executable}" >&2
    exit 66
  }
done

sha256_file() {
  local digest_and_name digest
  digest_and_name=$(/usr/bin/sha256sum -- "$1")
  digest=${digest_and_name%% *}
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]] || {
    echo "could not parse SHA-256 digest for: $1" >&2
    return 66
  }
  printf '%s' "${digest}"
}

sha256_text() {
  local digest_and_marker digest
  digest_and_marker=$(printf '%s' "$1" | /usr/bin/sha256sum)
  digest=${digest_and_marker%% *}
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]] || {
    echo 'could not parse SHA-256 digest for text' >&2
    return 66
  }
  printf '%s' "${digest}"
}

if [[ $# -ne 2 ]]; then
  echo 'Usage: DOCKER_HOST=unix://... verify-host-capacity.sh STATE_ROOT OUTPUT_RECEIPT' >&2
  exit 64
fi

readonly state_root=$1
readonly output=$2
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

script_source=${BASH_SOURCE[0]}
[[ ${script_source} = /* ]] || script_source=${PWD}/${script_source}
script_source=$(/usr/bin/realpath -e -- "${script_source}")
script_dir=${script_source%/*}
process_identity=${script_dir}/isolated_process_identity.py
process_identity_sha256=28ea7928529c55596174496fee625066fa05bfb0d8f6a077991aed715c1c1b15
[[ $(sha256_file "${process_identity}") == "${process_identity_sha256}" ]] || {
  echo 'process identity source digest differs' >&2
  exit 66
}

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

runtime_digest=$(sha256_text "${state_root}")
runtime_id=${runtime_digest:0:12}
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
[[ $(sha256_file "${snapshot_helper}") == "${storage_sha}" ]] || {
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
projection_receipt=$(/usr/bin/jq -cS '.receipt' "${projection}")
projection_receipt_sha256=$(sha256_text "${projection_receipt}")
[[ ${projection_receipt_sha256} == "$(/usr/bin/jq -er '.authorityReceiptSha256' <<<"${storage_operation}")" ]] || {
  echo 'user storage projection payload digest differs from root authority' >&2
  exit 66
}

[[ ${DOCKER_HOST:-} == "unix://$(/usr/bin/jq -er '.socket' "${start}")" ]] || {
  echo 'DOCKER_HOST differs from v4 start receipt' >&2
  exit 66
}
[[ -z ${DOCKER_CONTEXT:-} ]] || { echo 'DOCKER_CONTEXT must be unset' >&2; exit 66; }
docker_root=$(
  /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    DOCKER_HOST="${DOCKER_HOST}" /usr/bin/docker info --format '{{.DockerRootDir}}'
)
docker_server_id=$(
  /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    DOCKER_HOST="${DOCKER_HOST}" /usr/bin/docker info --format '{{.ID}}'
)
[[ ${docker_root} == "$(/usr/bin/jq -er '.dataRoot' "${start}")" ]] || { echo 'live Docker data root differs' >&2; exit 66; }
[[ ${docker_server_id} == "$(/usr/bin/jq -er '.serverId' "${start}")" ]] || { echo 'live Docker server identity differs' >&2; exit 66; }

cpu_count=$(
  /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/nproc
)
memory_available_kib=$(
  /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    /usr/bin/awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo
)
[[ ${cpu_count} =~ ^[1-9][0-9]*$ ]] || { echo 'available CPU observation is invalid' >&2; exit 66; }
[[ ${memory_available_kib} =~ ^[0-9]+$ ]] || { echo 'available memory observation is invalid' >&2; exit 66; }
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
reasons_json=$(printf '%s\n' "${reasons[@]:-}" | /usr/bin/sed '/^$/d' | /usr/bin/jq -R . | /usr/bin/jq -s .)

temporary=$(/usr/bin/mktemp -- "$(/usr/bin/dirname -- "${output}")/.host-capacity.XXXXXX")
cleanup_output() {
  trap - EXIT INT TERM
  /usr/bin/unlink -- "${temporary}" 2>/dev/null || true
}
trap cleanup_output EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
/usr/bin/jq -n -S \
  --arg outcome "${outcome}" \
  --arg observedAt "$(/usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 TZ=UTC /usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg stateRoot "${state_root}" --arg dockerHost "${DOCKER_HOST}" \
  --arg dockerRoot "${docker_root}" --arg dockerServerId "${docker_server_id}" \
  --arg startReceiptSha256 "$(sha256_file "${start}")" \
  --arg controlReceiptSha256 "$(sha256_file "${control}")" \
  --arg projectionSha256 "$(sha256_file "${projection}")" \
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
/usr/bin/chmod 0600 "${temporary}"
/usr/bin/mv --no-copy --update=none-fail -T -- "${temporary}" "${output}"
trap - EXIT INT TERM
[[ ${outcome} == passed ]]
