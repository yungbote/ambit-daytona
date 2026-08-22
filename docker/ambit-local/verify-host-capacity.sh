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

for directory in / /bin /usr /usr/bin; do
  identity=$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${directory}")
  [[ ${identity} == 0:0:*:directory ]] || {
    echo "host gate tool directory authority differs: ${directory}" >&2
    exit 66
  }
  mode=${identity#0:0:}; mode=${mode%%:*}
  (( (8#${mode} & 8#022) == 0 )) || {
    echo "host gate tool directory is writable: ${directory}" >&2
    exit 66
  }
done

trusted_executables=(
  /usr/bin/awk
  /usr/bin/bash
  /usr/bin/chmod
  /usr/bin/date
  /usr/bin/dirname
  /usr/bin/docker
  /usr/bin/env
  /usr/bin/id
  /usr/bin/jq
  /usr/bin/mktemp
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
  identity=$(/usr/bin/stat -Lc '%u:%g:%a:%F' -- "${executable}")
  [[ ${identity} == 0:0:*:'regular file' ]] || {
    echo "host gate executable authority differs: ${executable}" >&2
    exit 66
  }
  mode=${identity#0:0:}; mode=${mode%%:*}
  (( (8#${mode} & 8#022) == 0 && (8#${mode} & 8#111) != 0 )) || {
    echo "host gate executable mode is unsafe: ${executable}" >&2
    exit 66
  }
done

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
runtime_digest=$(printf '%s' "${state_root}" | /usr/bin/sha256sum)
runtime_digest=${runtime_digest%% *}
expected_socket=/run/ambit-c16b-docker-api-${runtime_digest:0:12}/docker.sock
runtime_root=/run/ambit-c16b-docker-${runtime_digest:0:12}
[[ ${DOCKER_HOST:-} == "unix://${expected_socket}" ]] || {
  echo 'DOCKER_HOST differs from the exact caller API socket' >&2
  exit 66
}
[[ -z ${DOCKER_CONTEXT:-} ]] || { echo 'DOCKER_CONTEXT must be unset' >&2; exit 66; }

script_source=${BASH_SOURCE[0]}
[[ ${script_source} = /* ]] || script_source=${PWD}/${script_source}
script_source=$(/usr/bin/realpath -e -- "${script_source}")
script_dir=${script_source%/*}
supervisor=${script_dir}/isolated_runtime_supervisor.py
supervisor_sha256=ea7a1e2c3ca2ead63b9be3e201a28f68e7e0b98c9b01903375c1b9e390297f2a
observed_supervisor_sha=$(/usr/bin/sha256sum -- "${supervisor}")
observed_supervisor_sha=${observed_supervisor_sha%% *}
[[ ${observed_supervisor_sha} == "${supervisor_sha256}" ]] || {
  echo 'isolated runtime supervisor source digest differs' >&2
  exit 66
}

read -r -d '' runtime_snapshot_loader <<'PY' || true
import hashlib
import hmac
import os
import stat
import sys

runtime_root, fallback_path, fallback_digest, *arguments = sys.argv[1:]
chosen = fallback_path
control_present = False
parent = os.stat("/run", follow_symlinks=False)
if not (stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and parent.st_gid == 0 and stat.S_IMODE(parent.st_mode) & 0o022 == 0):
    raise SystemExit("runtime snapshot parent authority differs")
try:
    root_fd = os.open(runtime_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except FileNotFoundError:
    root_fd = None
if root_fd is not None:
    try:
        root = os.fstat(root_fd)
        if not (root.st_uid == 0 and root.st_gid == 0 and stat.S_IMODE(root.st_mode) == 0o700):
            raise SystemExit("runtime snapshot root authority differs")
        try:
            os.stat("runtime-control.json", dir_fd=root_fd, follow_symlinks=False)
            control_present = True
        except FileNotFoundError:
            pass
        try:
            descriptor = os.open("isolated_runtime_supervisor.py", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            chosen = runtime_root + "/isolated_runtime_supervisor.py"
        except FileNotFoundError:
            descriptor = None
    finally:
        os.close(root_fd)
else:
    descriptor = None
if descriptor is None:
    chosen = fallback_path
    descriptor = os.open(fallback_path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    identity = os.fstat(descriptor)
    if (not stat.S_ISREG(identity.st_mode) or identity.st_size > 2 * 1024 * 1024
            or (identity.st_size == 0 and (chosen == fallback_path or control_present))):
        raise SystemExit("runtime supervisor source identity is invalid")
    if chosen != fallback_path and not (identity.st_uid == 0 and identity.st_gid == 0 and identity.st_nlink == 1 and identity.st_dev == root.st_dev and stat.S_IMODE(identity.st_mode) == 0o400):
        raise SystemExit("runtime supervisor snapshot authority differs")
    source = bytearray()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        source.extend(block)
finally:
    os.close(descriptor)
actual = hashlib.sha256(source).hexdigest()
if chosen == fallback_path and not hmac.compare_digest(actual, fallback_digest):
    raise SystemExit("fallback supervisor digest differs")
if chosen != fallback_path and not hmac.compare_digest(actual, fallback_digest):
    fallback_fd = os.open(fallback_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fallback_source = bytearray()
        while True:
            block = os.read(fallback_fd, 1024 * 1024)
            if not block:
                break
            fallback_source.extend(block)
    finally:
        os.close(fallback_fd)
    if not hmac.compare_digest(hashlib.sha256(fallback_source).hexdigest(), fallback_digest):
        raise SystemExit("fallback supervisor digest differs")
    if not control_present and fallback_source.startswith(source):
        source = fallback_source
        actual = fallback_digest
        chosen = fallback_path
sys.argv = [chosen, *arguments]
globals()["__file__"] = chosen
globals()["__package__"] = None
globals()["__verified_source_sha256__"] = actual
globals()["__fallback_script_directory__"] = os.path.dirname(fallback_path)
exec(compile(source, chosen, "exec"), globals(), globals())
PY

invoke_status() {
  /usr/bin/sudo -n -- \
    /usr/bin/python3 -I -S -B -c "${runtime_snapshot_loader}" \
    "${runtime_root}" "${supervisor}" "${supervisor_sha256}" status \
    "${state_root}" "${caller_uid}" "${caller_gid}"
}

first_status=$(invoke_status)
/usr/bin/jq -e --arg stateRoot "${state_root}" '
  (keys | sort) == ["outcome","ready","rootReadySha256","schema","socket","stateRoot"] and
  .schema == "ambit.local-daytona-isolated-docker-status/v1" and
  .outcome == "ready" and .stateRoot == $stateRoot and
  (.rootReadySha256 | test("^[0-9a-f]{64}$")) and
  .ready.schema == "ambit.local-daytona-isolated-docker/v5" and
  .ready.outcome == "passed" and .ready.stateRoot == $stateRoot and
  .ready.socket == .socket and
  .ready.storage.lifecycleSchema == "ambit.local-daytona-runner-storage-operation/v3" and
  .ready.storage.receiptSchema == "ambit.local-daytona-runner-storage/v3" and
  .ready.storage.innerRunnerDataRoot.path == "/home/.ambit-c16b-runner-storage/runner-docker/inner-runner" and
  (.ready.workloadCgroupParent | test("^/ambit-c16b-docker-[0-9a-f]{12}$")) and
  .ready.cgroup.path == ("/sys/fs/cgroup" + .ready.workloadCgroupParent) and
  .ready.dataRoot == "/home/.ambit-c16b-runner-storage/outer-docker" and
  .ready.containerd.root == "/home/.ambit-c16b-runner-storage/outer-containerd"
' <<<"${first_status}" >/dev/null || { echo 'root runtime status authority is invalid' >&2; exit 66; }

ready=$(/usr/bin/jq -cS '.ready' <<<"${first_status}")
namespace=$(/usr/bin/jq -cS '.mountNamespace' <<<"${ready}")
supervisor_pid=$(/usr/bin/jq -er '.supervisorProcessIdentity.pid' <<<"${ready}")
runtime_root=$(/usr/bin/jq -er '.runtimeRoot' <<<"${ready}")
storage_sha=$(/usr/bin/jq -er '.storageLifecycleSourceSha256' <<<"${ready}")
snapshot_helper=${runtime_root}/runner-storage-lifecycle.py
namespace_device=$(/usr/bin/jq -er '.device' <<<"${namespace}")
namespace_inode=$(/usr/bin/jq -er '.inode' <<<"${namespace}")

read -r -d '' storage_launcher <<'PY' || true
import hashlib
import hmac
import os
import re
import stat
import sys

path, expected, expected_uid, expected_gid, *arguments = sys.argv[1:]
if os.geteuid() != 0 or os.getegid() != 0:
    raise SystemExit("storage observer launcher is not root")
for name, expected_value in (("SUDO_UID", expected_uid), ("SUDO_GID", expected_gid)):
    value = os.environ.get(name)
    if value is None or re.fullmatch(r"[0-9]+", value) is None or str(int(value)) != value or value != expected_value:
        raise SystemExit("storage observer sudo requester differs")
requester_uid = expected_uid
requester_gid = expected_gid
os.chdir("/")
os.environ.clear()
os.environ.update({"HOME":"/root","LC_ALL":"C.UTF-8","PATH":"/usr/bin:/bin","SUDO_UID":requester_uid,"SUDO_GID":requester_gid})
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    identity = os.fstat(descriptor)
    root = os.stat(os.path.dirname(path), follow_symlinks=False)
    if not (stat.S_ISDIR(root.st_mode) and root.st_uid == 0 and root.st_gid == 0 and stat.S_IMODE(root.st_mode) == 0o700):
        raise SystemExit("runtime storage snapshot root differs")
    if not (stat.S_ISREG(identity.st_mode) and identity.st_uid == 0 and identity.st_gid == 0 and identity.st_nlink == 1 and identity.st_dev == root.st_dev and stat.S_IMODE(identity.st_mode) == 0o400 and 0 < identity.st_size <= 2 * 1024 * 1024):
        raise SystemExit("runtime storage helper snapshot identity differs")
    source = bytearray()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        source.extend(block)
finally:
    os.close(descriptor)
if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), expected):
    raise SystemExit("runtime storage helper snapshot digest differs")
sys.argv = [path, *arguments]
globals()["__file__"] = path
globals()["__package__"] = None
exec(compile(source, path, "exec"), globals(), globals())
PY

storage_operation=$(
  /usr/bin/sudo -n -- /usr/bin/nsenter --mount="/proc/${supervisor_pid}/ns/mnt" -- \
    /usr/bin/python3 -I -S -B -c "${storage_launcher}" \
    "${snapshot_helper}" "${storage_sha}" "${caller_uid}" "${caller_gid}" \
    observe-private "${state_root}" "${caller_uid}" "${caller_gid}" \
    "${namespace_device}" "${namespace_inode}"
)

second_status=$(invoke_status)
[[ $(/usr/bin/jq -cS . <<<"${second_status}") == $(/usr/bin/jq -cS . <<<"${first_status}") ]] || {
  echo 'root runtime authority changed during storage observation' >&2
  exit 66
}
expected_storage_digest=$(/usr/bin/jq -er '.storage.projectionDigest' <<<"${ready}")
/usr/bin/jq -e --arg digest "${expected_storage_digest}" --argjson namespace "${namespace}" '
  .schema == "ambit.local-daytona-runner-storage-operation/v3" and
  .outcome == "observed" and
  .mountNamespace == (($namespace.device|tostring) + ":" + ($namespace.inode|tostring)) and
  .authorityRoot == "/home/.ambit-c16b-runner-storage" and
  .mountTarget == "/home/.ambit-c16b-runner-storage/runner-docker" and
  .authorityReceiptSha256 == $digest and
  .receipt.schema == "ambit.local-daytona-runner-storage/v3" and
  .receipt.lifecycleState == "attached" and
  .receipt.mountNamespace == $namespace and
  .receipt.innerRunnerDataRoot.path == "/home/.ambit-c16b-runner-storage/runner-docker/inner-runner"
' <<<"${storage_operation}" >/dev/null || { echo 'private namespace storage observation is invalid' >&2; exit 66; }

projection_digests=$(
  /usr/bin/python3 -I -S -B -c '
import hashlib, json, os, stat, sys
evidence_path, expected_digest, expected_uid, expected_gid = sys.argv[1:]
parent = os.open(evidence_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    parent_identity = os.fstat(parent)
    if not (stat.S_ISDIR(parent_identity.st_mode) and parent_identity.st_uid == int(expected_uid)
            and parent_identity.st_gid == int(expected_gid) and stat.S_IMODE(parent_identity.st_mode) == 0o700):
        raise SystemExit(66)
    descriptor = os.open("runner-docker-storage.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        identity = os.fstat(descriptor)
        literal = os.stat("runner-docker-storage.json", dir_fd=parent, follow_symlinks=False)
        if not (stat.S_ISREG(identity.st_mode) and identity.st_uid == int(expected_uid)
                and identity.st_gid == int(expected_gid) and stat.S_IMODE(identity.st_mode) == 0o600
                and identity.st_nlink == 1 and identity.st_dev == parent_identity.st_dev
                and (identity.st_dev, identity.st_ino) == (literal.st_dev, literal.st_ino)
                and 0 < identity.st_size <= 1024 * 1024):
            raise SystemExit(66)
        raw = bytearray()
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            raw.extend(block)
    finally:
        os.close(descriptor)
finally:
    os.close(parent)
def object_no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value
document = json.loads(raw, object_pairs_hook=object_no_duplicates)
if (not isinstance(document, dict)
        or set(document) != {"schema", "authorityReceiptSha256", "receipt"}
        or document.get("schema") != "ambit.local-daytona-runner-storage-projection/v2"
        or document.get("authorityReceiptSha256") != expected_digest
        or not isinstance(document.get("receipt"), dict)
        or document["receipt"].get("schema") != "ambit.local-daytona-runner-storage/v3"):
    raise SystemExit(66)
whole_canonical = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
if raw != whole_canonical:
    raise SystemExit(66)
canonical = (json.dumps(document["receipt"], sort_keys=True, separators=(",", ":")) + "\n").encode()
receipt_digest = hashlib.sha256(canonical).hexdigest()
if receipt_digest != expected_digest:
    raise SystemExit(66)
print(receipt_digest, hashlib.sha256(raw).hexdigest())
' "${evidence_root}" "${expected_storage_digest}" "${caller_uid}" "${caller_gid}"
)
projection_receipt_digest=${projection_digests%% *}
projection_file_digest=${projection_digests#* }
[[ ${projection_receipt_digest} =~ ^[0-9a-f]{64}$ && ${projection_file_digest} =~ ^[0-9a-f]{64}$ ]] || {
  echo 'runner storage projection digest output is invalid' >&2
  exit 66
}
[[ ${projection_receipt_digest} == "${expected_storage_digest}" ]] || {
  echo 'runner storage projection payload digest differs from root authority' >&2
  exit 66
}

socket=$(/usr/bin/jq -er '.socket' <<<"${ready}")
[[ ${socket} == "${expected_socket}" ]] || { echo 'root ready API socket differs from derived authority' >&2; exit 66; }
docker_info=$(
  /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 DOCKER_HOST="${DOCKER_HOST}" \
    /usr/bin/docker info --format '{{json .}}'
)
docker_root=$(/usr/bin/jq -er '.DockerRootDir' <<<"${docker_info}")
docker_server_id=$(/usr/bin/jq -er '.ID' <<<"${docker_info}")
[[ ${docker_root} == $(/usr/bin/jq -er '.dataRoot' <<<"${ready}") ]] || { echo 'live Docker data root differs' >&2; exit 66; }
[[ ${docker_server_id} == $(/usr/bin/jq -er '.serverId' <<<"${ready}") ]] || { echo 'live Docker server identity differs' >&2; exit 66; }
third_status=$(invoke_status)
[[ $(/usr/bin/jq -cS . <<<"${third_status}") == $(/usr/bin/jq -cS . <<<"${first_status}") ]] || {
  echo 'root runtime authority changed during Docker observation' >&2
  exit 66
}

cpu_count=$(/usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/nproc)
memory_available_kib=$(
  /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    /usr/bin/awk '$1 == "MemAvailable:" { print $2 }' /proc/meminfo
)
[[ ${cpu_count} =~ ^[1-9][0-9]*$ && ${memory_available_kib} =~ ^[0-9]+$ ]] || {
  echo 'host dynamic capacity observation is invalid' >&2
  exit 66
}
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
  --arg rootReadySha256 "$(/usr/bin/jq -er '.rootReadySha256' <<<"${first_status}")" \
  --arg cgroupParent "$(/usr/bin/jq -er '.workloadCgroupParent' <<<"${ready}")" \
  --arg projectionSha256 "${projection_file_digest}" \
  --argjson cpu "${cpu_count}" --argjson memory "${memory_available_bytes}" \
  --argjson storage "${storage_available_bytes}" --argjson reasons "${reasons_json}" \
  --argjson namespace "${namespace}" \
  --argjson supervisor "$({ /usr/bin/jq -cS '.supervisorProcessIdentity' <<<"${ready}"; })" \
  --argjson containerd "$({ /usr/bin/jq -cS '.containerd.processIdentity' <<<"${ready}"; })" \
  --argjson dockerd "$({ /usr/bin/jq -cS '.dockerProcessIdentity' <<<"${ready}"; })" \
  --argjson socketRoot "$({ /usr/bin/jq -cS '.socketRootIdentity' <<<"${ready}"; })" \
  --argjson socketIdentity "$({ /usr/bin/jq -cS '.socketIdentity' <<<"${ready}"; })" \
  --argjson runnerStorage "$({ /usr/bin/jq -cS '.receipt' <<<"${storage_operation}"; })" '
  {
    schema:"ambit.local-daytona-host-capacity-headroom/v5",
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
      socketRootIdentity:$socketRoot,socketIdentity:$socketIdentity,rootReadySha256:$rootReadySha256,
      workloadCgroupParent:$cgroupParent
    },
    runnerStorage:$runnerStorage,
    runnerStorageProjectionSha256:$projectionSha256,
    observed:{cpuCores:$cpu,memoryAvailableBytes:$memory,storageAvailableBytes:$storage,stateRoot:$stateRoot},
    reasons:$reasons
  }' >"${temporary}"
/usr/bin/chmod 0600 -- "${temporary}"
/usr/bin/python3 -I -S -B -c '
import os, stat, sys
temporary, output = sys.argv[1:]
descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
try:
    value = os.fstat(descriptor)
    if not stat.S_ISREG(value.st_mode) or stat.S_IMODE(value.st_mode) != 0o600:
        raise SystemExit(66)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
parent = os.open(os.path.dirname(output), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.link(temporary, output, follow_symlinks=False)
    os.fsync(parent)
    os.unlink(temporary)
    os.fsync(parent)
finally:
    os.close(parent)
' "${temporary}" "${output}"
trap - EXIT INT TERM
[[ ${outcome} == passed ]]
