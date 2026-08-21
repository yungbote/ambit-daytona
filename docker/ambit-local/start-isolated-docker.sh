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
[[ $(/usr/bin/realpath -e -- "${state_root}") == "${state_root}" ]] || {
  echo 'STATE_ROOT must be an existing canonical non-symlink path' >&2
  exit 64
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
supervisor=${script_dir}/isolated_runtime_supervisor.py
process_identity=${script_dir}/isolated_process_identity.py
supervisor_sha256=0e89e566b79e968b7b37fb322e15968f8df2a4a838c6832715682b976d12daeb
process_identity_sha256=28ea7928529c55596174496fee625066fa05bfb0d8f6a077991aed715c1c1b15
storage_lifecycle_sha256=991c7db087d88390d67263183afa70908710be40b49e8d5d3059958a8362641e

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
    if not stat.S_ISREG(identity.st_mode):
        raise SystemExit("pinned Python source is not regular")
    if not 0 < identity.st_size <= 2 * 1024 * 1024:
        raise SystemExit("pinned Python source size is invalid")
    source = bytearray()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        source.extend(block)
finally:
    os.close(descriptor)
actual = hashlib.sha256(source).hexdigest()
if not hmac.compare_digest(actual, expected):
    raise SystemExit("pinned Python source digest differs")
sys.argv = [path, *arguments]
globals()["__file__"] = path
globals()["__package__"] = None
exec(compile(source, path, "exec"), globals(), globals())
PY

for path in "${supervisor}" "${process_identity}"; do
  [[ -f ${path} && ! -L ${path} ]] || {
    echo "isolated runtime source is absent or unsafe: ${path}" >&2
    exit 66
  }
done
[[ $(/usr/bin/sha256sum "${supervisor}" | /usr/bin/cut -d' ' -f1) == "${supervisor_sha256}" ]] || {
  echo 'isolated runtime supervisor source digest differs' >&2
  exit 66
}
[[ $(/usr/bin/sha256sum "${process_identity}" | /usr/bin/cut -d' ' -f1) == "${process_identity_sha256}" ]] || {
  echo 'isolated process identity source digest differs' >&2
  exit 66
}

trusted_root_executable() {
  local path=$1 owner_group mode
  [[ -e ${path} ]] || { echo "required root executable is absent: ${path}" >&2; return 1; }
  owner_group=$(/usr/bin/stat -Lc '%u:%g' -- "${path}")
  mode=$(/usr/bin/stat -Lc '%a' -- "${path}")
  [[ ${owner_group} == 0:0 ]] || { echo "root executable owner differs: ${path}" >&2; return 1; }
  (( (8#${mode} & 8#022) == 0 )) || { echo "root executable is writable: ${path}" >&2; return 1; }
  [[ $(/usr/bin/stat -Lc '%F' -- "${path}") == 'regular file' ]] || {
    echo "root executable is not regular: ${path}" >&2
    return 1
  }
}
for command_path in /usr/bin/env /usr/bin/python3 /usr/bin/sudo /usr/bin/unshare; do
  trusted_root_executable "${command_path}"
done

caller_uid=$(/usr/bin/id -u)
caller_gid=$(/usr/bin/id -g)
[[ ${caller_uid} =~ ^[1-9][0-9]*$ && ${caller_gid} =~ ^[0-9]+$ ]] || {
  echo 'isolated runtime caller identity is invalid' >&2
  exit 66
}
[[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${state_root}") == "${caller_uid}:${caller_gid}:700:directory" ]] || {
  echo 'isolated runtime state root owner, group, mode, or type differs' >&2
  exit 66
}
evidence_root=${state_root}/evidence
[[ -d ${evidence_root} && ! -L ${evidence_root} ]] || {
  echo 'isolated runtime evidence root is absent or unsafe' >&2
  exit 66
}
[[ $(/usr/bin/realpath -e -- "${evidence_root}") == "${evidence_root}" ]] || {
  echo 'isolated runtime evidence root is not canonical' >&2
  exit 66
}
[[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${evidence_root}") == "${caller_uid}:${caller_gid}:700:directory" ]] || {
  echo 'isolated runtime evidence root owner, group, mode, or type differs' >&2
  exit 66
}

runtime_id=$(printf '%s' "${state_root}" | /usr/bin/sha256sum | /usr/bin/cut -c1-12)
runtime_root=/run/ambit-c16b-docker-${runtime_id}
socket=${runtime_root}/docker.sock
control_receipt=${evidence_root}/outer-docker-control.json
start_receipt=${evidence_root}/outer-docker-receipt.json
supervisor_log=${evidence_root}/outer-supervisor.log
boot_id=$(/usr/bin/tr -d '\n' </proc/sys/kernel/random/boot_id)
[[ ${boot_id} =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
  echo 'kernel boot identity is invalid' >&2
  exit 66
}
python_executable=$(/usr/bin/readlink -e -- /usr/bin/python3)

supervisor_arguments_sha256=$(
  printf '%s\0' /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${supervisor}" "${supervisor_sha256}" supervise "${state_root}" \
    "${caller_uid}" "${caller_gid}" |
    /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1
)

require_regular_receipt() {
  local path=$1
  [[ -f ${path} && ! -L ${path} ]] || {
    echo "isolated runtime receipt is not a regular file: ${path}" >&2
    return 1
  }
  [[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${path}") == "${caller_uid}:${caller_gid}:600:regular file" ]] || {
    echo "isolated runtime receipt owner, group, mode, or type differs: ${path}" >&2
    return 1
  }
}

validate_control_shape() {
  require_regular_receipt "${control_receipt}"
  /usr/bin/jq -e \
    --arg bootId "${boot_id}" --arg stateRoot "${state_root}" \
    --arg runtimeRoot "${runtime_root}" --arg supervisorSha "${supervisor_sha256}" \
    --arg identitySha "${process_identity_sha256}" --arg storageSha "${storage_lifecycle_sha256}" \
    --arg argumentsSha "${supervisor_arguments_sha256}" --arg executable "${python_executable}" \
    --argjson callerUid "${caller_uid}" --argjson callerGid "${caller_gid}" '
      (keys | sort) == [
        "bootId", "caller", "mountNamespace", "observedAt", "outcome",
        "processIdentitySourceSha256", "runtimeRoot", "runtimeRootIdentity", "schema",
        "stateRoot", "storageLifecycleSourceSha256", "supervisorProcessIdentity",
        "supervisorSourceSha256"
      ] and
      .schema == "ambit.local-daytona-isolated-docker-control/v1" and
      .outcome == "active" and .bootId == $bootId and .stateRoot == $stateRoot and
      .caller == {uid:$callerUid,gid:$callerGid} and
      .supervisorSourceSha256 == $supervisorSha and
      .processIdentitySourceSha256 == $identitySha and
      .storageLifecycleSourceSha256 == $storageSha and .runtimeRoot == $runtimeRoot and
      (.runtimeRootIdentity | keys | sort) == ["device","inode","mode","uid"] and
      .runtimeRootIdentity.uid == 0 and .runtimeRootIdentity.mode == 448 and
      (.mountNamespace | keys | sort) == ["device","inode"] and
      (.supervisorProcessIdentity | keys | sort) == [
        "argumentsSha256","executable","mountNamespace","parentPid","pid",
        "procInode","startTimeTicks"
      ] and
      .supervisorProcessIdentity.executable == $executable and
      .supervisorProcessIdentity.argumentsSha256 == $argumentsSha and
      .supervisorProcessIdentity.mountNamespace == .mountNamespace and
      (.supervisorProcessIdentity.parentPid | type) == "number" and
      .supervisorProcessIdentity.parentPid > 0 and
      (.supervisorProcessIdentity.pid | type) == "number" and
      .supervisorProcessIdentity.pid > 0
    ' "${control_receipt}" >/dev/null
}

invoke_process_identity() {
  local operation=$1 pid namespace parent_pid
  pid=$(/usr/bin/jq -r '.supervisorProcessIdentity.pid' "${control_receipt}")
  namespace=$(/usr/bin/jq -cS '.mountNamespace' "${control_receipt}")
  parent_pid=$(/usr/bin/jq -r '.supervisorProcessIdentity.parentPid' "${control_receipt}")
  /usr/bin/sudo -n /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${process_identity}" "${process_identity_sha256}" "${operation}" \
    "${pid}" /usr/bin/python3 0 "${supervisor_arguments_sha256}" \
    --parent-pid "${parent_pid}" --mount-namespace "${namespace}"
}

verify_live_supervisor() {
  validate_control_shape
  local expected observed
  expected=$(/usr/bin/jq -cS '.supervisorProcessIdentity' "${control_receipt}")
  observed=$(invoke_process_identity verify-digest)
  [[ ${observed} == "${expected}" ]] || {
    echo 'isolated runtime supervisor identity changed' >&2
    return 1
  }
}

validate_start_receipt() {
  require_regular_receipt "${start_receipt}"
  local expected_supervisor expected_namespace
  expected_supervisor=$(/usr/bin/jq -cS '.supervisorProcessIdentity' "${control_receipt}")
  expected_namespace=$(/usr/bin/jq -cS '.mountNamespace' "${control_receipt}")
  /usr/bin/jq -e \
    --arg bootId "${boot_id}" --arg stateRoot "${state_root}" \
    --arg runtimeRoot "${runtime_root}" --arg socket "${socket}" \
    --arg dataRoot '/home/.ambit-c16b-runner-storage/runner-docker/outer-docker' \
    --arg supervisorSha "${supervisor_sha256}" --arg identitySha "${process_identity_sha256}" \
    --arg storageSha "${storage_lifecycle_sha256}" --argjson supervisor "${expected_supervisor}" \
    --argjson namespace "${expected_namespace}" '
      .schema == "ambit.local-daytona-isolated-docker/v4" and .outcome == "passed" and
      .bootId == $bootId and .stateRoot == $stateRoot and .runtimeRoot == $runtimeRoot and
      .socket == $socket and .dataRoot == $dataRoot and
      .supervisorSourceSha256 == $supervisorSha and
      .processIdentitySourceSha256 == $identitySha and
      .storageLifecycleSourceSha256 == $storageSha and
      .supervisorProcessIdentity == $supervisor and .mountNamespace == $namespace and
      .storage.lifecycleSchema == "ambit.local-daytona-runner-storage-operation/v2" and
      .storage.receiptSchema == "ambit.local-daytona-runner-storage/v2" and
      (.storage.projectionDigest | test("^[0-9a-f]{64}$")) and
      .storage.authorityRoot == "/home/.ambit-c16b-runner-storage" and
      .storage.target == "/home/.ambit-c16b-runner-storage/runner-docker" and
      .storage.mountNamespace == $namespace
    ' "${start_receipt}" >/dev/null
}

recover_previous_boot_receipts() {
  require_regular_receipt "${control_receipt}"
  local receipt_boot receipt_state receipt_runtime receipt_schema
  receipt_schema=$(/usr/bin/jq -er '.schema' "${control_receipt}")
  receipt_boot=$(/usr/bin/jq -er '.bootId' "${control_receipt}")
  receipt_state=$(/usr/bin/jq -er '.stateRoot' "${control_receipt}")
  receipt_runtime=$(/usr/bin/jq -er '.runtimeRoot' "${control_receipt}")
  [[ ${receipt_boot} =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  [[ ${receipt_schema} == ambit.local-daytona-isolated-docker-control/v1 ]] || return 1
  [[ ${receipt_boot} != "${boot_id}" && ${receipt_state} == "${state_root}" && ${receipt_runtime} == "${runtime_root}" ]] || return 1
  [[ ! -e ${runtime_root} ]] || { echo 'previous-boot runtime root unexpectedly remains' >&2; return 1; }
  if [[ -e ${start_receipt} ]]; then
    require_regular_receipt "${start_receipt}"
    [[ $(/usr/bin/jq -er '.schema' "${start_receipt}") == ambit.local-daytona-isolated-docker/v4 ]] || return 1
    /usr/bin/unlink -- "${start_receipt}"
  fi
  /usr/bin/unlink -- "${control_receipt}"
}

if [[ -e ${control_receipt} ]]; then
  receipt_boot=$(/usr/bin/jq -er '.bootId' "${control_receipt}" 2>/dev/null || true)
  if [[ -n ${receipt_boot} && ${receipt_boot} != "${boot_id}" ]]; then
    recover_previous_boot_receipts || {
      echo 'previous-boot isolated runtime state could not be safely reduced' >&2
      exit 65
    }
  else
    verify_live_supervisor || {
      echo 'isolated runtime control exists without its exact live supervisor' >&2
      exit 65
    }
    [[ -e ${start_receipt} ]] || {
      echo 'isolated runtime supervisor is active but startup is not complete' >&2
      exit 75
    }
    validate_start_receipt || { echo 'isolated runtime start receipt is invalid' >&2; exit 65; }
    printf 'export DOCKER_HOST=unix://%s\n' "${socket}"
    exit 0
  fi
fi

[[ ! -e ${start_receipt} ]] || { echo 'start receipt exists without control receipt' >&2; exit 65; }
[[ ! -e ${runtime_root} ]] || { echo 'runtime root exists without control receipt' >&2; exit 65; }

if [[ -e ${supervisor_log} ]]; then
  require_regular_receipt "${supervisor_log}"
else
  ( set -o noclobber; umask 077; : >"${supervisor_log}" ) || {
    echo 'isolated runtime supervisor log could not be created exclusively' >&2
    exit 66
  }
  /usr/bin/chmod 0600 "${supervisor_log}"
fi

exec {supervisor_log_fd}>>"${supervisor_log}"
/usr/bin/sudo -n /usr/bin/env -i -C / \
  PATH=/usr/bin:/bin LC_ALL=C.UTF-8 HOME=/root \
  SUDO_UID="${caller_uid}" SUDO_GID="${caller_gid}" \
  AMBIT_SUPERVISOR_ARGUMENTS_SHA256="${supervisor_arguments_sha256}" \
  AMBIT_SUPERVISOR_SOURCE_SHA256="${supervisor_sha256}" \
  /usr/bin/unshare --mount --propagation private \
  /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
  "${supervisor}" "${supervisor_sha256}" supervise \
  "${state_root}" "${caller_uid}" "${caller_gid}" \
  </dev/null >&${supervisor_log_fd} 2>&1 &
launcher_pid=$!

for _ in $(/usr/bin/seq 1 900); do
  if [[ -e ${start_receipt} ]]; then
    verify_live_supervisor && validate_start_receipt || {
      echo 'isolated runtime published an invalid startup authority' >&2
      exit 68
    }
    disown "${launcher_pid}" 2>/dev/null || true
    exec {supervisor_log_fd}>&-
    printf 'export DOCKER_HOST=unix://%s\n' "${socket}"
    exit 0
  fi
  if [[ ! -e /proc/${launcher_pid} ]]; then
    set +e
    wait "${launcher_pid}"
    status=$?
    set -e
    echo "isolated runtime supervisor exited before readiness (status ${status})" >&2
    exit 68
  fi
  /usr/bin/sleep 0.1
done

echo 'isolated runtime supervisor did not publish readiness within 90 seconds' >&2
exit 68
