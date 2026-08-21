#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: stop-isolated-docker.sh STATE_ROOT' >&2
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
process_identity_sha256=683b9e03db64fc0eaed797ee80de20af59963a075345243cc31bc8dc84a28f77

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

[[ -f ${process_identity} && ! -L ${process_identity} ]] || {
  echo 'isolated process identity source is absent or unsafe' >&2
  exit 66
}
[[ $(/usr/bin/sha256sum "${process_identity}" | /usr/bin/cut -d' ' -f1) == "${process_identity_sha256}" ]] || {
  echo 'isolated process identity source digest differs' >&2
  exit 66
}
for command_path in /usr/bin/env /usr/bin/python3 /usr/bin/sudo; do
  command_owner=$(/usr/bin/stat -Lc '%u:%g' -- "${command_path}")
  command_mode=$(/usr/bin/stat -Lc '%a' -- "${command_path}")
  [[ ${command_owner} == 0:0 && $(/usr/bin/stat -Lc '%F' -- "${command_path}") == 'regular file' ]] || {
    echo "root stop executable authority differs: ${command_path}" >&2
    exit 66
  }
  (( (8#${command_mode} & 8#022) == 0 )) || {
    echo "root stop executable is writable: ${command_path}" >&2
    exit 66
  }
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
[[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${evidence_root}") == "${caller_uid}:${caller_gid}:700:directory" ]] || {
  echo 'isolated runtime evidence root owner, group, mode, or type differs' >&2
  exit 66
}

runtime_id=$(printf '%s' "${state_root}" | /usr/bin/sha256sum | /usr/bin/cut -c1-12)
runtime_root=/run/ambit-c16b-docker-${runtime_id}
control_receipt=${evidence_root}/outer-docker-control.json
start_receipt=${evidence_root}/outer-docker-receipt.json
stop_receipt=${evidence_root}/outer-docker-stop-receipt.json
boot_id=$(/usr/bin/tr -d '\n' </proc/sys/kernel/random/boot_id)
[[ ${boot_id} =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || {
  echo 'kernel boot identity is invalid' >&2
  exit 66
}
python_executable=$(/usr/bin/readlink -e -- /usr/bin/python3)

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

if [[ ! -e ${control_receipt} ]]; then
  [[ ! -e ${start_receipt} ]] || {
    echo 'start receipt exists without a supervisor control authority' >&2
    exit 65
  }
  if [[ -e ${stop_receipt} && ! -e ${runtime_root} ]]; then
    require_regular_receipt "${stop_receipt}"
    /usr/bin/jq -e \
      --arg bootId "${boot_id}" --arg stateRoot "${state_root}" '
        .schema == "ambit.local-daytona-isolated-docker-stop/v1" and
        .outcome == "passed" and .bootId == $bootId and .stateRoot == $stateRoot and
        .runtimeRootRemoved == true
      ' "${stop_receipt}" >/dev/null || {
      echo 'isolated runtime stop receipt is invalid' >&2
      exit 65
    }
    printf 'isolated Docker/containerd supervisor is already stopped\n'
    exit 0
  fi
  echo 'isolated Docker/containerd supervisor is not active' >&2
  exit 65
fi

require_regular_receipt "${control_receipt}"
recorded_supervisor_sha256=$(/usr/bin/jq -r '.supervisorSourceSha256' "${control_receipt}")
recorded_process_identity_sha256=$(/usr/bin/jq -r '.processIdentitySourceSha256' "${control_receipt}")
recorded_storage_lifecycle_sha256=$(/usr/bin/jq -r '.storageLifecycleSourceSha256' "${control_receipt}")
for digest in \
  "${recorded_supervisor_sha256}" \
  "${recorded_process_identity_sha256}" \
  "${recorded_storage_lifecycle_sha256}"; do
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]] || {
    echo 'isolated runtime control source digest is invalid' >&2
    exit 65
  }
done
supervisor_arguments_sha256=$(
  printf '%s\0' /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${supervisor}" "${recorded_supervisor_sha256}" supervise "${state_root}" \
    "${caller_uid}" "${caller_gid}" |
    /usr/bin/sha256sum | /usr/bin/cut -d' ' -f1
)
expected_supervisor=$(/usr/bin/jq -cS '.supervisorProcessIdentity' "${control_receipt}")
namespace=$(/usr/bin/jq -cS '.mountNamespace' "${control_receipt}")
supervisor_pid=$(/usr/bin/jq -r '.supervisorProcessIdentity.pid' "${control_receipt}")
parent_pid=$(/usr/bin/jq -r '.supervisorProcessIdentity.parentPid' "${control_receipt}")

/usr/bin/jq -e \
  --arg bootId "${boot_id}" --arg stateRoot "${state_root}" \
  --arg runtimeRoot "${runtime_root}" --arg supervisorSha "${recorded_supervisor_sha256}" \
  --arg identitySha "${recorded_process_identity_sha256}" \
  --arg storageSha "${recorded_storage_lifecycle_sha256}" \
  --arg argumentsSha "${supervisor_arguments_sha256}" --arg executable "${python_executable}" \
  --argjson callerUid "${caller_uid}" --argjson callerGid "${caller_gid}" '
    (keys | sort) == [
      "bootId", "caller", "mountNamespace", "observedAt", "outcome",
      "processIdentitySourceSha256", "runtimeRoot", "runtimeRootIdentity", "schema",
      "stateRoot", "storageLifecycleSourceSha256", "supervisorProcessIdentity",
      "supervisorSourceSha256"
    ] and
    .schema == "ambit.local-daytona-isolated-docker-control/v1" and
    (.outcome == "active" or .outcome == "stopping") and
    .bootId == $bootId and .stateRoot == $stateRoot and
    .caller == {uid:$callerUid,gid:$callerGid} and .runtimeRoot == $runtimeRoot and
    .supervisorSourceSha256 == $supervisorSha and
    .processIdentitySourceSha256 == $identitySha and
    .storageLifecycleSourceSha256 == $storageSha and
    .supervisorProcessIdentity.executable == $executable and
    .supervisorProcessIdentity.argumentsSha256 == $argumentsSha and
    .supervisorProcessIdentity.mountNamespace == .mountNamespace and
    (.supervisorProcessIdentity.parentPid | type) == "number" and
    .supervisorProcessIdentity.parentPid > 0 and
    (.supervisorProcessIdentity.pid | type) == "number" and
    .supervisorProcessIdentity.pid > 0
  ' "${control_receipt}" >/dev/null || {
  echo 'isolated runtime control receipt is invalid or unsupported' >&2
  exit 65
}

invoke_process_identity() {
  local operation=$1
  /usr/bin/sudo -n /usr/bin/env -i -C / PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
    /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${process_identity}" "${process_identity_sha256}" "${operation}" \
    "${supervisor_pid}" /usr/bin/python3 0 "${supervisor_arguments_sha256}" \
    --parent-pid "${parent_pid}" --mount-namespace "${namespace}"
}

verified_supervisor=$(invoke_process_identity verify-digest) || {
  echo 'control receipt does not bind the exact live isolated runtime supervisor' >&2
  exit 66
}
[[ ${verified_supervisor} == "${expected_supervisor}" ]] || {
  echo 'isolated runtime supervisor continuity proof differs before stop' >&2
  exit 66
}
observed_supervisor=$(invoke_process_identity signal-exact) || {
  echo 'refused to signal a process that is not the exact isolated runtime supervisor' >&2
  exit 66
}
[[ ${observed_supervisor} == "${expected_supervisor}" ]] || {
  echo 'isolated runtime supervisor identity changed at stop boundary' >&2
  exit 66
}

for _ in $(/usr/bin/seq 1 7200); do
  if [[ ! -e /proc/${supervisor_pid} ]]; then
    break
  fi
  if [[ ! -e ${control_receipt} && ! -e ${start_receipt} && ! -e ${runtime_root} && -e ${stop_receipt} ]] &&
    ! invoke_process_identity verify-digest >/dev/null 2>&1; then
    # The pidfd-targeted supervisor is gone and the numeric PID has already
    # been reused. Never wait on or signal the unrelated successor.
    break
  fi
  /usr/bin/sleep 0.1
done
if [[ -e /proc/${supervisor_pid} ]] && invoke_process_identity verify-digest >/dev/null 2>&1; then
  echo 'isolated runtime supervisor did not complete ordered shutdown within 720 seconds' >&2
  exit 67
fi
[[ ! -e ${control_receipt} && ! -e ${start_receipt} && ! -e ${runtime_root} ]] || {
  echo 'isolated runtime control, start receipt, or runtime root remained after stop' >&2
  exit 67
}
require_regular_receipt "${stop_receipt}"
/usr/bin/jq -e \
  --arg bootId "${boot_id}" --arg stateRoot "${state_root}" \
  --argjson supervisor "${expected_supervisor}" '
    .schema == "ambit.local-daytona-isolated-docker-stop/v1" and
    .outcome == "passed" and .bootId == $bootId and .stateRoot == $stateRoot and
    .supervisorProcessIdentity == $supervisor and
    (
      ((.storageProjectionDigest | type) == "string" and
        (.storageProjectionDigest | test("^[0-9a-f]{64}$"))) or
      (.reason == "startup_failure" and .storageProjectionDigest == null)
    ) and
    .runtimeRootRemoved == true
  ' "${stop_receipt}" >/dev/null || {
  echo 'isolated runtime stop receipt is invalid' >&2
  exit 67
}

printf 'stopped task-owned Docker/containerd supervisor and detached private runner storage\n'
