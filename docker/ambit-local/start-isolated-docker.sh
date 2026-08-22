#!/usr/bin/bash -p
set -euo pipefail
umask 077
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
PATH=/usr/bin:/bin
LC_ALL=C.UTF-8
readonly PATH LC_ALL

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
[[ $(/usr/bin/realpath -e -- "${evidence_root}") == "${evidence_root}" ]] || {
  echo 'isolated runtime evidence root is absent or noncanonical' >&2
  exit 66
}
[[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${evidence_root}") == "${caller_uid}:${caller_gid}:700:directory" ]] || {
  echo 'isolated runtime evidence root owner, group, mode, or type differs' >&2
  exit 66
}

script_dir=$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)
supervisor=${script_dir}/isolated_runtime_supervisor.py
supervisor_sha256=69138beedc9ff533ba5f86bcd9bc982cd3147f865e428c838a6c13053005643c

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
globals()["__verified_source_sha256__"] = expected
exec(compile(source, path, "exec"), globals(), globals())
PY

read -r -d '' runtime_snapshot_loader <<'PY' || true
import hashlib
import hmac
import os
import stat
import sys

runtime_root, fallback_path, fallback_digest, *arguments = sys.argv[1:]
chosen = fallback_path
expected = fallback_digest
control_present = False
try:
    parent = os.stat("/run", follow_symlinks=False)
    if not (stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and parent.st_gid == 0 and stat.S_IMODE(parent.st_mode) & 0o022 == 0):
        raise SystemExit("runtime snapshot parent authority differs")
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
            snapshot_fd = os.open("isolated_runtime_supervisor.py", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
            chosen = runtime_root + "/isolated_runtime_supervisor.py"
        except FileNotFoundError:
            snapshot_fd = None
    finally:
        os.close(root_fd)
else:
    snapshot_fd = None
if snapshot_fd is None:
    chosen = fallback_path
    snapshot_fd = os.open(fallback_path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    identity = os.fstat(snapshot_fd)
    if not stat.S_ISREG(identity.st_mode) or not 0 < identity.st_size <= 2 * 1024 * 1024:
        raise SystemExit("runtime supervisor source identity is invalid")
    if chosen != fallback_path and not (identity.st_uid == 0 and identity.st_gid == 0 and stat.S_IMODE(identity.st_mode) == 0o400):
        raise SystemExit("runtime supervisor snapshot authority differs")
    source = bytearray()
    while True:
        block = os.read(snapshot_fd, 1024 * 1024)
        if not block:
            break
        source.extend(block)
finally:
    os.close(snapshot_fd)
actual = hashlib.sha256(source).hexdigest()
if chosen == fallback_path and not hmac.compare_digest(actual, expected):
    raise SystemExit("fallback supervisor digest differs")
if chosen != fallback_path and not hmac.compare_digest(actual, expected):
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
    if not hmac.compare_digest(hashlib.sha256(fallback_source).hexdigest(), expected):
        raise SystemExit("fallback supervisor digest differs")
    if not control_present and fallback_source.startswith(source):
        source = fallback_source
        actual = expected
        chosen = fallback_path
sys.argv = [chosen, *arguments]
globals()["__file__"] = chosen
globals()["__package__"] = None
globals()["__verified_source_sha256__"] = actual
exec(compile(source, chosen, "exec"), globals(), globals())
PY

[[ -f ${supervisor} && ! -L ${supervisor} ]] || {
  echo 'isolated runtime supervisor source is absent or unsafe' >&2
  exit 66
}
observed_supervisor_sha=$(/usr/bin/sha256sum -- "${supervisor}")
observed_supervisor_sha=${observed_supervisor_sha%% *}
[[ ${observed_supervisor_sha} == "${supervisor_sha256}" ]] || {
  echo 'isolated runtime supervisor source digest differs' >&2
  exit 66
}

trusted_root_executable() {
  local path=$1 owner_group mode
  [[ -e ${path} ]] || { echo "required root executable is absent: ${path}" >&2; return 1; }
  owner_group=$(/usr/bin/stat -Lc '%u:%g' -- "${path}")
  mode=$(/usr/bin/stat -Lc '%a' -- "${path}")
  [[ ${owner_group} == 0:0 && $(/usr/bin/stat -Lc '%F' -- "${path}") == 'regular file' ]] || {
    echo "root executable authority differs: ${path}" >&2
    return 1
  }
  (( (8#${mode} & 8#022) == 0 )) || {
    echo "root executable is writable: ${path}" >&2
    return 1
  }
}
for command_path in /usr/bin/python3 /usr/bin/sudo /usr/bin/unshare; do
  trusted_root_executable "${command_path}"
done

runtime_id=$(printf '%s' "${state_root}" | /usr/bin/sha256sum)
runtime_id=${runtime_id%% *}
runtime_id=${runtime_id:0:12}
runtime_root=/run/ambit-c16b-docker-${runtime_id}
socket=/run/ambit-c16b-docker-api-${runtime_id}/docker.sock
supervisor_log=${evidence_root}/outer-supervisor.log

invoke_supervisor() {
  local operation=$1
  /usr/bin/sudo -n -- \
    /usr/bin/python3 -I -S -B -c "${runtime_snapshot_loader}" \
    "${runtime_root}" "${supervisor}" "${supervisor_sha256}" "${operation}" \
    "${state_root}" "${caller_uid}" "${caller_gid}"
}

status_socket() {
  /usr/bin/python3 -I -S -B -c '
import json, re, sys
expected_state, expected_socket = sys.argv[1:]
value = json.load(sys.stdin)
if not isinstance(value, dict) or value.get("schema") != "ambit.local-daytona-isolated-docker-status/v1":
    raise SystemExit(66)
if value.get("stateRoot") != expected_state or value.get("outcome") not in ("absent", "starting", "ready"):
    raise SystemExit(66)
if value["outcome"] != "ready":
    print(value["outcome"])
    raise SystemExit(0)
if set(value) != {"schema", "outcome", "stateRoot", "socket", "rootReadySha256", "ready"}:
    raise SystemExit(66)
ready = value["ready"]
if not isinstance(ready, dict) or ready.get("schema") != "ambit.local-daytona-isolated-docker/v5":
    raise SystemExit(66)
if value["socket"] != expected_socket or ready.get("socket") != expected_socket:
    raise SystemExit(66)
if not isinstance(value["rootReadySha256"], str) or re.fullmatch(r"[0-9a-f]{64}", value["rootReadySha256"]) is None:
    raise SystemExit(66)
print(expected_socket)
' "${state_root}" "${socket}"
}

status_value=''
if status_value=$(invoke_supervisor status 2>/dev/null); then
  parsed=$(status_socket <<<"${status_value}") || {
    echo 'isolated runtime status authority is invalid' >&2
    exit 65
  }
  if [[ ${parsed} == "${socket}" ]]; then
    printf 'export DOCKER_HOST=unix://%s\n' "${socket}"
    exit 0
  fi
fi

if [[ -e ${supervisor_log} ]]; then
  [[ -f ${supervisor_log} && ! -L ${supervisor_log} ]] || {
    echo 'isolated runtime supervisor log is unsafe' >&2
    exit 66
  }
  [[ $(/usr/bin/stat -c '%u:%g:%a:%F' -- "${supervisor_log}") == "${caller_uid}:${caller_gid}:600:regular file" ]] || {
    echo 'isolated runtime supervisor log identity differs' >&2
    exit 66
  }
else
  ( set -o noclobber; : >"${supervisor_log}" ) || {
    echo 'isolated runtime supervisor log could not be created exclusively' >&2
    exit 66
  }
  /usr/bin/chmod 0600 -- "${supervisor_log}"
fi

exec {supervisor_log_fd}>>"${supervisor_log}"
launch_runtime() {
  /usr/bin/sudo -n -- \
    /usr/bin/unshare --mount --propagation private --wd / \
    /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${supervisor}" "${supervisor_sha256}" supervise \
    "${state_root}" "${caller_uid}" "${caller_gid}" \
    </dev/null >&${supervisor_log_fd} 2>&1 &
  launcher_pid=$!
  launcher_active=true
}
launch_runtime

for _ in $(/usr/bin/seq 1 1800); do
  if status_value=$(invoke_supervisor status 2>/dev/null); then
    parsed=$(status_socket <<<"${status_value}") || {
      echo 'isolated runtime published an invalid status authority' >&2
      exit 68
    }
    if [[ ${parsed} == "${socket}" ]]; then
      disown "${launcher_pid}" 2>/dev/null || true
      exec {supervisor_log_fd}>&-
      printf 'export DOCKER_HOST=unix://%s\n' "${socket}"
      exit 0
    fi
  elif [[ ${launcher_active} == false ]]; then
    /usr/bin/sleep 0.5
    launch_runtime
  fi
  if [[ ${launcher_active} == true ]] && ! /usr/bin/kill -0 "${launcher_pid}" 2>/dev/null; then
    set +e
    wait "${launcher_pid}"
    status=$?
    set -e
    launcher_active=false
    if status_value=$(invoke_supervisor status 2>/dev/null); then
      parsed=$(status_socket <<<"${status_value}") || exit 68
      if [[ ${parsed} == "${socket}" ]]; then
        exec {supervisor_log_fd}>&-
        printf 'export DOCKER_HOST=unix://%s\n' "${socket}"
        exit 0
      fi
      if [[ ${parsed} == absent ]]; then
        echo "isolated runtime supervisor exited before readiness (status ${status})" >&2
        exit 68
      fi
    elif [[ ${status} -eq 66 ]]; then
      /usr/bin/sleep 0.5
      launch_runtime
    fi
    if [[ ${status} -ne 66 ]]; then
      echo "isolated runtime supervisor exited before readiness (status ${status})" >&2
      exit 68
    fi
  fi
  /usr/bin/sleep 0.1
done

echo 'isolated runtime did not become ready before timeout; use stop-isolated-docker.sh to recover' >&2
exit 75
