#!/usr/bin/bash -p
set -euo pipefail
umask 077
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
PATH=/usr/bin:/bin
LC_ALL=C.UTF-8
readonly PATH LC_ALL

if [[ $# -ne 1 ]]; then
  echo 'Usage: stop-isolated-docker.sh STATE_ROOT' >&2
  exit 64
fi

state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || {
  echo 'STATE_ROOT must be a specific absolute path below /home' >&2
  exit 64
}
caller_uid=$(/usr/bin/id -u)
caller_gid=$(/usr/bin/id -g)
[[ ${caller_uid} =~ ^[1-9][0-9]*$ && ${caller_gid} =~ ^[0-9]+$ ]] || {
  echo 'isolated runtime caller identity is invalid' >&2
  exit 66
}
operation=ensure-stopped
if [[ -e ${state_root} || -L ${state_root} ]]; then
  [[ $(/usr/bin/realpath -e -- "${state_root}") == "${state_root}" ]] || {
    echo 'STATE_ROOT must be an existing canonical non-symlink path' >&2
    exit 64
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
else
  [[ $(/usr/bin/realpath -m -- "${state_root}") == "${state_root}" ]] || {
    echo 'absent original STATE_ROOT path is not lexically canonical' >&2
    exit 64
  }
  operation=ensure-stopped-orphaned
fi

script_dir=$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)
supervisor=${script_dir}/isolated_runtime_supervisor.py
supervisor_sha256=bcc04455e659c0fba2f36180a325907ae8e19171b06e8b2c6a7f8d3fe924a4e7

read -r -d '' runtime_snapshot_loader <<'PY' || true
import hashlib
import hmac
import os
import stat
import sys

runtime_root, fallback_path, fallback_digest, *arguments = sys.argv[1:]
chosen = fallback_path
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

for command_path in /usr/bin/python3 /usr/bin/sudo /usr/bin/unshare; do
  owner_group=$(/usr/bin/stat -Lc '%u:%g' -- "${command_path}")
  mode=$(/usr/bin/stat -Lc '%a' -- "${command_path}")
  [[ ${owner_group} == 0:0 && $(/usr/bin/stat -Lc '%F' -- "${command_path}") == 'regular file' ]] || {
    echo "root stop executable authority differs: ${command_path}" >&2
    exit 66
  }
  (( (8#${mode} & 8#022) == 0 )) || {
    echo "root stop executable is writable: ${command_path}" >&2
    exit 66
  }
done

runtime_id=$(printf '%s' "${state_root}" | /usr/bin/sha256sum)
runtime_id=${runtime_id%% *}
runtime_root=/run/ambit-c16b-docker-${runtime_id:0:12}

result=$(
  /usr/bin/sudo -n -- \
    /usr/bin/unshare --mount --propagation private --wd / \
    /usr/bin/python3 -I -S -B -c "${runtime_snapshot_loader}" \
    "${runtime_root}" "${supervisor}" "${supervisor_sha256}" "${operation}" \
    "${state_root}" "${caller_uid}" "${caller_gid}"
)

/usr/bin/python3 -I -S -B -c '
import json, sys
expected_state = sys.argv[1]
value = json.load(sys.stdin)
if set(value) != {
    "schema", "outcome", "observedAt", "bootId", "stateRoot",
    "runtimeRootRemoved", "socketRootRemoved", "cgroupRemoved",
}:
    raise SystemExit(66)
if (
    value["schema"] != "ambit.local-daytona-isolated-docker-stop/v2"
    or value["outcome"] != "passed"
    or value["stateRoot"] != expected_state
    or value["runtimeRootRemoved"] is not True
    or value["socketRootRemoved"] is not True
    or value["cgroupRemoved"] is not True
):
    raise SystemExit(66)
' "${state_root}" <<<"${result}" || {
  echo 'isolated runtime stop authority is invalid' >&2
  exit 65
}

printf 'isolated Docker/containerd runtime is stopped and ephemeral authorities are removed\n'
