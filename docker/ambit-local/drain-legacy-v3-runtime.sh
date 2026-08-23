#!/usr/bin/bash -p
set -euo pipefail
umask 077
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
PATH=/usr/bin:/bin
LC_ALL=C.UTF-8
readonly PATH LC_ALL

usage() {
  cat >&2 <<'EOF'
Usage:
  drain-legacy-v3-runtime.sh verify-only /home/bote/m/.local/ambit-daytona-c16b/state
  drain-legacy-v3-runtime.sh drain /home/bote/m/.local/ambit-daytona-c16b/state VERIFICATION_SHA256
  drain-legacy-v3-runtime.sh resume /home/bote/m/.local/ambit-daytona-c16b/state
EOF
  exit 64
}

[[ $# -ge 2 && $# -le 3 ]] || usage
operation=$1
state_root=$2
expected_state_root=/home/bote/m/.local/ambit-daytona-c16b/state
[[ ${state_root} == "${expected_state_root}" ]] || {
  echo 'legacy-v3 drain accepts only the exact audited STATE_ROOT' >&2
  exit 64
}
[[ $(/usr/bin/realpath -e -- "${state_root}") == "${state_root}" ]] || {
  echo 'legacy-v3 STATE_ROOT is not an existing canonical path' >&2
  exit 64
}

caller_uid=$(/usr/bin/id -u)
caller_gid=$(/usr/bin/id -g)
[[ ${caller_uid} == 1000 && ${caller_gid} == 1000 ]] || {
  echo 'legacy-v3 drain caller identity differs from the audited runtime' >&2
  exit 77
}

script_source=$(/usr/bin/realpath -e -- "${BASH_SOURCE[0]}")
script_dir=${script_source%/*}
tool=${script_dir}/legacy_v3_drain.py
tool_sha256=8ebf60906abe8b91d1c310e69eb9645ce60258ca8201ee6dc5e9428493ad6460
control_root=/run/ambit-c16b-legacy-v3-drain-1577287b8182

read -r -d '' pinned_loader <<'PY' || true
import hashlib
import hmac
import json
import os
import stat
import sys

mode, authority_path, expected_sha256, operation, state_root, caller_uid, caller_gid, *tail = sys.argv[1:]
if mode not in {"repo", "resume"}:
    raise SystemExit("legacy-v3 loader mode differs")
if os.geteuid() != 0 or os.getegid() != 0:
    raise SystemExit("legacy-v3 loader is not privileged")
if os.environ.get("SUDO_UID") != caller_uid or os.environ.get("SUDO_GID") != caller_gid:
    raise SystemExit("legacy-v3 authenticated sudo caller differs")
if state_root != "/home/bote/m/.local/ambit-daytona-c16b/state":
    raise SystemExit("legacy-v3 loader state binding differs")

def duplicate_rejector(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit("legacy-v3 capsule contains a duplicate JSON field")
        value[key] = item
    return value

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

TERMINAL_TIMESTAMP_SENTINEL = "2000-01-01T00:00:00.000000+00:00"

def terminal_projection_value_for(control, *, observed_at, boot_id):
    return {
        "schema": "ambit.local-daytona-legacy-v3-drain-terminal/v1",
        "outcome": "drained",
        "observedAt": observed_at,
        "bootId": boot_id,
        "stateRoot": "/home/bote/m/.local/ambit-daytona-c16b/state",
        "legacyReceiptSha256": "c7b6f7f5f77ae5569a918cd33a811aa855b781f3c007df6f9f19bf1d3f458c21",
        "legacyReceiptArchive": "/home/bote/m/.local/ambit-daytona-c16b/state/evidence/outer-docker-receipt.legacy-v3-c7b6f7f5f77ae556.json",
        "controlSha256": hashlib.sha256(canonical(control)).hexdigest(),
        "sourceSha256": control["sourceSha256"],
        "control": control,
        "persistentDataPreserved": [
            "/home/bote/m/.local/ambit-daytona-c16b/state/outer-docker",
            "/home/bote/m/.local/ambit-daytona-c16b/state/outer-containerd",
            "/home/bote/m/.local/ambit-daytona-c16b/state/registry",
        ],
        "legacyRuntimeRemoved": True,
        "cgroupMutationPerformed": False,
        "forceKillPerformed": False,
    }

class DescriptorCustody:
    def __init__(self, label):
        self.label = label
        self.descriptors = []

    def open(self, *args, **kwargs):
        descriptor = os.open(*args, **kwargs)
        try:
            self.descriptors.append(descriptor)
        except BaseException as error:
            try:
                os.close(descriptor)
            except BaseException as cleanup_error:
                error.add_note(self.label + " registration cleanup also failed: " + str(cleanup_error))
            raise
        return descriptor

    def release(self, descriptor):
        matches = [index for index, value in enumerate(self.descriptors) if value == descriptor]
        if len(matches) != 1:
            raise SystemExit(self.label + " transfer is unowned or ambiguous")
        self.descriptors.pop(matches[0])
        return descriptor

    def close_descriptor(self, descriptor):
        self.release(descriptor)
        os.close(descriptor)

    def close(self):
        first_error = None
        while self.descriptors:
            descriptor = self.descriptors.pop()
            try:
                os.close(descriptor)
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    def __enter__(self):
        return self

    def __exit__(self, _exception_type, active_error, _traceback):
        try:
            self.close()
        except BaseException as cleanup_error:
            if active_error is None:
                raise
            active_error.add_note(self.label + " cleanup also failed: " + str(cleanup_error))

def read_bound_at(directory_fd, name, maximum, *, expected_device=None):
    with DescriptorCustody("legacy-v3 bound read " + name) as custody:
        descriptor = custody.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if not (
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o400
            and before.st_nlink == 1
            and 0 < before.st_size <= maximum
            and (expected_device is None or before.st_dev == expected_device)
        ):
            raise SystemExit("legacy-v3 capsule file identity differs: " + name)
        source = bytearray()
        while len(source) <= maximum:
            block = os.read(descriptor, min(64 * 1024, maximum + 1 - len(source)))
            if not block:
                break
            source.extend(block)
        after = os.fstat(descriptor)
        literal = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not (
            len(source) == before.st_size
            and (after.st_dev, after.st_ino, after.st_size, after.st_uid, after.st_gid,
                 stat.S_IMODE(after.st_mode), after.st_nlink)
            == (before.st_dev, before.st_ino, before.st_size, before.st_uid, before.st_gid,
                stat.S_IMODE(before.st_mode), before.st_nlink)
            and (literal.st_dev, literal.st_ino) == (before.st_dev, before.st_ino)
        ):
            raise SystemExit("legacy-v3 capsule file changed during read: " + name)
        return bytes(source)

def execute_source(source, display_name, control_root_fd=None):
    if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), expected_sha256):
        raise SystemExit("legacy-v3 pinned Python source digest differs")
    os.chdir("/")
    os.environ.clear()
    os.environ.update({
        "HOME": "/root", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin",
        "SUDO_UID": caller_uid, "SUDO_GID": caller_gid,
    })
    sys.argv = [display_name, operation, state_root, caller_uid, caller_gid, *tail]
    namespace = {
        "__name__": "__main__",
        "__file__": display_name,
        "__package__": None,
        "__legacy_pinned_source_bytes__": source,
    }
    if control_root_fd is not None:
        namespace["__legacy_control_root_fd__"] = control_root_fd
    exec(compile(source, display_name, "exec"), namespace, namespace)

if mode == "repo":
    with DescriptorCustody("legacy-v3 repository source") as custody:
        descriptor = custody.open(authority_path, os.O_RDONLY | os.O_NOFOLLOW)
        before = os.fstat(descriptor)
        if not (
            stat.S_ISREG(before.st_mode)
            and before.st_uid == int(caller_uid)
            and before.st_gid == int(caller_gid)
            and stat.S_IMODE(before.st_mode) == 0o644
            and before.st_nlink == 1
            and 0 < before.st_size <= 4 * 1024 * 1024
        ):
            raise SystemExit("legacy-v3 repository source identity differs")
        source = bytearray()
        while len(source) <= 4 * 1024 * 1024:
            block = os.read(descriptor, min(64 * 1024, 4 * 1024 * 1024 + 1 - len(source)))
            if not block:
                break
            source.extend(block)
        after = os.fstat(descriptor)
        literal = os.stat(authority_path, follow_symlinks=False)
        if not (
            len(source) == before.st_size
            and (after.st_dev, after.st_ino, after.st_size, after.st_uid, after.st_gid,
                 stat.S_IMODE(after.st_mode), after.st_nlink)
            == (before.st_dev, before.st_ino, before.st_size, before.st_uid, before.st_gid,
                stat.S_IMODE(before.st_mode), before.st_nlink)
            and (literal.st_dev, literal.st_ino) == (before.st_dev, before.st_ino)
        ):
            raise SystemExit("legacy-v3 repository source changed during admission")
        source = bytes(source)
    display_name = authority_path
def execute_resume_owned(custody):
    if authority_path != "/run/ambit-c16b-legacy-v3-drain-1577287b8182":
        raise SystemExit("legacy-v3 control-root path differs")
    run_fd = custody.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    run_identity = os.fstat(run_fd)
    if not (
        stat.S_ISDIR(run_identity.st_mode)
        and run_identity.st_uid == 0
        and run_identity.st_gid == 0
        and stat.S_IMODE(run_identity.st_mode) & 0o022 == 0
    ):
        raise SystemExit("legacy-v3 control parent differs")
    control_root_fd = custody.open(
        "ambit-c16b-legacy-v3-drain-1577287b8182",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=run_fd,
    )
    root = os.fstat(control_root_fd)
    literal = os.stat(
        "ambit-c16b-legacy-v3-drain-1577287b8182",
        dir_fd=run_fd,
        follow_symlinks=False,
    )
    if not (
        stat.S_ISDIR(root.st_mode)
        and root.st_uid == 0
        and root.st_gid == 0
        and stat.S_IMODE(root.st_mode) == 0o700
        and (literal.st_dev, literal.st_ino) == (root.st_dev, root.st_ino)
    ):
        raise SystemExit("legacy-v3 root control identity differs")
    custody.close_descriptor(run_fd)
    allowed = {
        "legacy_v3_drain.py", "control.json", "state.json",
        ".legacy_v3_drain.py.pending", ".control.json.pending", ".state.json.pending",
    }
    entries = set(os.listdir(control_root_fd))
    if not {"legacy_v3_drain.py", "control.json", "state.json"} <= entries <= allowed:
        raise SystemExit("legacy-v3 root control roster differs")
    source = read_bound_at(control_root_fd, "legacy_v3_drain.py", 4 * 1024 * 1024, expected_device=root.st_dev)
    raw_control = read_bound_at(control_root_fd, "control.json", 2 * 1024 * 1024, expected_device=root.st_dev)
    raw_state = read_bound_at(control_root_fd, "state.json", 2 * 1024 * 1024, expected_device=root.st_dev)
    control = json.loads(raw_control, object_pairs_hook=duplicate_rejector)
    state = json.loads(raw_state, object_pairs_hook=duplicate_rejector)
    if not isinstance(control, dict) or set(control) != {
        "schema", "observedAt", "bootId", "stateRoot", "caller",
        "verificationSha256", "sourceSha256", "authority",
    }:
        raise SystemExit("legacy-v3 root control shape differs")
    if not isinstance(state, dict) or set(state) != {
        "schema", "observedAt", "bootId", "stateRoot", "controlSha256", "phase",
        "netnsMarkerIdentity",
    }:
        raise SystemExit("legacy-v3 root state shape differs")
    boot_path = "/proc/sys/kernel/random/boot_id"
    boot_fd = custody.open(boot_path, os.O_RDONLY | os.O_NOFOLLOW)
    boot_before = os.fstat(boot_fd)
    boot_raw = os.read(boot_fd, 129)
    boot_tail = os.read(boot_fd, 1)
    boot_after = os.fstat(boot_fd)
    boot_literal = os.stat(boot_path, follow_symlinks=False)
    if not (
        stat.S_ISREG(boot_before.st_mode)
        and boot_before.st_uid == 0
        and boot_before.st_gid == 0
        and not boot_tail
        and 0 < len(boot_raw) <= 128
        and (boot_after.st_dev, boot_after.st_ino, stat.S_IFMT(boot_after.st_mode))
        == (boot_before.st_dev, boot_before.st_ino, stat.S_IFMT(boot_before.st_mode))
        == (boot_literal.st_dev, boot_literal.st_ino, stat.S_IFMT(boot_literal.st_mode))
    ):
        raise SystemExit("legacy-v3 boot identity file differs")
    custody.close_descriptor(boot_fd)
    boot_id = boot_raw.decode("ascii", "strict").strip()
    phases = {
        "stopping_intent_final", "runtime_custody_transferred", "docker_api_revoked",
        "dockerd_stop_requested", "dockerd_stopped", "container_graph_quiesced",
        "containerd_stop_requested", "containerd_stopped", "mounts_settled",
        "runtime_reducing", "runtime_empty", "archive_intent_final",
    }
    if not (
        control["schema"] == "ambit.local-daytona-legacy-v3-drain-control/v1"
        and state["schema"] == "ambit.local-daytona-legacy-v3-drain-state/v1"
        and control["bootId"] == state["bootId"] == boot_id
        and control["stateRoot"] == state["stateRoot"] == state_root
        and control["caller"] == {"uid": 1000, "gid": 1000}
        and isinstance(control["authority"], dict)
        and hmac.compare_digest(control["verificationSha256"], hashlib.sha256(canonical(control["authority"])).hexdigest())
        and hmac.compare_digest(state["controlSha256"], hashlib.sha256(canonical(control)).hexdigest())
        and state["phase"] in phases
        and (
            (state["phase"] in {"mounts_settled", "runtime_reducing", "runtime_empty", "archive_intent_final"}
             and isinstance(state["netnsMarkerIdentity"], dict))
            or
            (state["phase"] not in {"mounts_settled", "runtime_reducing", "runtime_empty", "archive_intent_final"}
             and state["netnsMarkerIdentity"] is None)
        )
    ):
        raise SystemExit("legacy-v3 root control binding differs")
    if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), control["sourceSha256"]):
        raise SystemExit("legacy-v3 root source snapshot differs")
    terminal_observed_at = (
        state["observedAt"]
        if state["phase"] == "archive_intent_final"
        else TERMINAL_TIMESTAMP_SENTINEL
    )
    terminal_projection = terminal_projection_value_for(
        control,
        observed_at=terminal_observed_at,
        boot_id=state["bootId"],
    )
    if not (0 < len(canonical(terminal_projection)) <= 2 * 1024 * 1024):
        raise SystemExit("legacy-v3 terminal projection is too large")
    display_name = authority_path + "/legacy_v3_drain.py"
    execute_source(source, display_name, control_root_fd)

if mode == "repo":
    execute_source(source, display_name)
else:
    with DescriptorCustody("legacy-v3 resume authority") as resume_custody:
        execute_resume_owned(resume_custody)
PY

invoke_tool() {
  local mode=$1
  shift
  /usr/bin/sudo -n -- /usr/bin/python3 -I -S -B -c "${pinned_loader}" \
    "${mode}" "$@"
}

case ${operation} in
  verify-only)
    [[ $# -eq 2 ]] || usage
    invoke_tool repo "${tool}" "${tool_sha256}" verify-only \
      "${state_root}" "${caller_uid}" "${caller_gid}"
    ;;
  drain)
    [[ $# -eq 3 && $3 =~ ^[0-9a-f]{64}$ ]] || usage
    invoke_tool repo "${tool}" "${tool_sha256}" drain \
      "${state_root}" "${caller_uid}" "${caller_gid}" "$3"
    ;;
  resume)
    [[ $# -eq 2 ]] || usage
    if [[ -e ${control_root} || -L ${control_root} ]]; then
      invoke_tool resume "${control_root}" "${tool_sha256}" resume \
        "${state_root}" "${caller_uid}" "${caller_gid}"
    else
      invoke_tool repo "${tool}" "${tool_sha256}" resume \
        "${state_root}" "${caller_uid}" "${caller_gid}"
    fi
    ;;
  *)
    usage
    ;;
esac
