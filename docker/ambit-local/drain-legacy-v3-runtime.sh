#!/usr/bin/bash
set -euo pipefail
umask 077

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
tool_sha256=994cfe5091144cfd45fefb7e84e5d072635ffda9fb22198292868aa0391331d1

run_repo_tool() {
  local observed_tool_sha
  observed_tool_sha=$(/usr/bin/sha256sum -- "${tool}")
  observed_tool_sha=${observed_tool_sha%% *}
  [[ ${observed_tool_sha} == "${tool_sha256}" && -f ${tool} && ! -L ${tool} ]] || {
    echo 'legacy-v3 drain tool source differs from its pinned candidate' >&2
    exit 66
  }
  /usr/bin/sudo -n /usr/bin/env -i \
    PATH=/usr/bin:/bin \
    LC_ALL=C.UTF-8 \
    HOME=/root \
    SUDO_UID="${caller_uid}" \
    SUDO_GID="${caller_gid}" \
    /usr/bin/python3 -I -S "${tool}" "$@"
}

case ${operation} in
  verify-only)
    [[ $# -eq 2 ]] || usage
    run_repo_tool verify-only "${state_root}" "${caller_uid}" "${caller_gid}"
    ;;
  drain)
    [[ $# -eq 3 && $3 =~ ^[0-9a-f]{64}$ ]] || usage
    run_repo_tool drain "${state_root}" "${caller_uid}" "${caller_gid}" "$3"
    ;;
  resume)
    [[ $# -eq 2 ]] || usage
    control_root=/run/ambit-c16b-legacy-v3-drain-1577287b8182
    read -r -d '' snapshot_loader <<'PY' || true
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

control_root = Path(sys.argv[1])
snapshot = control_root / "legacy_v3_drain.py"
control = control_root / "control.json"
root_stat = os.stat(control_root, follow_symlinks=False)
if not (
    stat.S_ISDIR(root_stat.st_mode)
    and root_stat.st_uid == 0
    and root_stat.st_gid == 0
    and stat.S_IMODE(root_stat.st_mode) == 0o700
):
    raise SystemExit("legacy-v3 root control identity differs")
control_fd = os.open(control, os.O_RDONLY | os.O_NOFOLLOW)
try:
    control_stat = os.fstat(control_fd)
    if not (
        stat.S_ISREG(control_stat.st_mode)
        and control_stat.st_uid == 0
        and control_stat.st_gid == 0
        and stat.S_IMODE(control_stat.st_mode) == 0o400
        and control_stat.st_nlink == 1
        and control_stat.st_size <= 2 * 1024 * 1024
    ):
        raise SystemExit("legacy-v3 root control file identity differs")
    raw_control = os.read(control_fd, 2 * 1024 * 1024 + 1)
finally:
    os.close(control_fd)
value = json.loads(raw_control)
if set(value) != {
    "schema", "observedAt", "bootId", "stateRoot", "caller",
    "verificationSha256", "sourceSha256", "authority",
}:
    raise SystemExit("legacy-v3 root control shape differs")
snapshot_fd = os.open(snapshot, os.O_RDONLY | os.O_NOFOLLOW)
try:
    snapshot_stat = os.fstat(snapshot_fd)
    if not (
        stat.S_ISREG(snapshot_stat.st_mode)
        and snapshot_stat.st_uid == 0
        and snapshot_stat.st_gid == 0
        and stat.S_IMODE(snapshot_stat.st_mode) == 0o400
        and snapshot_stat.st_nlink == 1
        and snapshot_stat.st_size <= 4 * 1024 * 1024
    ):
        raise SystemExit("legacy-v3 root source snapshot identity differs")
    digest = hashlib.sha256()
    while True:
        chunk = os.read(snapshot_fd, 64 * 1024)
        if not chunk:
            break
        digest.update(chunk)
finally:
    os.close(snapshot_fd)
if digest.hexdigest() != value["sourceSha256"]:
    raise SystemExit("legacy-v3 root source snapshot differs")
os.execv(
    "/usr/bin/python3",
    [
        "/usr/bin/python3", "-I", "-S", str(snapshot), "resume",
        sys.argv[2], sys.argv[3], sys.argv[4],
    ],
)
PY
    /usr/bin/sudo -n /usr/bin/env -i \
      PATH=/usr/bin:/bin \
      LC_ALL=C.UTF-8 \
      HOME=/root \
      SUDO_UID="${caller_uid}" \
      SUDO_GID="${caller_gid}" \
      /usr/bin/python3 -I -S -c "${snapshot_loader}" \
      "${control_root}" "${state_root}" "${caller_uid}" "${caller_gid}"
    ;;
  *)
    usage
    ;;
esac
