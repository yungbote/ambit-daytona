#!/usr/bin/bash -p
set -euo pipefail
umask 077
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH
PATH=/usr/bin:/bin
LC_ALL=C.UTF-8
readonly PATH LC_ALL

legacy_v2=false
if [[ ${1:-} == --legacy-v2 ]]; then
  legacy_v2=true
  shift
fi
if [[ $# -ne 1 ]]; then
  echo 'Usage: remove-runner-storage.sh [--legacy-v2] STATE_ROOT' >&2
  exit 64
fi

state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || {
  echo 'STATE_ROOT must be a specific path below /home' >&2
  exit 64
}
caller_uid=$(/usr/bin/id -u)
caller_gid=$(/usr/bin/id -g)
if [[ -e ${state_root} || -L ${state_root} ]]; then
  [[ $(/usr/bin/realpath -e -- "${state_root}") == "${state_root}" ]] || {
    echo 'STATE_ROOT must be an existing canonical non-symlink path' >&2
    exit 64
  }
  [[ $(/usr/bin/stat -c '%u:%g:%a' -- "${state_root}") == "${caller_uid}:${caller_gid}:700" ]] || {
    echo 'STATE_ROOT owner, group, or mode differs' >&2
    exit 66
  }
else
  [[ $(/usr/bin/realpath -m -- "${state_root}") == "${state_root}" ]] || {
    echo 'absent original STATE_ROOT path is not lexically canonical' >&2
    exit 64
  }
fi
helper_operation=remove-authority
[[ ${legacy_v2} == false ]] || helper_operation=remove-legacy-v2-authority

script_dir=$(cd "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && /usr/bin/pwd -P)
lifecycle_helper=${script_dir}/runner-storage-lifecycle.py
lifecycle_helper_sha256=62472dcefdfee225b417eab16b31fcfc9d265d127574c8d8febb22ccbf1522fb
[[ -f ${lifecycle_helper} && ! -L ${lifecycle_helper} ]] || {
  echo 'runner storage lifecycle helper is absent or unsafe' >&2
  exit 66
}

/usr/bin/sudo -n -- /usr/bin/python3 -I -S -B -c '
import hashlib
import hmac
import os
import re
import stat
import sys

path, expected, expected_uid, expected_gid, *arguments = sys.argv[1:]
def authenticated_requester(name, expected_value):
    value = os.environ.get(name)
    if value is None or re.fullmatch(r"[0-9]+", value) is None:
        raise SystemExit("sudo requester identity is absent or invalid")
    parsed = int(value)
    if str(parsed) != value or value != expected_value:
        raise SystemExit("sudo requester identity differs")
    return value

if os.geteuid() != 0 or os.getegid() != 0:
    raise SystemExit("runner storage lifecycle launcher is not privileged")
requester_uid = authenticated_requester("SUDO_UID", expected_uid)
requester_gid = authenticated_requester("SUDO_GID", expected_gid)
os.chdir("/")
os.environ.clear()
os.environ.update({
    "HOME": "/root",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "SUDO_UID": requester_uid,
    "SUDO_GID": requester_gid,
})
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    identity = os.fstat(descriptor)
    if not stat.S_ISREG(identity.st_mode) or not 0 < identity.st_size <= 1024 * 1024:
        raise SystemExit("runner storage lifecycle helper identity is invalid")
    source = bytearray()
    while True:
        block = os.read(descriptor, 1024 * 1024)
        if not block:
            break
        source.extend(block)
finally:
    os.close(descriptor)
if not hmac.compare_digest(hashlib.sha256(source).hexdigest(), expected):
    raise SystemExit("runner storage lifecycle helper digest differs")
sys.argv = [path, *arguments]
globals()["__file__"] = path
globals()["__package__"] = None
exec(compile(source, path, "exec"), globals(), globals())
' "${lifecycle_helper}" "${lifecycle_helper_sha256}" \
  "${caller_uid}" "${caller_gid}" \
  "${helper_operation}" "${state_root}" "${caller_uid}" "${caller_gid}"
