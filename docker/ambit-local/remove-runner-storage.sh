#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: remove-runner-storage.sh STATE_ROOT' >&2
  exit 64
fi

state_root=$1
[[ ${state_root} =~ ^/home/[^/]+/[A-Za-z0-9._/-]+$ ]] || {
  echo 'STATE_ROOT must be a specific path below /home' >&2
  exit 64
}
[[ $(realpath -e -- "${state_root}") == "${state_root}" ]] || {
  echo 'STATE_ROOT must be an existing canonical non-symlink path' >&2
  exit 64
}
caller_uid=$(id -u)
caller_gid=$(id -g)
[[ $(stat -c '%u:%g:%a' -- "${state_root}") == "${caller_uid}:${caller_gid}:700" ]] || {
  echo 'STATE_ROOT owner, group, or mode differs' >&2
  exit 66
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lifecycle_helper=${script_dir}/runner-storage-lifecycle.py
lifecycle_helper_sha256=991c7db087d88390d67263183afa70908710be40b49e8d5d3059958a8362641e
[[ -f ${lifecycle_helper} && ! -L ${lifecycle_helper} ]] || {
  echo 'runner storage lifecycle helper is absent or unsafe' >&2
  exit 66
}

sudo -n /usr/bin/env -i -C / \
  PATH=/usr/bin:/bin \
  LC_ALL=C.UTF-8 \
  /usr/bin/python3 -I -S -B -c '
import hashlib
import hmac
import os
import stat
import sys

path, expected, *arguments = sys.argv[1:]
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
  remove-authority "${state_root}" "${caller_uid}" "${caller_gid}"
