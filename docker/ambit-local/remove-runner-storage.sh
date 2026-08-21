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

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
lifecycle_helper=${script_dir}/runner-storage-lifecycle.py
lifecycle_helper_sha256=12088aff9f0dbfc478dda91cb28d8a9a281c4bb6ac918f41f6c859858483a107
target=${state_root}/runner-docker
image=${state_root}/capacity/runner-docker.xfs
evidence_root=${state_root}/evidence
receipt=${evidence_root}/runner-docker-storage.json
image_bytes=64424509440

for command_name in flock id jq python3 realpath stat sudo unlink; do
  command -v "${command_name}" >/dev/null || {
    echo "required runner-storage command is absent: ${command_name}" >&2
    exit 66
  }
done
[[ -f ${lifecycle_helper} && ! -L ${lifecycle_helper} ]] || { echo 'runner storage lifecycle helper is absent or unsafe' >&2; exit 66; }
for directory in "${target}" "${evidence_root}"; do
  [[ -d ${directory} && ! -L ${directory} ]] || { echo "runner storage directory is invalid: ${directory}" >&2; exit 66; }
  [[ $(realpath -e -- "${directory}") == "${directory}" ]] || { echo "runner storage directory is non-canonical: ${directory}" >&2; exit 66; }
done

caller_uid=$(id -u)
caller_gid=$(id -g)
[[ ${caller_uid} =~ ^[1-9][0-9]*$ && ${caller_gid} =~ ^[0-9]+$ ]] || {
  echo 'runner storage caller identity is invalid' >&2
  exit 66
}

exec {lifecycle_fd}<"${state_root}"
state_root_handle=/proc/$$/fd/${lifecycle_fd}
lifecycle_identity=$(stat -Lc '%d:%i' -- "${state_root_handle}")
[[ $(stat -c '%d:%i' -- "${state_root}") == "${lifecycle_identity}" ]] || {
  echo 'runner storage state root changed before lifecycle lock' >&2
  exit 66
}
flock -x "${lifecycle_fd}"
[[ $(stat -c '%d:%i' -- "${state_root}") == "${lifecycle_identity}" ]] || {
  echo 'runner storage state root changed while acquiring lifecycle lock' >&2
  exit 66
}

invoke_lifecycle_helper() {
  sudo -n python3 -c '
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
        raise SystemExit("runner storage lifecycle helper is not regular")
    if not 0 < identity.st_size <= 1024 * 1024:
        raise SystemExit("runner storage lifecycle helper size is invalid")
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
    raise SystemExit("runner storage lifecycle helper digest differs")
sys.argv = [path, *arguments]
globals()["__file__"] = path
globals()["__package__"] = None
exec(compile(source, path, "exec"), globals(), globals())
' "${lifecycle_helper}" "${lifecycle_helper_sha256}" "$@"
}

inspect_state() {
  invoke_lifecycle_helper \
    inspect \
    "${state_root_handle}" \
    "${state_root}" \
    "${caller_uid}" \
    "${caller_gid}" \
    "${image_bytes}" \
    --operation remove
}

invoke_state_transition() {
  local command_name=$1
  shift
  invoke_lifecycle_helper \
    "${command_name}" \
    "${state_root_handle}" \
    "${state_root}" \
    "${caller_uid}" \
    "${caller_gid}" \
    "${image_bytes}" \
    "$@"
}

require_inspection() {
  jq -e \
    --arg stateRoot "${state_root}" '
      .schema == "ambit.local-daytona-runner-storage-lifecycle/v1" and
      .operation == "remove" and
      .stateRoot == $stateRoot and
      (.disposition | type == "string") and
      ((.imageIdentity == null) or
        (.imageIdentity | keys | sort == ["device", "inode", "logicalBytes"]))
    ' <<<"$1" >/dev/null || {
    echo 'runner storage lifecycle inspection is invalid' >&2
    return 66
  }
}

trap 'exit 130' INT
trap 'exit 143' TERM

inspection=$(inspect_state)
require_inspection "${inspection}"
disposition=$(jq -er '.disposition' <<<"${inspection}")
expected_device=$(jq -r '.imageIdentity.device // "none"' <<<"${inspection}")
expected_inode=$(jq -r '.imageIdentity.inode // "none"' <<<"${inspection}")
receipt_present=false
if [[ -e ${receipt} || -L ${receipt} ]]; then
  receipt_present=true
  [[ -f ${receipt} && ! -L ${receipt} ]] || { echo 'runner storage receipt is invalid' >&2; exit 66; }
fi

case ${disposition} in
  already_absent|remove_empty_capacity)
    [[ ${receipt_present} == false ]] || {
      echo 'runner storage receipt exists without its image' >&2
      exit 66
    }
    ;;
  remove_image_and_capacity)
    if [[ ${receipt_present} == true ]]; then
      [[ $(jq -er '.image.path' "${receipt}") == "${image}" ]] || { echo 'runner storage receipt image path differs' >&2; exit 66; }
      [[ $(jq -er '.image.device' "${receipt}") == "${expected_device}" ]] || { echo 'runner storage receipt image device differs' >&2; exit 66; }
      [[ $(jq -er '.image.inode' "${receipt}") == "${expected_inode}" ]] || { echo 'runner storage receipt image inode differs' >&2; exit 66; }
    fi
    ;;
  *)
    echo 'runner storage remove disposition is invalid' >&2
    exit 66
    ;;
esac

invoke_state_transition teardown-runtime "${expected_device}" "${expected_inode}" >/dev/null
if [[ ${receipt_present} == true ]]; then
  unlink -- "${receipt}"
fi
invoke_state_transition remove-objects "${expected_device}" "${expected_inode}" >/dev/null

final_inspection=$(inspect_state)
require_inspection "${final_inspection}"
[[ $(jq -er '.disposition' <<<"${final_inspection}") == already_absent ]] || {
  echo 'runner storage objects remained after removal' >&2
  exit 66
}
printf '%s\n' "removed ${target} runtime, ${image}, and ${receipt}"
