#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo 'Usage: prepare-runner-storage.sh STATE_ROOT' >&2
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
verifier=${script_dir}/verify-runner-storage.py
lifecycle_helper=${script_dir}/runner-storage-lifecycle.py
lifecycle_helper_sha256=12088aff9f0dbfc478dda91cb28d8a9a281c4bb6ac918f41f6c859858483a107
target=${state_root}/runner-docker
image=${state_root}/capacity/runner-docker.xfs
evidence_root=${state_root}/evidence
receipt=${evidence_root}/runner-docker-storage.json
image_bytes=64424509440

for command_name in chmod findmnt flock id jq mktemp mv python3 realpath stat sudo; do
  command -v "${command_name}" >/dev/null || {
    echo "required runner-storage command is absent: ${command_name}" >&2
    exit 66
  }
done
[[ -f ${verifier} && ! -L ${verifier} ]] || { echo 'runner storage verifier is absent or unsafe' >&2; exit 66; }
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
  local operation=$1
  invoke_lifecycle_helper \
    inspect \
    "${state_root_handle}" \
    "${state_root}" \
    "${caller_uid}" \
    "${caller_gid}" \
    "${image_bytes}" \
    --operation "${operation}"
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
      .stateRoot == $stateRoot and
      (.disposition | type == "string") and
      ((.imageIdentity == null) or
        (.imageIdentity | keys | sort == ["device", "inode", "logicalBytes"]))
    ' <<<"$1" >/dev/null || {
    echo 'runner storage lifecycle inspection is invalid' >&2
    return 66
  }
}

target_mount_observation() {
  local mount_table
  mount_table=$(findmnt --json --list -o TARGET) || {
    echo 'runner storage target mount observation failed' >&2
    return 66
  }
  jq -cer --arg target "${target}" '
    [.filesystems[]?.target] as $targets
    | {
        exact: [$targets[] | select(. == $target)] | length,
        tree: [$targets[] | select(. == $target or startswith($target + "/"))] | length
      }
  ' <<<"${mount_table}"
}

temporary=
mutation_started=false
cleanup_failed_prepare() {
  trap - EXIT INT TERM
  set +e
  local current expected_device expected_inode
  if [[ -n ${temporary} && -e ${temporary} ]]; then
    unlink -- "${temporary}"
  fi
  if [[ ${mutation_started} == true ]]; then
    current=$(inspect_state remove)
    if require_inspection "${current}"; then
      expected_device=$(jq -r '.imageIdentity.device // "none"' <<<"${current}")
      expected_inode=$(jq -r '.imageIdentity.inode // "none"' <<<"${current}")
      invoke_state_transition teardown-runtime "${expected_device}" "${expected_inode}" >/dev/null
      if [[ ! -e ${receipt} && ! -L ${receipt} ]]; then
        invoke_state_transition remove-objects "${expected_device}" "${expected_inode}" >/dev/null
      fi
    fi
  fi
}
trap cleanup_failed_prepare EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

write_current_receipt() {
  local current expected_uuid
  current=$(python3 "${verifier}" "${state_root}")
  if [[ -f ${receipt} && ! -L ${receipt} ]]; then
    expected_uuid=$(jq -er '.filesystem.uuid' "${receipt}")
    [[ $(jq -er '.filesystem.uuid' <<<"${current}") == "${expected_uuid}" ]] || {
      echo 'runner storage filesystem UUID changed across recovery' >&2
      return 66
    }
  fi
  temporary=$(mktemp "${evidence_root}/.runner-storage.XXXXXX.json")
  printf '%s\n' "${current}" > "${temporary}"
  chmod 0600 "${temporary}"
  mv -- "${temporary}" "${receipt}"
  temporary=
}

inspection=$(inspect_state prepare)
require_inspection "${inspection}"
disposition=$(jq -er '.disposition' <<<"${inspection}")
receipt_present=false
if [[ -e ${receipt} || -L ${receipt} ]]; then
  receipt_present=true
fi

case ${disposition} in
  create_new)
    [[ ${receipt_present} == false ]] || {
      echo 'runner storage receipt exists without a published image; remove storage before retrying' >&2
      exit 65
    }
    mutation_started=true
    transition=$(invoke_state_transition create-and-mount)
    jq -e '
      .schema == "ambit.local-daytona-runner-storage-lifecycle/v1" and
      (.loopDevice | type == "string") and
      (.filesystemUuid | type == "string")
    ' <<<"${transition}" >/dev/null || {
      echo 'runner storage create transition receipt is invalid' >&2
      exit 66
    }
    ;;
  existing_published_candidate)
    [[ ${receipt_present} == true && -f ${receipt} && ! -L ${receipt} ]] || {
      echo 'runner storage published image lacks its safe receipt; remove storage before retrying' >&2
      exit 65
    }
    expected_device=$(jq -er '.imageIdentity.device' <<<"${inspection}")
    expected_inode=$(jq -er '.imageIdentity.inode' <<<"${inspection}")
    [[ $(jq -er '.image.path' "${receipt}") == "${image}" ]] || { echo 'runner storage receipt image path differs' >&2; exit 66; }
    [[ $(jq -er '.image.device' "${receipt}") == "${expected_device}" ]] || { echo 'runner storage receipt image device differs' >&2; exit 66; }
    [[ $(jq -er '.image.inode' "${receipt}") == "${expected_inode}" ]] || { echo 'runner storage receipt image inode differs' >&2; exit 66; }
    mount_observation=$(target_mount_observation)
    mounts=$(jq -er '.exact' <<<"${mount_observation}")
    mount_tree=$(jq -er '.tree' <<<"${mount_observation}")
    [[ ${mounts} =~ ^[0-9]+$ && ${mount_tree} =~ ^[0-9]+$ ]] || { echo 'runner storage target mount count is invalid' >&2; exit 66; }
    if (( mounts > 0 )); then
      (( mounts == 1 && mount_tree == 1 )) || { echo 'runner storage target has multiple or nested global mounts' >&2; exit 66; }
    else
      expected_uuid=$(jq -er '.filesystem.uuid' "${receipt}")
      mutation_started=true
      transition=$(invoke_state_transition \
        recover-and-mount \
        "${expected_device}" \
        "${expected_inode}" \
        "${expected_uuid}")
      jq -e --arg expectedUuid "${expected_uuid}" '
        .schema == "ambit.local-daytona-runner-storage-lifecycle/v1" and
        .filesystemUuid == $expectedUuid and
        (.loopDevice | type == "string")
      ' <<<"${transition}" >/dev/null || {
        echo 'runner storage recovery transition receipt is invalid' >&2
        exit 66
      }
    fi
    ;;
  teardown_required)
    echo 'runner storage is an incomplete creation prefix; run remove-runner-storage.sh before retrying' >&2
    exit 65
    ;;
  *)
    echo 'runner storage prepare disposition is invalid' >&2
    exit 66
    ;;
esac

write_current_receipt
mutation_started=false
trap - EXIT INT TERM
printf '%s\n' "${receipt}"
