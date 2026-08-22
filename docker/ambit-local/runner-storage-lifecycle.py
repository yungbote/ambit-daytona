#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, NoReturn


OPERATION_SCHEMA = "ambit.local-daytona-runner-storage-operation/v3"
RECEIPT_SCHEMA = "ambit.local-daytona-runner-storage/v3"
PROJECTION_SCHEMA = "ambit.local-daytona-runner-storage-projection/v2"
AUTHORITY_ROOT = Path("/home/.ambit-c16b-runner-storage")
AUTHORITY_NAME = AUTHORITY_ROOT.name
HOME_ROOT = Path("/home")
CLAIM_DOMAIN = "ambit.local-daytona-runner-storage-claim/v1"
CLAIM_PREFIX = ".ambit-c16b-runner-storage.claim."
CLAIM_PENDING_NAME = ".ambit-c16b-runner-storage.pending-claim"
LEGACY_RECEIPT_SCHEMA = "ambit.local-daytona-runner-storage/v2"
LEGACY_LOCK_NAME = "lifecycle.lock"
LEGACY_RECEIPT_TEMP_NAME = re.compile(
    r"^\.storage-receipt\.json\.[1-9][0-9]*\.[0-9a-f]{16}$"
)
LEGACY_PROJECTION_TEMP_NAME = re.compile(
    r"^\.runner-docker-storage\.json\.[1-9][0-9]*\.[0-9a-f]{16}$"
)
IMAGE_NAME = "runner-docker.xfs"
TARGET_NAME = "runner-docker"
RUNNER_DATA_NAME = "inner-runner"
OUTER_DOCKER_NAME = "outer-docker"
OUTER_CONTAINERD_NAME = "outer-containerd"
RUNTIME_ROOT_PREFIX = Path("/run/ambit-c16b-docker-")
SOCKET_ROOT_PREFIX = Path("/run/ambit-c16b-docker-api-")
CGROUP_ROOT_PREFIX = Path("/sys/fs/cgroup/ambit-c16b-docker-")
RUNTIME_PARENT = Path("/run")
GLOBAL_RUNTIME_LEASE_NAME = "ambit-c16b-docker-global.lock"
RUNTIME_ROOT_NAME = re.compile(r"^ambit-c16b-docker-[0-9a-f]{12}$")
SOCKET_ROOT_NAME = re.compile(r"^ambit-c16b-docker-api-[0-9a-f]{12}$")
CGROUP_ROOT_NAME = re.compile(r"^ambit-c16b-docker-[0-9a-f]{12}$")
LEGACY_TMP_RUNTIME_NAME = re.compile(r"^ambit-c16b-docker-[0-9a-f]{12}$")
RECEIPT_NAME = "storage-receipt.json"
USER_PROJECTION_NAME = "runner-docker-storage.json"
RECEIPT_PENDING_NAME = f".{RECEIPT_NAME}.pending"
PROJECTION_PENDING_NAME = f".{USER_PROJECTION_NAME}.pending"
IDENTITY_VERIFIER_NAME = "verify-runner-storage.py"
IDENTITY_VERIFIER_SHA256 = "59c530e8c502c546689967c33c540217d2762ff9d3f8ef7424ba52462c554f0b"
IMAGE_BYTES = 60 * 1024**3
MAX_DOCUMENT_BYTES = 1024 * 1024
LIFECYCLE_LOCK_TIMEOUT_SECONDS = 15.0
MUTATION_TIMEOUT_SECONDS = 120.0
MUTATION_TERMINATION_GRACE_SECONDS = 5.0
LOOP_DEVICE = re.compile(r"^/dev/loop[0-9]+$")
FILESYSTEM_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
OPAQUE_MOUNT_ROOT = re.compile(r"^[a-z][a-z0-9_-]*:\[[1-9][0-9]*\]$")
TRUSTED_TOOLS = {
    "blkid": Path("/usr/bin/blkid"),
    "findmnt": Path("/usr/bin/findmnt"),
    "losetup": Path("/usr/bin/losetup"),
    "mkfs.xfs": Path("/usr/bin/mkfs.xfs"),
    "mount": Path("/usr/bin/mount"),
    "python": Path("/usr/bin/python3"),
    "umount": Path("/usr/bin/umount"),
    "xfs_info": Path("/usr/bin/xfs_info"),
}
TOOL_ENVIRONMENT = {"HOME": "/root", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}
MUTATION_GUARDIAN = r"""
import ctypes
import os
import signal
import subprocess
import sys
import time

lock_fd = int(sys.argv[1])
inherited = tuple(int(value) for value in sys.argv[2].split(",") if value)
timeout = float(sys.argv[3])
grace = float(sys.argv[4])
command = sys.argv[5:]
os.fstat(lock_fd)
tool_fds = tuple(sorted(set(inherited) | {lock_fd}))
parent_pid = os.getpid()
libc = ctypes.CDLL(None, use_errno=True)

def bind_tool_to_guardian():
    for watched in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
        signal.signal(watched, signal.SIG_DFL)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        os._exit(70)
    if os.getppid() != parent_pid:
        os._exit(71)

child = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    pass_fds=tool_fds,
    start_new_session=True,
    preexec_fn=bind_tool_to_guardian,
)

requested_signal = None
def request_shutdown(signum, _frame):
    global requested_signal
    requested_signal = signum

for watched in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
    signal.signal(watched, request_shutdown)

deadline = time.monotonic() + timeout
stdout = b""
stderr = b""
while child.poll() is None and requested_signal is None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        break
    try:
        stdout, stderr = child.communicate(timeout=min(0.2, remaining))
    except subprocess.TimeoutExpired:
        continue

timed_out = child.poll() is None and requested_signal is None
if child.poll() is None:
    relayed = signal.SIGTERM if timed_out else requested_signal
    try:
        os.killpg(child.pid, relayed)
    except ProcessLookupError:
        pass
    try:
        stdout, stderr = child.communicate(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = child.communicate()
else:
    stdout, stderr = child.communicate()

sys.stdout.buffer.write(stdout)
sys.stderr.buffer.write(stderr)
if timed_out:
    raise SystemExit(124)
if requested_signal is not None:
    raise SystemExit(128 + requested_signal)
raise SystemExit(child.returncode)
"""

NodeKind = Literal["absent", "directory", "regular", "symlink", "other"]
ImageState = Literal[
    "absent",
    "root_0600_incomplete_prepublication",
    "root_0600_exact",
]
LifecyclePrefixState = Literal[
    "absent_unclaimed",
    "pending_claim",
    "pending_legacy_authority",
    "claim_only",
    "claimed_authority",
    "legacy_empty_authority",
    "legacy_authority",
]


class RunnerStorageLifecycleError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunnerStorageLifecycleError(message)


def fail(message: str, status: int = 66) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(status)


def plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def configure_secure_umask() -> None:
    os.umask(0o077)


def mutation_pass_fds(
    context: AuthorityContext, pass_fds: tuple[int, ...]
) -> tuple[int, ...]:
    require(context.exclusive and context.home_fd is not None, "mutation lock is absent")
    return tuple(sorted({*pass_fds, context.home_fd}))


def node_kind(mode: int) -> NodeKind:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


@dataclass(frozen=True)
class NodeFacts:
    kind: NodeKind
    owner_uid: int | None = None
    owner_gid: int | None = None
    mode: int | None = None
    device: int | None = None
    inode: int | None = None
    size: int | None = None
    link_count: int | None = None


def absent_node() -> NodeFacts:
    return NodeFacts(kind="absent")


def facts_from_stat(value: os.stat_result) -> NodeFacts:
    return NodeFacts(
        kind=node_kind(value.st_mode),
        owner_uid=value.st_uid,
        owner_gid=value.st_gid,
        mode=stat.S_IMODE(value.st_mode),
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        link_count=value.st_nlink,
    )


def classify_image(node: NodeFacts, *, authority_device: int) -> ImageState:
    if node.kind == "absent":
        require(node == absent_node(), "absent runner image carries identity fields")
        return "absent"
    require(node.kind == "regular", "runner image is not a regular file")
    require(node.owner_uid == 0 and node.owner_gid == 0, "runner image owner differs")
    require(node.mode == 0o600, "runner image mode differs")
    require(node.device == authority_device, "runner image is on a foreign filesystem")
    require(plain_int(node.inode) and node.inode > 0, "runner image inode is invalid")
    require(node.link_count == 1, "runner image link count differs")
    require(
        plain_int(node.size) and 0 <= node.size <= IMAGE_BYTES,
        "runner image size is invalid",
    )
    if node.size == IMAGE_BYTES:
        return "root_0600_exact"
    return "root_0600_incomplete_prepublication"


def classify_lifecycle_prefix(
    authority: NodeFacts,
    claim: NodeFacts,
    claim_names: tuple[str, ...],
    expected_claim_name: str,
    *,
    home_device: int,
    expected_claim_size: int,
    allow_legacy_empty: bool,
    authority_empty: bool,
    pending: NodeFacts | None = None,
    admit_legacy_authority: bool = False,
) -> LifecyclePrefixState:
    pending = absent_node() if pending is None else pending
    require(
        not claim_names or claim_names == (expected_claim_name,),
        "runner storage lifecycle claim differs",
    )
    if pending.kind != "absent":
        require(not claim_names, "pending lifecycle claim has a final claim")
        require(
            pending.kind == "regular"
            and pending.owner_uid == 0
            and pending.owner_gid == 0
            and pending.mode == 0o600
            and pending.device == home_device
            and plain_int(pending.inode)
            and pending.inode > 0
            and plain_int(pending.size)
            and 0 <= pending.size <= MAX_DOCUMENT_BYTES
            and pending.link_count == 1,
            "pending lifecycle claim identity differs",
        )
        if authority.kind == "absent":
            require(
                authority == absent_node(),
                "absent authority carries identity fields",
            )
            return "pending_claim"
        require(
            admit_legacy_authority,
            "pending lifecycle claim has a storage authority",
        )
    else:
        require(
            pending == absent_node(),
            "absent pending lifecycle claim carries identity fields",
        )
    if claim_names:
        require(
            claim.kind == "regular"
            and claim.owner_uid == 0
            and claim.owner_gid == 0
            and claim.mode == 0o600
            and claim.device == home_device
            and plain_int(claim.inode)
            and claim.inode > 0
            and plain_int(claim.size)
            and claim.size == expected_claim_size
            and claim.link_count == 1,
            "runner storage lifecycle claim identity differs",
        )
    else:
        require(claim == absent_node(), "absent lifecycle claim carries identity fields")
    if authority.kind == "absent":
        require(authority == absent_node(), "absent authority carries identity fields")
        return "claim_only" if claim_names else "absent_unclaimed"
    require(authority.kind == "directory", "runner storage authority root is not a directory")
    require(
        authority.owner_uid == 0
        and authority.owner_gid == 0
        and authority.mode == 0o700
        and authority.device == home_device
        and plain_int(authority.inode)
        and authority.inode > 0,
        "runner storage authority root identity differs",
    )
    if claim_names:
        return "claimed_authority"
    if admit_legacy_authority:
        return "pending_legacy_authority" if pending.kind != "absent" else "legacy_authority"
    require(
        allow_legacy_empty and authority_empty,
        "runner storage authority has no lifecycle claim",
    )
    return "legacy_empty_authority"


def prepare_disposition(image_state: ImageState, receipt_present: bool) -> str:
    if image_state == "absent" and not receipt_present:
        return "create"
    if image_state == "root_0600_exact" and receipt_present:
        return "recover"
    return "teardown_required"


def lstat_at(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def require_descriptor_entry(directory_fd: int, name: str, descriptor: int) -> None:
    path_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    descriptor_stat = os.fstat(descriptor)
    require(
        (path_stat.st_dev, path_stat.st_ino)
        == (descriptor_stat.st_dev, descriptor_stat.st_ino),
        f"runner authority entry changed: {name}",
    )


def unlink_bound_leaf(
    directory_fd: int,
    name: str,
    *,
    label: str,
    allowed_kinds: tuple[NodeKind, ...],
    owner_uid: int | None = None,
    owner_gid: int | None = None,
    required_mode: int | None = None,
    minimum_size: int | None = None,
    maximum_size: int | None = None,
    required_link_count: int | None = None,
    expected_identity: tuple[int, int] | None = None,
) -> bool:
    initial = lstat_at(directory_fd, name)
    if initial is None:
        return False
    descriptor = os.open(
        name,
        os.O_PATH | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        observed = os.fstat(descriptor)
        observed_kind = node_kind(observed.st_mode)
        require(observed_kind in allowed_kinds, f"{label} kind differs")
        require(
            (initial.st_dev, initial.st_ino) == (observed.st_dev, observed.st_ino),
            f"{label} changed during admission",
        )
        if owner_uid is not None:
            require(observed.st_uid == owner_uid, f"{label} owner differs")
        if owner_gid is not None:
            require(observed.st_gid == owner_gid, f"{label} group differs")
        if required_mode is not None:
            require(stat.S_IMODE(observed.st_mode) == required_mode, f"{label} mode differs")
        if minimum_size is not None:
            require(observed.st_size >= minimum_size, f"{label} size differs")
        if maximum_size is not None:
            require(observed.st_size <= maximum_size, f"{label} size differs")
        if required_link_count is not None:
            require(
                observed.st_nlink == required_link_count,
                f"{label} link count differs",
            )
        require(
            observed.st_dev == os.fstat(directory_fd).st_dev,
            f"{label} is on a foreign filesystem",
        )
        if expected_identity is not None:
            require(
                (observed.st_dev, observed.st_ino) == expected_identity,
                f"{label} identity differs",
            )
        # This is deliberately the final check before the parent-confined
        # unlink.  It binds the admitted O_PATH inode to the current entry
        # under the serialized/no-hostile-root (or caller-confined) model; it
        # does not pretend unlinkat is an atomic compare-and-delete primitive.
        require_descriptor_entry(directory_fd, name, descriptor)
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        return True
    finally:
        os.close(descriptor)


def remove_tree_descriptor_relative(directory_fd: int, name: str) -> None:
    value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    require(stat.S_ISDIR(value.st_mode), f"destructive tree root is not a directory: {name}")
    child_fd = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=directory_fd,
    )
    try:
        require_descriptor_entry(directory_fd, name, child_fd)
        for nested in tuple(sorted(os.listdir(child_fd))):
            nested_value = os.stat(nested, dir_fd=child_fd, follow_symlinks=False)
            if stat.S_ISDIR(nested_value.st_mode):
                remove_tree_descriptor_relative(child_fd, nested)
            else:
                unlink_bound_leaf(
                    child_fd,
                    nested,
                    label=f"destructive tree leaf: {nested}",
                    allowed_kinds=("regular", "symlink", "other"),
                    expected_identity=(nested_value.st_dev, nested_value.st_ino),
                )
        require(not os.listdir(child_fd), f"destructive tree did not become empty: {name}")
        os.fsync(child_fd)
        require_descriptor_entry(directory_fd, name, child_fd)
        os.rmdir(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(child_fd)


def require_root_directory(value: os.stat_result, mode: int, label: str) -> None:
    require(stat.S_ISDIR(value.st_mode), f"{label} is not a directory")
    require(value.st_uid == 0 and value.st_gid == 0, f"{label} owner differs")
    require(stat.S_IMODE(value.st_mode) == mode, f"{label} mode differs")


def remove_admitted_pending(
    directory_fd: int,
    name: str,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    try:
        unlink_bound_leaf(
            directory_fd,
            name,
            label=f"pending receipt identity differs: {name}",
            allowed_kinds=("regular",),
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            required_mode=0o600,
            minimum_size=0,
            maximum_size=MAX_DOCUMENT_BYTES,
            required_link_count=1,
        )
    except RunnerStorageLifecycleError as error:
        raise RunnerStorageLifecycleError(
            f"pending receipt identity differs: {name}"
        ) from error


@dataclass(frozen=True)
class DirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int

    def document(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "device": self.device,
            "inode": self.inode,
            "ownerUid": self.owner_uid,
            "ownerGid": self.owner_gid,
            "mode": f"{self.mode:04o}",
        }


def directory_identity(path: Path, value: os.stat_result) -> DirectoryIdentity:
    require(stat.S_ISDIR(value.st_mode), f"directory identity is not a directory: {path}")
    return DirectoryIdentity(
        path=path,
        device=value.st_dev,
        inode=value.st_ino,
        owner_uid=value.st_uid,
        owner_gid=value.st_gid,
        mode=stat.S_IMODE(value.st_mode),
    )


def require_directory_identity_stat(
    observed: os.stat_result,
    identity: DirectoryIdentity,
) -> None:
    expected = (
        identity.device,
        identity.inode,
        identity.owner_uid,
        identity.owner_gid,
        identity.mode,
    )
    require(
        stat.S_ISDIR(observed.st_mode)
        and (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
        == expected,
        f"pinned directory identity changed: {identity.path}",
    )


def require_pinned_directory(directory_fd: int, identity: DirectoryIdentity) -> None:
    require_directory_identity_stat(os.fstat(directory_fd), identity)
    require_directory_identity_stat(
        os.stat(identity.path, follow_symlinks=False),
        identity,
    )


def claim_binding_document(
    state_root: DirectoryIdentity,
    evidence: DirectoryIdentity,
    caller_uid: int,
    caller_gid: int,
) -> dict[str, Any]:
    return {
        "domain": CLAIM_DOMAIN,
        "authorityRoot": str(AUTHORITY_ROOT),
        "caller": {"uid": caller_uid, "gid": caller_gid},
        "stateRootIdentity": state_root.document(),
        "evidenceDirectoryIdentity": evidence.document(),
    }


def claim_name_for_identity(
    state_root: DirectoryIdentity,
    evidence: DirectoryIdentity,
    caller_uid: int,
    caller_gid: int,
) -> str:
    return f"{CLAIM_PREFIX}{sha256_bytes(claim_bytes_for_identity(state_root, evidence, caller_uid, caller_gid))}"


def claim_bytes_for_identity(
    state_root: DirectoryIdentity,
    evidence: DirectoryIdentity,
    caller_uid: int,
    caller_gid: int,
) -> bytes:
    return (
        json.dumps(
            claim_binding_document(state_root, evidence, caller_uid, caller_gid),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def open_absolute_directory_no_symlinks(path: Path) -> int:
    require(path.is_absolute(), f"directory path is not absolute: {path}")
    require(
        os.path.normpath(str(path)) == str(path),
        f"directory path is not lexically canonical: {path}",
    )
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            child = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_caller_directories(
    state_root: Path, caller_uid: int, caller_gid: int
) -> tuple[int, DirectoryIdentity, int, DirectoryIdentity]:
    require(state_root.is_absolute(), "STATE_ROOT is not absolute")
    require(str(state_root).startswith(f"{HOME_ROOT}/"), "STATE_ROOT is outside /home")
    state_fd = open_absolute_directory_no_symlinks(state_root)
    evidence_fd: int | None = None
    try:
        state_identity = directory_identity(state_root, os.fstat(state_fd))
        require(
            state_identity.owner_uid == caller_uid
            and state_identity.owner_gid == caller_gid
            and state_identity.mode == 0o700,
            "user state root authority differs",
        )
        require_pinned_directory(state_fd, state_identity)
        evidence_path = state_root / "evidence"
        evidence_fd = os.open(
            "evidence",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=state_fd,
        )
        evidence_identity = directory_identity(evidence_path, os.fstat(evidence_fd))
        require(
            evidence_identity.owner_uid == caller_uid
            and evidence_identity.owner_gid == caller_gid
            and evidence_identity.mode == 0o700,
            "user evidence directory authority differs",
        )
        require(
            evidence_identity.device == state_identity.device,
            "user evidence directory is on a foreign filesystem",
        )
        require_pinned_directory(evidence_fd, evidence_identity)
        return state_fd, state_identity, evidence_fd, evidence_identity
    except BaseException:
        if evidence_fd is not None:
            os.close(evidence_fd)
        os.close(state_fd)
        raise


def acquire_lifecycle_lock(home_fd: int, *, exclusive: bool) -> None:
    operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    deadline = time.monotonic() + LIFECYCLE_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(home_fd, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise RunnerStorageLifecycleError("runner storage lifecycle lock timed out")
            time.sleep(0.05)


def claim_roster(home_fd: int) -> tuple[str, ...]:
    return tuple(
        sorted(name for name in os.listdir(home_fd) if name.startswith(CLAIM_PREFIX))
    )


def read_bounded_descriptor(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(descriptor, 64 * 1024)
        if not block:
            return b"".join(chunks)
        total += len(block)
        require(total <= limit, "bounded descriptor exceeds its limit")
        chunks.append(block)


def require_claim_identity(
    home_fd: int,
    claim_name: str,
    expected: bytes,
) -> bytes:
    value = lstat_at(home_fd, claim_name)
    require(value is not None, "runner storage lifecycle claim is absent")
    assert value is not None
    require(
        stat.S_ISREG(value.st_mode)
        and value.st_uid == 0
        and value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o600
        and value.st_dev == os.fstat(home_fd).st_dev
        and value.st_nlink == 1
        and value.st_size == len(expected),
        "runner storage lifecycle claim identity differs",
    )
    descriptor = os.open(claim_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=home_fd)
    try:
        require_descriptor_entry(home_fd, claim_name, descriptor)
        actual = read_bounded_descriptor(descriptor, len(expected))
    finally:
        os.close(descriptor)
    require(actual == expected, "runner storage lifecycle claim bytes differ")
    require(
        sha256_bytes(expected) == claim_name.removeprefix(CLAIM_PREFIX),
        "runner storage lifecycle claim digest differs",
    )
    return actual


def create_claim(home_fd: int, claim_name: str, expected: bytes) -> None:
    require(lstat_at(home_fd, claim_name) is None, "runner storage lifecycle claim exists")
    descriptor = os.open(
        CLAIM_PENDING_NAME,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=home_fd,
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(expected):
            offset += os.write(descriptor, expected[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(
        CLAIM_PENDING_NAME,
        claim_name,
        src_dir_fd=home_fd,
        dst_dir_fd=home_fd,
    )
    os.fsync(home_fd)
    require_claim_identity(home_fd, claim_name, expected)


def seal_claim(home_fd: int, claim_name: str, expected: bytes) -> None:
    require_claim_identity(home_fd, claim_name, expected)
    descriptor = os.open(claim_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=home_fd)
    try:
        require_descriptor_entry(home_fd, claim_name, descriptor)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(home_fd)
    require_claim_identity(home_fd, claim_name, expected)


def directory_identity_from_document(value: object, label: str) -> DirectoryIdentity:
    require(isinstance(value, dict), f"{label} is not an object")
    assert isinstance(value, dict)
    require(
        set(value) == {"path", "device", "inode", "ownerUid", "ownerGid", "mode"},
        f"{label} shape differs",
    )
    require(
        isinstance(value["path"], str)
        and Path(value["path"]).is_absolute()
        and os.path.normpath(value["path"]) == value["path"],
        f"{label} path is invalid",
    )
    for field in ("device", "inode", "ownerUid", "ownerGid"):
        require(plain_int(value[field]), f"{label} coordinate is invalid: {field}")
    require(
        isinstance(value["mode"], str) and re.fullmatch(r"[0-7]{4}", value["mode"]),
        f"{label} mode is invalid",
    )
    return DirectoryIdentity(
        Path(value["path"]),
        value["device"],
        value["inode"],
        value["ownerUid"],
        value["ownerGid"],
        int(value["mode"], 8),
    )


def read_claim_document(
    home_fd: int,
    claim_name: str,
) -> tuple[bytes, dict[str, Any], DirectoryIdentity, DirectoryIdentity]:
    value = lstat_at(home_fd, claim_name)
    require(value is not None, "runner storage lifecycle claim is absent")
    assert value is not None
    require(
        stat.S_ISREG(value.st_mode)
        and value.st_uid == 0
        and value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o600
        and value.st_dev == os.fstat(home_fd).st_dev
        and value.st_nlink == 1
        and 0 < value.st_size <= MAX_DOCUMENT_BYTES,
        "runner storage lifecycle claim document identity differs",
    )
    descriptor = os.open(claim_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=home_fd)
    try:
        require_descriptor_entry(home_fd, claim_name, descriptor)
        raw = read_bounded_descriptor(descriptor, MAX_DOCUMENT_BYTES)
    finally:
        os.close(descriptor)
    document = json.loads(raw)
    require(isinstance(document, dict), "runner storage lifecycle claim is not an object")
    assert isinstance(document, dict)
    require(
        raw == canonical_json_bytes(document),
        "runner storage lifecycle claim is not canonical JSON",
    )
    require(
        sha256_bytes(raw) == claim_name.removeprefix(CLAIM_PREFIX),
        "runner storage lifecycle claim filename digest differs",
    )
    require(
        set(document)
        == {"domain", "authorityRoot", "caller", "stateRootIdentity", "evidenceDirectoryIdentity"}
        and document["domain"] == CLAIM_DOMAIN
        and document["authorityRoot"] == str(AUTHORITY_ROOT),
        "runner storage lifecycle claim document differs",
    )
    state = directory_identity_from_document(
        document["stateRootIdentity"], "claim state-root identity"
    )
    evidence = directory_identity_from_document(
        document["evidenceDirectoryIdentity"], "claim evidence identity"
    )
    return raw, document, state, evidence


@dataclass
class AuthorityContext:
    state_fd: int | None
    evidence_fd: int | None
    projection_evidence_fd: int | None
    state_identity: DirectoryIdentity
    evidence_identity: DirectoryIdentity
    caller_uid: int
    caller_gid: int
    home_fd: int | None
    root_fd: int | None
    target_fd: int | None
    image_fd: int | None
    authority_device: int
    image_state: ImageState
    roster: tuple[str, ...]
    exclusive: bool
    claim_name: str
    claim_bytes: bytes
    claim_present: bool
    legacy_unclaimed: bool
    orphaned_binding: bool = False

    def close(self) -> None:
        for name in (
            "image_fd",
            "target_fd",
            "root_fd",
            "home_fd",
            "projection_evidence_fd",
            "evidence_fd",
            "state_fd",
        ):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def __enter__(self) -> AuthorityContext:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def require_context_binding(context: AuthorityContext) -> None:
    require(
        context.home_fd is not None,
        "lifecycle identity descriptors are absent",
    )
    if context.orphaned_binding:
        require(
            context.state_fd is None and context.evidence_fd is None,
            "orphaned lifecycle binding unexpectedly has caller descriptors",
        )
        if context.projection_evidence_fd is not None:
            require_directory_identity_stat(
                os.fstat(context.projection_evidence_fd),
                context.evidence_identity,
            )
    else:
        require(
            context.projection_evidence_fd is None,
            "bound lifecycle context unexpectedly has a projection-only descriptor",
        )
        require(
            context.state_fd is not None and context.evidence_fd is not None,
            "caller lifecycle identity descriptors are absent",
        )
        require_pinned_directory(context.state_fd, context.state_identity)
        require_pinned_directory(context.evidence_fd, context.evidence_identity)
    home = os.fstat(context.home_fd)
    require_root_directory(home, 0o755, "/home authority parent")
    require(
        home.st_dev
        == context.state_identity.device
        == context.evidence_identity.device,
        "lifecycle identities use different backing filesystems",
    )
    claims = claim_roster(context.home_fd)
    if context.claim_present:
        require(claims == (context.claim_name,), "runner storage lifecycle claim differs")
        require_claim_identity(
            context.home_fd,
            context.claim_name,
            context.claim_bytes,
        )
    else:
        require(not claims, "unexpected runner storage lifecycle claim exists")


def user_projection_directory_fd(context: AuthorityContext) -> int | None:
    if context.orphaned_binding:
        return context.projection_evidence_fd
    return context.evidence_fd


def runtime_authority_paths(state_root: Path) -> tuple[Path, Path, Path]:
    identifier = sha256_bytes(str(state_root).encode())[:12]
    return (
        Path(f"{RUNTIME_ROOT_PREFIX}{identifier}"),
        Path(f"{SOCKET_ROOT_PREFIX}{identifier}"),
        Path(f"{CGROUP_ROOT_PREFIX}{identifier}"),
    )


def runtime_lease_path(state_root: Path) -> Path:
    require(state_root.is_absolute(), "runtime deletion state path is invalid")
    return RUNTIME_PARENT / GLOBAL_RUNTIME_LEASE_NAME


@dataclass
class RuntimeDeletionLease:
    parent_fd: int
    descriptor: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def __enter__(self) -> RuntimeDeletionLease:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def acquire_runtime_deletion_lease(state_root: Path) -> RuntimeDeletionLease:
    path = runtime_lease_path(state_root)
    parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    try:
        parent = os.fstat(parent_fd)
        require_root_directory(parent, 0o755, "runtime lease parent")
        descriptor = os.open(
            path.name,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        value = os.fstat(descriptor)
        literal = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            stat.S_ISREG(value.st_mode)
            and value.st_uid == 0
            and value.st_gid == 0
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_nlink == 1
            and (value.st_dev, value.st_ino) == (literal.st_dev, literal.st_ino),
            "runtime deletion lease identity differs",
        )
        deadline = time.monotonic() + LIFECYCLE_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RunnerStorageLifecycleError(
                        "isolated runtime lease is busy during storage deletion"
                    )
                time.sleep(0.05)
        os.fsync(descriptor)
        os.fsync(parent_fd)
        return RuntimeDeletionLease(parent_fd, descriptor)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
        raise


def require_inherited_runtime_lease(descriptor: int, state_root: Path) -> None:
    require(
        plain_int(descriptor) and descriptor >= 3,
        "inherited runtime lease descriptor is invalid",
    )
    path = runtime_lease_path(state_root)
    parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    contender: int | None = None
    try:
        require_root_directory(os.fstat(parent_fd), 0o755, "runtime lease parent")
        observed = os.fstat(descriptor)
        literal = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o600
            and observed.st_nlink == 1
            and (observed.st_dev, observed.st_ino)
            == (literal.st_dev, literal.st_ino)
            and (fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE)
            == os.O_RDWR
            and os.readlink(f"/proc/self/fd/{descriptor}") == str(path),
            "inherited runtime lease identity differs",
        )
        contender = os.open(
            path.name,
            os.O_RDWR | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        require_descriptor_entry(parent_fd, path.name, contender)
        try:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(contender, fcntl.LOCK_UN)
            raise RunnerStorageLifecycleError(
                "inherited runtime lease is not exclusively held"
            )
        try:
            # Re-locking the inherited open-file description succeeds only
            # for its own flock.  A distinct holder would reject this call.
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RunnerStorageLifecycleError(
                "inherited runtime lease belongs to a different holder"
            ) from error
        try:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(contender, fcntl.LOCK_UN)
            raise RunnerStorageLifecycleError(
                "inherited runtime lease lost exclusive ownership"
            )
    except OSError as error:
        raise RunnerStorageLifecycleError(
            "inherited runtime lease proof failed"
        ) from error
    finally:
        if contender is not None:
            os.close(contender)
        os.close(parent_fd)


def require_runtime_absent(context: AuthorityContext) -> None:
    require_runtime_paths_absent(context.state_identity.path)
    require(
        not task_runtime_authority_roster(),
        "every task runtime authority must be removed before storage deletion",
    )


def require_runtime_paths_absent(state_root: Path) -> None:
    for path in runtime_authority_paths(state_root):
        try:
            os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            continue
        raise RunnerStorageLifecycleError(
            f"isolated runtime authority must be removed before storage deletion: {path}"
        )


def open_authority(
    *,
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
    create: bool,
    exclusive: bool,
    allow_legacy_empty: bool = False,
    allow_orphaned_binding: bool = False,
    required_tools: tuple[str, ...] = (),
) -> AuthorityContext:
    state_fd: int | None = None
    evidence_fd: int | None = None
    projection_evidence_fd: int | None = None
    state_identity: DirectoryIdentity | None = None
    evidence_identity: DirectoryIdentity | None = None
    try:
        state_fd, state_identity, evidence_fd, evidence_identity = open_caller_directories(
            state_root, caller_uid, caller_gid
        )
    except FileNotFoundError:
        require(
            allow_orphaned_binding,
            "caller state binding is absent",
        )
    home_fd: int | None = None
    root_fd: int | None = None
    target_fd: int | None = None
    image_fd: int | None = None
    try:
        for tool_name in required_tools:
            trusted_tool(tool_name)
        home_fd = os.open(HOME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        home_stat = os.fstat(home_fd)
        require_root_directory(home_stat, 0o755, "/home authority parent")
        acquire_lifecycle_lock(home_fd, exclusive=exclusive)
        claims = claim_roster(home_fd)
        authority_stat = lstat_at(home_fd, AUTHORITY_NAME)
        require(
            lstat_at(home_fd, CLAIM_PENDING_NAME) is None,
            "pending lifecycle claim requires lease-proven recovery",
        )
        orphaned_binding = False
        if state_identity is None or evidence_identity is None:
            require(
                allow_orphaned_binding and len(claims) == 1,
                "orphaned lifecycle claim is absent or ambiguous",
            )
            claim_name = claims[0]
            claim_bytes, claim_document, stored_state, stored_evidence = read_claim_document(
                home_fd, claim_name
            )
            require(
                claim_document.get("caller") == {"uid": caller_uid, "gid": caller_gid}
                and stored_state.path == state_root,
                "orphaned lifecycle caller or original path differs",
            )
            state_identity = stored_state
            evidence_identity = stored_evidence
            orphaned_binding = True
        else:
            require(
                home_stat.st_dev == state_identity.device == evidence_identity.device,
                "lifecycle identities use different backing filesystems",
            )
            claim_name = claim_name_for_identity(
                state_identity, evidence_identity, caller_uid, caller_gid
            )
            claim_bytes = claim_bytes_for_identity(
                state_identity, evidence_identity, caller_uid, caller_gid
            )
            if claims and claims != (claim_name,) and allow_orphaned_binding:
                require(len(claims) == 1, "orphaned lifecycle claim is ambiguous")
                stored_name = claims[0]
                stored_bytes, claim_document, stored_state, stored_evidence = read_claim_document(
                    home_fd, stored_name
                )
                require(
                    claim_document.get("caller") == {"uid": caller_uid, "gid": caller_gid},
                    "orphaned lifecycle caller differs",
                )
                current_coordinates = (
                    state_identity.device,
                    state_identity.inode,
                    state_identity.owner_uid,
                    state_identity.owner_gid,
                    state_identity.mode,
                    evidence_identity.device,
                    evidence_identity.inode,
                    evidence_identity.owner_uid,
                    evidence_identity.owner_gid,
                    evidence_identity.mode,
                )
                stored_coordinates = (
                    stored_state.device,
                    stored_state.inode,
                    stored_state.owner_uid,
                    stored_state.owner_gid,
                    stored_state.mode,
                    stored_evidence.device,
                    stored_evidence.inode,
                    stored_evidence.owner_uid,
                    stored_evidence.owner_gid,
                    stored_evidence.mode,
                )
                require(
                    current_coordinates == stored_coordinates,
                    "relocated lifecycle identity coordinates differ",
                )
                os.close(state_fd)
                state_fd = None
                projection_evidence_fd = evidence_fd
                evidence_fd = None
                state_identity = stored_state
                evidence_identity = stored_evidence
                claim_name = stored_name
                claim_bytes = stored_bytes
                orphaned_binding = True
        require(
            state_identity is not None and evidence_identity is not None,
            "resolved lifecycle binding is absent",
        )
        require(
            home_stat.st_dev == state_identity.device == evidence_identity.device,
            "resolved lifecycle binding uses a foreign filesystem",
        )
        claim_present = claims == (claim_name,)
        legacy_unclaimed = False
        claim_stat = lstat_at(home_fd, claim_name) if claim_present else None
        claim_facts = absent_node() if claim_stat is None else facts_from_stat(claim_stat)
        authority_facts = (
            absent_node() if authority_stat is None else facts_from_stat(authority_stat)
        )
        if authority_stat is None:
            classify_lifecycle_prefix(
                authority_facts,
                claim_facts,
                claims,
                claim_name,
                home_device=home_stat.st_dev,
                expected_claim_size=len(claim_bytes),
                allow_legacy_empty=False,
                authority_empty=True,
            )
        elif claim_present:
            classify_lifecycle_prefix(
                authority_facts,
                claim_facts,
                claims,
                claim_name,
                home_device=home_stat.st_dev,
                expected_claim_size=len(claim_bytes),
                allow_legacy_empty=False,
                authority_empty=False,
            )
        elif claims:
            raise RunnerStorageLifecycleError("runner storage lifecycle claim differs")
        if authority_stat is None and create:
            require(exclusive, "authority creation requires an exclusive lifecycle lock")
            if not claim_present:
                create_claim(home_fd, claim_name, claim_bytes)
                claim_present = True
            else:
                seal_claim(home_fd, claim_name, claim_bytes)
            os.mkdir(AUTHORITY_NAME, mode=0o700, dir_fd=home_fd)
            os.fsync(home_fd)
            authority_stat = os.stat(
                AUTHORITY_NAME, dir_fd=home_fd, follow_symlinks=False
            )
        elif authority_stat is not None and not claim_present:
            require(
                allow_legacy_empty and exclusive,
                "runner storage authority has no lifecycle claim",
            )
            legacy_unclaimed = True
        if claim_present:
            if authority_stat is None and exclusive:
                seal_claim(home_fd, claim_name, claim_bytes)
            require_claim_identity(home_fd, claim_name, claim_bytes)

        if authority_stat is None:
            return AuthorityContext(
                state_fd=state_fd,
                evidence_fd=evidence_fd,
                projection_evidence_fd=projection_evidence_fd,
                state_identity=state_identity,
                evidence_identity=evidence_identity,
                caller_uid=caller_uid,
                caller_gid=caller_gid,
                home_fd=home_fd,
                root_fd=None,
                target_fd=None,
                image_fd=None,
                authority_device=home_stat.st_dev,
                image_state="absent",
                roster=(),
                exclusive=exclusive,
                claim_name=claim_name,
                claim_bytes=claim_bytes,
                claim_present=claim_present,
                legacy_unclaimed=False,
                orphaned_binding=orphaned_binding,
            )

        require_root_directory(authority_stat, 0o700, "runner storage authority root")
        require(
            authority_stat.st_dev == home_stat.st_dev,
            "runner storage authority is on a foreign filesystem",
        )
        root_fd = os.open(
            AUTHORITY_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=home_fd,
        )
        require_descriptor_entry(home_fd, AUTHORITY_NAME, root_fd)
        roster = tuple(sorted(os.listdir(root_fd)))
        if legacy_unclaimed:
            classify_lifecycle_prefix(
                facts_from_stat(os.fstat(root_fd)),
                absent_node(),
                (),
                claim_name,
                home_device=home_stat.st_dev,
                expected_claim_size=len(claim_bytes),
                allow_legacy_empty=True,
                authority_empty=not roster,
            )
            return AuthorityContext(
                state_fd=state_fd,
                evidence_fd=evidence_fd,
                projection_evidence_fd=projection_evidence_fd,
                state_identity=state_identity,
                evidence_identity=evidence_identity,
                caller_uid=caller_uid,
                caller_gid=caller_gid,
                home_fd=home_fd,
                root_fd=root_fd,
                target_fd=None,
                image_fd=None,
                authority_device=home_stat.st_dev,
                image_state="absent",
                roster=(),
                exclusive=exclusive,
                claim_name=claim_name,
                claim_bytes=claim_bytes,
                claim_present=False,
                legacy_unclaimed=True,
                orphaned_binding=orphaned_binding,
            )

        if create and lstat_at(root_fd, TARGET_NAME) is None:
            os.mkdir(TARGET_NAME, mode=0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        target_stat = lstat_at(root_fd, TARGET_NAME)
        if target_stat is not None:
            require_root_directory(target_stat, 0o700, "runner storage mount target")
            target_fd = os.open(
                TARGET_NAME,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            require_descriptor_entry(root_fd, TARGET_NAME, target_fd)
        elif create:
            raise RunnerStorageLifecycleError("runner storage target creation failed")

        image_stat = lstat_at(root_fd, IMAGE_NAME)
        if image_stat is None:
            image_facts = absent_node()
        else:
            require(node_kind(image_stat.st_mode) == "regular", "runner image is not regular")
            image_fd = os.open(IMAGE_NAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=root_fd)
            require_descriptor_entry(root_fd, IMAGE_NAME, image_fd)
            image_facts = facts_from_stat(os.fstat(image_fd))
        roster = tuple(sorted(os.listdir(root_fd)))
        allowed = {
            TARGET_NAME,
            IMAGE_NAME,
            RECEIPT_NAME,
            RECEIPT_PENDING_NAME,
            OUTER_DOCKER_NAME,
            OUTER_CONTAINERD_NAME,
        }
        foreign = tuple(name for name in roster if name not in allowed)
        require(not foreign, "runner storage authority contains a foreign entry")
        for name, modes in (
            (OUTER_DOCKER_NAME, {0o700, 0o710}),
            (OUTER_CONTAINERD_NAME, {0o700}),
        ):
            value = lstat_at(root_fd, name)
            if value is not None:
                require(
                    stat.S_ISDIR(value.st_mode)
                    and value.st_uid == 0
                    and value.st_gid == 0
                    and stat.S_IMODE(value.st_mode) in modes
                    and value.st_dev == home_stat.st_dev,
                    f"outer daemon storage authority differs: {name}",
                )
        image_state = classify_image(image_facts, authority_device=home_stat.st_dev)
        context = AuthorityContext(
            state_fd=state_fd,
            evidence_fd=evidence_fd,
            projection_evidence_fd=projection_evidence_fd,
            state_identity=state_identity,
            evidence_identity=evidence_identity,
            caller_uid=caller_uid,
            caller_gid=caller_gid,
            home_fd=home_fd,
            root_fd=root_fd,
            target_fd=target_fd,
            image_fd=image_fd,
            authority_device=home_stat.st_dev,
            image_state=image_state,
            roster=roster,
            exclusive=exclusive,
            claim_name=claim_name,
            claim_bytes=claim_bytes,
            claim_present=True,
            legacy_unclaimed=False,
            orphaned_binding=orphaned_binding,
        )
        require_context_binding(context)
        if exclusive:
            projection_fd = user_projection_directory_fd(context)
            if projection_fd is not None:
                remove_admitted_pending(
                    projection_fd,
                    PROJECTION_PENDING_NAME,
                    owner_uid=caller_uid,
                    owner_gid=caller_gid,
                )
            reconcile_receipt_pending(context)
            context.roster = tuple(sorted(os.listdir(root_fd)))
        return context
    except BaseException:
        for descriptor in (
            image_fd,
            target_fd,
            root_fd,
            home_fd,
            projection_evidence_fd,
            evidence_fd,
            state_fd,
        ):
            if descriptor is not None:
                os.close(descriptor)
        raise


def require_trusted_parent_chain(path: Path, name: str) -> None:
    for parent in (path.parent, *path.parent.parents):
        value = os.stat(parent, follow_symlinks=False)
        require(stat.S_ISDIR(value.st_mode), f"trusted tool parent is not a directory: {name}")
        require(
            value.st_uid == 0 and value.st_gid == 0,
            f"trusted tool parent owner differs: {name}",
        )
        require(
            stat.S_IMODE(value.st_mode) & 0o022 == 0,
            f"trusted tool parent is writable: {name}",
        )


def trusted_tool(name: str) -> str:
    path = TRUSTED_TOOLS[name]
    require(path.is_absolute(), f"trusted tool path is not absolute: {name}")
    literal = os.stat(path, follow_symlinks=False)
    require(
        stat.S_ISREG(literal.st_mode) or stat.S_ISLNK(literal.st_mode),
        f"trusted tool literal is not regular or a symlink: {name}",
    )
    require(
        literal.st_uid == 0 and literal.st_gid == 0,
        f"trusted tool literal owner differs: {name}",
    )
    if stat.S_ISREG(literal.st_mode):
        require(
            stat.S_IMODE(literal.st_mode) & 0o022 == 0,
            f"trusted tool literal is writable: {name}",
        )
    require_trusted_parent_chain(path, name)
    resolved = path.resolve(strict=True)
    require_trusted_parent_chain(resolved, name)
    value = os.stat(resolved, follow_symlinks=False)
    require(stat.S_ISREG(value.st_mode), f"trusted tool target is not regular: {name}")
    require(
        value.st_uid == 0 and value.st_gid == 0,
        f"trusted tool target owner differs: {name}",
    )
    require(
        stat.S_IMODE(value.st_mode) & 0o022 == 0,
        f"trusted tool target is writable: {name}",
    )
    require(stat.S_IMODE(value.st_mode) & 0o111 != 0, f"trusted tool is not executable: {name}")
    return str(resolved)


def run_tool(
    context: AuthorityContext,
    name: str,
    *args: str,
    mutation: bool = False,
    pass_fds: tuple[int, ...] = (),
) -> str:
    require_context_binding(context)
    tool_command = [trusted_tool(name), *args]
    retained = set(pass_fds)
    if mutation:
        retained = set(mutation_pass_fds(context, pass_fds))
        assert context.home_fd is not None
        inherited_for_tool = tuple(sorted(retained))
        result = subprocess.run(
            [
                trusted_tool("python"),
                "-I",
                "-S",
                "-B",
                "-c",
                MUTATION_GUARDIAN,
                str(context.home_fd),
                ",".join(str(value) for value in inherited_for_tool),
                str(MUTATION_TIMEOUT_SECONDS),
                str(MUTATION_TERMINATION_GRACE_SECONDS),
                *tool_command,
            ],
            check=True,
            capture_output=True,
            cwd="/",
            env=TOOL_ENVIRONMENT,
            text=True,
            pass_fds=tuple(sorted(retained)),
            timeout=(
                MUTATION_TIMEOUT_SECONDS
                + MUTATION_TERMINATION_GRACE_SECONDS
                + 5.0
            ),
        )
    else:
        result = subprocess.run(
            tool_command,
            check=True,
            capture_output=True,
            cwd="/",
            env=TOOL_ENVIRONMENT,
            text=True,
            pass_fds=tuple(sorted(retained)),
            timeout=120,
        )
    return result.stdout.strip()


def decode_mount_path(value: str) -> str:
    return (
        value.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
    )


@dataclass(frozen=True)
class MountRootCoordinate:
    absolute: Path | None = None
    opaque: str | None = None

    def __post_init__(self) -> None:
        require(
            (self.absolute is None) != (self.opaque is None),
            "mount-root coordinate must have exactly one representation",
        )
        if self.absolute is not None:
            require(self.absolute.is_absolute(), "absolute mount-root coordinate is relative")
        if self.opaque is not None:
            require(
                OPAQUE_MOUNT_ROOT.fullmatch(self.opaque) is not None,
                "opaque mount-root identity is invalid",
            )

    @classmethod
    def parse(cls, value: str, filesystem_type: str) -> MountRootCoordinate:
        candidate = Path(value)
        if candidate.is_absolute():
            return cls(absolute=candidate)
        require(
            filesystem_type == "nsfs"
            and OPAQUE_MOUNT_ROOT.fullmatch(value) is not None,
            "mountinfo root is neither absolute nor an admitted nsfs identity",
        )
        return cls(opaque=value)

    def wire(self) -> str:
        if self.absolute is not None:
            require(self.opaque is None, "mount-root coordinate is ambiguous")
            return str(self.absolute)
        require(
            self.opaque is not None
            and OPAQUE_MOUNT_ROOT.fullmatch(self.opaque) is not None,
            "opaque mount-root identity is invalid",
        )
        return self.opaque

    def at_or_below(self, root: MountRootCoordinate) -> bool:
        if self.absolute is not None and root.absolute is not None:
            return path_at_or_below(self.absolute, root.absolute)
        if self.opaque is not None and root.opaque is not None:
            return self.opaque == root.opaque
        return False

    def translate(self, relative: Path) -> MountRootCoordinate:
        if self.absolute is not None:
            return MountRootCoordinate(absolute=self.absolute / relative)
        require(
            relative == Path("."),
            "opaque mount-root identity cannot address a descendant",
        )
        self.wire()
        return self


@dataclass(frozen=True)
class MountRecord:
    device_number: str
    target: str
    optional_fields: tuple[str, ...]
    mount_root: str = "/"
    filesystem_type: str = "none"

    def root_coordinate(self) -> MountRootCoordinate:
        return MountRootCoordinate.parse(self.mount_root, self.filesystem_type)


@dataclass(frozen=True)
class NamespaceObservation:
    namespace_id: str
    representative_pid: int
    records: tuple[MountRecord, ...]


@dataclass(frozen=True)
class NamespaceOccurrence:
    namespace_id: str
    representative_pid: int
    device_number: str
    target: str
    mount_root: str = "/"


def read_mount_records(path: str = "/proc/self/mountinfo") -> tuple[MountRecord, ...]:
    records: list[MountRecord] = []
    with open(path, encoding="utf-8") as source:
        for raw in source:
            fields = raw.rstrip("\n").split(" ")
            require("-" in fields and len(fields) >= 10, "mountinfo record is invalid")
            separator = fields.index("-")
            require(separator >= 6, "mountinfo separator is invalid")
            require(separator + 1 < len(fields), "mountinfo filesystem type is absent")
            filesystem_type = fields[separator + 1]
            mount_root = decode_mount_path(fields[3])
            target = decode_mount_path(fields[4])
            require(
                Path(target).is_absolute(),
                "mountinfo target is not absolute",
            )
            MountRootCoordinate.parse(mount_root, filesystem_type)
            records.append(
                MountRecord(
                    device_number=fields[2],
                    target=target,
                    optional_fields=tuple(fields[6:separator]),
                    mount_root=mount_root,
                    filesystem_type=filesystem_type,
                )
            )
    return tuple(records)


def namespace_id(path: str = "/proc/self/ns/mnt") -> str:
    value = os.stat(path)
    return f"{value.st_dev}:{value.st_ino}"


def require_private_mount_record(record: MountRecord) -> None:
    propagation = tuple(
        field
        for field in record.optional_fields
        if field.startswith(("shared:", "master:", "propagate_from:"))
    )
    require(not propagation, "mount authority is not private")


def mount_contains_path(record: MountRecord, path: Path) -> bool:
    target = Path(record.target)
    require(target.is_absolute(), "mount target is not absolute")
    try:
        path.relative_to(target)
        return True
    except ValueError:
        return False


def require_private_namespace(expected_device: int, expected_inode: int) -> str:
    expected = f"{expected_device}:{expected_inode}"
    observed = namespace_id()
    require(observed == expected, "helper mount namespace identity differs")
    home_candidates = [
        record
        for record in read_mount_records()
        if mount_contains_path(record, HOME_ROOT)
    ]
    require(home_candidates, "/home mount authority is absent")
    authority = max(home_candidates, key=lambda value: len(value.target))
    require_private_mount_record(authority)
    return observed


def read_namespace_roster_once() -> tuple[NamespaceObservation, ...]:
    own = namespace_id()
    observations: dict[str, NamespaceObservation] = {
        own: NamespaceObservation(own, os.getpid(), read_mount_records())
    }
    try:
        entries = tuple(sorted(os.listdir("/proc")))
    except OSError as error:
        raise RunnerStorageLifecycleError("mount namespace roster is unreadable") from error
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        ns_path = f"/proc/{pid}/ns/mnt"
        mount_path = f"/proc/{pid}/mountinfo"
        try:
            before = namespace_id(ns_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise RunnerStorageLifecycleError(f"namespace unreadable for pid {pid}") from error
        try:
            records = read_mount_records(mount_path)
            after = namespace_id(ns_path)
        except OSError as error:
            raise RunnerStorageLifecycleError(
                f"observed namespace disappeared for pid {pid}"
            ) from error
        require(before == after, f"namespace changed for pid {pid}")
        if before in observations:
            require(
                records == observations[before].records,
                f"mount record view differs across namespace representatives: {before}",
            )
            continue
        observations[before] = NamespaceObservation(before, pid, records)
    return tuple(observations[key] for key in sorted(observations))


def stable_namespace_pair() -> tuple[
    tuple[NamespaceObservation, ...], tuple[NamespaceObservation, ...]
]:
    first = read_namespace_roster_once()
    second = read_namespace_roster_once()
    require(
        tuple(item.namespace_id for item in first)
        == tuple(item.namespace_id for item in second),
        "mount namespace roster changed across proof passes",
    )
    return first, second


def stable_occurrences(
    predicate: Any,
) -> tuple[NamespaceOccurrence, ...]:
    first, second = stable_namespace_pair()

    def project(values: tuple[NamespaceObservation, ...]) -> tuple[NamespaceOccurrence, ...]:
        result = [
            NamespaceOccurrence(
                namespace_id=namespace.namespace_id,
                representative_pid=namespace.representative_pid,
                device_number=record.device_number,
                target=record.target,
                mount_root=record.mount_root,
            )
            for namespace in values
            for record in namespace.records
            if predicate(record)
        ]
        return tuple(
            sorted(
                result,
                key=lambda item: (
                    item.namespace_id,
                    item.device_number,
                    item.mount_root,
                    item.target,
                ),
            )
        )

    first_result = project(first)
    second_result = project(second)
    require(
        tuple(
            (item.namespace_id, item.device_number, item.mount_root, item.target)
            for item in first_result
        )
        == tuple(
            (item.namespace_id, item.device_number, item.mount_root, item.target)
            for item in second_result
        ),
        "mount occurrence roster changed across proof passes",
    )
    return second_result


def path_at_or_below(candidate: Path, root: Path) -> bool:
    require(candidate.is_absolute() and root.is_absolute(), "mount path is not absolute")
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def mount_source_anchors(
    records: tuple[MountRecord, ...],
    path: Path,
) -> tuple[tuple[str, MountRootCoordinate], ...]:
    candidates = [
        record
        for record in records
        if path_at_or_below(path, Path(record.target))
    ]
    require(candidates, "mount backing record is absent")
    deepest = max(len(Path(record.target).parts) for record in candidates)
    base_coordinates = {
        (
            record.device_number,
            record.root_coordinate().translate(path.relative_to(Path(record.target))),
        )
        for record in candidates
        if len(Path(record.target).parts) == deepest
    }
    require(len(base_coordinates) == 1, "mount backing coordinate is ambiguous")
    anchors = set(base_coordinates)
    anchors.update(
        (record.device_number, record.root_coordinate())
        for record in records
        if path_at_or_below(Path(record.target), path)
    )
    return tuple(sorted(anchors, key=lambda value: (value[0], value[1].wire())))


def record_references_path(
    record: MountRecord,
    path: Path,
    source_anchors: tuple[tuple[str, MountRootCoordinate], ...],
) -> bool:
    target = Path(record.target)
    mount_root = record.root_coordinate()
    return path_at_or_below(target, path) or (
        any(
            record.device_number == source_device
            and mount_root.at_or_below(source_prefix)
            for source_device, source_prefix in source_anchors
        )
    )


def path_occurrences(path: Path) -> tuple[NamespaceOccurrence, ...]:
    require(path.is_absolute(), "mount observation path is not absolute")
    own_namespace = namespace_id()
    first, second = stable_namespace_pair()

    def own_observation(
        observations: tuple[NamespaceObservation, ...],
    ) -> NamespaceObservation:
        matches = tuple(
            observation
            for observation in observations
            if observation.namespace_id == own_namespace
        )
        require(len(matches) == 1, "helper mount namespace observation is absent")
        return matches[0]

    first_anchors = mount_source_anchors(own_observation(first).records, path)
    second_anchors = mount_source_anchors(own_observation(second).records, path)
    require(
        first_anchors == second_anchors,
        "mount backing anchors changed across proof passes",
    )

    def project(
        observations: tuple[NamespaceObservation, ...],
        source_anchors: tuple[tuple[str, MountRootCoordinate], ...],
    ) -> tuple[NamespaceOccurrence, ...]:
        result = (
            NamespaceOccurrence(
                namespace_id=observation.namespace_id,
                representative_pid=observation.representative_pid,
                device_number=record.device_number,
                target=record.target,
                mount_root=record.mount_root,
            )
            for observation in observations
            for record in observation.records
            if record_references_path(record, path, source_anchors)
        )
        return tuple(
            sorted(
                result,
                key=lambda item: (
                    item.namespace_id,
                    item.device_number,
                    item.mount_root,
                    item.target,
                ),
            )
        )

    first_result = project(first, first_anchors)
    second_result = project(second, second_anchors)
    require(
        tuple(
            (item.namespace_id, item.device_number, item.mount_root, item.target)
            for item in first_result
        )
        == tuple(
            (item.namespace_id, item.device_number, item.mount_root, item.target)
            for item in second_result
        ),
        "mount occurrence roster changed across proof passes",
    )
    return second_result


def task_runtime_authority_roster() -> tuple[str, ...]:
    authorities: list[str] = []
    for parent, patterns in (
        (RUNTIME_PARENT, (RUNTIME_ROOT_NAME, SOCKET_ROOT_NAME)),
        (Path("/sys/fs/cgroup"), (CGROUP_ROOT_NAME,)),
        (Path("/tmp"), (LEGACY_TMP_RUNTIME_NAME,)),
    ):
        try:
            names = tuple(sorted(os.listdir(parent)))
        except OSError as error:
            raise RunnerStorageLifecycleError(
                f"task runtime authority parent is unreadable: {parent}"
            ) from error
        for name in names:
            if any(pattern.fullmatch(name) is not None for pattern in patterns):
                authorities.append(str(parent / name))
    return tuple(sorted(set(authorities)))


def lifecycle_prefix_state(
    home_fd: int,
    *,
    allow_legacy_empty: bool,
    admit_legacy_authority: bool = False,
) -> LifecyclePrefixState:
    home = os.fstat(home_fd)
    require_root_directory(home, 0o755, "/home authority parent")
    claims = claim_roster(home_fd)
    require(len(claims) <= 1, "runner storage lifecycle claim is ambiguous")
    claim_facts = absent_node()
    expected_claim_name = f"{CLAIM_PREFIX}{'0' * 64}"
    expected_claim_size = 0
    if claims:
        expected_claim_name = claims[0]
        raw, _, _, _ = read_claim_document(home_fd, expected_claim_name)
        expected_claim_size = len(raw)
        claim_stat = lstat_at(home_fd, expected_claim_name)
        require(claim_stat is not None, "runner storage lifecycle claim disappeared")
        assert claim_stat is not None
        claim_facts = facts_from_stat(claim_stat)

    pending_stat = lstat_at(home_fd, CLAIM_PENDING_NAME)
    pending_facts = absent_node() if pending_stat is None else facts_from_stat(pending_stat)
    authority_stat = lstat_at(home_fd, AUTHORITY_NAME)
    authority_facts = (
        absent_node() if authority_stat is None else facts_from_stat(authority_stat)
    )
    authority_empty = True
    authority_fd: int | None = None
    if authority_stat is not None:
        require(
            stat.S_ISDIR(authority_stat.st_mode),
            "runner storage authority root is not a directory",
        )
        authority_fd = os.open(
            AUTHORITY_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=home_fd,
        )
        try:
            require_descriptor_entry(home_fd, AUTHORITY_NAME, authority_fd)
            authority_empty = not os.listdir(authority_fd)
        finally:
            os.close(authority_fd)

    return classify_lifecycle_prefix(
        authority_facts,
        claim_facts,
        claims,
        expected_claim_name,
        home_device=home.st_dev,
        expected_claim_size=expected_claim_size,
        allow_legacy_empty=allow_legacy_empty,
        authority_empty=authority_empty,
        pending=pending_facts,
        admit_legacy_authority=admit_legacy_authority,
    )


def require_pending_runtime_roster(
    state_root: Path,
    *,
    allow_current_runtime: bool,
) -> None:
    roster = set(task_runtime_authority_roster())
    expected = {str(path) for path in runtime_authority_paths(state_root)}
    if allow_current_runtime:
        require(
            bool(roster) and roster <= expected,
            "pending lifecycle claim runtime authority is foreign, legacy, or absent",
        )
        return
    require(not roster, "pending lifecycle claim has a task runtime authority")
    require_runtime_paths_absent(state_root)


def reduce_lifecycle_prefix(
    home_fd: int,
    state_root: Path,
    *,
    allow_current_runtime: bool,
    allow_legacy_empty: bool,
    admit_legacy_authority: bool = False,
) -> LifecyclePrefixState:
    state = lifecycle_prefix_state(
        home_fd,
        allow_legacy_empty=allow_legacy_empty,
        admit_legacy_authority=admit_legacy_authority,
    )
    if state not in ("pending_claim", "pending_legacy_authority"):
        return state
    require_pending_runtime_roster(
        state_root,
        allow_current_runtime=allow_current_runtime,
    )
    require(
        not path_occurrences(AUTHORITY_ROOT),
        "pending lifecycle claim has an observable storage mount",
    )
    try:
        removed = unlink_bound_leaf(
            home_fd,
            CLAIM_PENDING_NAME,
            label="pending lifecycle claim identity differs",
            allowed_kinds=("regular",),
            owner_uid=0,
            owner_gid=0,
            required_mode=0o600,
            minimum_size=0,
            maximum_size=MAX_DOCUMENT_BYTES,
            required_link_count=1,
        )
    except RunnerStorageLifecycleError as error:
        raise RunnerStorageLifecycleError(
            "pending lifecycle claim identity differs"
        ) from error
    require(removed, "pending lifecycle claim disappeared during reduction")
    return lifecycle_prefix_state(
        home_fd,
        allow_legacy_empty=allow_legacy_empty,
        admit_legacy_authority=admit_legacy_authority,
    )


def state_root_is_absent(state_root: Path) -> bool:
    require(state_root.is_absolute(), "STATE_ROOT is not absolute")
    require(str(state_root).startswith(f"{HOME_ROOT}/"), "STATE_ROOT is outside /home")
    require(
        os.path.normpath(str(state_root)) == str(state_root),
        "STATE_ROOT is not lexically canonical",
    )
    try:
        descriptor = open_absolute_directory_no_symlinks(state_root)
    except FileNotFoundError:
        return True
    except OSError as error:
        raise RunnerStorageLifecycleError(
            "STATE_ROOT cannot be proven as a directory or absent"
        ) from error
    os.close(descriptor)
    return False


def reduce_removal_lifecycle_prefix(
    args: argparse.Namespace,
    runtime_lease_fd: int,
) -> bool:
    require_inherited_runtime_lease(runtime_lease_fd, args.state_root)
    home_fd = os.open(HOME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require_root_directory(os.fstat(home_fd), 0o755, "/home authority parent")
        acquire_lifecycle_lock(home_fd, exclusive=True)
        state = reduce_lifecycle_prefix(
            home_fd,
            args.state_root,
            allow_current_runtime=False,
            allow_legacy_empty=True,
        )
        if state != "absent_unclaimed" or not state_root_is_absent(args.state_root):
            return False
        require_pending_runtime_roster(
            args.state_root,
            allow_current_runtime=False,
        )
        require(
            not path_occurrences(AUTHORITY_ROOT),
            "absent lifecycle prefix still has an observable storage mount",
        )
        return True
    finally:
        os.close(home_fd)


def target_occurrences() -> tuple[NamespaceOccurrence, ...]:
    return path_occurrences(AUTHORITY_ROOT / TARGET_NAME)


def loop_device_number(loop_device: str) -> str:
    require(LOOP_DEVICE.fullmatch(loop_device) is not None, "loop device is invalid")
    value = os.stat(loop_device)
    require(stat.S_ISBLK(value.st_mode), "loop device is not a block device")
    return f"{os.major(value.st_rdev)}:{os.minor(value.st_rdev)}"


def loop_occurrences(loop_device: str) -> tuple[NamespaceOccurrence, ...]:
    device = loop_device_number(loop_device)
    return stable_occurrences(lambda record: record.device_number == device)


def associated_loops(context: AuthorityContext) -> tuple[str, ...]:
    require(context.image_fd is not None, "image descriptor is absent")
    handle = f"/proc/self/fd/{context.image_fd}"
    output = run_tool(
        context,
        "losetup",
        "--json",
        "--output",
        "NAME,BACK-FILE",
        "--associated",
        handle,
        pass_fds=(context.image_fd,),
    )
    parsed = json.loads(output or '{"loopdevices":[]}')
    devices = parsed.get("loopdevices")
    require(isinstance(devices, list), "loop observation is invalid")
    image_stat = os.fstat(context.image_fd)
    loops: list[str] = []
    for item in devices:
        require(isinstance(item, dict), "loop record is invalid")
        name = item.get("name")
        backing = item.get("back-file")
        require(isinstance(name, str) and LOOP_DEVICE.fullmatch(name), "loop name is invalid")
        require(isinstance(backing, str), "loop backing is invalid")
        backing_stat = os.stat(backing)
        require(
            (backing_stat.st_dev, backing_stat.st_ino)
            == (image_stat.st_dev, image_stat.st_ino),
            "loop backing differs from image descriptor",
        )
        loops.append(name)
    require(len(set(loops)) == len(loops), "loop observation is duplicated")
    return tuple(sorted(loops))


def attach_image(context: AuthorityContext) -> str:
    loops = associated_loops(context)
    require(len(loops) <= 1, "image has multiple loop devices")
    if loops:
        return loops[0]
    require(context.image_fd is not None, "image descriptor is absent")
    handle = f"/proc/self/fd/{context.image_fd}"
    loop = run_tool(
        context,
        "losetup",
        "--find",
        "--show",
        "--nooverlap",
        handle,
        mutation=True,
        pass_fds=(context.image_fd,),
    )
    require(LOOP_DEVICE.fullmatch(loop) is not None, "loop attachment is invalid")
    require(associated_loops(context) == (loop,), "loop attachment is ambiguous")
    return loop


def filesystem_uuid(context: AuthorityContext, loop_device: str) -> str:
    filesystem_type = run_tool(context, "blkid", "-s", "TYPE", "-o", "value", loop_device)
    value = run_tool(context, "blkid", "-s", "UUID", "-o", "value", loop_device)
    require(filesystem_type == "xfs", "runner image is not XFS")
    require(FILESYSTEM_UUID.fullmatch(value) is not None, "XFS UUID is invalid")
    return value


def create_image(context: AuthorityContext) -> None:
    require(context.root_fd is not None and context.image_fd is None, "image already exists")
    context.image_fd = os.open(
        IMAGE_NAME,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=context.root_fd,
    )
    os.fchown(context.image_fd, 0, 0)
    os.fchmod(context.image_fd, 0o600)
    os.ftruncate(context.image_fd, IMAGE_BYTES)
    os.fsync(context.image_fd)
    require_descriptor_entry(context.root_fd, IMAGE_NAME, context.image_fd)
    handle = f"/proc/self/fd/{context.image_fd}"
    run_tool(
        context,
        "mkfs.xfs",
        "-q",
        "-m",
        "crc=1,finobt=1",
        "-n",
        "ftype=1",
        "--",
        handle,
        mutation=True,
        pass_fds=(context.image_fd,),
    )
    os.fsync(context.image_fd)
    os.fsync(context.root_fd)
    context.image_state = "root_0600_exact"


def mount_image(context: AuthorityContext, loop_device: str, expected_namespace: str) -> None:
    require(context.target_fd is not None, "mount target descriptor is absent")
    require(not target_occurrences(), "runner target is already mounted")
    require(not loop_occurrences(loop_device), "runner loop is already mounted")
    require(not os.listdir(context.target_fd), "underlying mount target is not empty")
    handle = f"/proc/self/fd/{context.target_fd}"
    run_tool(
        context,
        "mount",
        "-t",
        "xfs",
        "-o",
        "rw,pquota,nosuid,nodev",
        "--",
        loop_device,
        handle,
        mutation=True,
        pass_fds=(context.target_fd,),
    )
    os.chown(AUTHORITY_ROOT / TARGET_NAME, 0, 0, follow_symlinks=False)
    os.chmod(AUTHORITY_ROOT / TARGET_NAME, 0o700, follow_symlinks=False)
    loop_mounts = loop_occurrences(loop_device)
    target_mounts = target_occurrences()
    require(
        len(loop_mounts) == 1
        and loop_mounts[0].namespace_id == expected_namespace
        and loop_mounts[0].target == str(AUTHORITY_ROOT / TARGET_NAME),
        "loop mounted outside the private authority namespace",
    )
    require(
        len(target_mounts) == 1
        and target_mounts[0].namespace_id == expected_namespace
        and target_mounts[0].device_number == loop_device_number(loop_device),
        "target mount differs from loop authority",
    )


def ensure_runner_data_root(context: AuthorityContext, loop_device: str) -> Path:
    mounted_fd = os.open(
        AUTHORITY_ROOT / TARGET_NAME,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        mounted = os.fstat(mounted_fd)
        require(
            (os.major(mounted.st_dev), os.minor(mounted.st_dev))
            == tuple(int(value) for value in loop_device_number(loop_device).split(":")),
            "runner data parent differs from loop device",
        )
        try:
            os.mkdir(RUNNER_DATA_NAME, 0o700, dir_fd=mounted_fd)
        except FileExistsError:
            pass
        data_fd = os.open(
            RUNNER_DATA_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=mounted_fd,
        )
        try:
            value = os.fstat(data_fd)
            require(
                value.st_uid == 0
                and value.st_gid == 0
                and stat.S_IMODE(value.st_mode) == 0o700
                and value.st_dev == mounted.st_dev,
                "inner runner data-root authority differs",
            )
            os.fsync(data_fd)
        finally:
            os.close(data_fd)
        os.fsync(mounted_fd)
    finally:
        os.close(mounted_fd)
    return AUTHORITY_ROOT / TARGET_NAME / RUNNER_DATA_NAME


def unmount_and_detach(context: AuthorityContext, loop_device: str, expected_namespace: str) -> None:
    loop_mounts = loop_occurrences(loop_device)
    target_mounts = target_occurrences()
    if loop_mounts:
        require(
            len(loop_mounts) == 1
            and loop_mounts[0].namespace_id == expected_namespace
            and loop_mounts[0].target == str(AUTHORITY_ROOT / TARGET_NAME),
            "loop has a foreign namespace mount",
        )
        require(
            len(target_mounts) == 1
            and target_mounts[0].namespace_id == expected_namespace
            and target_mounts[0].device_number == loop_device_number(loop_device),
            "target has a nested or foreign mount",
        )
        if context.target_fd is not None:
            os.close(context.target_fd)
            context.target_fd = None
        run_tool(context, "umount", "--", loop_device, mutation=True)
        require(not loop_occurrences(loop_device), "loop remained mounted")
        require(not target_occurrences(), "target remained mounted")
    else:
        require(not target_mounts, "target has a foreign mount")
    require(not loop_occurrences(loop_device), "loop remains mounted before detach")
    run_tool(context, "losetup", "--detach", loop_device, mutation=True)
    require(not associated_loops(context), "loop remained attached")


def read_exact_file(path: Path, expected_sha256: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        identity = os.fstat(descriptor)
        require(stat.S_ISREG(identity.st_mode), f"verified source is not regular: {path.name}")
        require(0 < identity.st_size <= MAX_DOCUMENT_BYTES, "verified source size is invalid")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(descriptor)
    value = b"".join(chunks)
    require(
        hmac.compare_digest(hashlib.sha256(value).hexdigest(), expected_sha256),
        f"verified source digest differs: {path.name}",
    )
    return value


def load_identity_verifier() -> dict[str, Any]:
    path = Path(__file__).with_name(IDENTITY_VERIFIER_NAME)
    source = read_exact_file(path, IDENTITY_VERIFIER_SHA256)
    namespace: dict[str, Any] = {
        "__name__": "ambit_runner_storage_identity_verifier",
        "__file__": str(path),
        "__package__": None,
    }
    exec(compile(source, str(path), "exec"), namespace, namespace)
    return namespace


def current_receipt(
    context: AuthorityContext,
    lifecycle_state: str,
) -> dict[str, Any]:
    require_context_binding(context)
    require(
        context.state_fd is not None and context.evidence_fd is not None,
        "caller identity descriptors are absent",
    )
    verifier = load_identity_verifier()
    observation = verifier["collect_storage_observation"](
        context.state_identity.path,
        authority_root=AUTHORITY_ROOT,
        observer_uid=context.caller_uid,
        observer_gid=context.caller_gid,
        state_root_fd=context.state_fd,
        evidence_fd=context.evidence_fd,
        authority_fd=context.root_fd,
        image_fd=context.image_fd,
    )
    receipt = verifier["validate_storage_identity_observation"](observation)
    receipt["lifecycleState"] = lifecycle_state
    validate_receipt(receipt, context, require_live_inner=True)
    return receipt


def read_json_at(directory_fd: int, name: str) -> dict[str, Any] | None:
    value = lstat_at(directory_fd, name)
    if value is None:
        return None
    require(
        stat.S_ISREG(value.st_mode)
        and value.st_uid == 0
        and value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o600
        and value.st_dev == os.fstat(directory_fd).st_dev
        and value.st_nlink == 1
        and 0 < value.st_size <= MAX_DOCUMENT_BYTES,
        f"authority JSON identity differs: {name}",
    )
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        require_descriptor_entry(directory_fd, name, descriptor)
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= MAX_DOCUMENT_BYTES, f"authority JSON is too large: {name}")
            chunks.append(block)
    finally:
        os.close(descriptor)
    source = b"".join(chunks)
    parsed = json.loads(source)
    require(isinstance(parsed, dict), f"authority JSON is not an object: {name}")
    require(
        hmac.compare_digest(source, canonical_json_bytes(parsed)),
        f"authority JSON is not canonical: {name}",
    )
    return parsed


def reconcile_receipt_pending(context: AuthorityContext) -> None:
    require_context_binding(context)
    require(context.root_fd is not None, "authority descriptor is absent")
    if lstat_at(context.root_fd, RECEIPT_PENDING_NAME) is None:
        return
    if lstat_at(context.root_fd, RECEIPT_NAME) is not None:
        remove_admitted_pending(
            context.root_fd,
            RECEIPT_PENDING_NAME,
            owner_uid=0,
            owner_gid=0,
        )
        return
    try:
        pending = read_json_at(context.root_fd, RECEIPT_PENDING_NAME)
    except (RunnerStorageLifecycleError, json.JSONDecodeError, UnicodeDecodeError):
        remove_admitted_pending(
            context.root_fd,
            RECEIPT_PENDING_NAME,
            owner_uid=0,
            owner_gid=0,
        )
        return
    require(pending is not None, "pending storage receipt disappeared")
    validate_receipt(pending, context)
    pending_fd = os.open(
        RECEIPT_PENDING_NAME,
        os.O_RDONLY | os.O_NOFOLLOW,
        dir_fd=context.root_fd,
    )
    try:
        require_descriptor_entry(context.root_fd, RECEIPT_PENDING_NAME, pending_fd)
        os.fsync(pending_fd)
    finally:
        os.close(pending_fd)
    os.replace(
        RECEIPT_PENDING_NAME,
        RECEIPT_NAME,
        src_dir_fd=context.root_fd,
        dst_dir_fd=context.root_fd,
    )
    os.fsync(context.root_fd)


def write_bytes_atomic(
    directory_fd: int,
    final_name: str,
    value: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    require(len(value) <= MAX_DOCUMENT_BYTES, "receipt output is too large")
    pending_names = {
        RECEIPT_NAME: RECEIPT_PENDING_NAME,
        USER_PROJECTION_NAME: PROJECTION_PENDING_NAME,
    }
    require(final_name in pending_names, "receipt destination is not admitted")
    temporary = pending_names[final_name]
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        os.fchown(descriptor, owner_uid, owner_gid)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(value):
            offset += os.write(descriptor, value[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(
            temporary,
            final_name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except OSError:
            pass
        raise


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def publish_user_projection(
    context: AuthorityContext,
    receipt: dict[str, Any],
    digest: str,
) -> dict[str, Any]:
    require_context_binding(context)
    require(context.evidence_fd is not None, "projection authority descriptor is absent")
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "receipt digest is invalid")
    projection = {
        "schema": PROJECTION_SCHEMA,
        "authorityReceiptSha256": digest,
        "receipt": receipt,
    }
    write_bytes_atomic(
        context.evidence_fd,
        USER_PROJECTION_NAME,
        canonical_json_bytes(projection),
        owner_uid=context.caller_uid,
        owner_gid=context.caller_gid,
    )
    return projection


def publish_receipt(
    context: AuthorityContext,
    receipt: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    require_context_binding(context)
    require(
        context.root_fd is not None and context.evidence_fd is not None,
        "receipt authority descriptors are absent",
    )
    receipt_bytes = canonical_json_bytes(receipt)
    write_bytes_atomic(context.root_fd, RECEIPT_NAME, receipt_bytes, owner_uid=0, owner_gid=0)
    digest = sha256_bytes(receipt_bytes)
    projection = publish_user_projection(context, receipt, digest)
    return digest, projection


def remove_user_projection(context: AuthorityContext) -> None:
    require_context_binding(context)
    directory_fd = user_projection_directory_fd(context)
    if directory_fd is None:
        return
    remove_admitted_pending(
        directory_fd,
        PROJECTION_PENDING_NAME,
        owner_uid=context.caller_uid,
        owner_gid=context.caller_gid,
    )
    try:
        unlink_bound_leaf(
            directory_fd,
            USER_PROJECTION_NAME,
            label="user storage projection identity differs",
            allowed_kinds=("regular",),
            owner_uid=context.caller_uid,
            owner_gid=context.caller_gid,
            required_mode=0o600,
            minimum_size=1,
            maximum_size=MAX_DOCUMENT_BYTES,
            required_link_count=1,
        )
    except RunnerStorageLifecycleError as error:
        raise RunnerStorageLifecycleError(
            "user storage projection identity differs"
        ) from error


def require_exact_identity_document(
    value: object,
    expected: dict[str, Any],
    label: str,
) -> None:
    require(isinstance(value, dict), f"{label} is absent")
    assert isinstance(value, dict)
    require(set(value) == set(expected), f"{label} shape differs")
    require(isinstance(value.get("path"), str), f"{label} path is invalid")
    for field in ("device", "inode", "ownerUid", "ownerGid"):
        require(plain_int(value.get(field)), f"{label} coordinate is invalid: {field}")
    require(isinstance(value.get("mode"), str), f"{label} mode is invalid")
    require(value == expected, f"{label} differs")


def validate_receipt(
    receipt: dict[str, Any],
    context: AuthorityContext,
    *,
    require_live_inner: bool = False,
) -> str:
    require(receipt.get("schema") == RECEIPT_SCHEMA, "storage receipt version is unsupported")
    require_context_binding(context)
    require(
        set(receipt)
        == {
            "schema",
            "lifecycleState",
            "stateRoot",
            "authorityClaimSha256",
            "caller",
            "stateRootIdentity",
            "evidenceDirectoryIdentity",
            "authorityRoot",
            "mountTarget",
            "innerRunnerDataRoot",
            "image",
            "loop",
            "filesystem",
            "mountNamespace",
            "backingFilesystem",
            "sandboxDiskPolicy",
        },
        "storage receipt shape differs",
    )
    require(
        receipt.get("lifecycleState") in ("attached", "detached"),
        "storage receipt lifecycle state is invalid",
    )
    require(
        receipt.get("stateRoot") == str(context.state_identity.path),
        "storage receipt state root differs",
    )
    require(
        context.claim_present
        and isinstance(receipt.get("authorityClaimSha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", receipt["authorityClaimSha256"])
        and receipt["authorityClaimSha256"]
        == context.claim_name.removeprefix(CLAIM_PREFIX),
        "storage receipt lifecycle claim differs",
    )
    caller = receipt.get("caller")
    require(
        isinstance(caller, dict)
        and set(caller) == {"uid", "gid"}
        and plain_int(caller.get("uid"))
        and plain_int(caller.get("gid"))
        and caller == {"uid": context.caller_uid, "gid": context.caller_gid},
        "storage receipt caller differs",
    )
    require_exact_identity_document(
        receipt.get("stateRootIdentity"),
        context.state_identity.document(),
        "storage receipt state-root identity",
    )
    require_exact_identity_document(
        receipt.get("evidenceDirectoryIdentity"),
        context.evidence_identity.document(),
        "storage receipt evidence identity",
    )
    authority = receipt.get("authorityRoot")
    image = receipt.get("image")
    filesystem = receipt.get("filesystem")
    mount_target = receipt.get("mountTarget")
    inner = receipt.get("innerRunnerDataRoot")
    require(isinstance(authority, dict), "storage receipt authority root is absent")
    require(isinstance(image, dict), "storage receipt image is absent")
    require(isinstance(filesystem, dict), "storage receipt filesystem is absent")
    require(isinstance(mount_target, dict), "storage receipt mount target is absent")
    require(isinstance(inner, dict), "storage receipt inner data root is absent")
    require(context.root_fd is not None and context.image_fd is not None, "storage objects are absent")
    root_stat = os.fstat(context.root_fd)
    image_stat = os.fstat(context.image_fd)
    require(
        set(authority) == {"path", "device", "inode", "ownerUid", "ownerGid", "mode"}
        and authority.get("path") == str(AUTHORITY_ROOT)
        and all(
            plain_int(authority.get(field))
            for field in ("device", "inode", "ownerUid", "ownerGid")
        )
        and authority.get("device") == root_stat.st_dev
        and authority.get("inode") == root_stat.st_ino
        and authority.get("ownerUid") == 0
        and authority.get("ownerGid") == 0
        and authority.get("mode") == "0700",
        "storage receipt authority identity differs",
    )
    require(
        set(image)
        == {
            "path",
            "logicalBytes",
            "allocatedBytes",
            "device",
            "inode",
            "ownerUid",
            "ownerGid",
            "mode",
        }
        and image.get("path") == str(AUTHORITY_ROOT / IMAGE_NAME)
        and all(
            plain_int(image.get(field))
            for field in (
                "logicalBytes",
                "allocatedBytes",
                "device",
                "inode",
                "ownerUid",
                "ownerGid",
            )
        )
        and image.get("device") == image_stat.st_dev
        and image.get("inode") == image_stat.st_ino
        and image_stat.st_uid == 0
        and image_stat.st_gid == 0
        and stat.S_IMODE(image_stat.st_mode) == 0o600
        and image_stat.st_nlink == 1
        and image_stat.st_size == IMAGE_BYTES
        and image.get("logicalBytes") == IMAGE_BYTES
        and image.get("ownerUid") == 0
        and image.get("ownerGid") == 0
        and image.get("mode") == "0600",
        "storage receipt image identity differs",
    )
    require(
        set(mount_target) == {"path", "device", "inode", "ownerUid", "ownerGid", "mode"}
        and mount_target.get("path") == str(AUTHORITY_ROOT / TARGET_NAME)
        and plain_int(mount_target.get("device"))
        and mount_target["device"] >= 0
        and plain_int(mount_target.get("inode"))
        and mount_target["inode"] > 0
        and mount_target.get("ownerUid") == 0
        and mount_target.get("ownerGid") == 0
        and plain_int(mount_target.get("ownerUid"))
        and plain_int(mount_target.get("ownerGid"))
        and mount_target.get("mode") == "0700",
        "storage receipt mount-target identity differs",
    )
    require(
        set(inner) == {"path", "device", "inode", "ownerUid", "ownerGid", "mode"}
        and inner.get("path") == str(AUTHORITY_ROOT / TARGET_NAME / RUNNER_DATA_NAME)
        and plain_int(inner.get("device"))
        and inner["device"] >= 0
        and plain_int(inner.get("inode"))
        and inner["inode"] > 0
        and inner.get("ownerUid") == 0
        and inner.get("ownerGid") == 0
        and plain_int(inner.get("ownerUid"))
        and plain_int(inner.get("ownerGid"))
        and inner.get("mode") == "0700"
        and inner.get("device") == mount_target.get("device"),
        "storage receipt inner data-root identity differs",
    )
    if require_live_inner:
        inner_path = AUTHORITY_ROOT / TARGET_NAME / RUNNER_DATA_NAME
        live = os.stat(inner_path, follow_symlinks=False)
        require(
            stat.S_ISDIR(live.st_mode)
            and (
                live.st_dev,
                live.st_ino,
                live.st_uid,
                live.st_gid,
                f"{stat.S_IMODE(live.st_mode):04o}",
            )
            == (
                inner["device"],
                inner["inode"],
                inner["ownerUid"],
                inner["ownerGid"],
                inner["mode"],
            ),
            "live inner runner data-root identity differs",
        )
    value = filesystem.get("uuid")
    require(isinstance(value, str) and FILESYSTEM_UUID.fullmatch(value), "receipt UUID is invalid")
    return value


def operation_result(
    outcome: str,
    namespace: str | None,
    digest: str | None,
    receipt: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema": OPERATION_SCHEMA,
        "outcome": outcome,
        "authorityRoot": str(AUTHORITY_ROOT),
        "mountTarget": str(AUTHORITY_ROOT / TARGET_NAME),
        "mountNamespace": namespace,
        "authorityReceiptSha256": digest,
        "receipt": receipt,
    }


def prepare_supervisor_storage_mutation(args: argparse.Namespace) -> None:
    require_inherited_runtime_lease(args.runtime_lease_fd, args.state_root)
    home_fd = os.open(HOME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require_root_directory(os.fstat(home_fd), 0o755, "/home authority parent")
        acquire_lifecycle_lock(home_fd, exclusive=True)
        reduce_lifecycle_prefix(
            home_fd,
            args.state_root,
            allow_current_runtime=True,
            allow_legacy_empty=False,
        )
    finally:
        os.close(home_fd)


def activate_private(args: argparse.Namespace) -> dict[str, Any]:
    prepare_supervisor_storage_mutation(args)
    with open_authority(
        state_root=args.state_root,
        caller_uid=args.caller_uid,
        caller_gid=args.caller_gid,
        create=True,
        exclusive=True,
        required_tools=(
            "blkid",
            "findmnt",
            "losetup",
            "mkfs.xfs",
            "mount",
            "python",
            "umount",
            "xfs_info",
        ),
    ) as context:
        expected_namespace = require_private_namespace(
            args.namespace_device, args.namespace_inode
        )
        require_context_binding(context)
        require(context.target_fd is not None, "storage target is absent")
        stored = read_json_at(context.root_fd, RECEIPT_NAME) if context.root_fd else None
        disposition = prepare_disposition(context.image_state, stored is not None)
        if disposition == "teardown_required":
            raise RunnerStorageLifecycleError(
                "storage prefix requires explicit remove before activation"
            )
        if disposition == "create":
            create_image(context)
        else:
            require(stored is not None, "storage receipt is absent")
            expected_uuid = validate_receipt(stored, context)
        loop = attach_image(context)
        observed_uuid = filesystem_uuid(context, loop)
        if disposition == "recover":
            require(observed_uuid == expected_uuid, "storage UUID changed across recovery")
        mounts = target_occurrences()
        if mounts:
            require(
                len(mounts) == 1
                and mounts[0].namespace_id == expected_namespace
                and mounts[0].device_number == loop_device_number(loop),
                "storage target is mounted outside expected namespace",
            )
        else:
            mount_image(context, loop, expected_namespace)
        os.chown(AUTHORITY_ROOT / TARGET_NAME, 0, 0, follow_symlinks=False)
        os.chmod(AUTHORITY_ROOT / TARGET_NAME, 0o700, follow_symlinks=False)
        ensure_runner_data_root(context, loop)
        receipt = current_receipt(context, "attached")
        digest, _ = publish_receipt(context, receipt)
        return operation_result("activated", expected_namespace, digest, receipt)


def deactivate_private(args: argparse.Namespace) -> dict[str, Any]:
    prepare_supervisor_storage_mutation(args)
    with open_authority(
        state_root=args.state_root,
        caller_uid=args.caller_uid,
        caller_gid=args.caller_gid,
        create=False,
        exclusive=True,
        required_tools=("blkid", "losetup", "python", "umount"),
    ) as context:
        expected_namespace = require_private_namespace(
            args.namespace_device, args.namespace_inode
        )
        require_context_binding(context)
        if context.root_fd is None:
            require(
                not path_occurrences(AUTHORITY_ROOT),
                "absent authority still has an observable mount",
            )
            return operation_result("deactivated", expected_namespace, None, None)
        stored = read_json_at(context.root_fd, RECEIPT_NAME)
        if stored is None:
            loops = associated_loops(context) if context.image_fd is not None else ()
            require(len(loops) <= 1, "storage loop identity is ambiguous")
            if loops:
                unmount_and_detach(context, loops[0], expected_namespace)
            else:
                require(
                    not target_occurrences(),
                    "unpublished storage target remains mounted without its loop",
                )
            return operation_result(
                "deactivated",
                expected_namespace,
                None,
                None,
            )
        require(context.image_fd is not None, "published storage image is absent")
        expected_uuid = validate_receipt(stored, context)
        loops = associated_loops(context)
        require(len(loops) <= 1, "storage loop identity is ambiguous")
        targets = target_occurrences()
        if stored.get("lifecycleState") == "detached":
            require(not loops, "detached storage receipt retains an image loop")
            require(not targets, "detached storage receipt retains a target mount")
            digest = sha256_bytes(canonical_json_bytes(stored))
            publish_user_projection(context, stored, digest)
            return operation_result("deactivated", expected_namespace, digest, stored)
        if loops:
            loop = loops[0]
            require(filesystem_uuid(context, loop) == expected_uuid, "storage UUID differs")
            unmount_and_detach(context, loop, expected_namespace)
        else:
            require(
                not targets,
                "storage target remains mounted without its image loop",
            )
        detached = dict(stored)
        detached["lifecycleState"] = "detached"
        detached["mountNamespace"] = {
            "device": args.namespace_device,
            "inode": args.namespace_inode,
        }
        detached["loop"] = None
        digest, _ = publish_receipt(context, detached)
        return operation_result("deactivated", expected_namespace, digest, detached)


def observe_private(args: argparse.Namespace) -> dict[str, Any]:
    with open_authority(
        state_root=args.state_root,
        caller_uid=args.caller_uid,
        caller_gid=args.caller_gid,
        create=False,
        exclusive=False,
        required_tools=("blkid", "findmnt", "losetup", "xfs_info"),
    ) as context:
        expected_namespace = require_private_namespace(
            args.namespace_device, args.namespace_inode
        )
        require_context_binding(context)
        require(context.root_fd is not None and context.image_fd is not None, "storage is absent")
        stored = read_json_at(context.root_fd, RECEIPT_NAME)
        require(stored is not None, "storage receipt is absent")
        expected_uuid = validate_receipt(stored, context, require_live_inner=True)
        current = current_receipt(context, "attached")
        require(
            current["filesystem"]["uuid"] == expected_uuid,
            "current storage UUID differs from receipt",
        )
        receipt_bytes = canonical_json_bytes(stored)
        digest = sha256_bytes(receipt_bytes)
        return operation_result("observed", expected_namespace, digest, current)


def _remove_authority_locked(args: argparse.Namespace) -> dict[str, Any]:
    with open_authority(
        state_root=args.state_root,
        caller_uid=args.caller_uid,
        caller_gid=args.caller_gid,
        create=False,
        exclusive=True,
        allow_legacy_empty=True,
        allow_orphaned_binding=True,
        required_tools=("losetup", "python"),
    ) as context:
        require_context_binding(context)
        require_runtime_absent(context)
        if context.root_fd is None:
            require(
                not path_occurrences(AUTHORITY_ROOT),
                "absent authority still has an observable mount",
            )
            remove_user_projection(context)
            if context.claim_present:
                require(context.home_fd is not None, "lifecycle lock descriptor is absent")
                require_context_binding(context)
                removed = unlink_bound_leaf(
                    context.home_fd,
                    context.claim_name,
                    label="runner storage lifecycle claim identity differs",
                    allowed_kinds=("regular",),
                    owner_uid=0,
                    owner_gid=0,
                    required_mode=0o600,
                    minimum_size=len(context.claim_bytes),
                    maximum_size=len(context.claim_bytes),
                    required_link_count=1,
                )
                require(removed, "runner storage lifecycle claim disappeared")
                context.claim_present = False
                require_context_binding(context)
            return operation_result("removed", None, None, None)
        if context.legacy_unclaimed:
            require(
                not path_occurrences(AUTHORITY_ROOT),
                "unclaimed legacy authority remains globally observable",
            )
            require(not os.listdir(context.root_fd), "unclaimed legacy authority is not empty")
            remove_user_projection(context)
            require(context.home_fd is not None, "lifecycle lock descriptor is absent")
            require_descriptor_entry(context.home_fd, AUTHORITY_NAME, context.root_fd)
            os.rmdir(AUTHORITY_NAME, dir_fd=context.home_fd)
            os.fsync(context.home_fd)
            os.close(context.root_fd)
            context.root_fd = None
            return operation_result("removed", None, None, None)
        stored = read_json_at(context.root_fd, RECEIPT_NAME)
        if stored is not None:
            validate_receipt(stored, context)
        require(
            not target_occurrences(),
            "storage target remains mounted in a namespace",
        )
        require(context.root_fd is not None, "authority descriptor is absent")
        if context.image_fd is not None:
            loops = associated_loops(context)
            require(len(loops) <= 1, "image has multiple loop devices")
            if loops:
                require(not loop_occurrences(loops[0]), "loop remains mounted")
                run_tool(context, "losetup", "--detach", loops[0], mutation=True)
                require(not associated_loops(context), "loop remained attached")
        remove_user_projection(context)
        receipt_stat = lstat_at(context.root_fd, RECEIPT_NAME)
        if receipt_stat is not None:
            removed = unlink_bound_leaf(
                context.root_fd,
                RECEIPT_NAME,
                label="authority receipt identity differs",
                allowed_kinds=("regular",),
                owner_uid=0,
                owner_gid=0,
                required_mode=0o600,
                minimum_size=1,
                maximum_size=MAX_DOCUMENT_BYTES,
                required_link_count=1,
                expected_identity=(receipt_stat.st_dev, receipt_stat.st_ino),
            )
            require(removed, "authority receipt disappeared")
        if context.image_fd is not None:
            image_stat = os.fstat(context.image_fd)
            removed = unlink_bound_leaf(
                context.root_fd,
                IMAGE_NAME,
                label="runner image identity differs",
                allowed_kinds=("regular",),
                owner_uid=0,
                owner_gid=0,
                required_mode=0o600,
                minimum_size=0,
                maximum_size=IMAGE_BYTES,
                required_link_count=1,
                expected_identity=(image_stat.st_dev, image_stat.st_ino),
            )
            require(removed, "runner image disappeared")
            os.close(context.image_fd)
            context.image_fd = None
        require(not target_occurrences(), "target mount appeared during removal")
        if context.target_fd is not None:
            require(not os.listdir(context.target_fd), "underlying target is not empty")
            require_descriptor_entry(context.root_fd, TARGET_NAME, context.target_fd)
            os.rmdir(TARGET_NAME, dir_fd=context.root_fd)
            os.fsync(context.root_fd)
            os.close(context.target_fd)
            context.target_fd = None
        for name in (OUTER_DOCKER_NAME, OUTER_CONTAINERD_NAME):
            path = AUTHORITY_ROOT / name
            value = lstat_at(context.root_fd, name)
            if value is not None:
                require(stat.S_ISDIR(value.st_mode), f"outer daemon root is not a directory: {name}")
                require(
                    not path_occurrences(path),
                    f"outer daemon root retains a mount: {name}",
                )
                remove_tree_descriptor_relative(context.root_fd, name)
        remaining = tuple(sorted(os.listdir(context.root_fd)))
        require(not remaining, "authority root contains residual entries")
        require(context.home_fd is not None, "lifecycle lock descriptor is absent")
        require_descriptor_entry(context.home_fd, AUTHORITY_NAME, context.root_fd)
        os.rmdir(AUTHORITY_NAME, dir_fd=context.home_fd)
        os.fsync(context.home_fd)
        os.close(context.root_fd)
        context.root_fd = None
        require_context_binding(context)
        removed = unlink_bound_leaf(
            context.home_fd,
            context.claim_name,
            label="runner storage lifecycle claim identity differs",
            allowed_kinds=("regular",),
            owner_uid=0,
            owner_gid=0,
            required_mode=0o600,
            minimum_size=len(context.claim_bytes),
            maximum_size=len(context.claim_bytes),
            required_link_count=1,
        )
        require(removed, "runner storage lifecycle claim disappeared")
        context.claim_present = False
        require_context_binding(context)
    return operation_result("removed", None, None, None)


def remove_authority(args: argparse.Namespace) -> dict[str, Any]:
    # The one global runtime lease is acquired before the total prefix
    # classifier and the storage helper's `/home` flock.  A new start cannot
    # appear between response-loss proof and destructive reduction.
    with acquire_runtime_deletion_lease(args.state_root) as lease:
        if reduce_removal_lifecycle_prefix(args, lease.descriptor):
            return operation_result("removed", None, None, None)
        return _remove_authority_locked(args)


def validate_legacy_v2_removal_receipt(
    receipt: dict[str, Any],
    *,
    state_identity: DirectoryIdentity,
    root_stat: os.stat_result,
    image_stat: os.stat_result,
) -> None:
    require(
        receipt.get("schema") == LEGACY_RECEIPT_SCHEMA,
        "legacy removal receipt schema differs",
    )
    require(receipt.get("stateRoot") == str(state_identity.path), "legacy state path differs")
    stored_state = receipt.get("stateRootIdentity")
    require(
        isinstance(stored_state, dict)
        and stored_state
        == {
            "device": state_identity.device,
            "inode": state_identity.inode,
            "ownerUid": state_identity.owner_uid,
            "ownerGid": state_identity.owner_gid,
            "mode": f"{state_identity.mode:04o}",
        },
        "legacy state identity differs",
    )
    authority = receipt.get("authorityRoot")
    image = receipt.get("image")
    filesystem = receipt.get("filesystem")
    require(
        isinstance(authority, dict)
        and authority.get("path") == str(AUTHORITY_ROOT)
        and authority.get("device") == root_stat.st_dev
        and authority.get("inode") == root_stat.st_ino,
        "legacy authority identity differs",
    )
    require(
        isinstance(image, dict)
        and image.get("path") == str(AUTHORITY_ROOT / IMAGE_NAME)
        and image.get("device") == image_stat.st_dev
        and image.get("inode") == image_stat.st_ino
        and image.get("logicalBytes") == IMAGE_BYTES,
        "legacy image identity differs",
    )
    require(
        isinstance(filesystem, dict)
        and isinstance(filesystem.get("uuid"), str)
        and FILESYSTEM_UUID.fullmatch(filesystem["uuid"]) is not None,
        "legacy filesystem identity differs",
    )


def remove_legacy_atomic_temporaries(
    directory_fd: int,
    pattern: re.Pattern[str],
    *,
    owner_uid: int,
    owner_gid: int,
    label: str,
) -> None:
    names = tuple(
        sorted(
            name
            for name in os.listdir(directory_fd)
            if pattern.fullmatch(name) is not None
        )
    )
    for name in names:
        try:
            removed = unlink_bound_leaf(
                directory_fd,
                name,
                label=f"legacy {label} temporary identity differs",
                allowed_kinds=("regular",),
                owner_uid=owner_uid,
                owner_gid=owner_gid,
                required_mode=0o600,
                minimum_size=0,
                maximum_size=MAX_DOCUMENT_BYTES,
                required_link_count=1,
            )
        except RunnerStorageLifecycleError as error:
            raise RunnerStorageLifecycleError(
                f"legacy {label} temporary identity differs"
            ) from error
        require(removed, f"legacy {label} temporary disappeared")


LegacyRemovalRoute = Literal["removed", "migrate", "ordinary"]


def classify_legacy_v2_removal_route(
    state: LifecyclePrefixState,
    *,
    state_root_absent: bool,
    authority_roster: tuple[str, ...] = (),
    receipt_schema: object = None,
) -> LegacyRemovalRoute:
    require(
        state != "pending_claim",
        "legacy prepublication pending claim is unsupported",
    )
    if state == "absent_unclaimed" and state_root_absent:
        return "removed"
    if state in ("pending_legacy_authority", "legacy_authority"):
        return "migrate"
    if state == "claimed_authority" and (
        LEGACY_LOCK_NAME in authority_roster
        or any(
            LEGACY_RECEIPT_TEMP_NAME.fullmatch(name) is not None
            for name in authority_roster
        )
        or receipt_schema == LEGACY_RECEIPT_SCHEMA
    ):
        return "migrate"
    return "ordinary"


def legacy_v2_removal_route(
    args: argparse.Namespace,
    runtime_lease_fd: int,
) -> LegacyRemovalRoute:
    require_inherited_runtime_lease(runtime_lease_fd, args.state_root)
    home_fd = os.open(HOME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_fd: int | None = None
    try:
        require_root_directory(os.fstat(home_fd), 0o755, "/home authority parent")
        acquire_lifecycle_lock(home_fd, exclusive=True)
        state = lifecycle_prefix_state(
            home_fd,
            allow_legacy_empty=True,
            admit_legacy_authority=True,
        )
        state_absent = state_root_is_absent(args.state_root)
        initial_route = classify_legacy_v2_removal_route(
            state,
            state_root_absent=state_absent,
        )
        if initial_route == "removed":
            require_pending_runtime_roster(
                args.state_root,
                allow_current_runtime=False,
            )
            require(
                not path_occurrences(AUTHORITY_ROOT),
                "absent legacy lifecycle prefix still has an observable storage mount",
            )
            return "removed"
        if initial_route == "migrate":
            return initial_route
        if state != "claimed_authority":
            return "ordinary"

        root_stat = lstat_at(home_fd, AUTHORITY_NAME)
        if root_stat is None:
            return "ordinary"
        root_fd = os.open(
            AUTHORITY_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=home_fd,
        )
        require_descriptor_entry(home_fd, AUTHORITY_NAME, root_fd)
        roster = tuple(sorted(os.listdir(root_fd)))
        receipt = read_json_at(root_fd, RECEIPT_NAME)
        return classify_legacy_v2_removal_route(
            state,
            state_root_absent=state_absent,
            authority_roster=roster,
            receipt_schema=None if receipt is None else receipt.get("schema"),
        )
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(home_fd)


def migrate_legacy_v2_for_removal(args: argparse.Namespace) -> None:
    state_fd: int | None = None
    evidence_fd: int | None = None
    live_state: DirectoryIdentity | None = None
    live_evidence: DirectoryIdentity | None = None
    try:
        state_fd, live_state, evidence_fd, live_evidence = open_caller_directories(
            args.state_root, args.caller_uid, args.caller_gid
        )
    except FileNotFoundError:
        pass
    home_fd: int | None = None
    root_fd: int | None = None
    image_fd: int | None = None
    legacy_lock_fd: int | None = None
    try:
        home_fd = os.open(HOME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        require_root_directory(os.fstat(home_fd), 0o755, "/home authority parent")
        acquire_lifecycle_lock(home_fd, exclusive=True)
        root_fd = os.open(
            AUTHORITY_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=home_fd,
        )
        require_descriptor_entry(home_fd, AUTHORITY_NAME, root_fd)
        root_stat = os.fstat(root_fd)
        require_root_directory(root_stat, 0o700, "legacy storage authority root")
        claims = claim_roster(home_fd)
        require(len(claims) <= 1, "legacy migration claim is ambiguous")
        if claims:
            claim_name = claims[0]
            claim_bytes, claim_document, state_identity, evidence_identity = (
                read_claim_document(home_fd, claim_name)
            )
            require(
                claim_document.get("caller")
                == {"uid": args.caller_uid, "gid": args.caller_gid},
                "legacy migration claim caller differs",
            )
            if live_state is None or live_evidence is None:
                require(
                    state_identity.path == args.state_root,
                    "legacy orphaned claim original path differs",
                )
            else:
                live_coordinates = (
                    live_state.device,
                    live_state.inode,
                    live_state.owner_uid,
                    live_state.owner_gid,
                    live_state.mode,
                    live_evidence.device,
                    live_evidence.inode,
                    live_evidence.owner_uid,
                    live_evidence.owner_gid,
                    live_evidence.mode,
                )
                stored_coordinates = (
                    state_identity.device,
                    state_identity.inode,
                    state_identity.owner_uid,
                    state_identity.owner_gid,
                    state_identity.mode,
                    evidence_identity.device,
                    evidence_identity.inode,
                    evidence_identity.owner_uid,
                    evidence_identity.owner_gid,
                    evidence_identity.mode,
                )
                require(
                    live_coordinates == stored_coordinates,
                    "legacy relocated claim coordinates differ",
                )
        else:
            require(
                live_state is not None and live_evidence is not None,
                "legacy prepublication migration requires the original state binding",
            )
            state_identity = live_state
            evidence_identity = live_evidence
            claim_bytes = claim_bytes_for_identity(
                state_identity,
                evidence_identity,
                args.caller_uid,
                args.caller_gid,
            )
            claim_name = f"{CLAIM_PREFIX}{sha256_bytes(claim_bytes)}"
        pending_claim = lstat_at(home_fd, CLAIM_PENDING_NAME)
        require(
            not (claims and pending_claim is not None),
            "legacy migration has both pending and final claims",
        )
        legacy_lock = lstat_at(root_fd, LEGACY_LOCK_NAME)
        if legacy_lock is not None:
            require(
                stat.S_ISREG(legacy_lock.st_mode)
                and legacy_lock.st_uid == 0
                and legacy_lock.st_gid == 0
                and stat.S_IMODE(legacy_lock.st_mode) == 0o600
                and legacy_lock.st_nlink == 1,
                "legacy lifecycle lock identity differs",
            )
            legacy_lock_fd = os.open(
                LEGACY_LOCK_NAME,
                os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            require_descriptor_entry(root_fd, LEGACY_LOCK_NAME, legacy_lock_fd)
            deadline = time.monotonic() + LIFECYCLE_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(legacy_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RunnerStorageLifecycleError("legacy lifecycle lock is busy")
                    time.sleep(0.05)
        else:
            require(
                claims == (claim_name,),
                "legacy lifecycle lock disappeared before durable migration claim",
            )
        image_fd = os.open(IMAGE_NAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=root_fd)
        require_descriptor_entry(root_fd, IMAGE_NAME, image_fd)
        image_stat = os.fstat(image_fd)
        require(
            stat.S_ISREG(image_stat.st_mode)
            and image_stat.st_uid == 0
            and image_stat.st_gid == 0
            and stat.S_IMODE(image_stat.st_mode) == 0o600
            and image_stat.st_size == IMAGE_BYTES,
            "legacy image node differs",
        )
        roster = tuple(sorted(os.listdir(root_fd)))
        foreign = tuple(
            name
            for name in roster
            if name not in {TARGET_NAME, IMAGE_NAME, RECEIPT_NAME, LEGACY_LOCK_NAME}
            and LEGACY_RECEIPT_TEMP_NAME.fullmatch(name) is None
        )
        require(not foreign, "legacy storage authority contains a foreign entry")
        receipt_stat = lstat_at(root_fd, RECEIPT_NAME)
        receipt = read_json_at(root_fd, RECEIPT_NAME)
        if receipt is not None:
            validate_legacy_v2_removal_receipt(
                receipt,
                state_identity=state_identity,
                root_stat=root_stat,
                image_stat=image_stat,
            )
        else:
            require(claims == (claim_name,), "legacy receipt disappeared before durable claim")
        if pending_claim is not None:
            require(
                legacy_lock is not None and receipt is not None and not claims,
                "legacy pending recovery requires exact lock and receipt authority",
            )
            reduced = reduce_lifecycle_prefix(
                home_fd,
                args.state_root,
                allow_current_runtime=False,
                allow_legacy_empty=False,
                admit_legacy_authority=True,
            )
            require(
                reduced == "legacy_authority",
                "legacy pending claim did not reduce to its exact authority",
            )
        if not claims:
            create_claim(home_fd, claim_name, claim_bytes)
        else:
            seal_claim(home_fd, claim_name, claim_bytes)
        remove_legacy_atomic_temporaries(
            root_fd,
            LEGACY_RECEIPT_TEMP_NAME,
            owner_uid=0,
            owner_gid=0,
            label="authority receipt",
        )
        if evidence_fd is not None:
            remove_legacy_atomic_temporaries(
                evidence_fd,
                LEGACY_PROJECTION_TEMP_NAME,
                owner_uid=args.caller_uid,
                owner_gid=args.caller_gid,
                label="user projection",
            )
        if legacy_lock is not None:
            removed = unlink_bound_leaf(
                root_fd,
                LEGACY_LOCK_NAME,
                label="legacy lifecycle lock identity differs",
                allowed_kinds=("regular",),
                owner_uid=0,
                owner_gid=0,
                required_mode=0o600,
                minimum_size=0,
                maximum_size=MAX_DOCUMENT_BYTES,
                required_link_count=1,
                expected_identity=(legacy_lock.st_dev, legacy_lock.st_ino),
            )
            require(removed, "legacy lifecycle lock disappeared")
        if receipt is not None:
            require(receipt_stat is not None, "legacy receipt identity is absent")
            assert receipt_stat is not None
            removed = unlink_bound_leaf(
                root_fd,
                RECEIPT_NAME,
                label="legacy authority receipt identity differs",
                allowed_kinds=("regular",),
                owner_uid=0,
                owner_gid=0,
                required_mode=0o600,
                minimum_size=1,
                maximum_size=MAX_DOCUMENT_BYTES,
                required_link_count=1,
                expected_identity=(receipt_stat.st_dev, receipt_stat.st_ino),
            )
            require(removed, "legacy authority receipt disappeared")
    finally:
        for descriptor in (legacy_lock_fd, image_fd, root_fd, home_fd, evidence_fd, state_fd):
            if descriptor is not None:
                os.close(descriptor)


def remove_legacy_v2_authority(args: argparse.Namespace) -> dict[str, Any]:
    with acquire_runtime_deletion_lease(args.state_root) as lease:
        require_inherited_runtime_lease(lease.descriptor, args.state_root)
        require_runtime_paths_absent(args.state_root)
        require(
            not task_runtime_authority_roster(),
            "legacy storage removal requires every task runtime authority absent",
        )
        require(
            not path_occurrences(AUTHORITY_ROOT),
            "legacy storage removal requires every authority mount absent",
        )
        route = legacy_v2_removal_route(args, lease.descriptor)
        if route == "removed":
            return operation_result("removed", None, None, None)
        if route == "migrate":
            migrate_legacy_v2_for_removal(args)
        return _remove_authority_locked(args)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    commands = value.add_subparsers(dest="command", required=True)
    for name in ("activate-private", "deactivate-private", "observe-private"):
        child = commands.add_parser(name)
        child.add_argument("state_root", type=Path)
        child.add_argument("caller_uid", type=int)
        child.add_argument("caller_gid", type=int)
        child.add_argument("namespace_device", type=int)
        child.add_argument("namespace_inode", type=int)
        if name != "observe-private":
            child.add_argument("runtime_lease_fd", type=int)
    for name in ("remove-authority", "remove-legacy-v2-authority"):
        remove = commands.add_parser(name)
        remove.add_argument("state_root", type=Path)
        remove.add_argument("caller_uid", type=int)
        remove.add_argument("caller_gid", type=int)
    return value


def require_requester_environment(caller_uid: int, caller_gid: int) -> None:
    require(
        os.environ.get("SUDO_UID") == str(caller_uid)
        and os.environ.get("SUDO_GID") == str(caller_gid),
        "requester environment identity differs",
    )


def require_root_credentials() -> None:
    status = Path("/proc/self/status").read_text(encoding="ascii")
    for label in ("Uid:", "Gid:"):
        line = next((item for item in status.splitlines() if item.startswith(label)), "")
        fields = line.split()[1:]
        require(
            len(fields) == 4 and all(value == "0" for value in fields),
            f"storage lifecycle {label[:-1].lower()} credentials are not fully root",
        )


def main() -> None:
    configure_secure_umask()
    args = parser().parse_args()
    require_root_credentials()
    require(args.caller_uid > 0 and args.caller_gid >= 0, "caller identity is invalid")
    require_requester_environment(args.caller_uid, args.caller_gid)
    handlers = {
        "activate-private": activate_private,
        "deactivate-private": deactivate_private,
        "observe-private": observe_private,
        "remove-authority": remove_authority,
        "remove-legacy-v2-authority": remove_legacy_v2_authority,
    }
    result = handlers[args.command](args)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (RunnerStorageLifecycleError, OSError, ValueError, subprocess.SubprocessError) as error:
        fail(str(error))
