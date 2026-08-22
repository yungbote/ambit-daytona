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
IMAGE_NAME = "runner-docker.xfs"
TARGET_NAME = "runner-docker"
RUNNER_DATA_NAME = "inner-runner"
OUTER_DOCKER_NAME = "outer-docker"
OUTER_CONTAINERD_NAME = "outer-containerd"
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
child = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    pass_fds=tool_fds,
    start_new_session=True,
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
    "claim_only",
    "claimed_authority",
    "legacy_empty_authority",
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
    allow_legacy_empty: bool,
    authority_empty: bool,
) -> LifecyclePrefixState:
    require(
        not claim_names or claim_names == (expected_claim_name,),
        "runner storage lifecycle claim differs",
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
            and claim.size == 0
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


def remove_disposition(image_state: ImageState, receipt_present: bool) -> str:
    if image_state == "absent" and not receipt_present:
        return "remove_empty_authority"
    if image_state.startswith("root_0600_"):
        if image_state == "root_0600_incomplete_prepublication" and receipt_present:
            raise RunnerStorageLifecycleError(
                "incomplete prepublication image unexpectedly has a receipt"
            )
        return "remove_image_authority"
    raise RunnerStorageLifecycleError("runner authority removal state is invalid")


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
                os.unlink(nested, dir_fd=child_fd)
                os.fsync(child_fd)
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
    value = lstat_at(directory_fd, name)
    if value is None:
        return
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        require_descriptor_entry(directory_fd, name, descriptor)
        value = os.fstat(descriptor)
        require(
            stat.S_ISREG(value.st_mode)
            and value.st_uid == owner_uid
            and value.st_gid == owner_gid
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_dev == os.fstat(directory_fd).st_dev
            and value.st_nlink == 1
            and 0 <= value.st_size <= MAX_DOCUMENT_BYTES,
            f"pending receipt identity differs: {name}",
        )
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(descriptor)


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


def require_pinned_directory(directory_fd: int, identity: DirectoryIdentity) -> None:
    descriptor = os.fstat(directory_fd)
    path_value = os.stat(identity.path, follow_symlinks=False)
    expected = (
        identity.device,
        identity.inode,
        identity.owner_uid,
        identity.owner_gid,
        identity.mode,
    )
    for observed in (descriptor, path_value):
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
    preimage = (
        json.dumps(
            claim_binding_document(state_root, evidence, caller_uid, caller_gid),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    return f"{CLAIM_PREFIX}{sha256_bytes(preimage)}"


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


def require_claim_identity(home_fd: int, claim_name: str) -> None:
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
        and value.st_size == 0,
        "runner storage lifecycle claim identity differs",
    )


def create_claim(home_fd: int, claim_name: str) -> None:
    descriptor = os.open(
        claim_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=home_fd,
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(home_fd)
    require_claim_identity(home_fd, claim_name)


@dataclass
class AuthorityContext:
    state_fd: int | None
    evidence_fd: int | None
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
    claim_present: bool
    legacy_unclaimed: bool

    def close(self) -> None:
        for name in (
            "image_fd",
            "target_fd",
            "root_fd",
            "home_fd",
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
        context.state_fd is not None
        and context.evidence_fd is not None
        and context.home_fd is not None,
        "lifecycle identity descriptors are absent",
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
        require_claim_identity(context.home_fd, context.claim_name)
    else:
        require(not claims, "unexpected runner storage lifecycle claim exists")


def open_authority(
    *,
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
    create: bool,
    exclusive: bool,
    allow_legacy_empty: bool = False,
    required_tools: tuple[str, ...] = (),
) -> AuthorityContext:
    state_fd, state_identity, evidence_fd, evidence_identity = open_caller_directories(
        state_root, caller_uid, caller_gid
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
        require(
            home_stat.st_dev == state_identity.device == evidence_identity.device,
            "lifecycle identities use different backing filesystems",
        )
        acquire_lifecycle_lock(home_fd, exclusive=exclusive)
        claim_name = claim_name_for_identity(
            state_identity, evidence_identity, caller_uid, caller_gid
        )
        claims = claim_roster(home_fd)
        authority_stat = lstat_at(home_fd, AUTHORITY_NAME)
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
                allow_legacy_empty=False,
                authority_empty=False,
            )
        elif claims:
            raise RunnerStorageLifecycleError("runner storage lifecycle claim differs")
        if authority_stat is None and create:
            require(exclusive, "authority creation requires an exclusive lifecycle lock")
            if not claim_present:
                create_claim(home_fd, claim_name)
                claim_present = True
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
            require_claim_identity(home_fd, claim_name)

        if authority_stat is None:
            return AuthorityContext(
                state_fd=state_fd,
                evidence_fd=evidence_fd,
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
                claim_present=claim_present,
                legacy_unclaimed=False,
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
                allow_legacy_empty=True,
                authority_empty=not roster,
            )
            return AuthorityContext(
                state_fd=state_fd,
                evidence_fd=evidence_fd,
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
                claim_present=False,
                legacy_unclaimed=True,
            )

        if exclusive:
            remove_admitted_pending(
                evidence_fd,
                PROJECTION_PENDING_NAME,
                owner_uid=caller_uid,
                owner_gid=caller_gid,
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
            claim_present=True,
            legacy_unclaimed=False,
        )
        require_context_binding(context)
        if exclusive:
            reconcile_receipt_pending(context)
            context.roster = tuple(sorted(os.listdir(root_fd)))
        return context
    except BaseException:
        for descriptor in (
            image_fd,
            target_fd,
            root_fd,
            home_fd,
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
class MountRecord:
    device_number: str
    target: str
    optional_fields: tuple[str, ...]


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


def read_mount_records(path: str = "/proc/self/mountinfo") -> tuple[MountRecord, ...]:
    records: list[MountRecord] = []
    with open(path, encoding="utf-8") as source:
        for raw in source:
            fields = raw.rstrip("\n").split(" ")
            require("-" in fields and len(fields) >= 10, "mountinfo record is invalid")
            separator = fields.index("-")
            records.append(
                MountRecord(
                    device_number=fields[2],
                    target=decode_mount_path(fields[4]),
                    optional_fields=tuple(fields[6:separator]),
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


def require_private_namespace(expected_device: int, expected_inode: int) -> str:
    expected = f"{expected_device}:{expected_inode}"
    observed = namespace_id()
    require(observed == expected, "helper mount namespace identity differs")
    home_candidates = [
        record
        for record in read_mount_records()
        if str(HOME_ROOT) == record.target or str(HOME_ROOT).startswith(f"{record.target}/")
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
        if before in observations:
            try:
                after = namespace_id(ns_path)
            except OSError as error:
                raise RunnerStorageLifecycleError(
                    f"observed namespace disappeared for pid {pid}"
                ) from error
            require(before == after, f"namespace changed for pid {pid}")
            continue
        try:
            records = read_mount_records(mount_path)
            after = namespace_id(ns_path)
        except OSError as error:
            raise RunnerStorageLifecycleError(
                f"observed namespace disappeared for pid {pid}"
            ) from error
        require(before == after, f"namespace changed for pid {pid}")
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
            )
            for namespace in values
            for record in namespace.records
            if predicate(record)
        ]
        return tuple(
            sorted(
                result,
                key=lambda item: (item.namespace_id, item.device_number, item.target),
            )
        )

    first_result = project(first)
    second_result = project(second)
    require(
        tuple((item.namespace_id, item.device_number, item.target) for item in first_result)
        == tuple((item.namespace_id, item.device_number, item.target) for item in second_result),
        "mount occurrence roster changed across proof passes",
    )
    return second_result


def path_occurrences(path: Path) -> tuple[NamespaceOccurrence, ...]:
    target = str(path)
    prefix = f"{target}/"
    return stable_occurrences(
        lambda record: record.target == target or record.target.startswith(prefix)
    )


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
    return digest, projection


def remove_user_projection(context: AuthorityContext) -> None:
    require_context_binding(context)
    require(context.evidence_fd is not None, "evidence descriptor is absent")
    value = lstat_at(context.evidence_fd, USER_PROJECTION_NAME)
    if value is not None:
        require(
            stat.S_ISREG(value.st_mode)
            and value.st_uid == context.caller_uid
            and value.st_gid == context.caller_gid
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_dev == os.fstat(context.evidence_fd).st_dev
            and value.st_nlink == 1
            and 0 < value.st_size <= MAX_DOCUMENT_BYTES,
            "user storage projection identity differs",
        )
        os.unlink(USER_PROJECTION_NAME, dir_fd=context.evidence_fd)
        os.fsync(context.evidence_fd)


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


def activate_private(args: argparse.Namespace) -> dict[str, Any]:
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


def remove_authority(args: argparse.Namespace) -> dict[str, Any]:
    with open_authority(
        state_root=args.state_root,
        caller_uid=args.caller_uid,
        caller_gid=args.caller_gid,
        create=False,
        exclusive=True,
        allow_legacy_empty=True,
        required_tools=("losetup", "python"),
    ) as context:
        require_context_binding(context)
        if context.root_fd is None:
            require(
                not path_occurrences(AUTHORITY_ROOT),
                "absent authority still has an observable mount",
            )
            remove_user_projection(context)
            if context.claim_present:
                require(context.home_fd is not None, "lifecycle lock descriptor is absent")
                require_context_binding(context)
                os.unlink(context.claim_name, dir_fd=context.home_fd)
                os.fsync(context.home_fd)
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
            require(
                stat.S_ISREG(receipt_stat.st_mode)
                and receipt_stat.st_uid == 0
                and receipt_stat.st_gid == 0
                and stat.S_IMODE(receipt_stat.st_mode) == 0o600
                and receipt_stat.st_dev == os.fstat(context.root_fd).st_dev
                and receipt_stat.st_nlink == 1
                and 0 < receipt_stat.st_size <= MAX_DOCUMENT_BYTES,
                "authority receipt identity differs",
            )
            os.unlink(RECEIPT_NAME, dir_fd=context.root_fd)
            os.fsync(context.root_fd)
        if context.image_fd is not None:
            require_descriptor_entry(context.root_fd, IMAGE_NAME, context.image_fd)
            os.unlink(IMAGE_NAME, dir_fd=context.root_fd)
            os.fsync(context.root_fd)
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
        os.unlink(context.claim_name, dir_fd=context.home_fd)
        os.fsync(context.home_fd)
        context.claim_present = False
        require_context_binding(context)
    return operation_result("removed", None, None, None)


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
    remove = commands.add_parser("remove-authority")
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
    }
    result = handlers[args.command](args)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (RunnerStorageLifecycleError, OSError, ValueError, subprocess.SubprocessError) as error:
        fail(str(error))
