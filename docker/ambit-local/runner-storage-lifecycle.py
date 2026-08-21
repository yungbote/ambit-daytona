#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, NoReturn


OPERATION_SCHEMA = "ambit.local-daytona-runner-storage-operation/v2"
RECEIPT_SCHEMA = "ambit.local-daytona-runner-storage/v2"
PROJECTION_SCHEMA = "ambit.local-daytona-runner-storage-projection/v1"
AUTHORITY_ROOT = Path("/home/.ambit-c16b-runner-storage")
AUTHORITY_NAME = AUTHORITY_ROOT.name
HOME_ROOT = Path("/home")
LOCK_NAME = "lifecycle.lock"
IMAGE_NAME = "runner-docker.xfs"
TARGET_NAME = "runner-docker"
RECEIPT_NAME = "storage-receipt.json"
USER_PROJECTION_NAME = "runner-docker-storage.json"
IDENTITY_VERIFIER_NAME = "verify-runner-storage.py"
IDENTITY_VERIFIER_SHA256 = "ff1d034329ada6f8c1596876779a990dbe7e1a0ada41f57442a899115c90579b"
IMAGE_BYTES = 60 * 1024**3
MAX_DOCUMENT_BYTES = 1024 * 1024
LOOP_DEVICE = re.compile(r"^/dev/loop[0-9]+$")
FILESYSTEM_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
TRUSTED_TOOLS = {
    "blkid": Path("/usr/bin/blkid"),
    "losetup": Path("/usr/bin/losetup"),
    "mkfs.xfs": Path("/usr/bin/mkfs.xfs"),
    "mount": Path("/usr/bin/mount"),
    "python": Path("/usr/bin/python3"),
    "umount": Path("/usr/bin/umount"),
}
MUTATION_GUARDIAN = r"""
import os
import subprocess
import sys

lock_fd = int(sys.argv[1])
inherited = tuple(int(value) for value in sys.argv[2].split(",") if value)
command = sys.argv[3:]
os.fstat(lock_fd)
child = subprocess.Popen(
    command,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    pass_fds=inherited,
)
stdout, stderr = child.communicate()
sys.stdout.buffer.write(stdout)
sys.stderr.buffer.write(stderr)
raise SystemExit(child.returncode)
"""

NodeKind = Literal["absent", "directory", "regular", "symlink", "other"]
ImageState = Literal[
    "absent",
    "root_0600_incomplete_prepublication",
    "root_0600_exact",
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


def strict_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def configure_secure_umask() -> None:
    os.umask(0o077)


def mutation_pass_fds(
    context: AuthorityContext, pass_fds: tuple[int, ...]
) -> tuple[int, ...]:
    require(context.exclusive and context.lock_fd is not None, "mutation lock is absent")
    return tuple(sorted({*pass_fds, context.lock_fd}))


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
    require(
        plain_int(node.size) and 0 <= node.size <= IMAGE_BYTES,
        "runner image size is invalid",
    )
    if node.size == IMAGE_BYTES:
        return "root_0600_exact"
    return "root_0600_incomplete_prepublication"


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


def require_root_directory(value: os.stat_result, mode: int, label: str) -> None:
    require(stat.S_ISDIR(value.st_mode), f"{label} is not a directory")
    require(value.st_uid == 0 and value.st_gid == 0, f"{label} owner differs")
    require(stat.S_IMODE(value.st_mode) == mode, f"{label} mode differs")


@dataclass
class AuthorityContext:
    home_fd: int
    root_fd: int | None
    lock_fd: int | None
    target_fd: int | None
    image_fd: int | None
    authority_device: int
    image_state: ImageState
    roster: tuple[str, ...]
    exclusive: bool

    def close(self) -> None:
        for name in ("image_fd", "target_fd", "lock_fd", "root_fd", "home_fd"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)

    def __enter__(self) -> AuthorityContext:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def open_authority(*, create: bool, exclusive: bool) -> AuthorityContext:
    home_fd = os.open(HOME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_fd: int | None = None
    lock_fd: int | None = None
    target_fd: int | None = None
    image_fd: int | None = None
    try:
        home_stat = os.fstat(home_fd)
        require_root_directory(home_stat, 0o755, "/home authority parent")
        fcntl.flock(home_fd, fcntl.LOCK_EX)
        authority_stat = lstat_at(home_fd, AUTHORITY_NAME)
        if authority_stat is None:
            require(create, "runner storage authority is absent")
            os.mkdir(AUTHORITY_NAME, mode=0o700, dir_fd=home_fd)
            os.fsync(home_fd)
            authority_stat = os.stat(
                AUTHORITY_NAME, dir_fd=home_fd, follow_symlinks=False
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
        lock_stat = lstat_at(root_fd, LOCK_NAME)
        if lock_stat is None:
            require(create, "runner storage lifecycle lock is absent")
            created_lock = os.open(
                LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=root_fd,
            )
            os.fchown(created_lock, 0, 0)
            os.fchmod(created_lock, 0o600)
            os.fsync(created_lock)
            os.close(created_lock)
            os.fsync(root_fd)
            lock_stat = os.stat(LOCK_NAME, dir_fd=root_fd, follow_symlinks=False)
        require(
            stat.S_ISREG(lock_stat.st_mode)
            and lock_stat.st_uid == 0
            and lock_stat.st_gid == 0
            and stat.S_IMODE(lock_stat.st_mode) == 0o600,
            "runner storage lifecycle lock identity differs",
        )
        lock_fd = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=root_fd)
        require_descriptor_entry(root_fd, LOCK_NAME, lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)

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
        allowed = {LOCK_NAME, TARGET_NAME, IMAGE_NAME, RECEIPT_NAME}
        foreign = tuple(name for name in roster if name not in allowed)
        require(not foreign, "runner storage authority contains a foreign entry")
        image_state = classify_image(image_facts, authority_device=home_stat.st_dev)
        return AuthorityContext(
            home_fd=home_fd,
            root_fd=root_fd,
            lock_fd=lock_fd,
            target_fd=target_fd,
            image_fd=image_fd,
            authority_device=home_stat.st_dev,
            image_state=image_state,
            roster=roster,
            exclusive=exclusive,
        )
    except BaseException:
        for descriptor in (image_fd, target_fd, lock_fd, root_fd, home_fd):
            if descriptor is not None:
                os.close(descriptor)
        raise


def trusted_tool(name: str) -> str:
    path = TRUSTED_TOOLS[name]
    value = os.stat(path, follow_symlinks=False)
    require(stat.S_ISREG(value.st_mode), f"trusted tool is not regular: {name}")
    require(value.st_uid == 0 and value.st_gid == 0, f"trusted tool owner differs: {name}")
    require(stat.S_IMODE(value.st_mode) & 0o022 == 0, f"trusted tool is writable: {name}")
    return str(path)


def run_tool(
    context: AuthorityContext,
    name: str,
    *args: str,
    mutation: bool = False,
    pass_fds: tuple[int, ...] = (),
) -> str:
    tool_command = [trusted_tool(name), *args]
    retained = set(pass_fds)
    if mutation:
        retained = set(mutation_pass_fds(context, pass_fds))
        assert context.lock_fd is not None
        inherited_for_tool = tuple(sorted(set(pass_fds)))
        result = subprocess.run(
            [
                trusted_tool("python"),
                "-I",
                "-S",
                "-B",
                "-c",
                MUTATION_GUARDIAN,
                str(context.lock_fd),
                ",".join(str(value) for value in inherited_for_tool),
                *tool_command,
            ],
            check=True,
            capture_output=True,
            text=True,
            pass_fds=tuple(sorted(retained)),
        )
    else:
        result = subprocess.run(
            tool_command,
            check=True,
            capture_output=True,
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


def target_occurrences() -> tuple[NamespaceOccurrence, ...]:
    target = str(AUTHORITY_ROOT / TARGET_NAME)
    prefix = f"{target}/"
    return stable_occurrences(
        lambda record: record.target == target or record.target.startswith(prefix)
    )


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
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
    lifecycle_state: str,
) -> dict[str, Any]:
    verifier = load_identity_verifier()
    observation = verifier["collect_storage_observation"](
        state_root,
        authority_root=AUTHORITY_ROOT,
        observer_uid=caller_uid,
        observer_gid=caller_gid,
    )
    receipt = verifier["validate_storage_identity_observation"](observation)
    receipt["lifecycleState"] = lifecycle_state
    return receipt


def read_json_at(directory_fd: int, name: str) -> dict[str, Any] | None:
    value = lstat_at(directory_fd, name)
    if value is None:
        return None
    require(
        stat.S_ISREG(value.st_mode)
        and value.st_uid == 0
        and value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o600,
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
    parsed = json.loads(b"".join(chunks))
    require(isinstance(parsed, dict), f"authority JSON is not an object: {name}")
    return parsed


def write_bytes_atomic(
    directory_fd: int,
    final_name: str,
    value: bytes,
    *,
    owner_uid: int,
    owner_gid: int,
) -> None:
    require(len(value) <= MAX_DOCUMENT_BYTES, "receipt output is too large")
    temporary = f".{final_name}.{os.getpid()}.{secrets.token_hex(8)}"
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


def open_user_evidence(state_root: Path, caller_uid: int, caller_gid: int) -> int:
    state = os.stat(state_root, follow_symlinks=False)
    require(
        stat.S_ISDIR(state.st_mode)
        and state.st_uid == caller_uid
        and state.st_gid == caller_gid
        and stat.S_IMODE(state.st_mode) == 0o700,
        "user state root authority differs",
    )
    evidence = state_root / "evidence"
    value = os.stat(evidence, follow_symlinks=False)
    require(
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == caller_uid
        and value.st_gid == caller_gid
        and stat.S_IMODE(value.st_mode) == 0o700,
        "user evidence directory authority differs",
    )
    return os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def publish_receipt(
    context: AuthorityContext,
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
    receipt: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    require(context.root_fd is not None, "authority descriptor is absent")
    receipt_bytes = canonical_json_bytes(receipt)
    write_bytes_atomic(context.root_fd, RECEIPT_NAME, receipt_bytes, owner_uid=0, owner_gid=0)
    digest = sha256_bytes(receipt_bytes)
    projection = {
        "schema": PROJECTION_SCHEMA,
        "authorityReceiptSha256": digest,
        "receipt": receipt,
    }
    evidence_fd = open_user_evidence(state_root, caller_uid, caller_gid)
    try:
        write_bytes_atomic(
            evidence_fd,
            USER_PROJECTION_NAME,
            canonical_json_bytes(projection),
            owner_uid=caller_uid,
            owner_gid=caller_gid,
        )
    finally:
        os.close(evidence_fd)
    return digest, projection


def remove_user_projection(state_root: Path, caller_uid: int, caller_gid: int) -> None:
    evidence_fd = open_user_evidence(state_root, caller_uid, caller_gid)
    try:
        value = lstat_at(evidence_fd, USER_PROJECTION_NAME)
        if value is not None:
            require(
                stat.S_ISREG(value.st_mode)
                and value.st_uid == caller_uid
                and value.st_gid == caller_gid
                and stat.S_IMODE(value.st_mode) == 0o600,
                "user storage projection identity differs",
            )
            os.unlink(USER_PROJECTION_NAME, dir_fd=evidence_fd)
            os.fsync(evidence_fd)
    finally:
        os.close(evidence_fd)


def validate_receipt(
    receipt: dict[str, Any], context: AuthorityContext, state_root: Path
) -> str:
    require(receipt.get("schema") == RECEIPT_SCHEMA, "storage receipt version is unsupported")
    require(
        receipt.get("lifecycleState") in ("attached", "detached"),
        "storage receipt lifecycle state is invalid",
    )
    require(receipt.get("stateRoot") == str(state_root), "storage receipt state root differs")
    authority = receipt.get("authorityRoot")
    image = receipt.get("image")
    filesystem = receipt.get("filesystem")
    require(isinstance(authority, dict), "storage receipt authority root is absent")
    require(isinstance(image, dict), "storage receipt image is absent")
    require(isinstance(filesystem, dict), "storage receipt filesystem is absent")
    require(context.root_fd is not None and context.image_fd is not None, "storage objects are absent")
    root_stat = os.fstat(context.root_fd)
    image_stat = os.fstat(context.image_fd)
    require(
        authority.get("path") == str(AUTHORITY_ROOT)
        and authority.get("device") == root_stat.st_dev
        and authority.get("inode") == root_stat.st_ino,
        "storage receipt authority identity differs",
    )
    require(
        image.get("path") == str(AUTHORITY_ROOT / IMAGE_NAME)
        and image.get("device") == image_stat.st_dev
        and image.get("inode") == image_stat.st_ino
        and image.get("logicalBytes") == IMAGE_BYTES,
        "storage receipt image identity differs",
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
    expected_namespace = require_private_namespace(
        args.namespace_device, args.namespace_inode
    )
    with open_authority(create=True, exclusive=True) as context:
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
            expected_uuid = validate_receipt(stored, context, args.state_root)
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
        receipt = current_receipt(
            args.state_root, args.caller_uid, args.caller_gid, "attached"
        )
        digest, _ = publish_receipt(
            context,
            args.state_root,
            args.caller_uid,
            args.caller_gid,
            receipt,
        )
        return operation_result("activated", expected_namespace, digest, receipt)


def deactivate_private(args: argparse.Namespace) -> dict[str, Any]:
    expected_namespace = require_private_namespace(
        args.namespace_device, args.namespace_inode
    )
    with open_authority(create=False, exclusive=True) as context:
        require(context.root_fd is not None and context.image_fd is not None, "storage is absent")
        stored = read_json_at(context.root_fd, RECEIPT_NAME)
        require(stored is not None, "storage receipt is absent")
        expected_uuid = validate_receipt(stored, context, args.state_root)
        loops = associated_loops(context)
        require(len(loops) == 1, "storage loop identity is absent or ambiguous")
        loop = loops[0]
        require(filesystem_uuid(context, loop) == expected_uuid, "storage UUID differs")
        unmount_and_detach(context, loop, expected_namespace)
        detached = dict(stored)
        detached["lifecycleState"] = "detached"
        detached["mountNamespace"] = {
            "device": args.namespace_device,
            "inode": args.namespace_inode,
        }
        detached["loop"] = None
        digest, _ = publish_receipt(
            context,
            args.state_root,
            args.caller_uid,
            args.caller_gid,
            detached,
        )
        return operation_result("deactivated", expected_namespace, digest, detached)


def observe_private(args: argparse.Namespace) -> dict[str, Any]:
    expected_namespace = require_private_namespace(
        args.namespace_device, args.namespace_inode
    )
    with open_authority(create=False, exclusive=False) as context:
        require(context.root_fd is not None and context.image_fd is not None, "storage is absent")
        stored = read_json_at(context.root_fd, RECEIPT_NAME)
        require(stored is not None, "storage receipt is absent")
        expected_uuid = validate_receipt(stored, context, args.state_root)
        current = current_receipt(
            args.state_root, args.caller_uid, args.caller_gid, "attached"
        )
        require(
            current["filesystem"]["uuid"] == expected_uuid,
            "current storage UUID differs from receipt",
        )
        receipt_bytes = canonical_json_bytes(stored)
        digest = sha256_bytes(receipt_bytes)
        return operation_result("observed", expected_namespace, digest, current)


def remove_authority(args: argparse.Namespace) -> dict[str, Any]:
    try:
        context = open_authority(create=False, exclusive=True)
    except RunnerStorageLifecycleError as error:
        if str(error) == "runner storage authority is absent":
            remove_user_projection(args.state_root, args.caller_uid, args.caller_gid)
            return operation_result("removed", None, None, None)
        raise
    with context:
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
        remove_user_projection(args.state_root, args.caller_uid, args.caller_gid)
        receipt_stat = lstat_at(context.root_fd, RECEIPT_NAME)
        if receipt_stat is not None:
            require(
                stat.S_ISREG(receipt_stat.st_mode)
                and receipt_stat.st_uid == 0
                and receipt_stat.st_gid == 0,
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
        remaining = tuple(sorted(os.listdir(context.root_fd)))
        require(remaining == (LOCK_NAME,), "authority root contains residual entries")
        require(context.lock_fd is not None, "authority lock descriptor is absent")
        require_descriptor_entry(context.root_fd, LOCK_NAME, context.lock_fd)
        os.unlink(LOCK_NAME, dir_fd=context.root_fd)
        os.fsync(context.root_fd)
        os.close(context.lock_fd)
        context.lock_fd = None
        require_descriptor_entry(context.home_fd, AUTHORITY_NAME, context.root_fd)
        os.rmdir(AUTHORITY_NAME, dir_fd=context.home_fd)
        os.fsync(context.home_fd)
        os.close(context.root_fd)
        context.root_fd = None
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


def main() -> None:
    configure_secure_umask()
    args = parser().parse_args()
    require(os.geteuid() == 0, "storage lifecycle helper is not privileged")
    require(args.caller_uid > 0 and args.caller_gid >= 0, "caller identity is invalid")
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
