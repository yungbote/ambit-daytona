#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, NoReturn


SCHEMA = "ambit.local-daytona-runner-storage-lifecycle/v1"
CAPACITY_NAME = "capacity"
IMAGE_NAME = "runner-docker.xfs"
TARGET_NAME = "runner-docker"
LOOP_DEVICE = re.compile(r"^/dev/loop[0-9]+$")
FILESYSTEM_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
TRUSTED_TOOLS = {
    "blkid": Path("/usr/bin/blkid"),
    "losetup": Path("/usr/bin/losetup"),
    "mkfs.xfs": Path("/usr/bin/mkfs.xfs"),
    "mount": Path("/usr/bin/mount"),
    "umount": Path("/usr/bin/umount"),
}

NodeKind = Literal["absent", "directory", "regular", "symlink", "other"]
Operation = Literal["prepare", "remove"]
Disposition = Literal[
    "create_new",
    "existing_published_candidate",
    "teardown_required",
    "already_absent",
    "remove_empty_capacity",
    "remove_image_and_capacity",
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


def validate_state_root_authority(
    *,
    descriptor_device: int,
    descriptor_inode: int,
    path_device: int,
    path_inode: int,
    path_owner_uid: int,
    path_owner_gid: int,
    path_mode: int,
    caller_uid: int,
    caller_gid: int,
) -> None:
    require(
        (descriptor_device, descriptor_inode) == (path_device, path_inode),
        "runner storage state root differs from its pinned descriptor",
    )
    require(
        path_owner_uid == caller_uid
        and path_owner_gid == caller_gid
        and path_mode == 0o700,
        "runner storage state root owner, group, or mode differs",
    )


@dataclass(frozen=True)
class NodeFacts:
    kind: NodeKind
    owner_uid: int | None = None
    owner_gid: int | None = None
    mode: int | None = None
    device: int | None = None
    inode: int | None = None
    size: int | None = None


@dataclass(frozen=True)
class CapacityPrefixFacts:
    state_root_device: int
    capacity: NodeFacts
    image: NodeFacts
    foreign_entries: tuple[str, ...] = ()


@dataclass(frozen=True)
class PrefixDecision:
    operation: Operation
    disposition: Disposition
    capacity_state: str
    image_state: str


def absent_node() -> NodeFacts:
    return NodeFacts(kind="absent")


def classify_capacity(
    node: NodeFacts, *, caller_uid: int, caller_gid: int, state_root_device: int
) -> str:
    if node.kind == "absent":
        require(node == absent_node(), "absent runner capacity root carries identity fields")
        return "absent"
    require(node.kind == "directory", "runner capacity root is not a directory")
    require(
        node.device == state_root_device,
        "runner capacity root is on a foreign backing filesystem",
    )
    require(plain_int(node.inode) and node.inode > 0, "runner capacity root inode is invalid")
    identity = (node.owner_uid, node.owner_gid, node.mode)
    if identity == (caller_uid, caller_gid, 0o700):
        return "caller_0700"
    if identity == (0, 0, 0o700):
        return "root_0700"
    if identity == (0, 0, 0o711):
        return "root_0711"
    raise RunnerStorageLifecycleError("runner capacity root ownership or mode differs")


def classify_image(
    node: NodeFacts,
    *,
    caller_uid: int,
    caller_gid: int,
    state_root_device: int,
    image_bytes: int,
) -> str:
    if node.kind == "absent":
        require(node == absent_node(), "absent runner storage image carries identity fields")
        return "absent"
    require(node.kind == "regular", "runner storage image is not a regular file")
    require(
        node.device == state_root_device,
        "runner storage image is on a foreign backing filesystem",
    )
    require(plain_int(node.inode) and node.inode > 0, "runner storage image inode is invalid")
    require(
        plain_int(node.size) and 0 <= node.size <= image_bytes,
        "runner storage image logical size is invalid",
    )
    size_state = "exact" if node.size == image_bytes else "incomplete_prepublication"
    identity = (node.owner_uid, node.owner_gid, node.mode)
    if identity == (caller_uid, caller_gid, 0o600):
        return f"caller_0600_{size_state}"
    if identity == (0, 0, 0o600):
        return f"root_0600_{size_state}"
    raise RunnerStorageLifecycleError("runner storage image ownership or mode differs")


def reduce_prefix_state(
    facts: CapacityPrefixFacts,
    *,
    operation: Operation,
    caller_uid: int,
    caller_gid: int,
    image_bytes: int,
) -> PrefixDecision:
    require(operation in ("prepare", "remove"), "runner storage operation is invalid")
    require(plain_int(caller_uid) and caller_uid > 0, "runner storage caller UID is invalid")
    require(plain_int(caller_gid) and caller_gid >= 0, "runner storage caller GID is invalid")
    require(plain_int(image_bytes) and image_bytes > 0, "runner storage image size is invalid")
    require(
        plain_int(facts.state_root_device) and facts.state_root_device >= 0,
        "runner storage state-root device is invalid",
    )
    require(not facts.foreign_entries, "runner capacity root contains a foreign entry")
    capacity_state = classify_capacity(
        facts.capacity,
        caller_uid=caller_uid,
        caller_gid=caller_gid,
        state_root_device=facts.state_root_device,
    )
    image_state = classify_image(
        facts.image,
        caller_uid=caller_uid,
        caller_gid=caller_gid,
        state_root_device=facts.state_root_device,
        image_bytes=image_bytes,
    )
    require(
        capacity_state != "absent" or image_state == "absent",
        "runner storage image exists without its capacity root",
    )
    require(
        capacity_state != "root_0711" or not image_state.startswith("caller_0600_"),
        "runner storage image has impossible ownership below a published capacity root",
    )

    if operation == "prepare":
        if image_state == "absent":
            disposition: Disposition = "create_new"
        elif capacity_state == "root_0711" and image_state == "root_0600_exact":
            disposition = "existing_published_candidate"
        else:
            disposition = "teardown_required"
    else:
        if capacity_state == "absent":
            disposition = "already_absent"
        elif image_state == "absent":
            disposition = "remove_empty_capacity"
        else:
            disposition = "remove_image_and_capacity"
    return PrefixDecision(
        operation=operation,
        disposition=disposition,
        capacity_state=capacity_state,
        image_state=image_state,
    )


def node_kind(mode: int) -> NodeKind:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


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


def lstat_at(name: str, directory_fd: int) -> os.stat_result | None:
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
        f"runner storage entry changed before descriptor-relative mutation: {name}",
    )


@dataclass
class OpenPrefix:
    state_root_fd: int
    state_root_path: Path
    facts: CapacityPrefixFacts
    capacity_fd: int | None = None
    image_fd: int | None = None

    def close(self) -> None:
        if self.image_fd is not None:
            os.close(self.image_fd)
            self.image_fd = None
        if self.capacity_fd is not None:
            os.close(self.capacity_fd)
            self.capacity_fd = None
        os.close(self.state_root_fd)

    def __enter__(self) -> OpenPrefix:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def open_state_root(
    state_root_handle: str,
    state_root_path: Path,
    caller_uid: int,
    caller_gid: int,
) -> tuple[int, os.stat_result]:
    require(state_root_path.is_absolute(), "runner storage state root is not absolute")
    require(str(state_root_path).startswith("/home/"), "runner storage state root is outside /home")
    require(
        state_root_path.resolve(strict=True) == state_root_path,
        "runner storage state root is not canonical",
    )
    state_root_fd = os.open(state_root_handle, os.O_RDONLY | os.O_DIRECTORY)
    try:
        descriptor_stat = os.fstat(state_root_fd)
        path_stat = os.stat(state_root_path, follow_symlinks=False)
        require(stat.S_ISDIR(path_stat.st_mode), "runner storage state root is not a directory")
        validate_state_root_authority(
            descriptor_device=descriptor_stat.st_dev,
            descriptor_inode=descriptor_stat.st_ino,
            path_device=path_stat.st_dev,
            path_inode=path_stat.st_ino,
            path_owner_uid=path_stat.st_uid,
            path_owner_gid=path_stat.st_gid,
            path_mode=stat.S_IMODE(path_stat.st_mode),
            caller_uid=caller_uid,
            caller_gid=caller_gid,
        )
        return state_root_fd, descriptor_stat
    except BaseException:
        os.close(state_root_fd)
        raise


def inspect_prefix(
    *,
    state_root_handle: str,
    state_root_path: Path,
    caller_uid: int,
    caller_gid: int,
) -> OpenPrefix:
    state_root_fd, state_root_stat = open_state_root(
        state_root_handle, state_root_path, caller_uid, caller_gid
    )
    capacity_fd: int | None = None
    image_fd: int | None = None
    try:
        capacity_stat = lstat_at(CAPACITY_NAME, state_root_fd)
        if capacity_stat is None:
            return OpenPrefix(
                state_root_fd=state_root_fd,
                state_root_path=state_root_path,
                facts=CapacityPrefixFacts(
                    state_root_device=state_root_stat.st_dev,
                    capacity=absent_node(),
                    image=absent_node(),
                ),
            )
        capacity_facts = facts_from_stat(capacity_stat)
        require(capacity_facts.kind == "directory", "runner capacity root is not a directory")
        capacity_fd = os.open(
            CAPACITY_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=state_root_fd,
        )
        opened_capacity_stat = os.fstat(capacity_fd)
        require(
            (opened_capacity_stat.st_dev, opened_capacity_stat.st_ino)
            == (capacity_stat.st_dev, capacity_stat.st_ino),
            "runner capacity root changed while opening its descriptor",
        )
        children = tuple(sorted(os.listdir(capacity_fd)))
        foreign_entries = tuple(name for name in children if name != IMAGE_NAME)
        image_stat = lstat_at(IMAGE_NAME, capacity_fd)
        if image_stat is None:
            image_facts = absent_node()
        else:
            image_facts = facts_from_stat(image_stat)
            require(image_facts.kind == "regular", "runner storage image is not a regular file")
            image_fd = os.open(
                IMAGE_NAME,
                os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=capacity_fd,
            )
            opened_image_stat = os.fstat(image_fd)
            require(
                (opened_image_stat.st_dev, opened_image_stat.st_ino)
                == (image_stat.st_dev, image_stat.st_ino),
                "runner storage image changed while opening its descriptor",
            )
        return OpenPrefix(
            state_root_fd=state_root_fd,
            state_root_path=state_root_path,
            capacity_fd=capacity_fd,
            image_fd=image_fd,
            facts=CapacityPrefixFacts(
                state_root_device=state_root_stat.st_dev,
                capacity=capacity_facts,
                image=image_facts,
                foreign_entries=foreign_entries,
            ),
        )
    except BaseException:
        if image_fd is not None:
            os.close(image_fd)
        if capacity_fd is not None:
            os.close(capacity_fd)
        os.close(state_root_fd)
        raise


def require_root_invocation(caller_uid: int, caller_gid: int) -> None:
    require(os.geteuid() == 0, "runner storage lifecycle helper is not privileged")
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    require(sudo_uid is not None and sudo_gid is not None, "runner storage sudo identity is absent")
    require(int(sudo_uid) == caller_uid, "runner storage sudo caller UID differs")
    require(int(sudo_gid) == caller_gid, "runner storage sudo caller GID differs")


def trusted_tool(name: str) -> str:
    path = TRUSTED_TOOLS[name]
    value = os.stat(path, follow_symlinks=False)
    require(stat.S_ISREG(value.st_mode), f"trusted runner storage tool is not regular: {name}")
    require(value.st_uid == 0 and value.st_gid == 0, f"trusted runner storage tool owner differs: {name}")
    require(stat.S_IMODE(value.st_mode) & 0o022 == 0, f"trusted runner storage tool is writable: {name}")
    return str(path)


def run_tool(name: str, *args: str, pass_fds: tuple[int, ...] = ()) -> str:
    result = subprocess.run(
        [trusted_tool(name), *args],
        check=True,
        capture_output=True,
        text=True,
        pass_fds=pass_fds,
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


@dataclass(frozen=True)
class MountNamespaceObservation:
    namespace_id: str
    representative_pid: int
    records: tuple[MountRecord, ...]


@dataclass(frozen=True)
class NamespaceMountOccurrence:
    namespace_id: str
    representative_pid: int
    target: str


def read_mount_records(path: str = "/proc/self/mountinfo") -> tuple[MountRecord, ...]:
    records: list[MountRecord] = []
    with open(path, encoding="utf-8") as mountinfo:
        for raw_line in mountinfo:
            fields = raw_line.rstrip("\n").split(" ")
            require(len(fields) >= 10 and "-" in fields, "mountinfo record is invalid")
            records.append(
                MountRecord(
                    device_number=fields[2],
                    target=decode_mount_path(fields[4]),
                )
            )
    return tuple(records)


def mount_namespace_id(path: str) -> str:
    value = os.stat(path)
    return f"{value.st_dev}:{value.st_ino}"


def read_observable_mount_namespaces() -> tuple[MountNamespaceObservation, ...]:
    try:
        own_namespace = mount_namespace_id("/proc/self/ns/mnt")
        own_records = read_mount_records()
    except (PermissionError, OSError) as error:
        raise RunnerStorageLifecycleError(
            "helper mount namespace is unreadable"
        ) from error
    observations: dict[str, MountNamespaceObservation] = {
        own_namespace: MountNamespaceObservation(
            namespace_id=own_namespace,
            representative_pid=os.getpid(),
            records=own_records,
        )
    }
    try:
        process_entries = tuple(sorted(os.listdir("/proc")))
    except OSError as error:
        raise RunnerStorageLifecycleError("observable mount namespace roster is unreadable") from error
    for entry in process_entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        namespace_path = f"/proc/{pid}/ns/mnt"
        mountinfo_path = f"/proc/{pid}/mountinfo"
        try:
            before = mount_namespace_id(namespace_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, OSError) as error:
            raise RunnerStorageLifecycleError(
                f"mount namespace identity is unreadable for pid {pid}"
            ) from error
        if before in observations:
            continue
        try:
            records = read_mount_records(mountinfo_path)
            after = mount_namespace_id(namespace_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, OSError) as error:
            raise RunnerStorageLifecycleError(
                f"mount namespace contents are unreadable for pid {pid}"
            ) from error
        if before != after:
            continue
        observations[before] = MountNamespaceObservation(
            namespace_id=before,
            representative_pid=pid,
            records=records,
        )
    return tuple(observations[key] for key in sorted(observations))


def loop_device_number(loop_device: str) -> str:
    require(LOOP_DEVICE.fullmatch(loop_device) is not None, "runner storage loop device is invalid")
    value = os.stat(loop_device)
    require(stat.S_ISBLK(value.st_mode), "runner storage loop device is not a block device")
    return f"{os.major(value.st_rdev)}:{os.minor(value.st_rdev)}"


def observable_mounts_for_loop(
    loop_device: str,
) -> tuple[NamespaceMountOccurrence, ...]:
    device_number = loop_device_number(loop_device)
    occurrences = [
        NamespaceMountOccurrence(
            namespace_id=namespace.namespace_id,
            representative_pid=namespace.representative_pid,
            target=record.target,
        )
        for namespace in read_observable_mount_namespaces()
        for record in namespace.records
        if record.device_number == device_number
    ]
    return tuple(
        sorted(
            occurrences,
            key=lambda value: (
                value.namespace_id,
                value.representative_pid,
                value.target,
            ),
        )
    )


def mounts_at_or_below(target: Path) -> tuple[MountRecord, ...]:
    prefix = f"{target}/"
    return tuple(
        record
        for record in read_mount_records()
        if record.target == str(target) or record.target.startswith(prefix)
    )


def associated_loops(image_fd: int) -> tuple[str, ...]:
    handle = f"/proc/self/fd/{image_fd}"
    output = run_tool(
        "losetup",
        "--json",
        "--output",
        "NAME,BACK-FILE",
        "--associated",
        handle,
        pass_fds=(image_fd,),
    )
    parsed = json.loads(output or '{"loopdevices":[]}')
    devices = parsed.get("loopdevices")
    require(isinstance(devices, list), "runner storage loop observation is invalid")
    loops: list[str] = []
    image_stat = os.fstat(image_fd)
    for device in devices:
        require(isinstance(device, dict), "runner storage loop record is invalid")
        name = device.get("name")
        backing_file = device.get("back-file")
        require(isinstance(name, str), "runner storage loop name is invalid")
        require(isinstance(backing_file, str), "runner storage loop backing is invalid")
        require(LOOP_DEVICE.fullmatch(name) is not None, "runner storage loop name is invalid")
        backing_stat = os.stat(backing_file)
        require(
            (backing_stat.st_dev, backing_stat.st_ino)
            == (image_stat.st_dev, image_stat.st_ino),
            "runner storage loop backing differs from its image descriptor",
        )
        loops.append(name)
    require(len(set(loops)) == len(loops), "runner storage loop observation is duplicated")
    return tuple(sorted(loops))


def attach_image(image_fd: int) -> str:
    loops = associated_loops(image_fd)
    require(len(loops) <= 1, "runner storage image has multiple loop devices")
    if loops:
        return loops[0]
    handle = f"/proc/self/fd/{image_fd}"
    loop_device = run_tool(
        "losetup",
        "--find",
        "--show",
        "--nooverlap",
        handle,
        pass_fds=(image_fd,),
    )
    require(LOOP_DEVICE.fullmatch(loop_device) is not None, "runner storage loop device is invalid")
    loops = associated_loops(image_fd)
    require(loops == (loop_device,), "runner storage loop attachment is ambiguous")
    return loop_device


def read_filesystem_identity(loop_device: str) -> tuple[str, str]:
    filesystem_type = run_tool("blkid", "-s", "TYPE", "-o", "value", loop_device)
    filesystem_uuid = run_tool("blkid", "-s", "UUID", "-o", "value", loop_device)
    require(filesystem_type == "xfs", "runner storage image is not XFS")
    require(
        FILESYSTEM_UUID.fullmatch(filesystem_uuid) is not None,
        "runner storage filesystem UUID is invalid",
    )
    return filesystem_type, filesystem_uuid


def open_target(state_root_fd: int, state_root_path: Path) -> tuple[int, Path]:
    target = state_root_path / TARGET_NAME
    target_fd = os.open(
        TARGET_NAME,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=state_root_fd,
    )
    target_stat = os.fstat(target_fd)
    require(stat.S_ISDIR(target_stat.st_mode), "runner storage target is not a directory")
    return target_fd, target


def mount_loop(state_root_fd: int, state_root_path: Path, loop_device: str) -> None:
    require(
        not observable_mounts_for_loop(loop_device),
        "runner storage loop is already mounted in an observable namespace",
    )
    target_fd, target = open_target(state_root_fd, state_root_path)
    try:
        require(not mounts_at_or_below(target), "runner storage target is already mounted")
        require(not os.listdir(target_fd), "runner storage target is not empty below its mount")
        handle = f"/proc/self/fd/{target_fd}"
        run_tool(
            "mount",
            "-t",
            "xfs",
            "-o",
            "pquota,nosuid,nodev",
            "--",
            loop_device,
            handle,
            pass_fds=(target_fd,),
        )
        own_namespace = mount_namespace_id("/proc/self/ns/mnt")
        observable_mounts = observable_mounts_for_loop(loop_device)
        require(
            len(observable_mounts) == 1
            and observable_mounts[0].namespace_id == own_namespace
            and observable_mounts[0].target == str(target),
            "runner storage mount target or namespace differs after mount",
        )
    finally:
        os.close(target_fd)


def require_target_ready(state_root_fd: int, state_root_path: Path) -> None:
    target_fd, target = open_target(state_root_fd, state_root_path)
    try:
        require(not mounts_at_or_below(target), "runner storage target is already mounted")
        require(not os.listdir(target_fd), "runner storage target is not empty below its mount")
    finally:
        os.close(target_fd)


def detach_loop(loop_device: str) -> None:
    require(
        not observable_mounts_for_loop(loop_device),
        "runner storage loop remains mounted in an observable namespace",
    )
    run_tool("losetup", "--detach", loop_device)


def teardown_runtime(prefix: OpenPrefix, expected_device: int | None, expected_inode: int | None) -> None:
    target = prefix.state_root_path / TARGET_NAME
    if prefix.image_fd is None:
        require(not mounts_at_or_below(target), "runner storage target is mounted without its image")
        return
    image_stat = os.fstat(prefix.image_fd)
    require(
        expected_device is not None and expected_inode is not None,
        "runner storage expected image identity is absent before runtime teardown",
    )
    require(
        (image_stat.st_dev, image_stat.st_ino) == (expected_device, expected_inode),
        "runner storage image identity differs before runtime teardown",
    )
    loops = associated_loops(prefix.image_fd)
    require(len(loops) <= 1, "runner storage image has multiple loop devices")
    if not loops:
        require(not mounts_at_or_below(target), "runner storage target has a foreign mount")
        return
    loop_device = loops[0]
    observable_mounts = observable_mounts_for_loop(loop_device)
    target_tree = mounts_at_or_below(target)
    if observable_mounts:
        own_namespace = mount_namespace_id("/proc/self/ns/mnt")
        require(
            len(observable_mounts) == 1
            and observable_mounts[0].namespace_id == own_namespace
            and observable_mounts[0].target == str(target),
            "runner storage loop has a mount in another observable namespace or target",
        )
        require(
            len(target_tree) == 1
            and target_tree[0].target == str(target)
            and target_tree[0].device_number == loop_device_number(loop_device),
            "runner storage target has a nested or foreign mount",
        )
        # Device-target unmount is unambiguous only after the complete global
        # major:minor roster above proves this exact target is the sole mount.
        # It also avoids holding an open file on the filesystem being unmounted.
        run_tool("umount", "--", loop_device)
        require(not mounts_at_or_below(target), "runner storage target remained mounted")
        require(
            not observable_mounts_for_loop(loop_device),
            "runner storage loop remained mounted in an observable namespace",
        )
    else:
        require(not target_tree, "runner storage target has a foreign mount")
    detach_loop(loop_device)
    require(not associated_loops(prefix.image_fd), "runner storage image loop remained attached")


def create_capacity_and_image(
    prefix: OpenPrefix, image_bytes: int, caller_uid: int, caller_gid: int
) -> None:
    require(prefix.image_fd is None, "runner storage image already exists")
    if prefix.capacity_fd is None:
        os.mkdir(CAPACITY_NAME, mode=0o700, dir_fd=prefix.state_root_fd)
        prefix.capacity_fd = os.open(
            CAPACITY_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=prefix.state_root_fd,
        )
    require_descriptor_entry(
        prefix.state_root_fd, CAPACITY_NAME, prefix.capacity_fd
    )
    original_capacity = prefix.facts.capacity
    was_caller_owned = (
        original_capacity.kind == "directory"
        and original_capacity.owner_uid == caller_uid
        and original_capacity.owner_gid == caller_gid
        and original_capacity.mode == 0o700
    )
    os.fchown(prefix.capacity_fd, 0, 0)
    os.fchmod(prefix.capacity_fd, 0o700)
    children = os.listdir(prefix.capacity_fd)
    if children:
        if was_caller_owned:
            os.fchown(prefix.capacity_fd, caller_uid, caller_gid)
            os.fchmod(prefix.capacity_fd, 0o700)
        raise RunnerStorageLifecycleError("runner capacity root changed before image creation")
    try:
        require_descriptor_entry(
            prefix.state_root_fd, CAPACITY_NAME, prefix.capacity_fd
        )
    except BaseException:
        if was_caller_owned:
            os.fchown(prefix.capacity_fd, caller_uid, caller_gid)
            os.fchmod(prefix.capacity_fd, 0o700)
        raise
    prefix.image_fd = os.open(
        IMAGE_NAME,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=prefix.capacity_fd,
    )
    os.ftruncate(prefix.image_fd, image_bytes)
    os.fsync(prefix.image_fd)
    os.fchown(prefix.image_fd, 0, 0)
    os.fchmod(prefix.image_fd, 0o600)
    os.fchmod(prefix.capacity_fd, 0o711)
    require_descriptor_entry(prefix.capacity_fd, IMAGE_NAME, prefix.image_fd)
    require_descriptor_entry(
        prefix.state_root_fd, CAPACITY_NAME, prefix.capacity_fd
    )
    os.fsync(prefix.capacity_fd)
    os.fsync(prefix.state_root_fd)


def format_attach_and_mount(prefix: OpenPrefix) -> tuple[str, str]:
    require(prefix.image_fd is not None, "runner storage image descriptor is absent")
    image_handle = f"/proc/self/fd/{prefix.image_fd}"
    run_tool(
        "mkfs.xfs",
        "-q",
        "-m",
        "crc=1,finobt=1",
        "-n",
        "ftype=1",
        "--",
        image_handle,
        pass_fds=(prefix.image_fd,),
    )
    loop_device = attach_image(prefix.image_fd)
    _, filesystem_uuid = read_filesystem_identity(loop_device)
    mount_loop(prefix.state_root_fd, prefix.state_root_path, loop_device)
    return loop_device, filesystem_uuid


def require_image_identity(prefix: OpenPrefix, expected_device: int, expected_inode: int) -> None:
    require(prefix.image_fd is not None, "runner storage image descriptor is absent")
    image_stat = os.fstat(prefix.image_fd)
    require(
        (image_stat.st_dev, image_stat.st_ino) == (expected_device, expected_inode),
        "runner storage image identity differs",
    )


def recover_attach_and_mount(
    prefix: OpenPrefix,
    *,
    expected_device: int,
    expected_inode: int,
    expected_uuid: str,
) -> tuple[str, str]:
    require_image_identity(prefix, expected_device, expected_inode)
    require(FILESYSTEM_UUID.fullmatch(expected_uuid) is not None, "expected filesystem UUID is invalid")
    require(prefix.image_fd is not None, "runner storage image descriptor is absent")
    loop_device = attach_image(prefix.image_fd)
    _, filesystem_uuid = read_filesystem_identity(loop_device)
    if filesystem_uuid != expected_uuid:
        if not observable_mounts_for_loop(loop_device):
            detach_loop(loop_device)
            require(
                not associated_loops(prefix.image_fd),
                "runner storage loop remained attached after UUID rejection",
            )
        raise RunnerStorageLifecycleError("runner storage filesystem UUID differs from its receipt")
    mount_loop(prefix.state_root_fd, prefix.state_root_path, loop_device)
    return loop_device, filesystem_uuid


def remove_objects(
    prefix: OpenPrefix,
    *,
    expected_device: int | None,
    expected_inode: int | None,
) -> None:
    target = prefix.state_root_path / TARGET_NAME
    require(not mounts_at_or_below(target), "runner storage target remains mounted")
    if prefix.image_fd is not None:
        require(
            expected_device is not None and expected_inode is not None,
            "runner storage expected image identity is absent",
        )
        require_image_identity(prefix, expected_device, expected_inode)
        require(not associated_loops(prefix.image_fd), "runner storage image loop remains attached")
        require(prefix.capacity_fd is not None, "runner capacity descriptor is absent")
        require_descriptor_entry(prefix.capacity_fd, IMAGE_NAME, prefix.image_fd)
        os.unlink(IMAGE_NAME, dir_fd=prefix.capacity_fd)
        os.fsync(prefix.capacity_fd)
        os.close(prefix.image_fd)
        prefix.image_fd = None
    if prefix.capacity_fd is not None:
        require(not os.listdir(prefix.capacity_fd), "runner capacity root is not empty")
        require_descriptor_entry(
            prefix.state_root_fd, CAPACITY_NAME, prefix.capacity_fd
        )
        os.rmdir(CAPACITY_NAME, dir_fd=prefix.state_root_fd)
        os.fsync(prefix.state_root_fd)
        os.close(prefix.capacity_fd)
        prefix.capacity_fd = None


def decision_json(prefix: OpenPrefix, decision: PrefixDecision) -> dict[str, object]:
    state_root = os.fstat(prefix.state_root_fd)
    capacity = prefix.facts.capacity
    image = prefix.facts.image
    return {
        "schema": SCHEMA,
        "operation": decision.operation,
        "disposition": decision.disposition,
        "stateRoot": str(prefix.state_root_path),
        "stateRootIdentity": {
            "device": state_root.st_dev,
            "inode": state_root.st_ino,
            "ownerUid": state_root.st_uid,
            "ownerGid": state_root.st_gid,
            "mode": stat.S_IMODE(state_root.st_mode),
        },
        "capacityState": decision.capacity_state,
        "capacityIdentity": (
            None
            if capacity.kind == "absent"
            else {
                "device": capacity.device,
                "inode": capacity.inode,
                "ownerUid": capacity.owner_uid,
                "ownerGid": capacity.owner_gid,
                "mode": capacity.mode,
            }
        ),
        "imageState": decision.image_state,
        "imageIdentity": (
            None
            if image.kind == "absent"
            else {"device": image.device, "inode": image.inode, "logicalBytes": image.size}
        ),
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    subparsers = value.add_subparsers(dest="command", required=True)
    for command in (
        "inspect",
        "create-and-mount",
        "recover-and-mount",
        "teardown-runtime",
        "remove-objects",
    ):
        child = subparsers.add_parser(command)
        child.add_argument("state_root_handle")
        child.add_argument("state_root_path", type=Path)
        child.add_argument("caller_uid", type=int)
        child.add_argument("caller_gid", type=int)
        child.add_argument("image_bytes", type=int)
        if command in ("recover-and-mount", "teardown-runtime", "remove-objects"):
            child.add_argument("expected_device")
            child.add_argument("expected_inode")
        if command == "recover-and-mount":
            child.add_argument("expected_uuid")
        if command == "inspect":
            child.add_argument("--operation", choices=("prepare", "remove"), default="prepare")
    return value


def optional_identity(value: str) -> int | None:
    if value == "none":
        return None
    parsed = int(value)
    require(parsed >= 0, "runner storage expected identity is invalid")
    return parsed


def main() -> None:
    args = parser().parse_args()
    require_root_invocation(args.caller_uid, args.caller_gid)
    with inspect_prefix(
        state_root_handle=args.state_root_handle,
        state_root_path=args.state_root_path,
        caller_uid=args.caller_uid,
        caller_gid=args.caller_gid,
    ) as prefix:
        operation: Operation = (
            args.operation
            if args.command == "inspect"
            else (
                "prepare"
                if args.command in ("create-and-mount", "recover-and-mount")
                else "remove"
            )
        )
        decision = reduce_prefix_state(
            prefix.facts,
            operation=operation,
            caller_uid=args.caller_uid,
            caller_gid=args.caller_gid,
            image_bytes=args.image_bytes,
        )
        result = decision_json(prefix, decision)
        if args.command == "create-and-mount":
            require(decision.disposition == "create_new", "runner storage is not creatable")
            require_target_ready(prefix.state_root_fd, prefix.state_root_path)
            create_capacity_and_image(
                prefix, args.image_bytes, args.caller_uid, args.caller_gid
            )
            loop_device, filesystem_uuid = format_attach_and_mount(prefix)
            result.update(loopDevice=loop_device, filesystemUuid=filesystem_uuid)
        elif args.command == "recover-and-mount":
            require(
                decision.disposition == "existing_published_candidate",
                "runner storage is not a published recovery candidate",
            )
            require_target_ready(prefix.state_root_fd, prefix.state_root_path)
            expected_device = optional_identity(args.expected_device)
            expected_inode = optional_identity(args.expected_inode)
            require(
                expected_device is not None and expected_inode is not None,
                "runner storage expected image identity is absent",
            )
            loop_device, filesystem_uuid = recover_attach_and_mount(
                prefix,
                expected_device=expected_device,
                expected_inode=expected_inode,
                expected_uuid=args.expected_uuid,
            )
            result.update(loopDevice=loop_device, filesystemUuid=filesystem_uuid)
        elif args.command == "teardown-runtime":
            teardown_runtime(
                prefix,
                optional_identity(args.expected_device),
                optional_identity(args.expected_inode),
            )
        elif args.command == "remove-objects":
            remove_objects(
                prefix,
                expected_device=optional_identity(args.expected_device),
                expected_inode=optional_identity(args.expected_inode),
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (RunnerStorageLifecycleError, OSError, ValueError, subprocess.SubprocessError) as error:
        fail(str(error))
