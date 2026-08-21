#!/usr/bin/env python3
"""Own one private-mount-namespace Docker runtime for the local C16b provider.

This file is never imported from the caller's Python environment.  The shell
launcher asks root-owned ``unshare`` to start root-owned Python with ``-I -S``;
that interpreter opens this file once, verifies its pinned SHA-256, and
compiles the same verified byte buffer.  The resulting process stays in the
foreground as the direct parent and lifecycle authority for containerd and
dockerd.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, NoReturn


START_SCHEMA = "ambit.local-daytona-isolated-docker/v4"
CONTROL_SCHEMA = "ambit.local-daytona-isolated-docker-control/v1"
STOP_SCHEMA = "ambit.local-daytona-isolated-docker-stop/v1"
STORAGE_OPERATION_SCHEMA = "ambit.local-daytona-runner-storage-operation/v2"
STORAGE_RECEIPT_SCHEMA = "ambit.local-daytona-runner-storage/v2"

AUTHORITY_ROOT = Path("/home/.ambit-c16b-runner-storage")
MOUNT_TARGET = AUTHORITY_ROOT / "runner-docker"
STORAGE_IMAGE = AUTHORITY_ROOT / "runner-docker.xfs"
RUNTIME_PARENT = Path("/run")
RUNTIME_PREFIX = "ambit-c16b-docker-"
RUNTIME_DIRECTORY_ENTRIES = {"containerd-state", "containerd-temp", "docker-exec"}
RUNTIME_REGULAR_ENTRIES = {
    "containerd.toml",
    "docker.pid",
    "dockerd.json",
    "runner-storage-lifecycle.py",
    "verify-runner-storage.py",
}
RUNTIME_SOCKET_ENTRIES = {"containerd.sock", "containerd.sock.ttrpc", "docker.sock"}
STATE_ROOT_RE = re.compile(r"^/home/[^/]+/[A-Za-z0-9._/-]+$")
RUNTIME_ROOT_RE = re.compile(r"^/run/ambit-c16b-docker-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
LOOP_DEVICE_RE = re.compile(r"^/dev/loop[0-9]+$")
IMAGE_BYTES = 60 * 1024**3
SANDBOX_BYTES = 20 * 1024**3
MAXIMUM_SANDBOXES = 2

PYTHON = Path("/usr/bin/python3")
CONTAINERD = Path("/usr/bin/containerd")
DOCKERD = Path("/usr/bin/dockerd")
DOCKER = Path("/usr/bin/docker")
IP = Path("/usr/bin/ip")
UMOUNT = Path("/usr/bin/umount")

PROCESS_IDENTITY_NAME = "isolated_process_identity.py"
PROCESS_IDENTITY_SHA256 = "28ea7928529c55596174496fee625066fa05bfb0d8f6a077991aed715c1c1b15"
STORAGE_LIFECYCLE_NAME = "runner-storage-lifecycle.py"
STORAGE_LIFECYCLE_SHA256 = "991c7db087d88390d67263183afa70908710be40b49e8d5d3059958a8362641e"
STORAGE_IDENTITY_VERIFIER_NAME = "verify-runner-storage.py"
STORAGE_IDENTITY_VERIFIER_SHA256 = (
    "ff1d034329ada6f8c1596876779a990dbe7e1a0ada41f57442a899115c90579b"
)

CONTROL_RECEIPT_NAME = "outer-docker-control.json"
START_RECEIPT_NAME = "outer-docker-receipt.json"
STOP_RECEIPT_NAME = "outer-docker-stop-receipt.json"

PINNED_EXEC_LOADER = r'''
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
        raise SystemExit("pinned Python source is not regular")
    if not 0 < identity.st_size <= 2 * 1024 * 1024:
        raise SystemExit("pinned Python source size is invalid")
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
    raise SystemExit("pinned Python source digest differs")
sys.argv = [path, *arguments]
globals()["__file__"] = path
globals()["__package__"] = None
exec(compile(source, path, "exec"), globals(), globals())
'''.strip()


class SupervisorError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SupervisorError(message)


def fail(message: str, status: int = 66) -> NoReturn:
    print(message, file=sys.stderr, flush=True)
    raise SystemExit(status)


def plain_int(value: object, name: str, *, positive: bool = False) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{name} is invalid")
    require(value > 0 if positive else value >= 0, f"{name} is invalid")
    return value


def exact_keys(value: object, expected: set[str], name: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{name} is not an object")
    require(set(value) == expected, f"{name} shape differs")
    return value


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def current_boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require(UUID_RE.fullmatch(value) is not None, "kernel boot identity is invalid")
    return value


def mount_namespace(path: str = "/proc/self/ns/mnt") -> dict[str, int]:
    observed = os.stat(path)
    return {"device": observed.st_dev, "inode": observed.st_ino}


def validate_namespace(value: object, name: str) -> dict[str, int]:
    parsed = exact_keys(value, {"device", "inode"}, name)
    return {
        "device": plain_int(parsed["device"], f"{name} device"),
        "inode": plain_int(parsed["inode"], f"{name} inode", positive=True),
    }


def mountinfo_is_private(raw: str) -> bool:
    saw_record = False
    for line in raw.splitlines():
        fields = line.split()
        require("-" in fields and len(fields) >= 10, "mountinfo record is invalid")
        separator = fields.index("-")
        require(separator >= 6, "mountinfo optional field boundary is invalid")
        optional = fields[6:separator]
        require(
            not any(
                item.startswith(("shared:", "master:", "propagate_from:"))
                for item in optional
            ),
            "supervisor mount namespace propagation is not private",
        )
        saw_record = True
    require(saw_record, "supervisor mount namespace has no mount records")
    return True


def prove_private_namespace(parent_pid: int) -> dict[str, int]:
    require(parent_pid > 0, "supervisor parent process id is invalid")
    before = mount_namespace()
    parent = mount_namespace(f"/proc/{parent_pid}/ns/mnt")
    require(before != parent, "supervisor did not enter a distinct mount namespace")
    mountinfo_is_private(Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
    after = mount_namespace()
    require(before == after, "supervisor mount namespace changed during proof")
    return before


def trusted_executable(path: Path) -> Path:
    literal = os.stat(path, follow_symlinks=False)
    require(
        literal.st_uid == 0
        and literal.st_gid == 0
        and (stat.S_ISREG(literal.st_mode) or stat.S_ISLNK(literal.st_mode)),
        f"trusted executable path authority differs: {path}",
    )
    if stat.S_ISREG(literal.st_mode):
        require(
            stat.S_IMODE(literal.st_mode) & 0o022 == 0,
            f"trusted executable path is writable: {path}",
        )
    resolved = path.resolve(strict=True)
    observed = resolved.stat()
    require(stat.S_ISREG(observed.st_mode), f"trusted executable is not regular: {path}")
    require(
        observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) & 0o022 == 0,
        f"trusted executable owner or mode differs: {path}",
    )
    return resolved


def read_pinned_source(path: Path, expected_sha256: str) -> bytes:
    require(SHA256_RE.fullmatch(expected_sha256) is not None, "pinned source digest is invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        identity = os.fstat(descriptor)
        require(stat.S_ISREG(identity.st_mode), "pinned source is not regular")
        require(0 < identity.st_size <= 2 * 1024 * 1024, "pinned source size is invalid")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(descriptor)
    source = b"".join(chunks)
    require(
        hmac.compare_digest(hashlib.sha256(source).hexdigest(), expected_sha256),
        f"pinned source digest differs: {path.name}",
    )
    return source


def load_process_verifier(script_directory: Path) -> Callable[..., dict[str, object]]:
    path = script_directory / PROCESS_IDENTITY_NAME
    source = read_pinned_source(path, PROCESS_IDENTITY_SHA256)
    namespace: dict[str, Any] = {
        "__name__": "ambit_pinned_isolated_process_identity",
        "__file__": str(path),
        "__package__": None,
    }
    exec(compile(source, str(path), "exec"), namespace, namespace)
    verifier = namespace.get("verify_process")
    require(callable(verifier), "pinned process verifier entrypoint is absent")
    return verifier


def set_child_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def direct_children() -> tuple[int, ...]:
    value = Path(f"/proc/self/task/{os.getpid()}/children").read_text(encoding="ascii")
    children: list[int] = []
    for item in value.split():
        require(item.isdigit() and int(item) > 0, "direct child roster is invalid")
        children.append(int(item))
    require(len(children) == len(set(children)), "direct child roster is duplicated")
    return tuple(sorted(children))


def require_exact_children(expected: set[int]) -> None:
    require(set(direct_children()) == expected, "supervisor direct child roster differs")


def wait_for_adopted_children(expected: set[int]) -> None:
    """Wait and reap descendants adopted through the supervisor subreaper.

    A killed lifecycle helper is allowed to leave its foreground mutation
    guardian running with the storage lock OFD.  Starting a second helper while
    that child is alive would deadlock on the same lock and would blur mutation
    ownership, so the supervisor waits without signalling it and reaps it
    before permitting another lifecycle transition.
    """

    while True:
        observed = set(direct_children())
        require(expected <= observed, "expected daemon child disappeared")
        adopted = observed - expected
        for pid in adopted:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
        if set(direct_children()) == expected:
            return
        time.sleep(0.1)


def process_arguments_sha256() -> str:
    raw = Path("/proc/self/cmdline").read_bytes()
    require(raw.endswith(b"\0") and raw.count(b"\0") >= 2, "supervisor argument vector is invalid")
    return hashlib.sha256(raw).hexdigest()


@dataclass
class StateAuthority:
    path: Path
    caller_uid: int
    caller_gid: int
    root_fd: int
    evidence_fd: int

    @classmethod
    def open(cls, path: Path, caller_uid: int, caller_gid: int) -> "StateAuthority":
        require(STATE_ROOT_RE.fullmatch(str(path)) is not None, "state root path is invalid")
        require(path.resolve(strict=True) == path, "state root is not canonical")
        root_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        evidence_fd: int | None = None
        try:
            root = os.fstat(root_fd)
            path_identity = os.stat(path, follow_symlinks=False)
            require(stat.S_ISDIR(root.st_mode), "state root is not a directory")
            require(
                (root.st_dev, root.st_ino) == (path_identity.st_dev, path_identity.st_ino),
                "state root changed while opening",
            )
            require(
                (root.st_uid, root.st_gid, stat.S_IMODE(root.st_mode))
                == (caller_uid, caller_gid, 0o700),
                "state root owner, group, or mode differs",
            )
            evidence_fd = os.open(
                "evidence",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
            evidence = os.fstat(evidence_fd)
            evidence_path = os.stat("evidence", dir_fd=root_fd, follow_symlinks=False)
            require(
                (evidence.st_dev, evidence.st_ino)
                == (evidence_path.st_dev, evidence_path.st_ino),
                "evidence root changed while opening",
            )
            require(
                stat.S_ISDIR(evidence.st_mode)
                and (evidence.st_uid, evidence.st_gid, stat.S_IMODE(evidence.st_mode))
                == (caller_uid, caller_gid, 0o700),
                "evidence root owner, group, or mode differs",
            )
            return cls(path, caller_uid, caller_gid, root_fd, evidence_fd)
        except BaseException:
            if evidence_fd is not None:
                os.close(evidence_fd)
            os.close(root_fd)
            raise

    def close(self) -> None:
        os.close(self.evidence_fd)
        os.close(self.root_fd)

    def __enter__(self) -> "StateAuthority":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self.evidence_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def unlink_regular(self, name: str) -> None:
        observed = os.stat(name, dir_fd=self.evidence_fd, follow_symlinks=False)
        require(stat.S_ISREG(observed.st_mode), f"evidence entry is not regular: {name}")
        os.unlink(name, dir_fd=self.evidence_fd)
        os.fsync(self.evidence_fd)

    def write_json(self, name: str, value: dict[str, object]) -> None:
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.evidence_fd,
        )
        try:
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fchown(descriptor, self.caller_uid, self.caller_gid)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        except BaseException:
            os.close(descriptor)
            os.unlink(temporary, dir_fd=self.evidence_fd)
            raise
        os.close(descriptor)
        os.rename(
            temporary,
            name,
            src_dir_fd=self.evidence_fd,
            dst_dir_fd=self.evidence_fd,
        )
        os.fsync(self.evidence_fd)


@dataclass(frozen=True)
class RuntimeIdentity:
    path: Path
    device: int
    inode: int
    uid: int
    mode: int

    def json(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "uid": self.uid,
            "mode": self.mode,
        }


def runtime_root_for(state_root: Path) -> Path:
    identifier = hashlib.sha256(str(state_root).encode()).hexdigest()[:12]
    return RUNTIME_PARENT / f"{RUNTIME_PREFIX}{identifier}"


def create_runtime_root(path: Path) -> RuntimeIdentity:
    require(RUNTIME_ROOT_RE.fullmatch(str(path)) is not None, "runtime root path is invalid")
    parent = os.stat(RUNTIME_PARENT, follow_symlinks=False)
    require(
        stat.S_ISDIR(parent.st_mode)
        and parent.st_uid == 0
        and parent.st_gid == 0
        and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
        "runtime parent authority differs",
    )
    os.mkdir(path, 0o700)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        identity = RuntimeIdentity(
            path=path,
            device=observed.st_dev,
            inode=observed.st_ino,
            uid=observed.st_uid,
            mode=stat.S_IMODE(observed.st_mode),
        )
        require(
            identity.uid == 0 and identity.mode == 0o700,
            "runtime root owner or mode differs",
        )
        for name in ("containerd-state", "docker-exec"):
            os.mkdir(name, 0o700, dir_fd=descriptor)
        os.fsync(descriptor)
        return identity
    except BaseException:
        shutil.rmtree(path)
        raise
    finally:
        os.close(descriptor)


def verify_runtime_root(identity: RuntimeIdentity) -> int:
    require(
        RUNTIME_ROOT_RE.fullmatch(str(identity.path)) is not None,
        "runtime root path is invalid",
    )
    descriptor = os.open(identity.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed = os.fstat(descriptor)
    require(
        (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            stat.S_IMODE(observed.st_mode),
        )
        == (identity.device, identity.inode, identity.uid, identity.mode),
        "runtime root identity changed",
    )
    return descriptor


def verify_runtime_entries(descriptor: int) -> None:
    observed_names = set(os.listdir(descriptor))
    allowed = RUNTIME_DIRECTORY_ENTRIES | RUNTIME_REGULAR_ENTRIES | RUNTIME_SOCKET_ENTRIES
    require(observed_names <= allowed, "runtime root contains a foreign entry")
    for name in observed_names:
        observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if name in RUNTIME_DIRECTORY_ENTRIES:
            expected_type = stat.S_ISDIR
        elif name in RUNTIME_REGULAR_ENTRIES:
            expected_type = stat.S_ISREG
        else:
            expected_type = stat.S_ISSOCK
        require(expected_type(observed.st_mode), f"runtime entry type differs: {name}")
        require(
            observed.st_uid == 0
            and (name in RUNTIME_SOCKET_ENTRIES or observed.st_gid == 0),
            f"runtime entry owner differs: {name}",
        )


def remove_runtime_root(identity: RuntimeIdentity) -> None:
    descriptor = verify_runtime_root(identity)
    try:
        verify_runtime_entries(descriptor)
    finally:
        os.close(descriptor)
    require(
        not mount_targets_below(
            identity.path,
            Path("/proc/self/mountinfo").read_text(encoding="utf-8"),
        ),
        "runtime root retains a mount",
    )
    shutil.rmtree(identity.path)
    require(not identity.path.exists(), "runtime root remained after cleanup")


def ensure_storage_directory(
    parent_fd: int,
    name: str,
    *,
    required_mode: int,
    recoverable_modes: set[int],
) -> Path:
    require(required_mode in recoverable_modes, "storage directory mode policy is invalid")
    try:
        os.mkdir(name, required_mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        observed = os.fstat(descriptor)
        require(
            stat.S_ISDIR(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) in recoverable_modes,
            f"persistent runtime directory authority differs: {name}",
        )
        os.fchmod(descriptor, required_mode)
        os.fsync(descriptor)
        require(
            stat.S_IMODE(os.fstat(descriptor).st_mode) == required_mode,
            f"persistent runtime directory mode did not settle: {name}",
        )
    finally:
        os.close(descriptor)
    return MOUNT_TARGET / name


def write_runtime_bytes(
    runtime_fd: int,
    name: str,
    content: bytes,
    *,
    mode: int,
) -> tuple[Path, str]:
    require("/" not in name and name not in ("", ".", ".."), "runtime file name is invalid")
    require(mode in (0o400, 0o600), "runtime file mode is invalid")
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
        dir_fd=runtime_fd,
    )
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        require(
            observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == mode,
            "runtime file owner or mode differs",
        )
    finally:
        os.close(descriptor)
    runtime_path = Path(os.readlink(f"/proc/self/fd/{runtime_fd}"))
    require(
        RUNTIME_ROOT_RE.fullmatch(str(runtime_path)) is not None,
        "runtime root descriptor path differs",
    )
    return runtime_path / name, hashlib.sha256(content).hexdigest()


def write_runtime_file(runtime_fd: int, name: str, content: str) -> tuple[Path, str]:
    return write_runtime_bytes(
        runtime_fd,
        name,
        content.encode("utf-8"),
        mode=0o600,
    )


def read_route_networks(
    raw: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    value = json.loads(raw)
    require(isinstance(value, list), "host route observation is not an array")
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for route in value:
        require(isinstance(route, dict), "host route record is invalid")
        destination = route.get("dst")
        if destination in (None, "default"):
            continue
        require(isinstance(destination, str), "host route destination is invalid")
        try:
            networks.append(ipaddress.ip_network(destination, strict=False))
        except ValueError as error:
            raise SupervisorError("host route destination is unparseable") from error
    return tuple(networks)


def require_address_pool_available(run: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    reserved = ipaddress.ip_network("172.30.0.0/16")
    result = run(
        [str(IP), "-j", "route", "show"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    for observed in read_route_networks(result.stdout):
        if observed.version == reserved.version:
            require(
                not observed.overlaps(reserved),
                f"isolated Docker address pool overlaps {observed}",
            )


def normalize_storage_operation(
    value: object,
    *,
    expected_outcome: str,
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
    expected_namespace: dict[str, int],
    allow_unpublished: bool = False,
) -> dict[str, object]:
    require(
        expected_outcome in ("activated", "observed", "deactivated"),
        "runner storage expected outcome is invalid",
    )
    plain_int(caller_uid, "runner storage caller UID", positive=True)
    plain_int(caller_gid, "runner storage caller GID")
    expected_namespace = validate_namespace(
        expected_namespace,
        "expected runner storage namespace",
    )
    require(isinstance(allow_unpublished, bool), "unpublished teardown policy is invalid")
    operation = exact_keys(
        value,
        {
            "schema",
            "outcome",
            "authorityRoot",
            "mountTarget",
            "mountNamespace",
            "authorityReceiptSha256",
            "receipt",
        },
        "runner storage operation",
    )
    require(
        operation["schema"] == STORAGE_OPERATION_SCHEMA,
        "runner storage operation schema differs",
    )
    require(operation["outcome"] == expected_outcome, "runner storage operation outcome differs")
    require(
        operation["authorityRoot"] == str(AUTHORITY_ROOT),
        "runner storage authority root differs",
    )
    require(operation["mountTarget"] == str(MOUNT_TARGET), "runner storage mount target differs")
    require(
        operation["mountNamespace"]
        == f"{expected_namespace['device']}:{expected_namespace['inode']}",
        "runner storage operation namespace differs",
    )
    digest = operation["authorityReceiptSha256"]
    if operation["receipt"] is None:
        require(
            expected_outcome == "deactivated"
            and allow_unpublished
            and digest is None,
            "unpublished runner storage teardown is not authorized",
        )
        return {
            "lifecycleSchema": STORAGE_OPERATION_SCHEMA,
            "receiptSchema": None,
            "projectionDigest": None,
            "authorityRoot": str(AUTHORITY_ROOT),
            "target": str(MOUNT_TARGET),
            "image": None,
            "loop": None,
            "filesystem": None,
            "mountNamespace": expected_namespace,
        }
    require(
        isinstance(digest, str) and SHA256_RE.fullmatch(digest) is not None,
        "runner storage projection digest is invalid",
    )

    receipt = exact_keys(
        operation["receipt"],
        {
            "schema",
            "lifecycleState",
            "stateRoot",
            "stateRootIdentity",
            "authorityRoot",
            "mountTarget",
            "image",
            "loop",
            "filesystem",
            "mountNamespace",
            "backingFilesystem",
            "sandboxDiskPolicy",
        },
        "runner storage receipt",
    )
    require(receipt["schema"] == STORAGE_RECEIPT_SCHEMA, "runner storage receipt schema differs")
    expected_lifecycle_state = "detached" if expected_outcome == "deactivated" else "attached"
    require(
        receipt["lifecycleState"] == expected_lifecycle_state,
        "runner storage receipt lifecycle state differs",
    )
    require(receipt["stateRoot"] == str(state_root), "runner storage receipt state root differs")
    state_identity = exact_keys(
        receipt["stateRootIdentity"],
        {"device", "inode", "ownerUid", "ownerGid", "mode"},
        "runner storage state identity",
    )
    state_device = plain_int(state_identity["device"], "runner storage state device")
    plain_int(state_identity["inode"], "runner storage state inode", positive=True)
    require(
        (
            plain_int(state_identity["ownerUid"], "runner storage state owner"),
            plain_int(state_identity["ownerGid"], "runner storage state group"),
            state_identity["mode"],
        )
        == (caller_uid, caller_gid, "0700"),
        "runner storage state owner, group, or mode differs",
    )

    authority = exact_keys(
        receipt["authorityRoot"],
        {"path", "device", "inode", "ownerUid", "ownerGid", "mode"},
        "runner storage authority identity",
    )
    require(
        authority["path"] == str(AUTHORITY_ROOT),
        "runner storage authority identity path differs",
    )
    authority_device = plain_int(authority["device"], "runner storage authority device")
    plain_int(authority["inode"], "runner storage authority inode", positive=True)
    require(
        (
            plain_int(authority["ownerUid"], "runner storage authority owner"),
            plain_int(authority["ownerGid"], "runner storage authority group"),
            authority["mode"],
        )
        == (0, 0, "0700"),
        "runner storage authority owner, group, or mode differs",
    )
    require(
        authority_device == state_device,
        "runner storage authority backing differs from the user state root",
    )

    target = exact_keys(
        receipt["mountTarget"],
        {"path", "device", "inode", "ownerUid", "ownerGid", "mode"},
        "runner storage target identity",
    )
    require(target["path"] == str(MOUNT_TARGET), "runner storage target identity path differs")
    plain_int(target["device"], "runner storage target device")
    plain_int(target["inode"], "runner storage target inode", positive=True)
    require(
        (
            plain_int(target["ownerUid"], "runner storage target owner"),
            plain_int(target["ownerGid"], "runner storage target group"),
            target["mode"],
        )
        == (0, 0, "0700"),
        "runner storage target owner, group, or mode differs",
    )

    image = exact_keys(
        receipt["image"],
        {
            "path",
            "device",
            "inode",
            "logicalBytes",
            "allocatedBytes",
            "ownerUid",
            "ownerGid",
            "mode",
        },
        "runner storage image identity",
    )
    require(image["path"] == str(STORAGE_IMAGE), "runner storage image path differs")
    require(
        (
            plain_int(image["ownerUid"], "runner storage image owner"),
            plain_int(image["ownerGid"], "runner storage image group"),
            image["mode"],
        )
        == (0, 0, "0600"),
        "runner storage image owner, group, or mode differs",
    )
    safe_image = {
        "device": plain_int(image["device"], "runner storage image device"),
        "inode": plain_int(image["inode"], "runner storage image inode", positive=True),
        "logicalBytes": plain_int(
            image["logicalBytes"],
            "runner storage image bytes",
            positive=True,
        ),
    }
    require(
        safe_image["device"] == authority_device,
        "runner storage image backing differs",
    )
    require(
        safe_image["logicalBytes"] == IMAGE_BYTES,
        "runner storage image size differs",
    )
    allocated_bytes = plain_int(image["allocatedBytes"], "runner storage image allocation")
    require(
        allocated_bytes <= safe_image["logicalBytes"],
        "runner storage image allocation is invalid",
    )

    if expected_outcome == "deactivated":
        require(receipt["loop"] is None, "detached runner storage retains a loop")
        safe_loop = None
    else:
        loop = exact_keys(
            receipt["loop"],
            {"device", "major", "minor"},
            "runner storage loop identity",
        )
        require(
            isinstance(loop["device"], str)
            and LOOP_DEVICE_RE.fullmatch(loop["device"]) is not None,
            "runner storage loop device is invalid",
        )
        safe_loop = {
            "device": loop["device"],
            "major": plain_int(loop["major"], "runner storage loop major", positive=True),
            "minor": plain_int(loop["minor"], "runner storage loop minor"),
        }
        require(
            (os.major(target["device"]), os.minor(target["device"]))
            == (safe_loop["major"], safe_loop["minor"]),
            "runner storage target device differs from its loop",
        )

    filesystem = exact_keys(
        receipt["filesystem"],
        {"type", "uuid", "mountOptions", "totalBytes", "freeBytes", "features"},
        "runner storage filesystem identity",
    )
    require(filesystem["type"] == "xfs", "runner storage filesystem type differs")
    require(
        isinstance(filesystem["uuid"], str) and UUID_RE.fullmatch(filesystem["uuid"]) is not None,
        "runner storage filesystem UUID is invalid",
    )
    require(
        isinstance(filesystem["mountOptions"], list)
        and all(isinstance(item, str) for item in filesystem["mountOptions"]),
        "runner storage mount options are invalid",
    )
    require(
        {"pquota", "nodev", "nosuid"} <= set(filesystem["mountOptions"])
        and "ro" not in filesystem["mountOptions"],
        "runner storage mount options differ",
    )
    total_bytes = plain_int(filesystem["totalBytes"], "runner storage total bytes", positive=True)
    free_bytes = plain_int(filesystem["freeBytes"], "runner storage free bytes")
    require(free_bytes <= total_bytes, "runner storage free bytes are invalid")
    require(
        isinstance(filesystem["features"], list)
        and all(isinstance(item, str) for item in filesystem["features"]),
        "runner storage filesystem features are invalid",
    )
    receipt_namespace = validate_namespace(
        receipt["mountNamespace"],
        "runner storage receipt namespace",
    )
    require(receipt_namespace == expected_namespace, "runner storage receipt namespace differs")

    backing = exact_keys(
        receipt["backingFilesystem"],
        {
            "device",
            "totalBytes",
            "freeBytes",
            "allocationDisposition",
            "minimumFreeBytes",
        },
        "runner storage backing filesystem",
    )
    backing_device = plain_int(backing["device"], "runner storage backing device")
    require(
        backing_device == authority_device,
        "runner storage backing filesystem identity differs",
    )
    backing_total = plain_int(
        backing["totalBytes"],
        "runner storage backing total bytes",
        positive=True,
    )
    backing_free = plain_int(backing["freeBytes"], "runner storage backing free bytes")
    require(backing_free <= backing_total, "runner storage backing free bytes are invalid")
    require(
        backing["allocationDisposition"] == "sparse_current_headroom_not_preallocated",
        "runner storage allocation disposition differs",
    )
    require(
        plain_int(backing["minimumFreeBytes"], "runner storage minimum free bytes", positive=True)
        == IMAGE_BYTES,
        "runner storage minimum free bytes differ",
    )
    policy = exact_keys(
        receipt["sandboxDiskPolicy"],
        {
            "perSandboxBytes",
            "maximumSandboxes",
            "aggregateBytes",
            "enforcement",
            "backingCapacity",
        },
        "runner storage sandbox disk policy",
    )
    per_sandbox = plain_int(policy["perSandboxBytes"], "sandbox disk bytes", positive=True)
    maximum = plain_int(policy["maximumSandboxes"], "sandbox disk count", positive=True)
    require(
        plain_int(policy["aggregateBytes"], "sandbox aggregate bytes", positive=True)
        == per_sandbox * maximum,
        "sandbox disk aggregate differs",
    )
    require(
        per_sandbox == SANDBOX_BYTES and maximum == MAXIMUM_SANDBOXES,
        "sandbox disk policy limits differ",
    )
    require(
        policy["enforcement"] == "xfs_project_quota_required",
        "sandbox disk enforcement differs",
    )
    require(
        policy["backingCapacity"] == "current_headroom_with_visible_enospc_failure",
        "sandbox backing capacity disposition differs",
    )

    return {
        "lifecycleSchema": STORAGE_OPERATION_SCHEMA,
        "receiptSchema": STORAGE_RECEIPT_SCHEMA,
        "projectionDigest": digest,
        "authorityRoot": str(AUTHORITY_ROOT),
        "target": str(MOUNT_TARGET),
        "image": safe_image,
        "loop": safe_loop,
        "filesystem": {"type": "xfs", "uuid": filesystem["uuid"]},
        "mountNamespace": receipt_namespace,
    }


def invoke_storage_helper(
    *,
    helper: Path,
    command: str,
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
    namespace: dict[str, int],
    expected_outcome: str,
    expected_children: set[int],
    allow_unpublished: bool = False,
) -> dict[str, object]:
    outcomes = {
        "activate-private": "activated",
        "observe-private": "observed",
        "deactivate-private": "deactivated",
    }
    require(command in outcomes, "storage helper command is invalid")
    require(outcomes[command] == expected_outcome, "storage helper outcome authority differs")
    require(
        not allow_unpublished or command == "deactivate-private",
        "unpublished storage policy is invalid for this operation",
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C.UTF-8",
        "SUDO_UID": str(caller_uid),
        "SUDO_GID": str(caller_gid),
    }
    process = subprocess.Popen(
        [
            str(PYTHON),
            "-I",
            "-S",
            "-B",
            "-c",
            PINNED_EXEC_LOADER,
            str(helper),
            STORAGE_LIFECYCLE_SHA256,
            command,
            str(state_root),
            str(caller_uid),
            str(caller_gid),
            str(namespace["device"]),
            str(namespace["inode"]),
        ],
        cwd="/",
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        close_fds=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        wait_for_adopted_children(expected_children)
        raise SupervisorError(f"runner storage {command} timed out")
    wait_for_adopted_children(expected_children)
    require(process.returncode == 0, f"runner storage {command} failed: {stderr.strip()}")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise SupervisorError(f"runner storage {command} output is invalid") from error
    return normalize_storage_operation(
        value,
        expected_outcome=expected_outcome,
        state_root=state_root,
        caller_uid=caller_uid,
        caller_gid=caller_gid,
        expected_namespace=namespace,
        allow_unpublished=allow_unpublished,
    )


def docker_config(
    *,
    data_root: Path,
    exec_root: Path,
    pidfile: Path,
    socket: Path,
    containerd_socket: Path,
) -> str:
    value = {
        "data-root": str(data_root),
        "exec-root": str(exec_root),
        "pidfile": str(pidfile),
        "hosts": [f"unix://{socket}"],
        "group": "docker",
        "containerd": str(containerd_socket),
        "containerd-namespace": "ambit-c16b",
        "containerd-plugins-namespace": "ambit-c16b-plugins",
        "bridge": "none",
        "default-address-pools": [{"base": "172.30.0.0/16", "size": 24}],
        "iptables": False,
        "ip6tables": False,
        "ip-forward": False,
        "ip-masq": False,
        "userland-proxy": True,
        "live-restore": False,
        "storage-driver": "overlay2",
        "log-driver": "local",
        "log-opts": {"max-size": "50m", "max-file": "3"},
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def containerd_config(*, root: Path, state: Path, socket: Path, temporary: Path) -> str:
    return f"""version = 3
root = '{root}'
state = '{state}'
temp = '{temporary}'
disabled_plugins = [
  'io.containerd.cri.v1.images',
  'io.containerd.cri.v1.runtime',
  'io.containerd.nri.v1.nri',
]
required_plugins = []
imports = []

[grpc]
  address = '{socket}'
  uid = 0
  gid = 0
"""


def wait_for(
    description: str,
    predicate: Callable[[], bool],
    *,
    timeout: float,
    interval: float = 0.1,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise SupervisorError(f"{description} did not become ready")


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def decode_mount_path(value: str) -> str:
    return (
        value.replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
        .replace(r"\134", "\\")
    )


def task_netns_mounts(runtime_root: Path, raw_mountinfo: str) -> tuple[Path, ...]:
    prefix = runtime_root / "docker-exec" / "netns"
    found: list[Path] = []
    for line in raw_mountinfo.splitlines():
        fields = line.split()
        require("-" in fields and len(fields) >= 10, "mountinfo record is invalid")
        separator = fields.index("-")
        target = Path(decode_mount_path(fields[4]))
        filesystem = fields[separator + 1]
        try:
            target.relative_to(prefix)
        except ValueError:
            continue
        require(target.parent == prefix, "task network namespace mount is nested unexpectedly")
        require(filesystem == "nsfs", "task network namespace mount type differs")
        found.append(target)
    require(len(found) == len(set(found)), "task network namespace mount is duplicated")
    return tuple(sorted(found, key=lambda item: len(item.parts), reverse=True))


def mount_targets_below(root: Path, raw_mountinfo: str) -> tuple[Path, ...]:
    found: list[Path] = []
    for line in raw_mountinfo.splitlines():
        fields = line.split()
        require("-" in fields and len(fields) >= 10, "mountinfo record is invalid")
        target = Path(decode_mount_path(fields[4]))
        try:
            target.relative_to(root)
        except ValueError:
            continue
        found.append(target)
    require(len(found) == len(set(found)), "runtime mount target is duplicated")
    return tuple(sorted(found, key=lambda item: len(item.parts), reverse=True))


class RuntimeSupervisor:
    def __init__(self, state_root: Path, caller_uid: int, caller_gid: int) -> None:
        self.state_root = state_root
        self.caller_uid = caller_uid
        self.caller_gid = caller_gid
        self.script_directory = Path(__file__).resolve(strict=True).parent
        self.namespace: dict[str, int] | None = None
        self.runtime_identity: RuntimeIdentity | None = None
        self.state: StateAuthority | None = None
        self.storage: dict[str, object] | None = None
        self.deactivated_storage: dict[str, object] | None = None
        self.runtime_removed = False
        self.storage_activation_attempted = False
        self.containerd_process: subprocess.Popen[bytes] | None = None
        self.docker_process: subprocess.Popen[bytes] | None = None
        self.containerd_identity: dict[str, object] | None = None
        self.docker_identity: dict[str, object] | None = None
        self.supervisor_identity: dict[str, object] | None = None
        self.stop_requested = False
        self.shutdown_reason = "operator_request"
        self.shutdown_started = False
        self.process_verifier: Callable[..., dict[str, object]] | None = None
        self.storage_helper_path: Path | None = None
        self.socket: Path | None = None
        self.containerd_socket: Path | None = None
        self.docker_config_path: Path | None = None
        self.containerd_config_path: Path | None = None
        self.docker_config_sha256: str | None = None
        self.containerd_config_sha256: str | None = None
        self.data_root: Path | None = None
        self.containerd_root: Path | None = None
        self.server_id: str | None = None
        self.server_version: str | None = None
        self.containerd_version: str | None = None

    def expected_child_pids(self) -> set[int]:
        result: set[int] = set()
        for process in (self.containerd_process, self.docker_process):
            if process is not None and process.poll() is None:
                result.add(process.pid)
        return result

    def request_stop(self, signum: int, _: object) -> None:
        if signum == signal.SIGTERM:
            self.stop_requested = True

    def reject_interrupted_startup(self) -> None:
        require(not self.stop_requested, "supervisor startup was stopped by the operator")

    def verify_own_identity(self) -> dict[str, object]:
        require(self.process_verifier is not None, "process verifier is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        expected_digest = os.environ.get("AMBIT_SUPERVISOR_ARGUMENTS_SHA256", "")
        require(
            SHA256_RE.fullmatch(expected_digest) is not None,
            "supervisor argument authority is absent",
        )
        require(
            process_arguments_sha256() == expected_digest,
            "supervisor process arguments differ from launcher authority",
        )
        identity = self.process_verifier(
            os.getpid(),
            PYTHON,
            None,
            expected_uid=0,
            expected_arguments_sha256=expected_digest,
            expected_mount_namespace=self.namespace,
        )
        return identity

    def invoke_storage(
        self,
        command: str,
        outcome: str,
        *,
        allow_unpublished: bool = False,
    ) -> dict[str, object]:
        require(self.namespace is not None, "supervisor namespace is absent")
        require(self.storage_helper_path is not None, "storage helper snapshot is absent")
        return invoke_storage_helper(
            helper=self.storage_helper_path,
            command=command,
            state_root=self.state_root,
            caller_uid=self.caller_uid,
            caller_gid=self.caller_gid,
            namespace=self.namespace,
            expected_outcome=outcome,
            expected_children=self.expected_child_pids(),
            allow_unpublished=allow_unpublished,
        )

    def write_control_receipt(self, outcome: str = "active") -> None:
        require(outcome in ("active", "stopping"), "control outcome is invalid")
        require(self.state is not None, "state authority is absent")
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.supervisor_identity is not None, "supervisor identity is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        value: dict[str, object] = {
            "schema": CONTROL_SCHEMA,
            "outcome": outcome,
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(self.state_root),
            "caller": {"uid": self.caller_uid, "gid": self.caller_gid},
            "supervisorSourceSha256": os.environ["AMBIT_SUPERVISOR_SOURCE_SHA256"],
            "processIdentitySourceSha256": PROCESS_IDENTITY_SHA256,
            "storageLifecycleSourceSha256": STORAGE_LIFECYCLE_SHA256,
            "runtimeRoot": str(self.runtime_identity.path),
            "runtimeRootIdentity": self.runtime_identity.json(),
            "mountNamespace": self.namespace,
            "supervisorProcessIdentity": self.supervisor_identity,
        }
        self.state.write_json(CONTROL_RECEIPT_NAME, value)

    def setup(self) -> None:
        require(os.geteuid() == 0 and os.getegid() == 0, "supervisor is not root")
        require(
            os.environ.get("SUDO_UID") == str(self.caller_uid)
            and os.environ.get("SUDO_GID") == str(self.caller_gid),
            "supervisor caller identity differs",
        )
        for executable in (PYTHON, CONTAINERD, DOCKERD, DOCKER, IP, UMOUNT):
            trusted_executable(executable)
        set_child_subreaper()
        require_exact_children(set())
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGQUIT, signal.SIG_IGN)
        self.namespace = prove_private_namespace(os.getppid())
        self.process_verifier = load_process_verifier(self.script_directory)
        self.supervisor_identity = self.verify_own_identity()
        self.state = StateAuthority.open(self.state_root, self.caller_uid, self.caller_gid)
        require(
            not self.state.exists(CONTROL_RECEIPT_NAME)
            and not self.state.exists(START_RECEIPT_NAME),
            "isolated runtime receipt already exists",
        )
        require_address_pool_available(subprocess.run)
        require_exact_children(set())
        if self.state.exists(STOP_RECEIPT_NAME):
            self.state.unlink_regular(STOP_RECEIPT_NAME)
        self.runtime_identity = create_runtime_root(runtime_root_for(self.state_root))
        self.snapshot_storage_sources()
        self.write_control_receipt()
        self.reject_interrupted_startup()
        self.storage_activation_attempted = True
        self.storage = self.invoke_storage("activate-private", "activated")
        self.reject_interrupted_startup()
        self.prepare_daemon_configuration()
        self.reject_interrupted_startup()
        self.start_daemons()
        self.reject_interrupted_startup()
        observed_storage = self.invoke_storage("observe-private", "observed")
        require(
            canonical_json(observed_storage) == canonical_json(self.storage),
            "runner storage projection changed after daemon startup",
        )
        self.reject_interrupted_startup()
        self.reprove_daemons()
        final_supervisor_identity = self.verify_own_identity()
        require(
            final_supervisor_identity == self.supervisor_identity,
            "supervisor identity changed during startup",
        )
        self.reject_interrupted_startup()
        self.write_start_receipt()

    def snapshot_storage_sources(self) -> None:
        require(self.runtime_identity is not None, "runtime identity is absent")
        helper_source = read_pinned_source(
            self.script_directory / STORAGE_LIFECYCLE_NAME,
            STORAGE_LIFECYCLE_SHA256,
        )
        verifier_source = read_pinned_source(
            self.script_directory / STORAGE_IDENTITY_VERIFIER_NAME,
            STORAGE_IDENTITY_VERIFIER_SHA256,
        )
        runtime_fd = verify_runtime_root(self.runtime_identity)
        try:
            helper_path, helper_digest = write_runtime_bytes(
                runtime_fd,
                STORAGE_LIFECYCLE_NAME,
                helper_source,
                mode=0o400,
            )
            _, verifier_digest = write_runtime_bytes(
                runtime_fd,
                STORAGE_IDENTITY_VERIFIER_NAME,
                verifier_source,
                mode=0o400,
            )
        finally:
            os.close(runtime_fd)
        require(
            helper_digest == STORAGE_LIFECYCLE_SHA256
            and verifier_digest == STORAGE_IDENTITY_VERIFIER_SHA256,
            "runtime storage source snapshot digest differs",
        )
        self.storage_helper_path = helper_path

    def prepare_daemon_configuration(self) -> None:
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.storage is not None, "storage activation is absent")
        target_fd = os.open(MOUNT_TARGET, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            target = os.fstat(target_fd)
            require(
                target.st_uid == 0
                and target.st_gid == 0
                and stat.S_IMODE(target.st_mode) == 0o700,
                "runner storage target owner or mode differs",
            )
            loop = exact_keys(
                self.storage["loop"],
                {"device", "major", "minor"},
                "active runner storage loop",
            )
            require(
                (os.major(target.st_dev), os.minor(target.st_dev))
                == (loop["major"], loop["minor"]),
                "runner storage target backing device changed after activation",
            )
            self.data_root = ensure_storage_directory(
                target_fd,
                "outer-docker",
                required_mode=0o710,
                recoverable_modes={0o700, 0o710},
            )
            self.containerd_root = ensure_storage_directory(
                target_fd,
                "outer-containerd",
                required_mode=0o700,
                recoverable_modes={0o700},
            )
        finally:
            os.close(target_fd)

        runtime_fd = verify_runtime_root(self.runtime_identity)
        try:
            runtime = self.runtime_identity.path
            self.socket = runtime / "docker.sock"
            self.containerd_socket = runtime / "containerd.sock"
            exec_root = runtime / "docker-exec"
            pidfile = runtime / "docker.pid"
            docker_value = docker_config(
                data_root=self.data_root,
                exec_root=exec_root,
                pidfile=pidfile,
                socket=self.socket,
                containerd_socket=self.containerd_socket,
            )
            containerd_value = containerd_config(
                root=self.containerd_root,
                state=runtime / "containerd-state",
                socket=self.containerd_socket,
                temporary=runtime / "containerd-temp",
            )
            self.docker_config_path, self.docker_config_sha256 = write_runtime_file(
                runtime_fd, "dockerd.json", docker_value
            )
            self.containerd_config_path, self.containerd_config_sha256 = write_runtime_file(
                runtime_fd, "containerd.toml", containerd_value
            )
        finally:
            os.close(runtime_fd)

    def daemon_environment(self) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": "/root"}

    def start_daemons(self) -> None:
        require(self.process_verifier is not None, "process verifier is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        require(self.containerd_config_path is not None, "containerd config is absent")
        require(self.docker_config_path is not None, "Docker config is absent")
        require(
            self.containerd_socket is not None and self.socket is not None,
            "daemon socket path is absent",
        )
        environment = self.daemon_environment()
        self.containerd_process = subprocess.Popen(
            [
                str(CONTAINERD),
                "--config",
                str(self.containerd_config_path),
                "--log-level",
                "info",
            ],
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
            stderr=sys.stderr,
            close_fds=True,
        )
        wait_for(
            "dedicated containerd",
            lambda: self.containerd_process is not None
            and self.containerd_process.poll() is None
            and self.containerd_socket is not None
            and self.containerd_socket.is_socket(),
            timeout=30,
        )
        first_containerd = self.process_verifier(
            self.containerd_process.pid,
            CONTAINERD,
            ("--config", str(self.containerd_config_path), "--log-level", "info"),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
        )
        self.containerd_version = subprocess.run(
            [str(CONTAINERD), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        require_exact_children({self.containerd_process.pid})

        self.docker_process = subprocess.Popen(
            [str(DOCKERD), "--config-file", str(self.docker_config_path)],
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
            stderr=sys.stderr,
            close_fds=True,
        )
        wait_for(
            "isolated Docker daemon",
            lambda: self.docker_process is not None
            and self.docker_process.poll() is None
            and self.socket is not None
            and self.socket.is_socket(),
            timeout=60,
        )
        first_docker = self.process_verifier(
            self.docker_process.pid,
            DOCKERD,
            ("--config-file", str(self.docker_config_path)),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
        )
        info = self.docker_command(
            "info",
            "--format",
            "{{json .}}",
        )
        try:
            info_value = json.loads(info)
        except json.JSONDecodeError as error:
            raise SupervisorError("isolated Docker info is invalid") from error
        require(isinstance(info_value, dict), "isolated Docker info is not an object")
        require(
            info_value.get("DockerRootDir") == str(self.data_root),
            "isolated Docker data root differs",
        )
        self.server_id = info_value.get("ID")
        self.server_version = info_value.get("ServerVersion")
        require(
            isinstance(self.server_id, str) and UUID_RE.fullmatch(self.server_id) is not None,
            "isolated Docker server identity is invalid",
        )
        require(
            isinstance(self.server_version, str) and 0 < len(self.server_version) <= 128,
            "isolated Docker server version is invalid",
        )
        second_containerd = self.process_verifier(
            self.containerd_process.pid,
            CONTAINERD,
            ("--config", str(self.containerd_config_path), "--log-level", "info"),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
        )
        second_docker = self.process_verifier(
            self.docker_process.pid,
            DOCKERD,
            ("--config-file", str(self.docker_config_path)),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
        )
        require(first_containerd == second_containerd, "containerd identity changed during startup")
        require(first_docker == second_docker, "dockerd identity changed during startup")
        self.containerd_identity = second_containerd
        self.docker_identity = second_docker
        require_exact_children({self.containerd_process.pid, self.docker_process.pid})

    def reprove_daemons(self) -> None:
        require(self.process_verifier is not None, "process verifier is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        require(self.containerd_process is not None, "containerd process is absent")
        require(self.docker_process is not None, "Docker process is absent")
        require(self.containerd_config_path is not None, "containerd config is absent")
        require(self.docker_config_path is not None, "Docker config is absent")
        require(
            self.containerd_process.poll() is None and self.docker_process.poll() is None,
            "isolated daemon exited before publication",
        )
        containerd_identity = self.process_verifier(
            self.containerd_process.pid,
            CONTAINERD,
            ("--config", str(self.containerd_config_path), "--log-level", "info"),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
        )
        docker_identity = self.process_verifier(
            self.docker_process.pid,
            DOCKERD,
            ("--config-file", str(self.docker_config_path)),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
        )
        require(
            containerd_identity == self.containerd_identity
            and docker_identity == self.docker_identity,
            "isolated daemon identity changed before publication",
        )
        require_exact_children(
            {self.containerd_process.pid, self.docker_process.pid}
        )

    def docker_command(self, *arguments: str) -> str:
        require(self.socket is not None, "Docker socket is absent")
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C.UTF-8",
            "HOME": "/root",
            "DOCKER_HOST": f"unix://{self.socket}",
        }
        result = subprocess.run(
            [str(DOCKER), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd="/",
            env=environment,
        )
        require_exact_children(self.expected_child_pids())
        return result.stdout.strip()

    def write_start_receipt(self) -> None:
        require(self.state is not None, "state authority is absent")
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.supervisor_identity is not None, "supervisor identity is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        require(self.storage is not None, "storage projection is absent")
        require(
            self.containerd_identity is not None
            and self.docker_identity is not None,
            "daemon identity is absent",
        )
        require(
            self.containerd_process is not None
            and self.docker_process is not None,
            "daemon process is absent",
        )
        require(
            self.socket is not None and self.containerd_socket is not None,
            "daemon socket is absent",
        )
        require(
            self.data_root is not None and self.containerd_root is not None,
            "daemon data root is absent",
        )
        value: dict[str, object] = {
            "schema": START_SCHEMA,
            "outcome": "passed",
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(self.state_root),
            "caller": {"uid": self.caller_uid, "gid": self.caller_gid},
            "supervisorSourceSha256": os.environ["AMBIT_SUPERVISOR_SOURCE_SHA256"],
            "processIdentitySourceSha256": PROCESS_IDENTITY_SHA256,
            "storageLifecycleSourceSha256": STORAGE_LIFECYCLE_SHA256,
            "runtimeRoot": str(self.runtime_identity.path),
            "runtimeRootIdentity": self.runtime_identity.json(),
            "supervisorProcessIdentity": self.supervisor_identity,
            "mountNamespace": self.namespace,
            "storage": self.storage,
            "socket": str(self.socket),
            "dataRoot": str(self.data_root),
            "execRoot": str(self.runtime_identity.path / "docker-exec"),
            "containerd": {
                "address": str(self.containerd_socket),
                "root": str(self.containerd_root),
                "version": self.containerd_version,
                "configSha256": self.containerd_config_sha256,
                "processIdentity": self.containerd_identity,
            },
            "network": {
                "defaultBridge": "disabled",
                "addressPool": "172.30.0.0/16",
                "hostFirewallMutation": False,
            },
            "serverId": self.server_id,
            "serverVersion": self.server_version,
            "configSha256": self.docker_config_sha256,
            "dockerProcessIdentity": self.docker_identity,
        }
        self.state.write_json(START_RECEIPT_NAME, value)

    def monitor(self) -> int:
        next_guardian_proof = 0.0
        while True:
            if self.stop_requested:
                if self.try_shutdown(self.shutdown_reason):
                    return 0
                self.stop_requested = False
            if self.shutdown_started:
                time.sleep(0.25)
                continue
            for name, process in (
                ("containerd", self.containerd_process),
                ("dockerd", self.docker_process),
            ):
                if process is not None and process.poll() is not None:
                    self.shutdown_reason = f"{name}_unexpected_exit"
                    if self.try_shutdown(self.shutdown_reason):
                        return 70
            if time.monotonic() >= next_guardian_proof:
                try:
                    observed_supervisor = self.verify_own_identity()
                except Exception as error:
                    print(
                        f"root guardian proof failed: {error}",
                        file=sys.stderr,
                        flush=True,
                    )
                    observed_supervisor = None
                if observed_supervisor != self.supervisor_identity:
                    self.shutdown_reason = "root_guardian_lost"
                    if self.try_shutdown(self.shutdown_reason):
                        return 71
                next_guardian_proof = time.monotonic() + 1.0
            time.sleep(0.25)

    def terminate_daemon(self, name: str, process: subprocess.Popen[bytes] | None) -> None:
        if process is None or process.poll() is not None:
            if process is not None:
                process.wait(timeout=0)
            return
        require(self.process_verifier is not None, "process verifier is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        if name == "dockerd":
            require(self.docker_config_path is not None, "Docker config is absent")
            executable = DOCKERD
            arguments = ("--config-file", str(self.docker_config_path))
            expected_identity = self.docker_identity
        elif name == "containerd":
            require(self.containerd_config_path is not None, "containerd config is absent")
            executable = CONTAINERD
            arguments = ("--config", str(self.containerd_config_path), "--log-level", "info")
            expected_identity = self.containerd_identity
        else:
            raise SupervisorError("unsupported daemon shutdown authority")
        observed_identity = self.process_verifier(
            process.pid,
            executable,
            arguments,
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
        )
        if expected_identity is not None:
            require(observed_identity == expected_identity, f"{name} identity changed before stop")
        process.terminate()
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired as error:
            raise SupervisorError(f"{name} did not stop within 60 seconds") from error

    def cleanup_task_netns(self) -> None:
        require(self.runtime_identity is not None, "runtime identity is absent")
        raw = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
        for target in task_netns_mounts(self.runtime_identity.path, raw):
            subprocess.run(
                [str(UMOUNT), "--", str(target)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
            )
            require_exact_children(self.expected_child_pids())
        remaining = task_netns_mounts(
            self.runtime_identity.path,
            Path("/proc/self/mountinfo").read_text(encoding="utf-8"),
        )
        require(not remaining, "task network namespace mount remained after cleanup")

    def try_shutdown(self, reason: str) -> bool:
        require(self.state is not None, "state authority is absent")
        first_attempt = not self.shutdown_started
        self.shutdown_started = True
        try:
            if first_attempt and self.state.exists(CONTROL_RECEIPT_NAME):
                self.write_control_receipt("stopping")
            # Docker owns running containers; it must drain before its dedicated
            # containerd.  The storage mount stays alive until both are reaped.
            self.terminate_daemon("dockerd", self.docker_process)
            self.terminate_daemon("containerd", self.containerd_process)
            wait_for_adopted_children(set())
            self.cleanup_task_netns()
            if self.storage_activation_attempted and self.deactivated_storage is None:
                self.deactivated_storage = self.invoke_storage(
                    "deactivate-private",
                    "deactivated",
                    allow_unpublished=self.storage is None,
                )
            if self.runtime_identity is not None and not self.runtime_removed:
                remove_runtime_root(self.runtime_identity)
                self.runtime_removed = True
            value: dict[str, object] = {
                "schema": STOP_SCHEMA,
                "outcome": "passed",
                "observedAt": utc_now(),
                "bootId": current_boot_id(),
                "stateRoot": str(self.state_root),
                "reason": reason,
                "supervisorProcessIdentity": self.supervisor_identity,
                "storageProjectionDigest": (
                    self.deactivated_storage["projectionDigest"]
                    if self.deactivated_storage is not None
                    else None
                ),
                "runtimeRootRemoved": True,
            }
            self.state.write_json(STOP_RECEIPT_NAME, value)
            if self.state.exists(START_RECEIPT_NAME):
                self.state.unlink_regular(START_RECEIPT_NAME)
            if self.state.exists(CONTROL_RECEIPT_NAME):
                self.state.unlink_regular(CONTROL_RECEIPT_NAME)
            return True
        except BaseException as error:
            failure: dict[str, object] = {
                "schema": STOP_SCHEMA,
                "outcome": "retry_required",
                "observedAt": utc_now(),
                "bootId": current_boot_id(),
                "stateRoot": str(self.state_root),
                "reason": reason,
                "error": str(error),
                "supervisorProcessIdentity": self.supervisor_identity,
                "runtimeRootRemoved": False,
            }
            self.state.write_json(STOP_RECEIPT_NAME, failure)
            print(f"isolated runtime shutdown requires retry: {error}", file=sys.stderr, flush=True)
            return False

    def run(self) -> int:
        try:
            self.setup()
        except BaseException as error:
            print(f"isolated runtime startup failed: {error}", file=sys.stderr, flush=True)
            if self.state is not None and self.runtime_identity is not None:
                self.stop_requested = True
                self.shutdown_reason = "startup_failure"
                while not self.try_shutdown(self.shutdown_reason):
                    signal.pause()
            raise
        return self.monitor()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument("operation", choices=("supervise",))
    value.add_argument("state_root", type=Path)
    value.add_argument("caller_uid")
    value.add_argument("caller_gid")
    return value


def main() -> None:
    args = parser().parse_args()
    require(re.fullmatch(r"[1-9][0-9]*", args.caller_uid) is not None, "caller UID is invalid")
    require(re.fullmatch(r"[0-9]+", args.caller_gid) is not None, "caller GID is invalid")
    source_digest = os.environ.get("AMBIT_SUPERVISOR_SOURCE_SHA256", "")
    require(SHA256_RE.fullmatch(source_digest) is not None, "supervisor source authority is absent")
    supervisor = RuntimeSupervisor(args.state_root, int(args.caller_uid), int(args.caller_gid))
    raise SystemExit(supervisor.run())


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        fail(str(error))
