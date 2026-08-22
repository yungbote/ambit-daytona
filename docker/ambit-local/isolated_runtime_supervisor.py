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
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, NoReturn


LIBC = ctypes.CDLL(None, use_errno=True)

START_SCHEMA = "ambit.local-daytona-isolated-docker/v5"
CONTROL_SCHEMA = "ambit.local-daytona-isolated-docker-control/v2"
STOP_SCHEMA = "ambit.local-daytona-isolated-docker-stop/v2"
STOPPING_SCHEMA = "ambit.local-daytona-isolated-docker-stopping/v1"
CONTROL_PROJECTION_SCHEMA = "ambit.local-daytona-isolated-docker-control-projection/v1"
READY_PROJECTION_SCHEMA = "ambit.local-daytona-isolated-docker-ready-projection/v1"
STORAGE_OPERATION_SCHEMA = "ambit.local-daytona-runner-storage-operation/v3"
STORAGE_RECEIPT_SCHEMA = "ambit.local-daytona-runner-storage/v3"

AUTHORITY_ROOT = Path("/home/.ambit-c16b-runner-storage")
MOUNT_TARGET = AUTHORITY_ROOT / "runner-docker"
STORAGE_IMAGE = AUTHORITY_ROOT / "runner-docker.xfs"
RUNTIME_PARENT = Path("/run")
RUNTIME_PREFIX = "ambit-c16b-docker-"
SOCKET_ROOT_PREFIX = "ambit-c16b-docker-api-"
LEASE_SUFFIX = ".lock"
STATE_ROOT_RE = re.compile(r"^/home/[^/]+/[A-Za-z0-9._/-]+$")
RUNTIME_ROOT_RE = re.compile(r"^/run/ambit-c16b-docker-[0-9a-f]{12}$")
SOCKET_ROOT_RE = re.compile(r"^/run/ambit-c16b-docker-api-[0-9a-f]{12}$")
LEASE_PATH_RE = re.compile(r"^/run/ambit-c16b-docker-[0-9a-f]{12}\.lock$")
CGROUP_PARENT = Path("/sys/fs/cgroup")
CGROUP_PREFIX = "ambit-c16b-docker-"
CGROUP_EXECUTION_NAME = "runtime"
CGROUP_PATH_RE = re.compile(r"^/sys/fs/cgroup/ambit-c16b-docker-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
DOCKER_DAEMON_ID_RE = re.compile(r"^[A-Z2-7]{4}(?::[A-Z2-7]{4}){11}$")
CONTAINERD_VERSION_RE = re.compile(r"\bv([0-9]+)\.[0-9]+\.[0-9]+(?:[-+][^\s]+)?\b")
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
SUPERVISOR_SNAPSHOT_NAME = "isolated_runtime_supervisor.py"
PROCESS_IDENTITY_SHA256 = "f22094f90f8797ee54ed439ee53e7f464ab59eff060cfbf252c6b8daa968a131"
STORAGE_LIFECYCLE_NAME = "runner-storage-lifecycle.py"
STORAGE_LIFECYCLE_SHA256 = "ecb7376d91031227bd5bd8514f2b68910449443f120a738e5c310543bad6f4eb"
STORAGE_IDENTITY_VERIFIER_NAME = "verify-runner-storage.py"
STORAGE_IDENTITY_VERIFIER_SHA256 = (
    "59c530e8c502c546689967c33c540217d2762ff9d3f8ef7424ba52462c554f0b"
)
RUNTIME_DIRECTORY_ENTRIES = {"containerd-state", "containerd-temp", "docker-exec"}
RUNTIME_REGULAR_ENTRIES = {
    "containerd.toml",
    "docker.pid",
    "dockerd.json",
    SUPERVISOR_SNAPSHOT_NAME,
    PROCESS_IDENTITY_NAME,
    STORAGE_LIFECYCLE_NAME,
    STORAGE_IDENTITY_VERIFIER_NAME,
    "runtime-control.json",
    "runtime-ready.json",
    "runtime-stopping.json",
    "runtime-stop.json",
    ".runtime-control.json.pending",
    ".runtime-ready.json.pending",
    ".runtime-stopping.json.pending",
    ".runtime-stop.json.pending",
}
RUNTIME_SOCKET_ENTRIES = {"containerd.sock", "containerd.sock.ttrpc"}

ROOT_CONTROL_NAME = "runtime-control.json"
ROOT_READY_NAME = "runtime-ready.json"
ROOT_STOPPING_NAME = "runtime-stopping.json"
ROOT_STOP_NAME = "runtime-stop.json"
SOCKET_NAME = "docker.sock"
LEGACY_V4_RUNTIME_MARKERS = {
    "dockerd.json",
    "containerd.toml",
    "docker.sock",
    "docker.pid",
    "containerd.sock",
}
LEGACY_V4_DIAGNOSTIC = (
    "legacy v4 runtime has no root control/supervisor snapshot; "
    "use the exact frozen v4 stop source or explicit root-admin cleanup"
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
globals()["__verified_source_sha256__"] = expected
globals()["__fallback_script_directory__"] = os.path.dirname(path)
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


def verified_supervisor_source_sha256() -> str:
    value = globals().get("__verified_source_sha256__")
    if value is None:
        value = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, "supervisor source digest is invalid")
    return value


def fallback_script_directory() -> Path:
    value = globals().get("__fallback_script_directory__")
    if value is None:
        return Path(__file__).resolve(strict=True).parent
    require(isinstance(value, str) and value.startswith("/"), "fallback source directory is invalid")
    return Path(value)


def require_root_credentials() -> None:
    status = Path("/proc/self/status").read_text(encoding="ascii")
    for label in ("Uid:", "Gid:"):
        line = next((item for item in status.splitlines() if item.startswith(label)), "")
        fields = line.split()[1:]
        require(
            len(fields) == 4 and all(value == "0" for value in fields),
            f"runtime {label[:-1].lower()} credentials are not fully root",
        )


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


def validate_docker_daemon_id(value: object) -> str:
    require(
        isinstance(value, str)
        and len(value) == 59
        and DOCKER_DAEMON_ID_RE.fullmatch(value) is not None,
        "isolated Docker server identity is invalid",
    )
    return value


def require_containerd_v2_or_later(value: str) -> str:
    require(isinstance(value, str) and 0 < len(value) <= 512, "containerd version is invalid")
    matches = CONTAINERD_VERSION_RE.findall(value)
    require(matches and int(matches[-1]) >= 2, "containerd 2.x or later is required")
    return value


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


def load_process_authority(script_directory: Path) -> dict[str, Any]:
    path = script_directory / PROCESS_IDENTITY_NAME
    source = read_pinned_source(path, PROCESS_IDENTITY_SHA256)
    namespace: dict[str, Any] = {
        "__name__": "ambit_pinned_isolated_process_identity",
        "__file__": str(path),
        "__package__": None,
    }
    exec(compile(source, str(path), "exec"), namespace, namespace)
    for name in (
        "verify_process",
        "validate_recorded_identity",
        "verify_recorded_process",
        "signal_recorded_process",
    ):
        require(callable(namespace.get(name)), f"pinned process authority entrypoint is absent: {name}")
    return namespace


def load_process_verifier(script_directory: Path) -> Callable[..., dict[str, object]]:
    return load_process_authority(script_directory)["verify_process"]


def set_child_subreaper() -> None:
    result = LIBC.prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def parent_death_preexec(expected_parent_pid: int) -> Callable[[], None]:
    def configure() -> None:
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
            signal.signal(signum, signal.SIG_DFL)
        result = LIBC.prctl(1, signal.SIGTERM, 0, 0, 0)  # PR_SET_PDEATHSIG
        if result != 0:
            os._exit(70)
        if os.getppid() != expected_parent_pid:
            os._exit(71)

    return configure


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


def wait_for_adopted_children(expected: set[int], *, timeout: float = 30.0) -> None:
    """Wait and reap descendants adopted through the supervisor subreaper.

    A killed lifecycle helper is allowed to leave its foreground mutation
    guardian running with the storage lock OFD.  Starting a second helper while
    that child is alive would deadlock on the same lock and would blur mutation
    ownership, so the supervisor waits without signalling it and reaps it
    before permitting another lifecycle transition.
    """

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
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
    raise SupervisorError("adopted child did not exit before timeout")


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

    def identity_json(self) -> dict[str, object]:
        root = os.fstat(self.root_fd)
        evidence = os.fstat(self.evidence_fd)
        return {
            "stateRoot": {
                "path": str(self.path),
                "device": root.st_dev,
                "inode": root.st_ino,
                "uid": root.st_uid,
                "gid": root.st_gid,
                "mode": stat.S_IMODE(root.st_mode),
            },
            "evidenceRoot": {
                "path": str(self.path / "evidence"),
                "device": evidence.st_dev,
                "inode": evidence.st_ino,
                "uid": evidence.st_uid,
                "gid": evidence.st_gid,
                "mode": stat.S_IMODE(evidence.st_mode),
            },
        }

    def exists(self, name: str) -> bool:
        try:
            os.stat(name, dir_fd=self.evidence_fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def unlink_regular(self, name: str) -> None:
        observed = os.stat(name, dir_fd=self.evidence_fd, follow_symlinks=False)
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_uid == self.caller_uid
            and observed.st_gid == self.caller_gid
            and stat.S_IMODE(observed.st_mode) == 0o600
            and observed.st_nlink == 1,
            f"evidence entry identity differs: {name}",
        )
        os.unlink(name, dir_fd=self.evidence_fd)
        os.fsync(self.evidence_fd)

    def write_json(self, name: str, value: dict[str, object]) -> None:
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        temporary = f".{name}.pending"
        pending = None
        try:
            pending = os.stat(temporary, dir_fd=self.evidence_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        if pending is not None:
            require(
                stat.S_ISREG(pending.st_mode)
                and pending.st_uid == self.caller_uid
                and pending.st_gid == self.caller_gid
                and stat.S_IMODE(pending.st_mode) == 0o600
                and pending.st_nlink == 1,
                f"evidence pending entry identity differs: {temporary}",
            )
            os.unlink(temporary, dir_fd=self.evidence_fd)
            os.fsync(self.evidence_fd)
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
        finally:
            os.close(descriptor)
        try:
            os.replace(
                temporary,
                name,
                src_dir_fd=self.evidence_fd,
                dst_dir_fd=self.evidence_fd,
            )
            os.fsync(self.evidence_fd)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=self.evidence_fd)
                os.fsync(self.evidence_fd)
            except OSError:
                pass
            raise


@dataclass(frozen=True)
class StoredStateAuthority:
    path: Path
    caller_uid: int
    caller_gid: int
    state_identity: dict[str, object]
    evidence_identity: dict[str, object]

    def identity_json(self) -> dict[str, object]:
        return {
            "stateRoot": self.state_identity,
            "evidenceRoot": self.evidence_identity,
        }


@dataclass(frozen=True)
class RuntimeIdentity:
    path: Path
    device: int
    inode: int
    uid: int
    gid: int
    mode: int

    def json(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "uid": self.uid,
            "gid": self.gid,
            "mode": self.mode,
        }


@dataclass(frozen=True)
class SocketPathIdentity:
    path: Path
    device: int
    inode: int
    uid: int
    gid: int
    mode: int

    def json(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "device": self.device,
            "inode": self.inode,
            "uid": self.uid,
            "gid": self.gid,
            "mode": self.mode,
        }


@dataclass(frozen=True)
class CgroupIdentity:
    path: Path
    device: int
    inode: int

    def json(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "device": self.device,
            "inode": self.inode,
        }


@dataclass
class RuntimeLease:
    path: Path
    parent_fd: int
    descriptor: int
    device: int
    inode: int

    @classmethod
    def acquire(cls, state_root: Path, *, blocking: bool = False) -> "RuntimeLease":
        path = lease_path_for(state_root)
        require(LEASE_PATH_RE.fullmatch(str(path)) is not None, "runtime lease path is invalid")
        parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor: int | None = None
        try:
            parent = os.fstat(parent_fd)
            require(
                stat.S_ISDIR(parent.st_mode)
                and parent.st_uid == 0
                and parent.st_gid == 0
                and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
                "runtime lease parent authority differs",
            )
            descriptor = os.open(
                path.name,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
            observed = os.fstat(descriptor)
            literal = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            require(
                stat.S_ISREG(observed.st_mode)
                and observed.st_uid == 0
                and observed.st_gid == 0
                and stat.S_IMODE(observed.st_mode) == 0o600
                and observed.st_nlink == 1
                and (observed.st_dev, observed.st_ino) == (literal.st_dev, literal.st_ino),
                "runtime lease identity differs",
            )
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            try:
                fcntl.flock(descriptor, flags)
            except BlockingIOError as error:
                raise SupervisorError("runtime lifecycle lease is busy") from error
            os.fsync(descriptor)
            os.fsync(parent_fd)
            return cls(path, parent_fd, descriptor, observed.st_dev, observed.st_ino)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent_fd)
            raise

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def __enter__(self) -> "RuntimeLease":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def runtime_id_for(state_root: Path) -> str:
    return hashlib.sha256(str(state_root).encode()).hexdigest()[:12]


def runtime_root_for(state_root: Path) -> Path:
    return RUNTIME_PARENT / f"{RUNTIME_PREFIX}{runtime_id_for(state_root)}"


def socket_root_for(state_root: Path) -> Path:
    return RUNTIME_PARENT / f"{SOCKET_ROOT_PREFIX}{runtime_id_for(state_root)}"


def lease_path_for(state_root: Path) -> Path:
    return RUNTIME_PARENT / f"{RUNTIME_PREFIX}{runtime_id_for(state_root)}{LEASE_SUFFIX}"


def cgroup_path_for(state_root: Path) -> Path:
    return CGROUP_PARENT / f"{CGROUP_PREFIX}{runtime_id_for(state_root)}"


def execution_cgroup_path(identity: CgroupIdentity) -> str:
    return f"/{identity.path.name}/{CGROUP_EXECUTION_NAME}"


def _read_fd_all(descriptor: int, *, limit: int = 64 * 1024) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(descriptor, 4096)
        if not block:
            return b"".join(chunks)
        total += len(block)
        require(total <= limit, "kernel authority document is too large")
        chunks.append(block)


def _read_at(directory_fd: int, name: str) -> str:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        return _read_fd_all(descriptor).decode("ascii", "strict")
    finally:
        os.close(descriptor)


def _write_at(directory_fd: int, name: str, value: bytes) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        offset = 0
        while offset < len(value):
            offset += os.write(descriptor, value[offset:])
    finally:
        os.close(descriptor)


def create_cgroup(state_root: Path) -> CgroupIdentity:
    path = cgroup_path_for(state_root)
    require(CGROUP_PATH_RE.fullmatch(str(path)) is not None, "runtime cgroup path is invalid")
    parent_fd = os.open(CGROUP_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    try:
        parent = os.fstat(parent_fd)
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == 0
            and parent.st_gid == 0
            and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
            "runtime cgroup parent authority differs",
        )
        parent_controllers = set(_read_at(parent_fd, "cgroup.controllers").split())
        require(
            {"cpu", "memory", "pids"} <= parent_controllers,
            "required cgroup v2 controllers are unavailable",
        )
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        observed = os.fstat(descriptor)
        literal = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            stat.S_ISDIR(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o700
            and (observed.st_dev, observed.st_ino) == (literal.st_dev, literal.st_ino),
            "runtime cgroup identity differs",
        )
        for name in ("cgroup.procs", "cgroup.events", "cgroup.kill"):
            value = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            require(stat.S_ISREG(value.st_mode), f"runtime cgroup control is absent: {name}")
        require(_read_at(descriptor, "cgroup.type").strip() == "domain", "runtime cgroup type differs")
        available = set(_read_at(descriptor, "cgroup.controllers").split())
        require(
            {"cpu", "memory", "pids"} <= available,
            "task cgroup controllers are unavailable",
        )
        _write_at(
            descriptor,
            "cgroup.subtree_control",
            b"+cpu +memory +pids\n",
        )
        enabled = set(_read_at(descriptor, "cgroup.subtree_control").split())
        require(
            {"cpu", "memory", "pids"} <= enabled,
            "task cgroup controllers were not enabled",
        )
        os.mkdir(CGROUP_EXECUTION_NAME, 0o700, dir_fd=descriptor)
        execution_fd = os.open(
            CGROUP_EXECUTION_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        try:
            execution = os.fstat(execution_fd)
            require(
                stat.S_ISDIR(execution.st_mode)
                and execution.st_uid == 0
                and execution.st_gid == 0
                and stat.S_IMODE(execution.st_mode) == 0o700,
                "runtime execution cgroup identity differs",
            )
        finally:
            os.close(execution_fd)
        return CgroupIdentity(path, observed.st_dev, observed.st_ino)
    except BaseException:
        if descriptor is not None:
            try:
                os.rmdir(CGROUP_EXECUTION_NAME, dir_fd=descriptor)
            except OSError:
                pass
            os.close(descriptor)
            descriptor = None
        try:
            os.rmdir(path.name, dir_fd=parent_fd)
        except OSError:
            pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def open_cgroup(identity: CgroupIdentity) -> int:
    require(CGROUP_PATH_RE.fullmatch(str(identity.path)) is not None, "runtime cgroup path is invalid")
    descriptor = os.open(identity.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed = os.fstat(descriptor)
    require(
        stat.S_ISDIR(observed.st_mode)
        and observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) == 0o700
        and (observed.st_dev, observed.st_ino) == (identity.device, identity.inode),
        "runtime cgroup identity changed",
    )
    return descriptor


def current_cgroup_path() -> str:
    records = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    require(len(records) == 1 and records[0].startswith("0::/"), "process cgroup v2 record differs")
    return records[0][3:]


def open_execution_cgroup(identity: CgroupIdentity) -> int:
    root_fd = open_cgroup(identity)
    try:
        descriptor = os.open(
            CGROUP_EXECUTION_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        observed = os.fstat(descriptor)
        require(
            stat.S_ISDIR(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o700,
            "runtime execution cgroup identity changed",
        )
        return descriptor
    finally:
        os.close(root_fd)


def enter_cgroup(identity: CgroupIdentity) -> None:
    descriptor = open_execution_cgroup(identity)
    try:
        _write_at(descriptor, "cgroup.procs", f"{os.getpid()}\n".encode("ascii"))
    finally:
        os.close(descriptor)
    require(
        current_cgroup_path() == execution_cgroup_path(identity),
        "supervisor did not enter task execution cgroup",
    )


def cgroup_is_populated(identity: CgroupIdentity) -> bool:
    descriptor = open_cgroup(identity)
    try:
        fields: dict[str, str] = {}
        for line in _read_at(descriptor, "cgroup.events").splitlines():
            parts = line.split()
            require(len(parts) == 2 and parts[0] not in fields, "cgroup events record is invalid")
            fields[parts[0]] = parts[1]
        require(fields.get("populated") in ("0", "1"), "cgroup populated state is absent")
        return fields["populated"] == "1"
    finally:
        os.close(descriptor)


def kill_cgroup_and_wait(identity: CgroupIdentity, *, timeout: float = 30.0) -> None:
    descriptor = open_cgroup(identity)
    try:
        _write_at(descriptor, "cgroup.kill", b"1\n")
    finally:
        os.close(descriptor)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not cgroup_is_populated(identity):
            return
        time.sleep(0.05)
    raise SupervisorError("runtime cgroup did not become empty")


def remove_empty_cgroup(identity: CgroupIdentity) -> None:
    require(not cgroup_is_populated(identity), "runtime cgroup is still populated")
    root_fd = open_cgroup(identity)
    try:
        remove_empty_cgroup_children(root_fd)
    finally:
        os.close(root_fd)
    parent_fd = os.open(CGROUP_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        literal = os.stat(identity.path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            (literal.st_dev, literal.st_ino) == (identity.device, identity.inode),
            "runtime cgroup entry changed before removal",
        )
        os.rmdir(identity.path.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def remove_empty_cgroup_children(directory_fd: int) -> None:
    for name in tuple(sorted(os.listdir(directory_fd))):
        value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISDIR(value.st_mode):
            continue
        require(
            value.st_uid == 0
            and value.st_gid == 0
            and stat.S_IMODE(value.st_mode) & 0o022 == 0,
            f"child cgroup authority differs: {name}",
        )
        child = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        try:
            remove_empty_cgroup_children(child)
            events = _read_at(child, "cgroup.events")
            require("populated 0" in events.splitlines(), "child cgroup is populated")
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=directory_fd)


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
            gid=observed.st_gid,
            mode=stat.S_IMODE(observed.st_mode),
        )
        require(
            identity.uid == 0 and identity.gid == 0 and identity.mode == 0o700,
            "runtime root owner or mode differs",
        )
        for name in ("containerd-state", "docker-exec"):
            os.mkdir(name, 0o700, dir_fd=descriptor)
        os.fsync(descriptor)
        return identity
    except BaseException:
        if descriptor is not None:
            for name in tuple(sorted(os.listdir(descriptor))):
                _remove_tree_entry(descriptor, name)
        parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.rmdir(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
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
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
        == (identity.device, identity.inode, identity.uid, identity.gid, identity.mode),
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


def reject_legacy_v4_runtime_roster(runtime_identity: RuntimeIdentity) -> None:
    descriptor = verify_runtime_root(runtime_identity)
    try:
        roster = set(os.listdir(descriptor))
    finally:
        os.close(descriptor)
    if (
        ROOT_CONTROL_NAME not in roster
        and SUPERVISOR_SNAPSHOT_NAME not in roster
        and roster & LEGACY_V4_RUNTIME_MARKERS
    ):
        raise SupervisorError(LEGACY_V4_DIAGNOSTIC)


def mount_references_under(raw_mountinfo: str, root: Path) -> tuple[str, ...]:
    records: list[tuple[str, Path, Path]] = []
    for line in raw_mountinfo.splitlines():
        fields = line.split()
        require("-" in fields and len(fields) >= 10, "mountinfo record is invalid")
        mount_root = Path(decode_mount_path(fields[3]))
        target = Path(decode_mount_path(fields[4]))
        require(mount_root.is_absolute() and target.is_absolute(), "mountinfo path is not absolute")
        records.append((fields[2], mount_root, target))
    bases: list[tuple[str, Path, Path]] = []
    for record in records:
        try:
            root.relative_to(record[2])
            bases.append(record)
        except ValueError:
            continue
    require(bases, "runtime mount backing record is absent")
    base_device, base_root, base_target = max(bases, key=lambda item: len(item[2].parts))
    source_prefix = base_root / root.relative_to(base_target)
    result: set[str] = set()
    for device, mount_root, target in records:
        target_reference = False
        source_reference = False
        try:
            target.relative_to(root)
            target_reference = True
        except ValueError:
            pass
        if device == base_device:
            try:
                mount_root.relative_to(source_prefix)
                source_reference = True
            except ValueError:
                pass
        if target_reference or source_reference:
            result.add(str(target))
    return tuple(sorted(result))


def _mount_targets_for_namespace(pid: int, root: Path) -> tuple[str, ...]:
    mountinfo = Path(f"/proc/{pid}/mountinfo").read_text(encoding="utf-8")
    return mount_references_under(mountinfo, root)


def _global_mount_roster_once(root: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    seen: dict[str, tuple[str, ...]] = {}
    entries = tuple(sorted(os.listdir("/proc")))
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        namespace_path = f"/proc/{pid}/ns/mnt"
        try:
            before_stat = os.stat(namespace_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise SupervisorError(f"mount namespace is unreadable for pid {pid}") from error
        namespace = f"{before_stat.st_dev}:{before_stat.st_ino}"
        if namespace in seen:
            try:
                after = os.stat(namespace_path)
            except OSError as error:
                raise SupervisorError(f"mount namespace disappeared for pid {pid}") from error
            require(
                (after.st_dev, after.st_ino) == (before_stat.st_dev, before_stat.st_ino),
                f"mount namespace changed for pid {pid}",
            )
            continue
        try:
            targets = _mount_targets_for_namespace(pid, root)
            after = os.stat(namespace_path)
        except OSError as error:
            raise SupervisorError(f"mount namespace disappeared for pid {pid}") from error
        require(
            (after.st_dev, after.st_ino) == (before_stat.st_dev, before_stat.st_ino),
            f"mount namespace changed for pid {pid}",
        )
        seen[namespace] = targets
    return tuple(sorted(seen.items()))


def stable_global_mount_targets(root: Path) -> tuple[tuple[str, str], ...]:
    first = _global_mount_roster_once(root)
    second = _global_mount_roster_once(root)
    require(first == second, "global mount namespace or target roster changed")
    return tuple(
        sorted((namespace, target) for namespace, targets in second for target in targets)
    )


def _remove_tree_entry(directory_fd: int, name: str) -> None:
    value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    require(value.st_uid == 0, f"runtime cleanup entry owner differs: {name}")
    if stat.S_ISDIR(value.st_mode):
        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            for nested in tuple(sorted(os.listdir(child))):
                _remove_tree_entry(child, nested)
            os.fsync(child)
        finally:
            os.close(child)
        os.rmdir(name, dir_fd=directory_fd)
    elif stat.S_ISREG(value.st_mode) or stat.S_ISSOCK(value.st_mode) or stat.S_ISLNK(value.st_mode):
        os.unlink(name, dir_fd=directory_fd)
    else:
        raise SupervisorError(f"runtime cleanup entry type differs: {name}")
    os.fsync(directory_fd)


def remove_runtime_root(identity: RuntimeIdentity) -> None:
    descriptor = verify_runtime_root(identity)
    try:
        verify_runtime_entries(descriptor)
        require(not stable_global_mount_targets(identity.path), "runtime root retains a mount")
        for name in tuple(sorted(os.listdir(descriptor))):
            _remove_tree_entry(descriptor, name)
        require(not os.listdir(descriptor), "runtime root did not become empty")
        parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            literal = os.stat(identity.path.name, dir_fd=parent_fd, follow_symlinks=False)
            require(
                (literal.st_dev, literal.st_ino) == (identity.device, identity.inode),
                "runtime root entry changed before removal",
            )
            os.rmdir(identity.path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(descriptor)


def create_socket_root(path: Path, caller_gid: int) -> SocketPathIdentity:
    require(SOCKET_ROOT_RE.fullmatch(str(path)) is not None, "Docker API root path is invalid")
    parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor: int | None = None
    try:
        parent = os.fstat(parent_fd)
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == 0
            and parent.st_gid == 0
            and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
            "Docker API parent authority differs",
        )
        os.mkdir(path.name, 0o700, dir_fd=parent_fd)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        os.fchown(descriptor, 0, caller_gid)
        os.fchmod(descriptor, 0o750)
        os.fsync(descriptor)
        os.fsync(parent_fd)
        observed = os.fstat(descriptor)
        literal = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            stat.S_ISDIR(observed.st_mode)
            and (observed.st_dev, observed.st_ino) == (literal.st_dev, literal.st_ino)
            and observed.st_uid == 0
            and observed.st_gid == caller_gid
            and stat.S_IMODE(observed.st_mode) == 0o750,
            "Docker API root identity differs after creation",
        )
        return SocketPathIdentity(
            path, observed.st_dev, observed.st_ino, 0, caller_gid, 0o750
        )
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        try:
            os.rmdir(path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except OSError:
            pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def verify_socket_root(identity: SocketPathIdentity, caller_gid: int) -> int:
    require(
        SOCKET_ROOT_RE.fullmatch(str(identity.path)) is not None,
        "Docker API root path is invalid",
    )
    descriptor = os.open(identity.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed = os.fstat(descriptor)
    require(
        stat.S_ISDIR(observed.st_mode)
        and (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
        == (
            identity.device,
            identity.inode,
            0,
            caller_gid,
            0o750,
        ),
        "Docker API root identity changed",
    )
    return descriptor


def capture_socket_identity(
    root: SocketPathIdentity,
    caller_gid: int,
) -> SocketPathIdentity:
    descriptor = verify_socket_root(root, caller_gid)
    try:
        require(os.listdir(descriptor) == [SOCKET_NAME], "Docker API root roster differs")
        observed = os.stat(SOCKET_NAME, dir_fd=descriptor, follow_symlinks=False)
        require(
            stat.S_ISSOCK(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == caller_gid
            and stat.S_IMODE(observed.st_mode) == 0o660
            and observed.st_dev == root.device,
            "Docker API socket identity differs",
        )
        return SocketPathIdentity(
            root.path / SOCKET_NAME,
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
    finally:
        os.close(descriptor)


def socket_entry_ready(root: SocketPathIdentity, caller_gid: int) -> bool:
    try:
        capture_socket_identity(root, caller_gid)
        return True
    except (OSError, SupervisorError):
        return False


def verify_socket_boundary(
    root: SocketPathIdentity,
    socket_identity: SocketPathIdentity,
    caller_gid: int,
) -> None:
    current = capture_socket_identity(root, caller_gid)
    require(current == socket_identity, "Docker API socket changed")
    require(
        socket_identity.path == root.path / SOCKET_NAME,
        "Docker API socket path differs",
    )


def remove_socket_root(
    root: SocketPathIdentity,
    socket_identity: SocketPathIdentity | None,
    caller_gid: int,
) -> None:
    parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = verify_socket_root(root, caller_gid)
    try:
        require(not stable_global_mount_targets(root.path), "Docker API root retains a mount")
        roster = tuple(sorted(os.listdir(descriptor)))
        require(roster in ((), (SOCKET_NAME,)), "Docker API root contains a foreign entry")
        if roster:
            observed = os.stat(SOCKET_NAME, dir_fd=descriptor, follow_symlinks=False)
            require(
                socket_identity is not None
                and stat.S_ISSOCK(observed.st_mode)
                and (
                    observed.st_dev,
                    observed.st_ino,
                    observed.st_uid,
                    observed.st_gid,
                    stat.S_IMODE(observed.st_mode),
                )
                == (
                    socket_identity.device,
                    socket_identity.inode,
                    0,
                    caller_gid,
                    0o660,
                ),
                "Docker API socket cannot be safely removed",
            )
            os.unlink(SOCKET_NAME, dir_fd=descriptor)
            os.fsync(descriptor)
        require(not os.listdir(descriptor), "Docker API root did not become empty")
        literal = os.stat(root.path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            (literal.st_dev, literal.st_ino) == (root.device, root.inode),
            "Docker API root entry changed before removal",
        )
        os.rmdir(root.path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(descriptor)
        os.close(parent_fd)


def ensure_storage_directory(
    parent_fd: int,
    parent_path: Path,
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
    os.fsync(parent_fd)
    return parent_path / name


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


def _root_manifest_pending(name: str) -> str:
    require(
        name in (ROOT_CONTROL_NAME, ROOT_READY_NAME, ROOT_STOPPING_NAME, ROOT_STOP_NAME),
        "root manifest name is invalid",
    )
    return f".{name}.pending"


def remove_root_manifest_pending(runtime_fd: int, name: str) -> None:
    pending_name = _root_manifest_pending(name)
    try:
        value = os.stat(pending_name, dir_fd=runtime_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    require(
        stat.S_ISREG(value.st_mode)
        and value.st_uid == 0
        and value.st_gid == 0
        and stat.S_IMODE(value.st_mode) == 0o400
        and value.st_nlink == 1
        and value.st_size <= 2 * 1024 * 1024,
        f"root manifest pending identity differs: {pending_name}",
    )
    os.unlink(pending_name, dir_fd=runtime_fd)
    os.fsync(runtime_fd)


def write_root_manifest(
    runtime_identity: RuntimeIdentity,
    name: str,
    value: dict[str, object],
) -> str:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    require(0 < len(encoded) <= 2 * 1024 * 1024, "root manifest size is invalid")
    runtime_fd = verify_runtime_root(runtime_identity)
    pending_name = _root_manifest_pending(name)
    try:
        require(
            not _entry_exists(runtime_fd, name),
            f"root manifest already exists: {name}",
        )
        remove_root_manifest_pending(runtime_fd, name)
        descriptor = os.open(
            pending_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=runtime_fd,
        )
        try:
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(pending_name, name, src_dir_fd=runtime_fd, dst_dir_fd=runtime_fd)
        os.fsync(runtime_fd)
    finally:
        os.close(runtime_fd)
    return hashlib.sha256(encoded).hexdigest()


def _entry_exists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def path_exists_nofollow(path: Path) -> bool:
    try:
        os.stat(path, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def read_root_manifest(runtime_identity: RuntimeIdentity, name: str) -> dict[str, Any] | None:
    require(
        name in (ROOT_CONTROL_NAME, ROOT_READY_NAME, ROOT_STOPPING_NAME, ROOT_STOP_NAME),
        "root manifest name is invalid",
    )
    runtime_fd = verify_runtime_root(runtime_identity)
    try:
        if not _entry_exists(runtime_fd, name):
            return None
        value = os.stat(name, dir_fd=runtime_fd, follow_symlinks=False)
        require(
            stat.S_ISREG(value.st_mode)
            and value.st_uid == 0
            and value.st_gid == 0
            and stat.S_IMODE(value.st_mode) == 0o400
            and value.st_nlink == 1
            and 0 < value.st_size <= 2 * 1024 * 1024,
            f"root manifest identity differs: {name}",
        )
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=runtime_fd)
        try:
            first = os.fstat(descriptor)
            require(
                (first.st_dev, first.st_ino) == (value.st_dev, value.st_ino),
                f"root manifest entry changed: {name}",
            )
            raw = _read_fd_all(descriptor, limit=2 * 1024 * 1024)
        finally:
            os.close(descriptor)
    finally:
        os.close(runtime_fd)
    parsed = json.loads(raw)
    require(isinstance(parsed, dict), f"root manifest is not an object: {name}")
    require(
        raw == (json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        f"root manifest is not canonical JSON: {name}",
    )
    return parsed


def read_route_networks(
    raw: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    value = json.loads(raw)
    require(isinstance(value, list), "host route observation is not an array")
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for route in value:
        require(isinstance(route, dict), "host route record is invalid")
        destination = route.get("dst")
        if destination == "default":
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
            "innerRunnerDataRoot": None,
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
        "runner storage receipt",
    )
    require(receipt["schema"] == STORAGE_RECEIPT_SCHEMA, "runner storage receipt schema differs")
    expected_lifecycle_state = "detached" if expected_outcome == "deactivated" else "attached"
    require(
        receipt["lifecycleState"] == expected_lifecycle_state,
        "runner storage receipt lifecycle state differs",
    )
    require(receipt["stateRoot"] == str(state_root), "runner storage receipt state root differs")
    require(
        isinstance(receipt["authorityClaimSha256"], str)
        and SHA256_RE.fullmatch(receipt["authorityClaimSha256"]) is not None,
        "runner storage claim digest is invalid",
    )
    require(
        receipt["caller"] == {"uid": caller_uid, "gid": caller_gid},
        "runner storage receipt caller differs",
    )
    state_identity = exact_keys(
        receipt["stateRootIdentity"],
        {"path", "device", "inode", "ownerUid", "ownerGid", "mode"},
        "runner storage state identity",
    )
    require(state_identity["path"] == str(state_root), "runner storage state identity path differs")
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
    evidence_identity = exact_keys(
        receipt["evidenceDirectoryIdentity"],
        {"path", "device", "inode", "ownerUid", "ownerGid", "mode"},
        "runner storage evidence identity",
    )
    require(
        evidence_identity["path"] == str(state_root / "evidence")
        and plain_int(evidence_identity["device"], "runner storage evidence device")
        == state_device
        and plain_int(evidence_identity["inode"], "runner storage evidence inode", positive=True)
        and (
            plain_int(evidence_identity["ownerUid"], "runner storage evidence owner"),
            plain_int(evidence_identity["ownerGid"], "runner storage evidence group"),
            evidence_identity["mode"],
        )
        == (caller_uid, caller_gid, "0700"),
        "runner storage evidence identity differs",
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
    inner = exact_keys(
        receipt["innerRunnerDataRoot"],
        {"path", "device", "inode", "ownerUid", "ownerGid", "mode"},
        "inner runner data root",
    )
    require(
        inner["path"] == str(MOUNT_TARGET / "inner-runner")
        and plain_int(inner["device"], "inner runner device") == target["device"]
        and plain_int(inner["inode"], "inner runner inode", positive=True)
        and (
            plain_int(inner["ownerUid"], "inner runner owner"),
            plain_int(inner["ownerGid"], "inner runner group"),
            inner["mode"],
        )
        == (0, 0, "0700"),
        "inner runner data-root identity differs",
    )
    safe_inner = {
        "path": inner["path"],
        "device": inner["device"],
        "inode": inner["inode"],
    }

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
        "innerRunnerDataRoot": safe_inner,
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
    socket_gid: int,
    containerd_socket: Path,
    cgroup_parent: str,
) -> str:
    require(
        re.fullmatch(r"/ambit-c16b-docker-[0-9a-f]{12}", cgroup_parent) is not None,
        "Docker cgroup parent is invalid",
    )
    value = {
        "data-root": str(data_root),
        "exec-root": str(exec_root),
        "pidfile": str(pidfile),
        "hosts": [f"unix://{socket}"],
        "group": str(socket_gid),
        "containerd": str(containerd_socket),
        "containerd-namespace": "ambit-c16b",
        "containerd-plugins-namespace": "ambit-c16b-plugins",
        "exec-opts": ["native.cgroupdriver=cgroupfs"],
        "cgroup-parent": cgroup_parent,
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


def existing_runtime_identity(
    path: Path,
    *,
    recoverable_modes: set[int] = {0o700},
) -> RuntimeIdentity:
    require(RUNTIME_ROOT_RE.fullmatch(str(path)) is not None, "runtime root path is invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        require(
            stat.S_ISDIR(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) in recoverable_modes,
            "existing runtime root identity differs",
        )
        return RuntimeIdentity(
            path,
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
    finally:
        os.close(descriptor)


def runtime_identity_from_json(value: object, path: Path) -> RuntimeIdentity:
    parsed = exact_keys(value, {"device", "inode", "uid", "gid", "mode"}, "runtime identity")
    result = RuntimeIdentity(
        path,
        plain_int(parsed["device"], "runtime device"),
        plain_int(parsed["inode"], "runtime inode", positive=True),
        plain_int(parsed["uid"], "runtime owner"),
        plain_int(parsed["gid"], "runtime group"),
        plain_int(parsed["mode"], "runtime mode"),
    )
    require((result.uid, result.gid, result.mode) == (0, 0, 0o700), "runtime owner or mode differs")
    return result


def socket_identity_from_json(
    value: object,
    expected_path: Path,
    *,
    expected_gid: int,
    expected_mode: int,
) -> SocketPathIdentity:
    parsed = exact_keys(
        value,
        {"path", "device", "inode", "uid", "gid", "mode"},
        "Docker API path identity",
    )
    require(parsed["path"] == str(expected_path), "Docker API identity path differs")
    result = SocketPathIdentity(
        expected_path,
        plain_int(parsed["device"], "Docker API device"),
        plain_int(parsed["inode"], "Docker API inode", positive=True),
        plain_int(parsed["uid"], "Docker API owner"),
        plain_int(parsed["gid"], "Docker API group"),
        plain_int(parsed["mode"], "Docker API mode"),
    )
    require(
        (result.uid, result.gid, result.mode) == (0, expected_gid, expected_mode),
        "Docker API owner, group, or mode differs",
    )
    return result


def cgroup_identity_from_json(value: object, state_root: Path) -> CgroupIdentity:
    expected_path = cgroup_path_for(state_root)
    parsed = exact_keys(value, {"path", "device", "inode"}, "runtime cgroup identity")
    require(parsed["path"] == str(expected_path), "runtime cgroup path differs")
    return CgroupIdentity(
        expected_path,
        plain_int(parsed["device"], "runtime cgroup device"),
        plain_int(parsed["inode"], "runtime cgroup inode", positive=True),
    )


def validate_control_authority(
    value: object,
    *,
    state: StateAuthority | StoredStateAuthority,
    runtime_identity: RuntimeIdentity,
    process_authority: dict[str, Any],
) -> dict[str, object]:
    control = exact_keys(
        value,
        {
            "schema",
            "outcome",
            "observedAt",
            "bootId",
            "stateRoot",
            "caller",
            "stateRootIdentity",
            "evidenceRootIdentity",
            "supervisorSourceSha256",
            "processIdentitySourceSha256",
            "storageLifecycleSourceSha256",
            "runtimeRoot",
            "runtimeRootIdentity",
            "socketRootIdentity",
            "cgroup",
            "mountNamespace",
            "supervisorProcessIdentity",
        },
        "root runtime control authority",
    )
    require(control["schema"] == CONTROL_SCHEMA, "root control schema is unsupported")
    require(control["outcome"] == "active", "root control outcome differs")
    require(control["bootId"] == current_boot_id(), "root control boot identity differs")
    require(control["stateRoot"] == str(state.path), "root control state path differs")
    require(
        control["caller"] == {"uid": state.caller_uid, "gid": state.caller_gid},
        "root control caller differs",
    )
    state_identity = state.identity_json()
    require(
        control["stateRootIdentity"] == state_identity["stateRoot"]
        and control["evidenceRootIdentity"] == state_identity["evidenceRoot"],
        "root control state identity differs",
    )
    require(
        control["supervisorSourceSha256"] == verified_supervisor_source_sha256()
        and control["processIdentitySourceSha256"] == PROCESS_IDENTITY_SHA256
        and control["storageLifecycleSourceSha256"] == STORAGE_LIFECYCLE_SHA256,
        "root control source authority differs",
    )
    require(control["runtimeRoot"] == str(runtime_identity.path), "root control runtime path differs")
    recorded_runtime = runtime_identity_from_json(control["runtimeRootIdentity"], runtime_identity.path)
    require(recorded_runtime == runtime_identity, "root control runtime identity differs")
    socket_root = socket_identity_from_json(
        control["socketRootIdentity"],
        socket_root_for(state.path),
        expected_gid=state.caller_gid,
        expected_mode=0o750,
    )
    cgroup = cgroup_identity_from_json(control["cgroup"], state.path)
    namespace = validate_namespace(control["mountNamespace"], "root control mount namespace")
    recorded_process = process_authority["validate_recorded_identity"](
        control["supervisorProcessIdentity"]
    )
    require(recorded_process["mountNamespace"] == namespace, "root control process namespace differs")
    require(
        recorded_process["cgroup"] == execution_cgroup_path(cgroup),
        "root control process cgroup differs",
    )
    return {
        "control": control,
        "runtime": recorded_runtime,
        "socketRoot": socket_root,
        "cgroup": cgroup,
        "namespace": namespace,
        "supervisor": recorded_process,
    }


def validate_ready_authority(
    value: object,
    *,
    control: dict[str, object],
    root_control_digest: str,
    process_authority: dict[str, Any],
) -> dict[str, object]:
    ready = exact_keys(
        value,
        {
            "schema",
            "outcome",
            "observedAt",
            "bootId",
            "stateRoot",
            "caller",
            "supervisorSourceSha256",
            "processIdentitySourceSha256",
            "storageLifecycleSourceSha256",
            "runtimeRoot",
            "runtimeRootIdentity",
            "rootControlSha256",
            "supervisorProcessIdentity",
            "mountNamespace",
            "cgroup",
            "workloadCgroupParent",
            "storage",
            "socket",
            "socketRootIdentity",
            "socketIdentity",
            "dataRoot",
            "execRoot",
            "containerd",
            "network",
            "serverId",
            "serverVersion",
            "configSha256",
            "dockerProcessIdentity",
        },
        "root runtime ready authority",
    )
    require(ready["schema"] == START_SCHEMA, "root ready schema is unsupported")
    require(ready["outcome"] == "passed", "root ready outcome differs")
    require(
        isinstance(ready["observedAt"], str) and 1 <= len(ready["observedAt"]) <= 64,
        "root ready observation time is invalid",
    )
    for field in (
        "bootId",
        "stateRoot",
        "caller",
        "supervisorSourceSha256",
        "processIdentitySourceSha256",
        "storageLifecycleSourceSha256",
        "runtimeRoot",
        "runtimeRootIdentity",
        "supervisorProcessIdentity",
        "mountNamespace",
        "cgroup",
    ):
        require(ready[field] == control[field], f"root ready control field differs: {field}")
    require(ready["rootControlSha256"] == root_control_digest, "root ready control digest differs")
    state_root = Path(str(control["stateRoot"]))
    ready_cgroup = cgroup_identity_from_json(ready["cgroup"], state_root)
    require(
        ready["workloadCgroupParent"] == f"/{ready_cgroup.path.name}",
        "root ready workload cgroup parent differs",
    )
    caller = exact_keys(control["caller"], {"uid", "gid"}, "root control caller")
    caller_gid = plain_int(caller["gid"], "root control caller group")
    socket_root = socket_identity_from_json(
        ready["socketRootIdentity"],
        socket_root_for(state_root),
        expected_gid=caller_gid,
        expected_mode=0o750,
    )
    socket_identity = socket_identity_from_json(
        ready["socketIdentity"],
        socket_root.path / SOCKET_NAME,
        expected_gid=caller_gid,
        expected_mode=0o660,
    )
    require(ready["socket"] == str(socket_identity.path), "root ready socket path differs")
    require(socket_identity.device == socket_root.device, "root ready socket backing differs")
    storage = exact_keys(
        ready["storage"],
        {
            "lifecycleSchema",
            "receiptSchema",
            "projectionDigest",
            "authorityRoot",
            "target",
            "innerRunnerDataRoot",
            "image",
            "loop",
            "filesystem",
            "mountNamespace",
        },
        "root ready storage projection",
    )
    require(
        storage["lifecycleSchema"] == STORAGE_OPERATION_SCHEMA
        and storage["receiptSchema"] == STORAGE_RECEIPT_SCHEMA
        and isinstance(storage["projectionDigest"], str)
        and SHA256_RE.fullmatch(storage["projectionDigest"]) is not None
        and storage["authorityRoot"] == str(AUTHORITY_ROOT)
        and storage["target"] == str(MOUNT_TARGET)
        and storage["mountNamespace"] == ready["mountNamespace"],
        "root ready storage authority differs",
    )
    inner = exact_keys(
        storage["innerRunnerDataRoot"],
        {"path", "device", "inode"},
        "root ready inner runner data root",
    )
    require(
        inner["path"] == str(MOUNT_TARGET / "inner-runner"),
        "root ready inner runner path differs",
    )
    plain_int(inner["device"], "root ready inner runner device")
    plain_int(inner["inode"], "root ready inner runner inode", positive=True)
    image = exact_keys(
        storage["image"],
        {"device", "inode", "logicalBytes"},
        "root ready storage image",
    )
    plain_int(image["device"], "root ready image device")
    plain_int(image["inode"], "root ready image inode", positive=True)
    require(image["logicalBytes"] == IMAGE_BYTES, "root ready image size differs")
    loop = exact_keys(
        storage["loop"],
        {"device", "major", "minor"},
        "root ready storage loop",
    )
    require(
        isinstance(loop["device"], str) and LOOP_DEVICE_RE.fullmatch(loop["device"]) is not None,
        "root ready loop device differs",
    )
    plain_int(loop["major"], "root ready loop major", positive=True)
    plain_int(loop["minor"], "root ready loop minor")
    filesystem = exact_keys(
        storage["filesystem"],
        {"type", "uuid"},
        "root ready storage filesystem",
    )
    require(
        filesystem["type"] == "xfs"
        and isinstance(filesystem["uuid"], str)
        and UUID_RE.fullmatch(filesystem["uuid"]) is not None,
        "root ready filesystem differs",
    )
    containerd = exact_keys(
        ready["containerd"],
        {"address", "root", "version", "configSha256", "processIdentity"},
        "root ready containerd",
    )
    require(containerd["root"] == str(AUTHORITY_ROOT / "outer-containerd"), "containerd root differs")
    require(
        containerd["address"] == str(runtime_root_for(state_root) / "containerd.sock")
        and isinstance(containerd["version"], str)
        and 0 < len(containerd["version"]) <= 256
        and isinstance(containerd["configSha256"], str)
        and SHA256_RE.fullmatch(containerd["configSha256"]) is not None,
        "root ready containerd authority differs",
    )
    require(ready["dataRoot"] == str(AUTHORITY_ROOT / "outer-docker"), "Docker data root differs")
    require(ready["execRoot"] == str(runtime_root_for(state_root) / "docker-exec"), "Docker exec root differs")
    require(
        ready["network"]
        == {
            "defaultBridge": "disabled",
            "addressPool": "172.30.0.0/16",
            "hostFirewallMutation": False,
        },
        "root ready network authority differs",
    )
    require(validate_docker_daemon_id(ready["serverId"]) == ready["serverId"], "Docker ID differs")
    require(
        isinstance(ready["serverVersion"], str)
        and 0 < len(ready["serverVersion"]) <= 128
        and isinstance(ready["configSha256"], str)
        and SHA256_RE.fullmatch(ready["configSha256"]) is not None,
        "root ready Docker version or config authority differs",
    )
    docker_identity = process_authority["validate_recorded_identity"](
        ready["dockerProcessIdentity"]
    )
    containerd_identity = process_authority["validate_recorded_identity"](
        containerd["processIdentity"]
    )
    supervisor_identity = process_authority["validate_recorded_identity"](
        ready["supervisorProcessIdentity"]
    )
    require(
        docker_identity["parentPid"] == supervisor_identity["pid"]
        and containerd_identity["parentPid"] == supervisor_identity["pid"]
        and docker_identity["mountNamespace"] == ready["mountNamespace"]
        and containerd_identity["mountNamespace"] == ready["mountNamespace"]
        and supervisor_identity["cgroup"] == execution_cgroup_path(
            ready_cgroup
        )
        and docker_identity["cgroup"] == supervisor_identity["cgroup"]
        and containerd_identity["cgroup"] == supervisor_identity["cgroup"],
        "root ready daemon topology differs",
    )
    return {
        "ready": ready,
        "socketRoot": socket_root,
        "socket": socket_identity,
        "docker": docker_identity,
        "containerd": containerd_identity,
    }


def canonical_document_digest(value: dict[str, object]) -> str:
    return hashlib.sha256(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ).hexdigest()


def _validate_snapshot_prefix(path: Path, expected: bytes) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) in (0o000, 0o400)
            and observed.st_nlink == 1
            and observed.st_size <= len(expected),
            f"pre-control snapshot identity differs: {path.name}",
        )
        actual = _read_fd_all(descriptor, limit=len(expected) + 1)
        require(expected.startswith(actual), f"pre-control snapshot bytes differ: {path.name}")
    finally:
        os.close(descriptor)


def classify_precontrol_roster(roster: set[str]) -> int:
    stages: list[set[str]] = [set()]
    current: set[str] = set()
    for name in (
        "containerd-state",
        "docker-exec",
        SUPERVISOR_SNAPSHOT_NAME,
        PROCESS_IDENTITY_NAME,
        STORAGE_LIFECYCLE_NAME,
        STORAGE_IDENTITY_VERIFIER_NAME,
        _root_manifest_pending(ROOT_CONTROL_NAME),
    ):
        current = current | {name}
        stages.append(current)
    require(roster in stages, "pre-control runtime roster is not a creation prefix")
    return stages.index(roster)


def reduce_precontrol_runtime(
    state_root: Path,
    caller_gid: int,
    script_directory: Path,
) -> None:
    runtime_path = runtime_root_for(state_root)
    socket_path = socket_root_for(state_root)
    cgroup_path = cgroup_path_for(state_root)

    try:
        runtime = existing_runtime_identity(runtime_path, recoverable_modes={0o000, 0o700})
    except FileNotFoundError:
        runtime = None
    if runtime is not None:
        if runtime.mode == 0o000:
            descriptor = os.open(runtime.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            runtime = RuntimeIdentity(
                runtime.path,
                runtime.device,
                runtime.inode,
                runtime.uid,
                runtime.gid,
                0o700,
            )
        runtime_fd = verify_runtime_root(runtime)
        try:
            roster = set(os.listdir(runtime_fd))
            classify_precontrol_roster(roster)
            for name in ("containerd-state", "docker-exec"):
                if name not in roster:
                    continue
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=runtime_fd,
                )
                try:
                    observed = os.fstat(descriptor)
                    require(
                        observed.st_uid == 0
                        and observed.st_gid == 0
                        and stat.S_IMODE(observed.st_mode) in (0o000, 0o700)
                        and not os.listdir(descriptor),
                        f"pre-control directory identity differs: {name}",
                    )
                finally:
                    os.close(descriptor)
            snapshots = {
                SUPERVISOR_SNAPSHOT_NAME: read_pinned_source(
                    script_directory / SUPERVISOR_SNAPSHOT_NAME,
                    verified_supervisor_source_sha256(),
                ),
                PROCESS_IDENTITY_NAME: read_pinned_source(
                    script_directory / PROCESS_IDENTITY_NAME,
                    PROCESS_IDENTITY_SHA256,
                ),
                STORAGE_LIFECYCLE_NAME: read_pinned_source(
                    script_directory / STORAGE_LIFECYCLE_NAME,
                    STORAGE_LIFECYCLE_SHA256,
                ),
                STORAGE_IDENTITY_VERIFIER_NAME: read_pinned_source(
                    script_directory / STORAGE_IDENTITY_VERIFIER_NAME,
                    STORAGE_IDENTITY_VERIFIER_SHA256,
                ),
            }
            for name, expected in snapshots.items():
                if name in roster:
                    _validate_snapshot_prefix(runtime_path / name, expected)
            pending = _root_manifest_pending(ROOT_CONTROL_NAME)
            if pending in roster:
                value = os.stat(pending, dir_fd=runtime_fd, follow_symlinks=False)
                require(
                    stat.S_ISREG(value.st_mode)
                    and value.st_uid == 0
                    and value.st_gid == 0
                    and stat.S_IMODE(value.st_mode) in (0o000, 0o400)
                    and value.st_nlink == 1
                    and value.st_size <= 2 * 1024 * 1024,
                    "pre-control manifest pending identity differs",
                )
        finally:
            os.close(runtime_fd)
        remove_runtime_root(runtime)

    try:
        socket_stat = os.stat(socket_path, follow_symlinks=False)
    except FileNotFoundError:
        socket_stat = None
    if socket_stat is not None:
        require(
            stat.S_ISDIR(socket_stat.st_mode)
            and socket_stat.st_uid == 0
            and socket_stat.st_gid in (0, caller_gid)
            and stat.S_IMODE(socket_stat.st_mode) in (0o000, 0o700, 0o750),
            "pre-control Docker API root identity differs",
        )
        socket_fd = os.open(socket_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent_fd = os.open(RUNTIME_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(not os.listdir(socket_fd), "pre-control Docker API root is not empty")
            require(not stable_global_mount_targets(socket_path), "pre-control Docker API root is mounted")
            os.rmdir(socket_path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
            os.close(socket_fd)

    try:
        cgroup_stat = os.stat(cgroup_path, follow_symlinks=False)
    except FileNotFoundError:
        cgroup_stat = None
    if cgroup_stat is not None:
        identity = CgroupIdentity(cgroup_path, cgroup_stat.st_dev, cgroup_stat.st_ino)
        require(not cgroup_is_populated(identity), "pre-control runtime cgroup is populated")
        remove_empty_cgroup(identity)


def remove_user_runtime_projections(state: StateAuthority) -> None:
    names = (
        CONTROL_RECEIPT_NAME,
        START_RECEIPT_NAME,
        STOP_RECEIPT_NAME,
        f".{CONTROL_RECEIPT_NAME}.pending",
        f".{START_RECEIPT_NAME}.pending",
        f".{STOP_RECEIPT_NAME}.pending",
    )
    for name in names:
        try:
            value = os.stat(name, dir_fd=state.evidence_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        require(
            stat.S_ISREG(value.st_mode)
            and value.st_uid == state.caller_uid
            and value.st_gid == state.caller_gid
            and stat.S_IMODE(value.st_mode) == 0o600
            and value.st_nlink == 1,
            f"runtime projection identity differs: {name}",
        )
        os.unlink(name, dir_fd=state.evidence_fd)
        os.fsync(state.evidence_fd)


class RuntimeSupervisor:
    def __init__(self, state_root: Path, caller_uid: int, caller_gid: int) -> None:
        self.state_root = state_root
        self.caller_uid = caller_uid
        self.caller_gid = caller_gid
        self.script_directory = Path(__file__).resolve(strict=True).parent
        self.precontrol_source_directory = fallback_script_directory()
        self.lease: RuntimeLease | None = None
        self.cgroup_identity: CgroupIdentity | None = None
        self.namespace: dict[str, int] | None = None
        self.runtime_identity: RuntimeIdentity | None = None
        self.socket_root_identity: SocketPathIdentity | None = None
        self.socket_identity: SocketPathIdentity | None = None
        self.state: StateAuthority | StoredStateAuthority | None = None
        self.storage: dict[str, object] | None = None
        self.deactivated_storage: dict[str, object] | None = None
        self.runtime_removed = False
        self.socket_root_removed = False
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
        self.root_control_digest: str | None = None
        self.root_ready_digest: str | None = None
        self.root_stopping_digest: str | None = None
        self.root_stop_digest: str | None = None
        self.arguments_sha256 = process_arguments_sha256()

    def expected_child_pids(self) -> set[int]:
        result: set[int] = set()
        for process in (self.containerd_process, self.docker_process):
            if process is not None and process.poll() is None:
                result.add(process.pid)
        return result

    def expected_execution_cgroup(self) -> str:
        require(self.cgroup_identity is not None, "runtime cgroup identity is absent")
        return execution_cgroup_path(self.cgroup_identity)

    def request_stop(self, signum: int, _: object) -> None:
        if signum == signal.SIGTERM:
            self.stop_requested = True

    def reject_interrupted_startup(self) -> None:
        require(not self.stop_requested, "supervisor startup was stopped by the operator")

    def verify_own_identity(self) -> dict[str, object]:
        require(self.process_verifier is not None, "process verifier is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        expected_digest = self.arguments_sha256
        require(process_arguments_sha256() == expected_digest, "supervisor process arguments changed")
        identity = self.process_verifier(
            os.getpid(),
            PYTHON,
            None,
            expected_uid=0,
            expected_arguments_sha256=expected_digest,
            expected_mount_namespace=self.namespace,
            expected_cgroup=self.expected_execution_cgroup(),
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

    def control_authority_value(self) -> dict[str, object]:
        require(self.state is not None, "state authority is absent")
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.socket_root_identity is not None, "Docker API root identity is absent")
        require(self.cgroup_identity is not None, "runtime cgroup identity is absent")
        require(self.supervisor_identity is not None, "supervisor identity is absent")
        require(self.namespace is not None, "supervisor namespace is absent")
        state_identity = self.state.identity_json()
        return {
            "schema": CONTROL_SCHEMA,
            "outcome": "active",
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(self.state_root),
            "caller": {"uid": self.caller_uid, "gid": self.caller_gid},
            "stateRootIdentity": state_identity["stateRoot"],
            "evidenceRootIdentity": state_identity["evidenceRoot"],
            "supervisorSourceSha256": verified_supervisor_source_sha256(),
            "processIdentitySourceSha256": PROCESS_IDENTITY_SHA256,
            "storageLifecycleSourceSha256": STORAGE_LIFECYCLE_SHA256,
            "runtimeRoot": str(self.runtime_identity.path),
            "runtimeRootIdentity": self.runtime_identity.json(),
            "socketRootIdentity": self.socket_root_identity.json(),
            "cgroup": self.cgroup_identity.json(),
            "mountNamespace": self.namespace,
            "supervisorProcessIdentity": self.supervisor_identity,
        }

    def write_control_receipt(self, outcome: str = "active") -> None:
        require(outcome in ("active", "stopping"), "control outcome is invalid")
        require(self.state is not None, "state authority is absent")
        require(self.runtime_identity is not None, "runtime identity is absent")
        if self.root_control_digest is None:
            require(outcome == "active", "root control must be published before stopping")
            control = self.control_authority_value()
            self.root_control_digest = write_root_manifest(
                self.runtime_identity,
                ROOT_CONTROL_NAME,
                control,
            )
        else:
            control = read_root_manifest(self.runtime_identity, ROOT_CONTROL_NAME)
            require(control is not None, "root control authority disappeared")
        self.state.write_json(
            CONTROL_RECEIPT_NAME,
            {
                "schema": CONTROL_PROJECTION_SCHEMA,
                "projectionState": outcome,
                "rootControlSha256": self.root_control_digest,
                "control": control,
            },
        )

    def write_shutdown_intent(self, reason: str) -> None:
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.cgroup_identity is not None, "runtime cgroup identity is absent")
        require(self.root_control_digest is not None, "root control authority is absent")
        require(self.supervisor_identity is not None, "supervisor identity is absent")
        if self.root_stopping_digest is not None:
            require(
                read_root_manifest(self.runtime_identity, ROOT_STOPPING_NAME) is not None,
                "root stopping authority disappeared",
            )
            return
        value: dict[str, object] = {
            "schema": STOPPING_SCHEMA,
            "outcome": "stopping",
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(self.state_root),
            "reason": reason,
            "rootControlSha256": self.root_control_digest,
            "runtimeRootIdentity": self.runtime_identity.json(),
            "cgroup": self.cgroup_identity.json(),
            "supervisorProcessIdentity": self.supervisor_identity,
        }
        self.root_stopping_digest = write_root_manifest(
            self.runtime_identity,
            ROOT_STOPPING_NAME,
            value,
        )

    def recover_existing_runtime(self, *, orphaned: bool = False) -> None:
        require(self.state is not None, "state authority is absent")
        require(self.namespace is not None, "recovery mount namespace is absent")
        runtime_path = runtime_root_for(self.state_root)
        try:
            runtime = existing_runtime_identity(runtime_path)
        except FileNotFoundError:
            reduce_precontrol_runtime(
                self.state_root,
                self.caller_gid,
                self.precontrol_source_directory,
            )
            if not orphaned:
                remove_user_runtime_projections(self.state)  # type: ignore[arg-type]
            return

        process_authority = load_process_authority(self.script_directory)
        control_value = read_root_manifest(runtime, ROOT_CONTROL_NAME)
        if control_value is None:
            reject_legacy_v4_runtime_roster(runtime)
            reduce_precontrol_runtime(
                self.state_root,
                self.caller_gid,
                self.precontrol_source_directory,
            )
            require(not orphaned, "orphaned pre-control runtime lacks durable caller authority")
            remove_user_runtime_projections(self.state)  # type: ignore[arg-type]
            return
        validated = validate_control_authority(
            control_value,
            state=self.state,
            runtime_identity=runtime,
            process_authority=process_authority,
        )
        root_control_digest = canonical_document_digest(control_value)
        ready_value = read_root_manifest(runtime, ROOT_READY_NAME)
        ready = (
            validate_ready_authority(
                ready_value,
                control=validated["control"],
                root_control_digest=root_control_digest,
                process_authority=process_authority,
            )
            if ready_value is not None
            else None
        )
        stopping_value = read_root_manifest(runtime, ROOT_STOPPING_NAME)
        if stopping_value is not None:
            stopping = exact_keys(
                stopping_value,
                {
                    "schema",
                    "outcome",
                    "observedAt",
                    "bootId",
                    "stateRoot",
                    "reason",
                    "rootControlSha256",
                    "runtimeRootIdentity",
                    "cgroup",
                    "supervisorProcessIdentity",
                },
                "root runtime stopping authority",
            )
            require(
                stopping["schema"] == STOPPING_SCHEMA
                and stopping["outcome"] == "stopping"
                and stopping["bootId"] == validated["control"]["bootId"]
                and stopping["stateRoot"] == str(self.state_root)
                and stopping["rootControlSha256"] == root_control_digest
                and stopping["runtimeRootIdentity"] == runtime.json()
                and stopping["cgroup"] == validated["cgroup"].json()
                and stopping["supervisorProcessIdentity"]
                == validated["supervisor"],
                "root stopping authority differs",
            )
        stop_value = read_root_manifest(runtime, ROOT_STOP_NAME)
        if stop_value is not None:
            stop = exact_keys(
                stop_value,
                {
                    "schema",
                    "outcome",
                    "observedAt",
                    "bootId",
                    "stateRoot",
                    "reason",
                    "supervisorProcessIdentity",
                    "runtimeRootIdentity",
                    "cgroup",
                    "rootStoppingSha256",
                    "storageProjectionDigest",
                    "socketRootRemoved",
                    "externalFinalizationRequired",
                },
                "root runtime stop authority",
            )
            require(
                stop["schema"] == STOP_SCHEMA
                and stop["outcome"] == "quiesced"
                and stop["bootId"] == validated["control"]["bootId"]
                and stop["stateRoot"] == str(self.state_root)
                and stop["runtimeRootIdentity"] == runtime.json()
                and stop["cgroup"] == validated["cgroup"].json()
                and isinstance(stop["rootStoppingSha256"], str)
                and stopping_value is not None
                and stop["rootStoppingSha256"]
                == canonical_document_digest(stopping_value)
                and stop["socketRootRemoved"] is True
                and stop["externalFinalizationRequired"] is True,
                "root stop authority differs",
            )
        if stop_value is None and stopping_value is None:
            socket_root_fd = verify_socket_root(
                validated["socketRoot"],
                self.caller_gid,
            )
            os.close(socket_root_fd)

        process_error = process_authority["ProcessIdentityError"]
        try:
            process_authority["verify_recorded_process"](
                validated["supervisor"],
                expected_uid=0,
                relax_parent_for_recovery=True,
            )
        except (process_error, FileNotFoundError, ProcessLookupError):
            pass
        else:
            raise SupervisorError("runtime lease was free while its exact supervisor remained live")

        cgroup = validated["cgroup"]
        if cgroup_is_populated(cgroup):
            kill_cgroup_and_wait(cgroup, timeout=60)

        socket_root = validated["socketRoot"]
        try:
            os.stat(socket_root.path, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            expected_socket = ready["socket"] if ready is not None else None
            if expected_socket is None:
                try:
                    expected_socket = capture_socket_identity(socket_root, self.caller_gid)
                except SupervisorError:
                    descriptor = verify_socket_root(socket_root, self.caller_gid)
                    try:
                        require(not os.listdir(descriptor), "unpublished Docker API root differs")
                    finally:
                        os.close(descriptor)
            remove_socket_root(socket_root, expected_socket, self.caller_gid)

        if not orphaned:
            helper = runtime.path / STORAGE_LIFECYCLE_NAME
            read_pinned_source(helper, STORAGE_LIFECYCLE_SHA256)
            read_pinned_source(
                runtime.path / STORAGE_IDENTITY_VERIFIER_NAME,
                STORAGE_IDENTITY_VERIFIER_SHA256,
            )
            self.runtime_identity = runtime
            self.storage_helper_path = helper
            self.storage_activation_attempted = True
            self.deactivated_storage = self.invoke_storage(
                "deactivate-private",
                "deactivated",
                allow_unpublished=True,
            )
        remove_runtime_root(runtime)
        remove_empty_cgroup(cgroup)
        if not orphaned:
            remove_user_runtime_projections(self.state)  # type: ignore[arg-type]
        self.runtime_identity = None
        self.storage_helper_path = None
        self.storage_activation_attempted = False
        self.deactivated_storage = None

    def setup(self) -> None:
        require_root_credentials()
        for executable in (PYTHON, CONTAINERD, DOCKERD, DOCKER, IP, UMOUNT):
            trusted_executable(executable)
        set_child_subreaper()
        require_exact_children(set())
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGQUIT, signal.SIG_IGN)
        require(self.lease is not None, "runtime lifecycle lease is absent")
        self.namespace = prove_private_namespace(os.getppid())
        self.process_verifier = load_process_verifier(self.script_directory)
        self.state = StateAuthority.open(self.state_root, self.caller_uid, self.caller_gid)
        self.recover_existing_runtime()
        require(
            not self.state.exists(CONTROL_RECEIPT_NAME)
            and not self.state.exists(START_RECEIPT_NAME),
            "isolated runtime receipt already exists",
        )
        require_exact_children(set())
        if self.state.exists(STOP_RECEIPT_NAME):
            self.state.unlink_regular(STOP_RECEIPT_NAME)
        self.cgroup_identity = create_cgroup(self.state_root)
        enter_cgroup(self.cgroup_identity)
        self.runtime_identity = create_runtime_root(runtime_root_for(self.state_root))
        self.socket_root_identity = create_socket_root(
            socket_root_for(self.state_root),
            self.caller_gid,
        )
        self.snapshot_storage_sources()
        self.supervisor_identity = self.verify_own_identity()
        self.write_control_receipt()
        require_address_pool_available(subprocess.run)
        require_exact_children(set())
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
        supervisor_source = read_pinned_source(
            self.script_directory / SUPERVISOR_SNAPSHOT_NAME,
            verified_supervisor_source_sha256(),
        )
        process_source = read_pinned_source(
            self.script_directory / PROCESS_IDENTITY_NAME,
            PROCESS_IDENTITY_SHA256,
        )
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
            _, supervisor_digest = write_runtime_bytes(
                runtime_fd,
                SUPERVISOR_SNAPSHOT_NAME,
                supervisor_source,
                mode=0o400,
            )
            _, process_digest = write_runtime_bytes(
                runtime_fd,
                PROCESS_IDENTITY_NAME,
                process_source,
                mode=0o400,
            )
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
            supervisor_digest == verified_supervisor_source_sha256()
            and process_digest == PROCESS_IDENTITY_SHA256
            and helper_digest == STORAGE_LIFECYCLE_SHA256
            and verifier_digest == STORAGE_IDENTITY_VERIFIER_SHA256,
            "runtime storage source snapshot digest differs",
        )
        self.storage_helper_path = helper_path

    def prepare_daemon_configuration(self) -> None:
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.storage is not None, "storage activation is absent")
        require(self.cgroup_identity is not None, "runtime cgroup authority is absent")
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
            runner_data = target_fd
            inner_fd = os.open(
                "inner-runner",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=runner_data,
            )
            try:
                inner = os.fstat(inner_fd)
                expected_inner = exact_keys(
                    self.storage["innerRunnerDataRoot"],
                    {"path", "device", "inode"},
                    "inner runner storage projection",
                )
                require(
                    inner.st_uid == 0
                    and inner.st_gid == 0
                    and stat.S_IMODE(inner.st_mode) == 0o700
                    and inner.st_dev == target.st_dev,
                    "inner runner data-root authority differs",
                )
                require(
                    expected_inner
                    == {
                        "path": str(MOUNT_TARGET / "inner-runner"),
                        "device": inner.st_dev,
                        "inode": inner.st_ino,
                    },
                    "inner runner data-root projection changed",
                )
            finally:
                os.close(inner_fd)
        finally:
            os.close(target_fd)

        authority_fd = os.open(
            AUTHORITY_ROOT,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            self.data_root = ensure_storage_directory(
                authority_fd,
                AUTHORITY_ROOT,
                "outer-docker",
                required_mode=0o710,
                recoverable_modes={0o700, 0o710},
            )
            self.containerd_root = ensure_storage_directory(
                authority_fd,
                AUTHORITY_ROOT,
                "outer-containerd",
                required_mode=0o700,
                recoverable_modes={0o700},
            )
        finally:
            os.close(authority_fd)

        runtime_fd = verify_runtime_root(self.runtime_identity)
        try:
            runtime = self.runtime_identity.path
            require(self.socket_root_identity is not None, "Docker API root is absent")
            self.socket = self.socket_root_identity.path / SOCKET_NAME
            self.containerd_socket = runtime / "containerd.sock"
            exec_root = runtime / "docker-exec"
            pidfile = runtime / "docker.pid"
            docker_value = docker_config(
                data_root=self.data_root,
                exec_root=exec_root,
                pidfile=pidfile,
                socket=self.socket,
                socket_gid=self.caller_gid,
                containerd_socket=self.containerd_socket,
                cgroup_parent=f"/{self.cgroup_identity.path.name}",
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
        require(self.socket_root_identity is not None, "Docker API root is absent")
        environment = self.daemon_environment()
        parent_pid = os.getpid()
        self.containerd_version = require_containerd_v2_or_later(
            subprocess.run(
                [str(CONTAINERD), "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
                cwd="/",
                env=environment,
            ).stdout.strip()
        )
        require_exact_children(set())
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
            preexec_fn=parent_death_preexec(parent_pid),
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
            expected_cgroup=self.expected_execution_cgroup(),
        )
        require_exact_children({self.containerd_process.pid})

        self.docker_process = subprocess.Popen(
            [str(DOCKERD), "--config-file", str(self.docker_config_path)],
            cwd="/",
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=sys.stderr,
            stderr=sys.stderr,
            close_fds=True,
            preexec_fn=parent_death_preexec(parent_pid),
        )
        wait_for(
            "isolated Docker daemon",
            lambda: self.docker_process is not None
            and self.docker_process.poll() is None
            and self.socket_root_identity is not None
            and socket_entry_ready(self.socket_root_identity, self.caller_gid),
            timeout=60,
        )
        self.socket_identity = capture_socket_identity(
            self.socket_root_identity,
            self.caller_gid,
        )
        first_docker = self.process_verifier(
            self.docker_process.pid,
            DOCKERD,
            ("--config-file", str(self.docker_config_path)),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
            expected_cgroup=self.expected_execution_cgroup(),
        )
        verify_socket_boundary(
            self.socket_root_identity,
            self.socket_identity,
            self.caller_gid,
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
        self.server_id = validate_docker_daemon_id(info_value.get("ID"))
        self.server_version = info_value.get("ServerVersion")
        require(
            isinstance(self.server_version, str) and 0 < len(self.server_version) <= 128,
            "isolated Docker server version is invalid",
        )
        verify_socket_boundary(
            self.socket_root_identity,
            self.socket_identity,
            self.caller_gid,
        )
        second_containerd = self.process_verifier(
            self.containerd_process.pid,
            CONTAINERD,
            ("--config", str(self.containerd_config_path), "--log-level", "info"),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
            expected_cgroup=self.expected_execution_cgroup(),
        )
        second_docker = self.process_verifier(
            self.docker_process.pid,
            DOCKERD,
            ("--config-file", str(self.docker_config_path)),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
            expected_cgroup=self.expected_execution_cgroup(),
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
            self.socket_root_identity is not None and self.socket_identity is not None,
            "Docker API socket identity is absent",
        )
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
            expected_cgroup=self.expected_execution_cgroup(),
        )
        docker_identity = self.process_verifier(
            self.docker_process.pid,
            DOCKERD,
            ("--config-file", str(self.docker_config_path)),
            expected_uid=0,
            expected_parent_pid=os.getpid(),
            expected_mount_namespace=self.namespace,
            expected_cgroup=self.expected_execution_cgroup(),
        )
        require(
            containerd_identity == self.containerd_identity
            and docker_identity == self.docker_identity,
            "isolated daemon identity changed before publication",
        )
        verify_socket_boundary(
            self.socket_root_identity,
            self.socket_identity,
            self.caller_gid,
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
            self.socket_root_identity is not None and self.socket_identity is not None,
            "Docker API socket authority is absent",
        )
        require(self.cgroup_identity is not None, "runtime cgroup authority is absent")
        require(self.root_control_digest is not None, "root control authority is absent")
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
            "supervisorSourceSha256": verified_supervisor_source_sha256(),
            "processIdentitySourceSha256": PROCESS_IDENTITY_SHA256,
            "storageLifecycleSourceSha256": STORAGE_LIFECYCLE_SHA256,
            "runtimeRoot": str(self.runtime_identity.path),
            "runtimeRootIdentity": self.runtime_identity.json(),
            "rootControlSha256": self.root_control_digest,
            "supervisorProcessIdentity": self.supervisor_identity,
            "mountNamespace": self.namespace,
            "cgroup": self.cgroup_identity.json(),
            "workloadCgroupParent": f"/{self.cgroup_identity.path.name}",
            "storage": self.storage,
            "socket": str(self.socket),
            "socketRootIdentity": self.socket_root_identity.json(),
            "socketIdentity": self.socket_identity.json(),
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
        self.root_ready_digest = write_root_manifest(
            self.runtime_identity,
            ROOT_READY_NAME,
            value,
        )
        self.state.write_json(
            START_RECEIPT_NAME,
            {
                "schema": READY_PROJECTION_SCHEMA,
                "rootReadySha256": self.root_ready_digest,
                "ready": value,
            },
        )

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
                    require(
                        self.socket_root_identity is not None
                        and self.socket_identity is not None,
                        "Docker API socket authority is absent",
                    )
                    verify_socket_boundary(
                        self.socket_root_identity,
                        self.socket_identity,
                        self.caller_gid,
                    )
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
        require(hasattr(os, "pidfd_open"), "pidfd process custody is unavailable")
        require(hasattr(signal, "pidfd_send_signal"), "pidfd signal delivery is unavailable")
        pidfd = os.pidfd_open(process.pid, 0)
        try:
            observed_identity = self.process_verifier(
                process.pid,
                executable,
                arguments,
                expected_uid=0,
                expected_parent_pid=os.getpid(),
                expected_mount_namespace=self.namespace,
                expected_cgroup=self.expected_execution_cgroup(),
            )
            require(expected_identity is not None, f"{name} recorded identity is absent")
            require(observed_identity == expected_identity, f"{name} identity changed before stop")
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired as error:
                raise SupervisorError(f"{name} did not stop within 60 seconds") from error
        finally:
            os.close(pidfd)

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
            if self.root_stopping_digest is None:
                self.write_shutdown_intent(reason)
            if first_attempt:
                self.write_control_receipt("stopping")
            # Docker owns running containers; it must drain before its dedicated
            # containerd.  The storage mount stays alive until both are reaped.
            self.terminate_daemon("dockerd", self.docker_process)
            self.terminate_daemon("containerd", self.containerd_process)
            wait_for_adopted_children(set())
            if self.socket_root_identity is not None and not self.socket_root_removed:
                remove_socket_root(
                    self.socket_root_identity,
                    self.socket_identity,
                    self.caller_gid,
                )
                self.socket_root_removed = True
            self.cleanup_task_netns()
            if self.storage_activation_attempted and self.deactivated_storage is None:
                self.deactivated_storage = self.invoke_storage(
                    "deactivate-private",
                    "deactivated",
                    allow_unpublished=self.storage is None,
                )
            require(self.runtime_identity is not None, "runtime identity is absent")
            require(self.cgroup_identity is not None, "runtime cgroup identity is absent")
            require(self.root_stopping_digest is not None, "root stopping authority is absent")
            existing_stop = read_root_manifest(self.runtime_identity, ROOT_STOP_NAME)
            if existing_stop is None:
                value: dict[str, object] = {
                    "schema": STOP_SCHEMA,
                    "outcome": "quiesced",
                    "observedAt": utc_now(),
                    "bootId": current_boot_id(),
                    "stateRoot": str(self.state_root),
                    "reason": reason,
                    "supervisorProcessIdentity": self.supervisor_identity,
                    "runtimeRootIdentity": self.runtime_identity.json(),
                    "cgroup": self.cgroup_identity.json(),
                    "rootStoppingSha256": self.root_stopping_digest,
                    "storageProjectionDigest": (
                        self.deactivated_storage["projectionDigest"]
                        if self.deactivated_storage is not None
                        else None
                    ),
                    "socketRootRemoved": True,
                    "externalFinalizationRequired": True,
                }
                self.root_stop_digest = write_root_manifest(
                    self.runtime_identity,
                    ROOT_STOP_NAME,
                    value,
                )
            else:
                value = exact_keys(
                    existing_stop,
                    {
                        "schema",
                        "outcome",
                        "observedAt",
                        "bootId",
                        "stateRoot",
                        "reason",
                        "supervisorProcessIdentity",
                        "runtimeRootIdentity",
                        "cgroup",
                        "rootStoppingSha256",
                        "storageProjectionDigest",
                        "socketRootRemoved",
                        "externalFinalizationRequired",
                    },
                    "existing root stop authority",
                )
                require(
                    value["schema"] == STOP_SCHEMA
                    and value["outcome"] == "quiesced"
                    and value["bootId"] == current_boot_id()
                    and value["stateRoot"] == str(self.state_root)
                    and value["reason"] == reason
                    and value["supervisorProcessIdentity"] == self.supervisor_identity
                    and value["runtimeRootIdentity"] == self.runtime_identity.json()
                    and value["cgroup"] == self.cgroup_identity.json()
                    and value["rootStoppingSha256"] == self.root_stopping_digest
                    and value["socketRootRemoved"] is True
                    and value["externalFinalizationRequired"] is True,
                    "existing root stop authority differs",
                )
                self.root_stop_digest = canonical_document_digest(value)
            require(self.root_stop_digest is not None, "root stop digest is absent")
            self.state.write_json(
                STOP_RECEIPT_NAME,
                {
                    "schema": "ambit.local-daytona-isolated-docker-stop-projection/v1",
                    "rootStopSha256": self.root_stop_digest,
                    "stop": value,
                },
            )
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
                "externalFinalizationRequired": True,
            }
            self.state.write_json(STOP_RECEIPT_NAME, failure)
            print(f"isolated runtime shutdown requires retry: {error}", file=sys.stderr, flush=True)
            return False

    def run(self) -> int:
        self.lease = RuntimeLease.acquire(self.state_root)
        try:
            try:
                self.setup()
            except BaseException as error:
                print(f"isolated runtime startup failed: {error}", file=sys.stderr, flush=True)
                if self.state is not None and self.runtime_identity is not None:
                    self.stop_requested = True
                    self.shutdown_reason = "startup_failure"
                    if not self.try_shutdown(self.shutdown_reason):
                        raise SupervisorError(
                            "startup recovery requires external cgroup finalization"
                        ) from error
                raise
            return self.monitor()
        finally:
            if self.state is not None:
                self.state.close()
                self.state = None
            if self.lease is not None:
                self.lease.close()
                self.lease = None


def _validated_existing_authorities(
    state: StateAuthority,
    script_directory: Path,
) -> tuple[RuntimeIdentity, dict[str, object], dict[str, object] | None, dict[str, Any]]:
    runtime = existing_runtime_identity(runtime_root_for(state.path))
    process_authority = load_process_authority(script_directory)
    control_value = read_root_manifest(runtime, ROOT_CONTROL_NAME)
    if control_value is None:
        reject_legacy_v4_runtime_roster(runtime)
    require(control_value is not None, "root runtime control authority is absent")
    validated = validate_control_authority(
        control_value,
        state=state,
        runtime_identity=runtime,
        process_authority=process_authority,
    )
    ready_value = read_root_manifest(runtime, ROOT_READY_NAME)
    ready = (
        validate_ready_authority(
            ready_value,
            control=validated["control"],
            root_control_digest=canonical_document_digest(control_value),
            process_authority=process_authority,
        )
        if ready_value is not None
        else None
    )
    return runtime, validated, ready, process_authority


def _stored_state_authority_from_control(
    control: object,
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
) -> StoredStateAuthority:
    require(isinstance(control, dict), "orphaned root control is not an object")
    assert isinstance(control, dict)
    require(
        control.get("schema") == CONTROL_SCHEMA
        and control.get("stateRoot") == str(state_root)
        and control.get("caller") == {"uid": caller_uid, "gid": caller_gid},
        "orphaned root control caller or state path differs",
    )
    state_identity = exact_keys(
        control.get("stateRootIdentity"),
        {"path", "device", "inode", "uid", "gid", "mode"},
        "orphaned state identity",
    )
    evidence_identity = exact_keys(
        control.get("evidenceRootIdentity"),
        {"path", "device", "inode", "uid", "gid", "mode"},
        "orphaned evidence identity",
    )
    require(
        state_identity["path"] == str(state_root)
        and evidence_identity["path"] == str(state_root / "evidence")
        and (state_identity["uid"], state_identity["gid"], state_identity["mode"])
        == (caller_uid, caller_gid, 0o700)
        and (evidence_identity["uid"], evidence_identity["gid"], evidence_identity["mode"])
        == (caller_uid, caller_gid, 0o700),
        "orphaned stored identity differs",
    )
    for label, identity in (
        ("state", state_identity),
        ("evidence", evidence_identity),
    ):
        plain_int(identity["device"], f"orphaned {label} device")
        plain_int(identity["inode"], f"orphaned {label} inode", positive=True)
        plain_int(identity["uid"], f"orphaned {label} owner")
        plain_int(identity["gid"], f"orphaned {label} group")
        plain_int(identity["mode"], f"orphaned {label} mode")
    require(
        state_identity["device"] == evidence_identity["device"],
        "orphaned state and evidence backing differ",
    )
    return StoredStateAuthority(
        state_root,
        caller_uid,
        caller_gid,
        state_identity,
        evidence_identity,
    )


def _validated_orphaned_authorities(
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
    script_directory: Path,
) -> tuple[
    StoredStateAuthority,
    RuntimeIdentity,
    dict[str, object],
    dict[str, object] | None,
    dict[str, Any],
]:
    runtime = existing_runtime_identity(runtime_root_for(state_root))
    process_authority = load_process_authority(script_directory)
    control_value = read_root_manifest(runtime, ROOT_CONTROL_NAME)
    if control_value is None:
        reject_legacy_v4_runtime_roster(runtime)
    require(control_value is not None, "orphaned root control authority is absent")
    state = _stored_state_authority_from_control(
        control_value,
        state_root,
        caller_uid,
        caller_gid,
    )
    validated = validate_control_authority(
        control_value,
        state=state,
        runtime_identity=runtime,
        process_authority=process_authority,
    )
    ready_value = read_root_manifest(runtime, ROOT_READY_NAME)
    ready = (
        validate_ready_authority(
            ready_value,
            control=validated["control"],
            root_control_digest=canonical_document_digest(control_value),
            process_authority=process_authority,
        )
        if ready_value is not None
        else None
    )
    return state, runtime, validated, ready, process_authority


def runtime_status(state_root: Path, caller_uid: int, caller_gid: int) -> dict[str, object]:
    with StateAuthority.open(state_root, caller_uid, caller_gid) as state:
        try:
            _, validated, ready, process_authority = _validated_existing_authorities(
                state,
                Path(__file__).resolve(strict=True).parent,
            )
        except FileNotFoundError:
            return {
                "schema": "ambit.local-daytona-isolated-docker-status/v1",
                "outcome": "absent",
                "stateRoot": str(state_root),
            }
        process_authority["verify_recorded_process"](
            validated["supervisor"],
            expected_uid=0,
            relax_parent_for_recovery=True,
        )
        require(cgroup_is_populated(validated["cgroup"]), "active runtime cgroup is empty")
        if ready is None:
            return {
                "schema": "ambit.local-daytona-isolated-docker-status/v1",
                "outcome": "starting",
                "stateRoot": str(state_root),
            }
        process_authority["verify_recorded_process"](
            ready["containerd"],
            expected_uid=0,
        )
        process_authority["verify_recorded_process"](
            ready["docker"],
            expected_uid=0,
        )
        verify_socket_boundary(
            ready["socketRoot"],
            ready["socket"],
            caller_gid,
        )
        return {
            "schema": "ambit.local-daytona-isolated-docker-status/v1",
            "outcome": "ready",
            "stateRoot": str(state_root),
            "socket": str(ready["socket"].path),
            "rootReadySha256": canonical_document_digest(ready["ready"]),
            "ready": ready["ready"],
        }


def acquire_runtime_lease_until(state_root: Path, *, timeout: float) -> RuntimeLease:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return RuntimeLease.acquire(state_root)
        except SupervisorError as error:
            if str(error) != "runtime lifecycle lease is busy":
                raise
        time.sleep(0.1)
    raise SupervisorError("runtime lifecycle lease remained busy")


def ensure_runtime_stopped(
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
) -> dict[str, object]:
    script_directory = Path(__file__).resolve(strict=True).parent
    state = StateAuthority.open(state_root, caller_uid, caller_gid)
    lease: RuntimeLease | None = None
    try:
        try:
            lease = RuntimeLease.acquire(state_root)
        except SupervisorError as error:
            require(str(error) == "runtime lifecycle lease is busy", str(error))
            deadline = time.monotonic() + 30.0
            validated = None
            process_authority = None
            while time.monotonic() < deadline:
                try:
                    _, validated, _, process_authority = _validated_existing_authorities(
                        state,
                        script_directory,
                    )
                    break
                except FileNotFoundError:
                    pass
                except SupervisorError as authority_error:
                    require(
                        str(authority_error) == "root runtime control authority is absent",
                        str(authority_error),
                    )
                if validated is None:
                    try:
                        lease = RuntimeLease.acquire(state_root)
                        break
                    except SupervisorError as retry_error:
                        require(
                            str(retry_error) == "runtime lifecycle lease is busy",
                            str(retry_error),
                        )
                    time.sleep(0.1)
            if lease is not None:
                validated = None
            require(
                lease is not None or (validated is not None and process_authority is not None),
                "live startup did not publish root control before stop timeout",
            )
        if lease is None:
            assert validated is not None and process_authority is not None
            try:
                process_authority["signal_recorded_process"](
                    validated["supervisor"],
                    expected_uid=0,
                    signum=signal.SIGTERM,
                    relax_parent_for_recovery=True,
                    exit_timeout_seconds=720.0,
                )
            except process_authority["ProcessIdentityError"]:
                # The immutable cgroup, rather than a recycled numeric PID, is
                # the recovery authority for every surviving descendant.
                kill_cgroup_and_wait(validated["cgroup"], timeout=60.0)
            lease = acquire_runtime_lease_until(state_root, timeout=60.0)

        supervisor = RuntimeSupervisor(state_root, caller_uid, caller_gid)
        supervisor.lease = lease
        supervisor.state = state
        supervisor.namespace = prove_private_namespace(os.getppid())
        supervisor.process_verifier = load_process_verifier(script_directory)
        set_child_subreaper()
        supervisor.recover_existing_runtime()
        value: dict[str, object] = {
            "schema": STOP_SCHEMA,
            "outcome": "passed",
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(state_root),
            "runtimeRootRemoved": True,
            "socketRootRemoved": True,
            "cgroupRemoved": True,
        }
        state.write_json(STOP_RECEIPT_NAME, value)
        return value
    finally:
        if lease is not None:
            lease.close()
        state.close()


def ensure_orphaned_runtime_stopped(
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
) -> dict[str, object]:
    script_directory = Path(__file__).resolve(strict=True).parent
    runtime_path = runtime_root_for(state_root)
    socket_path = socket_root_for(state_root)
    cgroup_path = cgroup_path_for(state_root)
    if not path_exists_nofollow(runtime_path):
        require(
            not path_exists_nofollow(socket_path),
            "orphaned socket root remains without root control authority",
        )
        if path_exists_nofollow(cgroup_path):
            value = os.stat(cgroup_path, follow_symlinks=False)
            identity = CgroupIdentity(cgroup_path, value.st_dev, value.st_ino)
            require(
                not cgroup_is_populated(identity),
                "orphaned cgroup remains populated without root control authority",
            )
            remove_empty_cgroup(identity)
        return {
            "schema": STOP_SCHEMA,
            "outcome": "passed",
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(state_root),
            "runtimeRootRemoved": True,
            "socketRootRemoved": True,
            "cgroupRemoved": True,
        }
    state, _, validated, _, process_authority = _validated_orphaned_authorities(
        state_root,
        caller_uid,
        caller_gid,
        script_directory,
    )
    lease: RuntimeLease | None = None
    try:
        try:
            lease = RuntimeLease.acquire(state_root)
        except SupervisorError as error:
            require(str(error) == "runtime lifecycle lease is busy", str(error))
            try:
                process_authority["signal_recorded_process"](
                    validated["supervisor"],
                    expected_uid=0,
                    signum=signal.SIGTERM,
                    relax_parent_for_recovery=True,
                    exit_timeout_seconds=720.0,
                )
            except process_authority["ProcessIdentityError"]:
                kill_cgroup_and_wait(validated["cgroup"], timeout=60.0)
            lease = acquire_runtime_lease_until(state_root, timeout=60.0)
        state, _, _, _, _ = _validated_orphaned_authorities(
            state_root,
            caller_uid,
            caller_gid,
            script_directory,
        )
        supervisor = RuntimeSupervisor(state_root, caller_uid, caller_gid)
        supervisor.lease = lease
        supervisor.state = state
        supervisor.namespace = prove_private_namespace(os.getppid())
        supervisor.process_verifier = load_process_verifier(script_directory)
        set_child_subreaper()
        supervisor.recover_existing_runtime(orphaned=True)
        return {
            "schema": STOP_SCHEMA,
            "outcome": "passed",
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(state_root),
            "runtimeRootRemoved": True,
            "socketRootRemoved": True,
            "cgroupRemoved": True,
        }
    finally:
        if lease is not None:
            lease.close()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    value.add_argument(
        "operation",
        choices=("supervise", "status", "ensure-stopped", "ensure-stopped-orphaned"),
    )
    value.add_argument("state_root", type=Path)
    value.add_argument("caller_uid")
    value.add_argument("caller_gid")
    return value


def main() -> None:
    os.umask(0o077)
    require(
        isinstance(globals().get("__verified_source_sha256__"), str),
        "supervisor was not entered through the hash-pinned launcher",
    )
    args = parser().parse_args()
    require(re.fullmatch(r"[1-9][0-9]*", args.caller_uid) is not None, "caller UID is invalid")
    require(re.fullmatch(r"[0-9]+", args.caller_gid) is not None, "caller GID is invalid")
    require_root_credentials()
    require(
        os.environ.get("SUDO_UID") == args.caller_uid
        and os.environ.get("SUDO_GID") == args.caller_gid,
        "authenticated sudo caller differs from arguments",
    )
    os.environ.clear()
    os.environ.update({"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": "/root"})
    caller_uid = int(args.caller_uid)
    caller_gid = int(args.caller_gid)
    if args.operation == "supervise":
        supervisor = RuntimeSupervisor(args.state_root, caller_uid, caller_gid)
        raise SystemExit(supervisor.run())
    if args.operation == "status":
        result = runtime_status(args.state_root, caller_uid, caller_gid)
    elif args.operation == "ensure-stopped":
        result = ensure_runtime_stopped(args.state_root, caller_uid, caller_gid)
    else:
        result = ensure_orphaned_runtime_stopped(
            args.state_root,
            caller_uid,
            caller_gid,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        fail(str(error))
