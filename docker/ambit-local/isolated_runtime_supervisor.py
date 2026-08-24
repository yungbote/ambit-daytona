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
from dataclasses import dataclass, field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping, NoReturn


LIBC = ctypes.CDLL(None, use_errno=True)

START_SCHEMA = "ambit.local-daytona-isolated-docker/v5"
CONTROL_SCHEMA = "ambit.local-daytona-isolated-docker-control/v2"
STOP_SCHEMA = "ambit.local-daytona-isolated-docker-stop/v2"
STOPPING_SCHEMA = "ambit.local-daytona-isolated-docker-stopping/v1"
NETNS_BASELINE_SCHEMA = "ambit.local-daytona-isolated-docker-netns-baseline/v1"
NETNS_DETACH_SCHEMA = "ambit.local-daytona-isolated-docker-netns-detach/v1"
CONTROL_PROJECTION_SCHEMA = "ambit.local-daytona-isolated-docker-control-projection/v1"
READY_PROJECTION_SCHEMA = "ambit.local-daytona-isolated-docker-ready-projection/v1"
STORAGE_OPERATION_SCHEMA = "ambit.local-daytona-runner-storage-operation/v3"
STORAGE_RECEIPT_SCHEMA = "ambit.local-daytona-runner-storage/v3"

AUTHORITY_ROOT = Path("/home/.ambit-c16b-runner-storage")
MOUNT_TARGET = AUTHORITY_ROOT / "runner-docker"
STORAGE_IMAGE = AUTHORITY_ROOT / "runner-docker.xfs"
RUNTIME_PARENT = Path("/run")
RUNTIME_PREFIX = "ambit-c16b-docker-"
RUNTIME_REMOVAL_PREFIX = "ambit-c16b-docker-removing-"
SOCKET_ROOT_PREFIX = "ambit-c16b-docker-api-"
GLOBAL_LEASE_NAME = "ambit-c16b-docker-global.lock"
STATE_ROOT_RE = re.compile(r"^/home/[^/]+/[A-Za-z0-9._/-]+$")
RUNTIME_ROOT_RE = re.compile(r"^/run/ambit-c16b-docker-[0-9a-f]{12}$")
RUNTIME_REMOVAL_ROOT_RE = re.compile(r"^/run/ambit-c16b-docker-removing-[0-9a-f]{12}$")
LEGACY_V3_STATE_ROOT = Path("/home/bote/m/.local/ambit-daytona-c16b/state")
LEGACY_V3_RECEIPT_SHA256 = "c7b6f7f5f77ae5569a918cd33a811aa855b781f3c007df6f9f19bf1d3f458c21"
LEGACY_V3_LIVE_RECEIPT = LEGACY_V3_STATE_ROOT / "evidence/outer-docker-receipt.json"
LEGACY_V3_TERMINAL_ARCHIVE = LEGACY_V3_STATE_ROOT / ("evidence/outer-docker-receipt.legacy-v3-c7b6f7f5f77ae556.json")
LEGACY_V3_PREPARED_ARCHIVE = LEGACY_V3_STATE_ROOT / (
    "evidence/.outer-docker-receipt.legacy-v3-c7b6f7f5f77ae556.prepared"
)
LEGACY_V3_CONTROL_ROOT = Path("/run/ambit-c16b-legacy-v3-drain-1577287b8182")
SOCKET_ROOT_RE = re.compile(r"^/run/ambit-c16b-docker-api-[0-9a-f]{12}$")
LEASE_PATH_RE = re.compile(r"^/run/ambit-c16b-docker-global\.lock$")
CGROUP_PARENT = Path("/sys/fs/cgroup")
CGROUP_PREFIX = "ambit-c16b-docker-"
CGROUP_EXECUTION_NAME = "runtime"
CGROUP_PATH_RE = re.compile(r"^/sys/fs/cgroup/ambit-c16b-docker-[0-9a-f]{12}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DOCKER_DAEMON_ID_RE = re.compile(r"^[A-Z2-7]{4}(?::[A-Z2-7]{4}){11}$")
CONTAINERD_VERSION_RE = re.compile(r"\bv([0-9]+)\.[0-9]+\.[0-9]+(?:[-+][^\s]+)?\b")
LOOP_DEVICE_RE = re.compile(r"^/dev/loop[0-9]+$")
OPAQUE_MOUNT_ROOT = re.compile(r"^[a-z][a-z0-9_-]*:\[[1-9][0-9]*\]$")
MOUNT_DEVICE_RE = re.compile(r"^(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)$")
TASK_NETNS_ENTRY_RE = re.compile(r"^[A-Za-z0-9._-]+$")
IMAGE_BYTES = 60 * 1024**3
SANDBOX_BYTES = 20 * 1024**3
MAXIMUM_SANDBOXES = 2

MountSourceAnchor = tuple[str, Path]
MountOccurrence = tuple[str, str]
AmbientNetnsSource = tuple[MountSourceAnchor, tuple[str, ...]]
TaskNetnsDetachEntry = tuple[
    Path,
    tuple[MountSourceAnchor, ...],
    tuple[str, ...],
    tuple[MountOccurrence, ...],
]

PYTHON = Path("/usr/bin/python3")
CONTAINERD = Path("/usr/bin/containerd")
DOCKERD = Path("/usr/bin/dockerd")
DOCKER = Path("/usr/bin/docker")
IP = Path("/usr/bin/ip")
UMOUNT = Path("/usr/bin/umount")

PROCESS_IDENTITY_NAME = "isolated_process_identity.py"
SUPERVISOR_SNAPSHOT_NAME = "isolated_runtime_supervisor.py"
PROCESS_IDENTITY_SHA256 = "8dc76b554bc5dd7810f217a0c5b082ada500d3bb9d0c5afce46e5415ed983b2c"
STORAGE_LIFECYCLE_NAME = "runner-storage-lifecycle.py"
STORAGE_LIFECYCLE_SHA256 = "62472dcefdfee225b417eab16b31fcfc9d265d127574c8d8febb22ccbf1522fb"
STORAGE_IDENTITY_VERIFIER_NAME = "verify-runner-storage.py"
STORAGE_IDENTITY_VERIFIER_SHA256 = "59c530e8c502c546689967c33c540217d2762ff9d3f8ef7424ba52462c554f0b"
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
    "runtime-netns-baseline.json",
    "runtime-netns-detach.json",
    "runtime-stop.json",
    ".runtime-control.json.pending",
    ".runtime-ready.json.pending",
    ".runtime-stopping.json.pending",
    ".runtime-netns-baseline.json.pending",
    ".runtime-netns-detach.json.pending",
    ".runtime-stop.json.pending",
}
RUNTIME_SOCKET_ENTRIES = {"containerd.sock", "containerd.sock.ttrpc"}

ROOT_CONTROL_NAME = "runtime-control.json"
ROOT_READY_NAME = "runtime-ready.json"
ROOT_STOPPING_NAME = "runtime-stopping.json"
ROOT_NETNS_BASELINE_NAME = "runtime-netns-baseline.json"
ROOT_NETNS_DETACH_NAME = "runtime-netns-detach.json"
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
LEGACY_TMP_RUNTIME_RE = re.compile(r"^/tmp/ambit-c16b-docker-[0-9a-f]{12}$")

CONTROL_RECEIPT_NAME = "outer-docker-control.json"
START_RECEIPT_NAME = "outer-docker-receipt.json"
STOP_RECEIPT_NAME = "outer-docker-stop-receipt.json"

PINNED_EXEC_LOADER = r"""
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
""".strip()


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


def _descriptor_roster(values: tuple[object, ...]) -> tuple[int, ...]:
    descriptors: list[int] = []
    for value in values:
        require(
            type(value) is int and value >= 0,
            "owned file descriptor is not a nonnegative built-in integer",
        )
        descriptor = value
        require(
            descriptor not in descriptors,
            "owned file descriptor roster contains a duplicate numeric alias",
        )
        descriptors.append(descriptor)
    return tuple(descriptors)


def _add_cleanup_note(
    primary: BaseException,
    descriptor: int,
    cleanup_error: BaseException,
) -> None:
    """Attach cleanup context without allowing hostile exceptions to mask primary."""

    try:
        primary.add_note(f"additional descriptor cleanup failure for fd {descriptor}: {type(cleanup_error).__name__}")
    except BaseException:
        pass


def _add_cleanup_validation_note(
    primary: BaseException,
    cleanup_error: BaseException,
) -> None:
    try:
        primary.add_note(f"descriptor cleanup authority validation failed: {type(cleanup_error).__name__}")
    except BaseException:
        pass


@dataclass
class CleanupOutcome:
    primary: BaseException | None

    def record(
        self,
        cleanup_error: BaseException,
        descriptor: int | None = None,
    ) -> None:
        if self.primary is None:
            mask = suspend_python_interruptions()
            try:
                self.primary = cleanup_error
            finally:
                restore_python_interruptions(mask)
            return
        if self.primary is cleanup_error:
            return
        if descriptor is None:
            _add_cleanup_validation_note(self.primary, cleanup_error)
        else:
            _add_cleanup_note(self.primary, descriptor, cleanup_error)


@dataclass(frozen=True)
class InterruptionMask:
    trace: Any
    profile: Any
    signal_mask: set[signal.Signals] | None


def suspend_python_interruptions() -> InterruptionMask:
    trace = sys.gettrace()
    profile = sys.getprofile()
    mask = InterruptionMask(trace, profile, None)
    first_error: BaseException | None = None
    try:
        sys.settrace(None)
    except BaseException as error:
        first_error = error
    try:
        sys.setprofile(None)
    except BaseException as error:
        if first_error is None:
            first_error = error
        else:
            _add_cleanup_validation_note(first_error, error)
    if first_error is not None:
        restore_python_interruptions(mask, first_error)
        raise first_error
    blockable = signal.valid_signals() - {signal.SIGKILL, signal.SIGSTOP}
    try:
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, blockable)
    except BaseException as error:
        restore_python_interruptions(mask, error)
        raise
    return InterruptionMask(trace, profile, previous)


def restore_python_interruptions(
    mask: InterruptionMask,
    first_error: BaseException | None = None,
) -> None:
    if mask.signal_mask is not None:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask.signal_mask)
        except BaseException as error:
            if first_error is None:
                first_error = error
            else:
                _add_cleanup_validation_note(first_error, error)

    def fail_stop_after_hook_attempts(primary: BaseException) -> NoReturn:
        try:
            sys.setprofile(mask.profile); sys.setprofile(None)  # noqa: E702
        except BaseException as hook_error:
            _add_cleanup_validation_note(primary, hook_error)
        try:
            sys.settrace(mask.trace); sys.settrace(None)  # noqa: E702
        except BaseException as hook_error:
            _add_cleanup_validation_note(primary, hook_error)
        try:
            sys.setprofile(None)
        except BaseException as hook_error:
            _add_cleanup_validation_note(primary, hook_error)
        try:
            sys.settrace(None)
        except BaseException as hook_error:
            _add_cleanup_validation_note(primary, hook_error)
        raise primary

    if first_error is not None:
        fail_stop_after_hook_attempts(first_error)
    try:
        sys.setprofile(mask.profile)
    except BaseException as error:
        fail_stop_after_hook_attempts(error)
    try:
        sys.settrace(mask.trace); return  # noqa: E702
    except BaseException as error:
        fail_stop_after_hook_attempts(error)


class DescriptorCustody:
    """Lexically own a distinct descriptor roster until close.

    Close marks the complete roster attempted before the first syscall.  A
    numeric descriptor is therefore never retried after an ambiguous close
    failure, while every other descriptor still receives one close attempt.
    """

    def __init__(self, descriptors: tuple[object, ...] = ()) -> None:
        self._owned = list(_descriptor_roster(descriptors))
        self._attempted: list[int] = []
        self._failures: list[tuple[int, BaseException]] = []
        self._merged_failure_count = 0
        self._cleanup_primary: BaseException | None = None
        self._primary_reported = False
        self._ambiguous_close = False
        self._closed = False

    def acquire(self, factory: Callable[[], object]) -> int:
        descriptor: object | None = None
        try:
            require(not self._closed, "descriptor custody is already closed")
            mask = suspend_python_interruptions()
            try:
                descriptor = factory()
                value = _descriptor_roster((*self._owned, descriptor))[-1]
                self._owned.append(value)
            finally:
                restore_python_interruptions(mask)
            return value
        except BaseException as primary:
            if type(descriptor) is int and descriptor >= 0 and descriptor not in self._owned:
                DescriptorCustody((descriptor,)).close(primary)
            raise

    @property
    def owned(self) -> tuple[int, ...]:
        return tuple(self._owned)

    @property
    def attempted(self) -> tuple[int, ...]:
        return tuple(self._attempted)

    @property
    def failures(self) -> tuple[tuple[int, BaseException], ...]:
        return tuple(self._failures)

    @property
    def disposition(self) -> str:
        if self._owned:
            return "pending"
        if self._ambiguous_close:
            return "ambiguous"
        if self._closed:
            return "complete"
        return "open"

    def _close_next(self) -> tuple[int, BaseException] | None:
        descriptor = self._owned[-1]
        if descriptor in self._attempted:
            self._owned.pop()
            return None
        cleanup_error: BaseException | None = None
        mask = suspend_python_interruptions()
        try:
            self._attempted.append(descriptor)
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_error = error
            self._owned.pop()
            if cleanup_error is not None:
                self._ambiguous_close = True
                self._record_cleanup_error(cleanup_error, descriptor)
                failure = (descriptor, cleanup_error)
                self._failures.append(failure)
                self._merged_failure_count = len(self._failures)
        finally:
            restore_python_interruptions(mask)
        if cleanup_error is not None:
            return failure
        return None

    def _record_cleanup_error(
        self,
        cleanup_error: BaseException,
        descriptor: int | None,
    ) -> None:
        if self._cleanup_primary is None:
            self._cleanup_primary = cleanup_error
            return
        if self._cleanup_primary is cleanup_error:
            return
        if descriptor is None:
            _add_cleanup_validation_note(self._cleanup_primary, cleanup_error)
        else:
            _add_cleanup_note(self._cleanup_primary, descriptor, cleanup_error)

    def _merge_recorded_failures(self) -> None:
        while self._merged_failure_count < len(self._failures):
            descriptor, cleanup_error = self._failures[self._merged_failure_count]
            self._record_cleanup_error(
                cleanup_error,
                descriptor,
            )
            self._merged_failure_count += 1

    def _recover_contextual_close_failure(self, driver_error: BaseException) -> None:
        contextual = driver_error.__context__
        if contextual is None or not self._attempted:
            return
        descriptor = self._attempted[-1]
        if any(recorded == descriptor for recorded, _ in self._failures):
            return
        self._failures.append((descriptor, contextual))

    def _drain(self) -> None:
        while self._owned:
            try:
                failure = self._close_next()
            except BaseException as driver_error:
                self._merge_recorded_failures()
                self._record_cleanup_error(
                    driver_error,
                    None,
                )
                continue
            if failure is not None:
                self._merge_recorded_failures()

    def close(self, primary: BaseException | None = None) -> None:
        if self._closed:
            return
        if primary is not None and self._cleanup_primary is not primary:
            if self._cleanup_primary is not None:
                _add_cleanup_validation_note(primary, self._cleanup_primary)
            self._cleanup_primary = primary
        while self._owned:
            try:
                self._drain()
            except BaseException as driver_error:
                self._recover_contextual_close_failure(driver_error)
                self._merge_recorded_failures()
                self._record_cleanup_error(
                    driver_error,
                    None,
                )
        self._merge_recorded_failures()
        self._closed = True
        if primary is None and self._cleanup_primary is not None:
            raise self._cleanup_primary

    def __enter__(self) -> "DescriptorCustody":
        require(not self._closed, "descriptor custody is already closed")
        return self

    def __exit__(
        self,
        _exception_type: object,
        primary: BaseException | None,
        _traceback: object,
    ) -> bool:
        outcome = CleanupOutcome(primary)
        _close_custody_roster_failure_total((self,), outcome)
        if primary is None and outcome.primary is not None:
            raise outcome.primary
        return False


class DescriptorCustodyGate:
    """Outer retry boundary for an interrupt before custody ``__exit__`` starts."""

    def __init__(self) -> None:
        self.custody = DescriptorCustody()

    def __enter__(self) -> "DescriptorCustodyGate":
        return self

    def __exit__(
        self,
        _exception_type: object,
        primary: BaseException | None,
        _traceback: object,
    ) -> bool:
        durable_primary = self.custody._cleanup_primary
        if (
            durable_primary is None
            and primary is not None
            and primary.__context__ is not None
            and not self.custody.attempted
        ):
            durable_primary = primary.__context__
        effective_primary = (
            durable_primary if durable_primary is not None else primary
        )
        if (
            effective_primary is not None
            and primary is not None
            and effective_primary is not primary
        ):
            _add_cleanup_validation_note(effective_primary, primary)
        outcome = CleanupOutcome(effective_primary)
        if self.custody.owned:
            _close_custody_roster_failure_total((self.custody,), outcome)
        if outcome.primary is not None and outcome.primary is not primary:
            raise outcome.primary
        if primary is None and outcome.primary is not None:
            raise outcome.primary
        return False


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
    require(
        isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
        "supervisor source digest is invalid",
    )
    return value


def fallback_script_directory() -> Path:
    value = globals().get("__fallback_script_directory__")
    if value is None:
        return Path(__file__).resolve(strict=True).parent
    require(
        isinstance(value, str) and value.startswith("/"),
        "fallback source directory is invalid",
    )
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
        isinstance(value, str) and len(value) == 59 and DOCKER_DAEMON_ID_RE.fullmatch(value) is not None,
        "isolated Docker server identity is invalid",
    )
    return value


def require_containerd_v2_or_later(value: str) -> str:
    require(
        isinstance(value, str) and 0 < len(value) <= 512,
        "containerd version is invalid",
    )
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
            not any(item.startswith(("shared:", "master:", "propagate_from:")) for item in optional),
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
        observed.st_uid == 0 and observed.st_gid == 0 and stat.S_IMODE(observed.st_mode) & 0o022 == 0,
        f"trusted executable owner or mode differs: {path}",
    )
    return resolved


def read_pinned_source(path: Path, expected_sha256: str) -> bytes:
    require(
        SHA256_RE.fullmatch(expected_sha256) is not None,
        "pinned source digest is invalid",
    )
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW))
        identity = os.fstat(descriptor)
        require(stat.S_ISREG(identity.st_mode), "pinned source is not regular")
        require(0 < identity.st_size <= 2 * 1024 * 1024, "pinned source size is invalid")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
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
        require(
            callable(namespace.get(name)),
            f"pinned process authority entrypoint is absent: {name}",
        )
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
    require(
        raw.endswith(b"\0") and raw.count(b"\0") >= 2,
        "supervisor argument vector is invalid",
    )
    return hashlib.sha256(raw).hexdigest()


@dataclass
class StateAuthority:
    path: Path
    caller_uid: int
    caller_gid: int
    root_fd: int
    evidence_fd: int
    _descriptors: DescriptorCustody = dataclass_field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        self._descriptors = (
            DescriptorCustody()
            if (self.root_fd, self.evidence_fd) == (-1, -1)
            else DescriptorCustody((self.root_fd, self.evidence_fd))
        )

    @classmethod
    def pending(cls, path: Path, caller_uid: int, caller_gid: int) -> "StateAuthority":
        return cls(path, caller_uid, caller_gid, -1, -1)

    def acquire(self) -> None:
        require(
            (self.root_fd, self.evidence_fd) == (-1, -1) and not self._descriptors.owned,
            "state authority is already acquired or retired",
        )
        try:
            require(
                STATE_ROOT_RE.fullmatch(str(self.path)) is not None,
                "state root path is invalid",
            )
            require(
                self.path.resolve(strict=True) == self.path,
                "state root is not canonical",
            )
            root_fd = self._descriptors.acquire(
                lambda: os.open(
                    self.path,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            )
            root = os.fstat(root_fd)
            path_identity = os.stat(self.path, follow_symlinks=False)
            require(stat.S_ISDIR(root.st_mode), "state root is not a directory")
            require(
                (root.st_dev, root.st_ino) == (path_identity.st_dev, path_identity.st_ino),
                "state root changed while opening",
            )
            require(
                (root.st_uid, root.st_gid, stat.S_IMODE(root.st_mode)) == (self.caller_uid, self.caller_gid, 0o700),
                "state root owner, group, or mode differs",
            )
            self.root_fd = root_fd
            evidence_fd = self._descriptors.acquire(
                lambda: os.open(
                    "evidence",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=root_fd,
                )
            )
            evidence = os.fstat(evidence_fd)
            evidence_path = os.stat("evidence", dir_fd=root_fd, follow_symlinks=False)
            require(
                (evidence.st_dev, evidence.st_ino) == (evidence_path.st_dev, evidence_path.st_ino),
                "evidence root changed while opening",
            )
            require(
                stat.S_ISDIR(evidence.st_mode)
                and (evidence.st_uid, evidence.st_gid, stat.S_IMODE(evidence.st_mode))
                == (self.caller_uid, self.caller_gid, 0o700),
                "evidence root owner, group, or mode differs",
            )
            self.evidence_fd = evidence_fd
        except BaseException as primary:
            self.root_fd = -1
            self.evidence_fd = -1
            self._descriptors.close(primary)
            raise

    def close(self, primary: BaseException | None = None) -> None:
        settle_runtime_authorities(state=self, lease=None, primary=primary)

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
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            descriptor = descriptors.acquire(
                lambda: os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=self.evidence_fd,
                )
            )
            observed = os.fstat(descriptor)
            literal = os.stat(name, dir_fd=self.evidence_fd, follow_symlinks=False)
            require(
                stat.S_ISREG(observed.st_mode)
                and observed.st_uid == self.caller_uid
                and observed.st_gid == self.caller_gid
                and stat.S_IMODE(observed.st_mode) == 0o600
                and observed.st_dev == os.fstat(self.evidence_fd).st_dev
                and observed.st_nlink == 1
                and (observed.st_dev, observed.st_ino) == (literal.st_dev, literal.st_ino),
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
            self.unlink_regular(temporary)
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            descriptor = descriptors.acquire(
                lambda: os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self.evidence_fd,
                )
            )
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fchown(descriptor, self.caller_uid, self.caller_gid)
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
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
                self.unlink_regular(temporary)
            except (FileNotFoundError, OSError, SupervisorError):
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


def writable_state_authority(
    value: StateAuthority | StoredStateAuthority,
) -> StateAuthority:
    require(isinstance(value, StateAuthority), "writable caller state authority is absent")
    return value


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
    _descriptors: DescriptorCustody = dataclass_field(
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        self._descriptors = (
            DescriptorCustody()
            if (self.parent_fd, self.descriptor) == (-1, -1)
            else DescriptorCustody((self.parent_fd, self.descriptor))
        )

    @classmethod
    def pending(cls, state_root: Path) -> "RuntimeLease":
        path = lease_path_for(state_root)
        return cls(path, -1, -1, -1, -1)

    def acquire(self, *, blocking: bool = False) -> None:
        path = self.path
        require(
            (self.parent_fd, self.descriptor, self.device, self.inode) == (-1, -1, -1, -1)
            and not self._descriptors.owned,
            "runtime lease is already acquired or retired",
        )
        require(
            LEASE_PATH_RE.fullmatch(str(path)) is not None,
            "runtime lease path is invalid",
        )
        try:
            parent_fd = self._descriptors.acquire(
                lambda: os.open(
                    RUNTIME_PARENT,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            )
            parent = os.fstat(parent_fd)
            require(
                stat.S_ISDIR(parent.st_mode)
                and parent.st_uid == 0
                and parent.st_gid == 0
                and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
                "runtime lease parent authority differs",
            )
            self.parent_fd = parent_fd
            descriptor = self._descriptors.acquire(
                lambda: os.open(
                    path.name,
                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_fd,
                )
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
            self.descriptor = descriptor
            self.device = observed.st_dev
            self.inode = observed.st_ino
        except BaseException as primary:
            self.parent_fd = -1
            self.descriptor = -1
            self.device = -1
            self.inode = -1
            self._descriptors.close(primary)
            if self._descriptors.disposition != "complete":
                raise SupervisorError(
                    "runtime lease cleanup is ambiguous; retry is forbidden"
                ) from primary
            raise

    def close(self, primary: BaseException | None = None) -> None:
        settle_runtime_authorities(state=None, lease=self, primary=primary)


def _authority_descriptor_pair(
    values: tuple[object, object],
    name: str,
) -> tuple[int, ...]:
    require(
        all(type(value) is int for value in values),
        f"{name} descriptor state is not built-in integer authority",
    )
    if values == (-1, -1):
        return ()
    require(
        all(value >= 0 for value in values),
        f"{name} descriptor state is partial or invalid",
    )
    return _descriptor_roster(values)


def _close_custody_roster(
    custodies: tuple[DescriptorCustody, ...],
    outcome: CleanupOutcome,
) -> None:
    for custody in custodies:
        while custody.owned:
            try:
                custody.close(outcome.primary)
            except BaseException as cleanup_error:
                if custody._cleanup_primary is not None and not custody._primary_reported:
                    outcome.record(custody._cleanup_primary)
                    custody._primary_reported = True
                outcome.record(cleanup_error)
        if custody._cleanup_primary is not None and not custody._primary_reported:
            outcome.record(custody._cleanup_primary)
            custody._primary_reported = True


def _close_custody_roster_failure_total(
    custodies: tuple[DescriptorCustody, ...],
    outcome: CleanupOutcome,
) -> None:
    while any(custody.owned for custody in custodies):
        try:
            _close_custody_roster(custodies, outcome)
        except BaseException as driver_error:
            outcome.record(driver_error)
    for custody in custodies:
        if custody._cleanup_primary is not None and not custody._primary_reported:
            outcome.record(custody._cleanup_primary)
            custody._primary_reported = True


def _retire_and_close_authorities(
    *,
    state: StateAuthority | None,
    lease: RuntimeLease | None,
    custodies: tuple[DescriptorCustody, ...],
    outcome: CleanupOutcome,
) -> None:
    try:
        if state is not None:
            state.root_fd = -1
            state.evidence_fd = -1
        if lease is not None:
            lease.parent_fd = -1
            lease.descriptor = -1
            lease.device = -1
            lease.inode = -1
    except BaseException as retirement_error:
        if state is not None:
            state.root_fd = -1
            state.evidence_fd = -1
        if lease is not None:
            lease.parent_fd = -1
            lease.descriptor = -1
            lease.device = -1
            lease.inode = -1
        outcome.record(retirement_error)
    _close_custody_roster_failure_total(custodies, outcome)


def _retire_and_close_authorities_failure_total(
    *,
    state: StateAuthority | None,
    lease: RuntimeLease | None,
    custodies: tuple[DescriptorCustody, ...],
    outcome: CleanupOutcome,
) -> None:
    while True:
        try:
            _retire_and_close_authorities(
                state=state,
                lease=lease,
                custodies=custodies,
                outcome=outcome,
            )
        except BaseException as driver_error:
            outcome.record(driver_error)
            if any(custody.owned for custody in custodies):
                continue
        return


def _close_runtime_authorities_once(
    *,
    state: StateAuthority | None,
    lease: RuntimeLease | None,
    primary: BaseException | None = None,
) -> bool:
    """Atomically retire and close the composed state/lease descriptor roster."""

    state_owned = state._descriptors.owned if state is not None else ()
    lease_owned = lease._descriptors.owned if lease is not None else ()
    try:
        _descriptor_roster((*lease_owned, *state_owned))
    except BaseException as cleanup_error:
        if primary is not None:
            _add_cleanup_validation_note(primary, cleanup_error)
            return False
        raise
    outcome = CleanupOutcome(primary)
    try:
        lease_descriptors = (
            _authority_descriptor_pair(
                (lease.parent_fd, lease.descriptor),
                "runtime lease",
            )
            if lease is not None
            else ()
        )
        state_descriptors = (
            _authority_descriptor_pair(
                (state.root_fd, state.evidence_fd),
                "state authority",
            )
            if state is not None
            else ()
        )
        require(
            lease_descriptors == lease_owned,
            "runtime lease descriptor projection differs from custody",
        )
        require(
            state_descriptors == state_owned,
            "state authority descriptor projection differs from custody",
        )
        _descriptor_roster((*lease_descriptors, *state_descriptors))
    except BaseException as cleanup_error:
        outcome.record(cleanup_error)
    custodies = tuple(
        custody
        for custody in (
            state._descriptors if state is not None else None,
            lease._descriptors if lease is not None else None,
        )
        if custody is not None
    )
    try:
        _retire_and_close_authorities_failure_total(
            state=state,
            lease=lease,
            custodies=custodies,
            outcome=outcome,
        )
    except BaseException as driver_error:
        outcome.record(driver_error)
        _retire_and_close_authorities_failure_total(
            state=state,
            lease=lease,
            custodies=custodies,
            outcome=outcome,
        )
    if primary is None and outcome.primary is not None:
        raise outcome.primary
    return True


def settle_runtime_authorities(
    *,
    state: StateAuthority | None,
    lease: RuntimeLease | None,
    primary: BaseException | None = None,
) -> bool:
    """Outer iterative retry/fail-stop gate for composed authority cleanup."""

    outcome = CleanupOutcome(primary)
    attempted = False
    while (
        not attempted
        or (state is not None and bool(state._descriptors.owned))
        or (lease is not None and bool(lease._descriptors.owned))
    ):
        attempted = True
        try:
            settled = _close_runtime_authorities_once(
                state=state,
                lease=lease,
                primary=outcome.primary,
            )
        except BaseException as cleanup_error:
            outcome.record(cleanup_error)
            continue
        if not settled:
            if primary is None and outcome.primary is not None:
                raise outcome.primary
            return False
    if primary is None and outcome.primary is not None:
        raise outcome.primary
    return True


def runtime_id_for(state_root: Path) -> str:
    return hashlib.sha256(str(state_root).encode()).hexdigest()[:12]


def runtime_root_for(state_root: Path) -> Path:
    return RUNTIME_PARENT / f"{RUNTIME_PREFIX}{runtime_id_for(state_root)}"


def runtime_removal_root_for(state_root: Path) -> Path:
    return RUNTIME_PARENT / f"{RUNTIME_REMOVAL_PREFIX}{runtime_id_for(state_root)}"


def socket_root_for(state_root: Path) -> Path:
    return RUNTIME_PARENT / f"{SOCKET_ROOT_PREFIX}{runtime_id_for(state_root)}"


def lease_path_for(state_root: Path) -> Path:
    require(state_root.is_absolute(), "runtime lease state path is invalid")
    return RUNTIME_PARENT / GLOBAL_LEASE_NAME


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
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(lambda: os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd))
        return _read_fd_all(descriptor).decode("ascii", "strict")


def _write_at(directory_fd: int, name: str, value: bytes) -> None:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(lambda: os.open(name, os.O_WRONLY | os.O_NOFOLLOW, dir_fd=directory_fd))
        offset = 0
        while offset < len(value):
            offset += os.write(descriptor, value[offset:])


def create_cgroup(state_root: Path) -> CgroupIdentity:
    path = cgroup_path_for(state_root)
    require(
        CGROUP_PATH_RE.fullmatch(str(path)) is not None,
        "runtime cgroup path is invalid",
    )
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        parent_fd = descriptors.acquire(lambda: os.open(CGROUP_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
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
            descriptor = descriptors.acquire(
                lambda: os.open(
                    path.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
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
            for name in (
                "cgroup.procs",
                "cgroup.events",
                "cgroup.freeze",
                "cgroup.kill",
            ):
                value = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                require(
                    stat.S_ISREG(value.st_mode),
                    f"runtime cgroup control is absent: {name}",
                )
            require(
                _read_at(descriptor, "cgroup.type").strip() == "domain",
                "runtime cgroup type differs",
            )
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
            execution_fd = descriptors.acquire(
                lambda: os.open(
                    CGROUP_EXECUTION_NAME,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            )
            execution = os.fstat(execution_fd)
            require(
                stat.S_ISDIR(execution.st_mode)
                and execution.st_uid == 0
                and execution.st_gid == 0
                and stat.S_IMODE(execution.st_mode) == 0o700,
                "runtime execution cgroup identity differs",
            )
            return CgroupIdentity(path, observed.st_dev, observed.st_ino)
        except BaseException:
            if descriptor is not None:
                try:
                    os.rmdir(CGROUP_EXECUTION_NAME, dir_fd=descriptor)
                except OSError:
                    pass
            try:
                os.rmdir(path.name, dir_fd=parent_fd)
            except OSError:
                pass
            raise


def open_cgroup(identity: CgroupIdentity, *, custody: DescriptorCustody) -> int:
    require(
        CGROUP_PATH_RE.fullmatch(str(identity.path)) is not None,
        "runtime cgroup path is invalid",
    )
    descriptor = custody.acquire(
        lambda: os.open(
            identity.path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    )
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
    require(
        len(records) == 1 and records[0].startswith("0::/"),
        "process cgroup v2 record differs",
    )
    return records[0][3:]


def open_execution_cgroup(identity: CgroupIdentity, *, custody: DescriptorCustody) -> int:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as roots:
        root_fd = open_cgroup(identity, custody=roots)
        descriptor = custody.acquire(
            lambda: os.open(
                CGROUP_EXECUTION_NAME,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=root_fd,
            )
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


def enter_cgroup(identity: CgroupIdentity) -> None:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = open_execution_cgroup(identity, custody=descriptors)
        _write_at(descriptor, "cgroup.procs", f"{os.getpid()}\n".encode("ascii"))
    require(
        current_cgroup_path() == execution_cgroup_path(identity),
        "supervisor did not enter task execution cgroup",
    )


def cgroup_events(identity: CgroupIdentity) -> dict[str, str]:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = open_cgroup(identity, custody=descriptors)
        fields: dict[str, str] = {}
        for line in _read_at(descriptor, "cgroup.events").splitlines():
            parts = line.split()
            require(
                len(parts) == 2 and parts[0] not in fields,
                "cgroup events record is invalid",
            )
            fields[parts[0]] = parts[1]
        require(fields.get("populated") in ("0", "1"), "cgroup populated state is absent")
        require(fields.get("frozen") in ("0", "1"), "cgroup frozen state is absent")
        return fields


def cgroup_is_populated(identity: CgroupIdentity) -> bool:
    return cgroup_events(identity)["populated"] == "1"


def freeze_cgroup_and_wait(identity: CgroupIdentity, *, timeout: float = 30.0) -> None:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = open_cgroup(identity, custody=descriptors)
        _write_at(descriptor, "cgroup.freeze", b"1\n")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cgroup_events(identity)["frozen"] == "1":
            return
        time.sleep(0.05)
    raise SupervisorError("runtime cgroup did not freeze")


def kill_cgroup_and_wait(identity: CgroupIdentity, *, timeout: float = 30.0) -> None:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = open_cgroup(identity, custody=descriptors)
        _write_at(descriptor, "cgroup.kill", b"1\n")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not cgroup_is_populated(identity):
            return
        time.sleep(0.05)
    raise SupervisorError("runtime cgroup did not become empty")


def remove_empty_cgroup(identity: CgroupIdentity) -> None:
    require(not cgroup_is_populated(identity), "runtime cgroup is still populated")
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        root_fd = open_cgroup(identity, custody=descriptors)
        remove_empty_cgroup_children(root_fd)
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        parent_fd = descriptors.acquire(lambda: os.open(CGROUP_PARENT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        literal = os.stat(identity.path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            (literal.st_dev, literal.st_ino) == (identity.device, identity.inode),
            "runtime cgroup entry changed before removal",
        )
        os.rmdir(identity.path.name, dir_fd=parent_fd)


def remove_empty_cgroup_children(directory_fd: int) -> None:
    for name in tuple(sorted(os.listdir(directory_fd))):
        value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISDIR(value.st_mode):
            continue
        require(
            value.st_uid == 0 and value.st_gid == 0 and stat.S_IMODE(value.st_mode) & 0o022 == 0,
            f"child cgroup authority differs: {name}",
        )
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            child = descriptors.acquire(
                lambda: os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            )
            remove_empty_cgroup_children(child)
            events = _read_at(child, "cgroup.events")
            require("populated 0" in events.splitlines(), "child cgroup is populated")
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
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(lambda: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
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


def verify_runtime_root(
    identity: RuntimeIdentity,
    *,
    custody: DescriptorCustody,
    path_pattern: re.Pattern[str] = RUNTIME_ROOT_RE,
) -> int:
    require(
        path_pattern.fullmatch(str(identity.path)) is not None,
        "runtime root path is invalid",
    )
    descriptor = custody.acquire(
        lambda: os.open(
            identity.path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    )
    observed = os.fstat(descriptor)
    require(
        (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
        == (
            identity.device,
            identity.inode,
            identity.uid,
            identity.gid,
            identity.mode,
        ),
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
            observed.st_uid == 0 and (name in RUNTIME_SOCKET_ENTRIES or observed.st_gid == 0),
            f"runtime entry owner differs: {name}",
        )


def reject_legacy_v4_runtime_roster(runtime_identity: RuntimeIdentity) -> None:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = verify_runtime_root(runtime_identity, custody=descriptors)
        roster = set(os.listdir(descriptor))
    if (
        ROOT_CONTROL_NAME not in roster
        and SUPERVISOR_SNAPSHOT_NAME not in roster
        and roster & LEGACY_V4_RUNTIME_MARKERS
    ):
        raise SupervisorError(LEGACY_V4_DIAGNOSTIC)


def mount_records(raw_mountinfo: str) -> tuple[tuple[str, Path, Path], ...]:
    records: list[tuple[str, Path, Path]] = []
    for line in raw_mountinfo.splitlines():
        fields = line.split()
        require("-" in fields and len(fields) >= 10, "mountinfo record is invalid")
        separator = fields.index("-")
        require(separator + 1 < len(fields), "mountinfo filesystem type is absent")
        filesystem_type = fields[separator + 1]
        mount_root = Path(decode_mount_path(fields[3]))
        target = Path(decode_mount_path(fields[4]))
        require(target.is_absolute(), "mountinfo target is not absolute")
        require(
            mount_root.is_absolute()
            or (filesystem_type == "nsfs" and OPAQUE_MOUNT_ROOT.fullmatch(str(mount_root)) is not None),
            "mountinfo root is neither absolute nor an admitted opaque identity",
        )
        records.append((fields[2], mount_root, target))
    return tuple(records)


def path_at_or_below(candidate: Path, root: Path) -> bool:
    require(candidate.is_absolute() and root.is_absolute(), "mount path is not absolute")
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def mount_root_at_or_below(candidate: Path, root: Path) -> bool:
    if candidate.is_absolute() and root.is_absolute():
        return path_at_or_below(candidate, root)
    if candidate.is_absolute() or root.is_absolute():
        return False
    require(
        OPAQUE_MOUNT_ROOT.fullmatch(str(candidate)) is not None and OPAQUE_MOUNT_ROOT.fullmatch(str(root)) is not None,
        "opaque mount-root identity is invalid",
    )
    return candidate == root


def translate_mount_root(mount_root: Path, relative: Path) -> Path:
    if mount_root.is_absolute():
        return mount_root / relative
    require(
        OPAQUE_MOUNT_ROOT.fullmatch(str(mount_root)) is not None,
        "opaque mount-root identity is invalid",
    )
    require(
        relative == Path("."),
        "opaque mount-root identity cannot address a descendant",
    )
    return mount_root


def mount_source_anchors(
    raw_mountinfo: str,
    root: Path,
) -> tuple[tuple[str, Path], ...]:
    records = mount_records(raw_mountinfo)
    bases: list[tuple[str, Path, Path]] = []
    for record in records:
        if path_at_or_below(root, record[2]):
            bases.append(record)
    require(bases, "runtime mount backing record is absent")
    deepest = max(len(record[2].parts) for record in bases)
    base_coordinates = {
        (
            device,
            translate_mount_root(mount_root, root.relative_to(target)),
        )
        for device, mount_root, target in bases
        if len(target.parts) == deepest
    }
    require(len(base_coordinates) == 1, "runtime mount backing coordinate is ambiguous")
    anchors = set(base_coordinates)
    anchors.update((device, mount_root) for device, mount_root, target in records if path_at_or_below(target, root))
    return tuple(sorted(anchors, key=lambda value: (value[0], str(value[1]))))


def mount_references_under(
    raw_mountinfo: str,
    root: Path,
    source_anchors: tuple[tuple[str, Path], ...] | None = None,
) -> tuple[str, ...]:
    records = mount_records(raw_mountinfo)
    anchors = mount_source_anchors(raw_mountinfo, root) if source_anchors is None else source_anchors
    require(anchors, "runtime mount source anchors are absent")
    for device, source_prefix in anchors:
        require(
            bool(device)
            and (source_prefix.is_absolute() or OPAQUE_MOUNT_ROOT.fullmatch(str(source_prefix)) is not None),
            "runtime mount source anchor is invalid",
        )
    result: set[str] = set()
    for device, mount_root, target in records:
        target_reference = path_at_or_below(target, root)
        source_reference = any(
            device == source_device and mount_root_at_or_below(mount_root, source_prefix)
            for source_device, source_prefix in anchors
        )
        if target_reference or source_reference:
            result.add(str(target))
    return tuple(sorted(result))


def _mount_targets_for_namespace(
    pid: int,
    root: Path,
    source_anchors: tuple[tuple[str, Path], ...],
) -> tuple[str, ...]:
    mountinfo = Path(f"/proc/{pid}/mountinfo").read_text(encoding="utf-8")
    return mount_references_under(mountinfo, root, source_anchors)


def _global_mount_roster_once(
    root: Path,
    source_anchors: tuple[tuple[str, Path], ...] | None = None,
) -> tuple[
    tuple[tuple[str, Path], ...],
    tuple[tuple[str, tuple[str, ...]], ...],
]:
    own_before = os.stat("/proc/self/ns/mnt")
    own_namespace = f"{own_before.st_dev}:{own_before.st_ino}"
    own_mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    anchors = source_anchors
    if anchors is None:
        anchors = mount_source_anchors(own_mountinfo, root)
    require(anchors, "runtime mount source anchors are absent")
    own_after = os.stat("/proc/self/ns/mnt")
    require(
        (own_after.st_dev, own_after.st_ino) == (own_before.st_dev, own_before.st_ino),
        "helper mount namespace changed during source proof",
    )
    # Never let a chrooted sibling become the representative for the helper's
    # own namespace. Its exact mountinfo supplied the source anchors and is the
    # corresponding canonical target observation.
    seen: dict[str, tuple[str, ...]] = {own_namespace: mount_references_under(own_mountinfo, root, anchors)}
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
                targets = _mount_targets_for_namespace(pid, root, anchors)
                after = os.stat(namespace_path)
            except OSError as error:
                raise SupervisorError(f"mount namespace disappeared for pid {pid}") from error
            require(
                (after.st_dev, after.st_ino) == (before_stat.st_dev, before_stat.st_ino),
                f"mount namespace changed for pid {pid}",
            )
            require(
                targets == seen[namespace],
                f"mount namespace visibility differs across representatives: {namespace}",
            )
            continue
        try:
            targets = _mount_targets_for_namespace(pid, root, anchors)
            after = os.stat(namespace_path)
        except OSError as error:
            raise SupervisorError(f"mount namespace disappeared for pid {pid}") from error
        require(
            (after.st_dev, after.st_ino) == (before_stat.st_dev, before_stat.st_ino),
            f"mount namespace changed for pid {pid}",
        )
        seen[namespace] = targets
    return anchors, tuple(sorted(seen.items()))


def stable_global_mount_targets(
    root: Path,
    *,
    source_anchors: tuple[tuple[str, Path], ...] | None = None,
) -> tuple[tuple[str, str], ...]:
    first = _global_mount_roster_once(root, source_anchors)
    second = _global_mount_roster_once(root, source_anchors)
    require(first == second, "global mount namespace or target roster changed")
    _, roster = second
    return tuple(sorted((namespace, target) for namespace, targets in roster for target in targets))


def mount_namespace_key(value: object) -> str:
    namespace = validate_namespace(value, "mount namespace")
    return f"{namespace['device']}:{namespace['inode']}"


def mount_source_anchor_document(anchor: tuple[str, Path]) -> dict[str, str]:
    device, root = anchor
    require(MOUNT_DEVICE_RE.fullmatch(device) is not None, "mount source device is invalid")
    if root.is_absolute():
        require(
            os.path.normpath(str(root)) == str(root),
            "mount source path is noncanonical",
        )
        kind = "absolute_path"
    else:
        require(
            OPAQUE_MOUNT_ROOT.fullmatch(str(root)) is not None,
            "opaque mount source identity is invalid",
        )
        kind = "opaque_nsfs_identity"
    return {"kind": kind, "device": device, "root": str(root)}


def mount_source_anchor_from_document(value: object) -> tuple[str, Path]:
    document = exact_keys(
        value,
        {"kind", "device", "root"},
        "task network namespace source anchor",
    )
    require(
        isinstance(document["device"], str) and MOUNT_DEVICE_RE.fullmatch(document["device"]) is not None,
        "task network namespace source device is invalid",
    )
    require(
        isinstance(document["root"], str),
        "task network namespace source root is invalid",
    )
    root = Path(document["root"])
    if document["kind"] == "absolute_path":
        require(
            root.is_absolute() and os.path.normpath(str(root)) == str(root),
            "task network namespace source path is invalid",
        )
    else:
        require(
            document["kind"] == "opaque_nsfs_identity"
            and not root.is_absolute()
            and OPAQUE_MOUNT_ROOT.fullmatch(str(root)) is not None,
            "task network namespace opaque source is invalid",
        )
    return document["device"], root


def current_network_namespace_anchor() -> MountSourceAnchor:
    path = "/proc/self/ns/net"
    token = os.readlink(path)
    require(
        OPAQUE_MOUNT_ROOT.fullmatch(token) is not None and token.startswith("net:["),
        "current network namespace identity is invalid",
    )
    observed = os.stat(path)
    require(
        int(token.removeprefix("net:[").removesuffix("]")) == observed.st_ino,
        "current network namespace inode differs",
    )
    return f"{os.major(observed.st_dev)}:{os.minor(observed.st_dev)}", Path(token)


def mount_occurrence_document(occurrence: MountOccurrence) -> dict[str, str]:
    namespace, target = occurrence
    require(
        MOUNT_DEVICE_RE.fullmatch(namespace) is not None,
        "mount namespace key is invalid",
    )
    path = Path(target)
    require(
        path.is_absolute() and os.path.normpath(str(path)) == str(path),
        "mount occurrence target is invalid",
    )
    return {"mountNamespace": namespace, "target": str(path)}


def mount_occurrence_from_document(value: object) -> MountOccurrence:
    document = exact_keys(
        value,
        {"mountNamespace", "target"},
        "ambient namespace mount occurrence",
    )
    require(
        isinstance(document["mountNamespace"], str)
        and MOUNT_DEVICE_RE.fullmatch(document["mountNamespace"]) is not None,
        "ambient mount namespace key is invalid",
    )
    require(isinstance(document["target"], str), "ambient mount target is invalid")
    target = Path(document["target"])
    require(
        target.is_absolute() and os.path.normpath(str(target)) == str(target),
        "ambient mount target is noncanonical",
    )
    return document["mountNamespace"], str(target)


def build_netns_baseline_manifest(
    *,
    runtime: RuntimeIdentity,
    state_root: Path,
    control_digest: str,
    recorded_namespace: object,
) -> dict[str, object]:
    namespace = validate_namespace(recorded_namespace, "recorded supervisor mount namespace")
    anchor = current_network_namespace_anchor()
    occurrences = stable_global_mount_targets(
        runtime.path / ".ambient-netns-baseline",
        source_anchors=(anchor,),
    )
    ambient_targets = tuple(sorted({target for _, target in occurrences}))
    return {
        "schema": NETNS_BASELINE_SCHEMA,
        "observedAt": utc_now(),
        "bootId": current_boot_id(),
        "stateRoot": str(state_root),
        "runtimeRootIdentity": runtime.json(),
        "rootControlSha256": control_digest,
        "mountNamespace": namespace,
        "ambientSources": [
            {
                "sourceAnchor": mount_source_anchor_document(anchor),
                "ambientTargets": list(ambient_targets),
            }
        ],
    }


def validate_netns_baseline_manifest(
    value: object,
    *,
    runtime: RuntimeIdentity,
    state_root: Path,
    control_digest: str,
    recorded_namespace: object,
) -> tuple[AmbientNetnsSource, ...]:
    manifest = exact_keys(
        value,
        {
            "schema",
            "observedAt",
            "bootId",
            "stateRoot",
            "runtimeRootIdentity",
            "rootControlSha256",
            "mountNamespace",
            "ambientSources",
        },
        "ambient network namespace baseline",
    )
    namespace = validate_namespace(recorded_namespace, "recorded supervisor mount namespace")
    require(
        manifest["schema"] == NETNS_BASELINE_SCHEMA
        and isinstance(manifest["observedAt"], str)
        and 0 < len(manifest["observedAt"]) <= 128
        and manifest["bootId"] == current_boot_id()
        and manifest["stateRoot"] == str(state_root)
        and manifest["runtimeRootIdentity"] == runtime.json()
        and manifest["rootControlSha256"] == control_digest
        and manifest["mountNamespace"] == namespace
        and isinstance(manifest["ambientSources"], list),
        "ambient network namespace baseline binding differs",
    )
    assert isinstance(manifest["ambientSources"], list)
    require(
        0 < len(manifest["ambientSources"]) <= 32,
        "ambient network namespace source roster is invalid",
    )
    parsed: list[AmbientNetnsSource] = []
    for item in manifest["ambientSources"]:
        source = exact_keys(
            item,
            {"sourceAnchor", "ambientTargets"},
            "ambient network namespace source",
        )
        require(
            isinstance(source["ambientTargets"], list),
            "ambient target roster is invalid",
        )
        assert isinstance(source["ambientTargets"], list)
        anchor = mount_source_anchor_from_document(source["sourceAnchor"])
        targets: list[str] = []
        for target_value in source["ambientTargets"]:
            require(isinstance(target_value, str), "ambient target is invalid")
            target = Path(target_value)
            require(
                target.is_absolute() and os.path.normpath(str(target)) == str(target),
                "ambient target is noncanonical",
            )
            targets.append(str(target))
        ambient_targets = tuple(targets)
        require(
            ambient_targets == tuple(sorted(set(ambient_targets))),
            "ambient target roster is not canonical and unique",
        )
        parsed.append((anchor, ambient_targets))
    require(
        parsed == sorted(parsed, key=lambda item: (item[0][0], str(item[0][1])))
        and len({anchor for anchor, _ in parsed}) == len(parsed),
        "ambient source roster is not canonical and unique",
    )
    return tuple(parsed)


def ensure_netns_baseline_manifest(
    *,
    runtime: RuntimeIdentity,
    state_root: Path,
    control_digest: str,
    recorded_namespace: object,
) -> tuple[str, tuple[AmbientNetnsSource, ...]]:
    value = read_root_manifest(runtime, ROOT_NETNS_BASELINE_NAME)
    if value is None:
        value = build_netns_baseline_manifest(
            runtime=runtime,
            state_root=state_root,
            control_digest=control_digest,
            recorded_namespace=recorded_namespace,
        )
        digest = write_root_manifest(runtime, ROOT_NETNS_BASELINE_NAME, value)
        value = read_root_manifest(runtime, ROOT_NETNS_BASELINE_NAME)
        require(value is not None, "ambient network namespace baseline disappeared")
    else:
        digest = canonical_document_digest(value)
    parsed = validate_netns_baseline_manifest(
        value,
        runtime=runtime,
        state_root=state_root,
        control_digest=control_digest,
        recorded_namespace=recorded_namespace,
    )
    require(digest == canonical_document_digest(value), "ambient baseline digest differs")
    return digest, parsed


def ambient_targets_for_anchor(
    anchor: MountSourceAnchor,
    sources: tuple[AmbientNetnsSource, ...],
) -> tuple[str, ...]:
    matches = tuple(targets for candidate, targets in sources if candidate == anchor)
    require(len(matches) <= 1, "ambient source baseline is ambiguous")
    return () if not matches else matches[0]


def validate_ready_netns_baseline(
    *,
    runtime: RuntimeIdentity,
    ready: dict[str, object],
    state_root: Path,
    control_digest: str,
    recorded_namespace: object,
) -> tuple[AmbientNetnsSource, ...]:
    value = read_root_manifest(runtime, ROOT_NETNS_BASELINE_NAME)
    require(value is not None, "ready runtime lacks its ambient network namespace baseline")
    require(
        canonical_document_digest(value) == ready["netnsBaselineSha256"],
        "root ready ambient network namespace baseline digest differs",
    )
    return validate_netns_baseline_manifest(
        value,
        runtime=runtime,
        state_root=state_root,
        control_digest=control_digest,
        recorded_namespace=recorded_namespace,
    )


def read_mountinfo_for_namespace(
    expected_namespace: object,
    *,
    preferred_pids: tuple[int, ...] = (),
) -> str | None:
    expected = mount_namespace_key(expected_namespace)
    candidates: list[int] = [os.getpid()]
    candidates.extend(plain_int(pid, "preferred namespace representative PID", positive=True) for pid in preferred_pids)
    try:
        candidates.extend(int(entry) for entry in sorted(os.listdir("/proc")) if entry.isdigit())
    except OSError as error:
        raise SupervisorError("mount namespace representative roster is unreadable") from error
    seen: set[int] = set()
    for pid in candidates:
        if pid in seen:
            continue
        seen.add(pid)
        namespace_path = f"/proc/{pid}/ns/mnt"
        try:
            before = os.stat(namespace_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise SupervisorError(f"mount namespace is unreadable for pid {pid}") from error
        if f"{before.st_dev}:{before.st_ino}" != expected:
            continue
        try:
            raw = Path(f"/proc/{pid}/mountinfo").read_text(encoding="utf-8")
            after = os.stat(namespace_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise SupervisorError(f"mount namespace disappeared for pid {pid}") from error
        require(
            (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino),
            f"mount namespace changed for pid {pid}",
        )
        return raw
    return None


def runtime_netns_entry_roster(runtime: RuntimeIdentity) -> tuple[str, ...]:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        runtime_fd = verify_runtime_root(runtime, custody=descriptors)
        try:
            docker_exec_fd = descriptors.acquire(
                lambda: os.open(
                    "docker-exec",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=runtime_fd,
                )
            )
        except FileNotFoundError:
            return ()
        docker_exec = os.fstat(docker_exec_fd)
        docker_exec_literal = os.stat("docker-exec", dir_fd=runtime_fd, follow_symlinks=False)
        require(
            stat.S_ISDIR(docker_exec.st_mode)
            and docker_exec.st_uid == 0
            and docker_exec.st_gid == 0
            and (docker_exec.st_dev, docker_exec.st_ino) == (docker_exec_literal.st_dev, docker_exec_literal.st_ino),
            "Docker execution root identity differs",
        )
        try:
            netns_fd = descriptors.acquire(
                lambda: os.open(
                    "netns",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=docker_exec_fd,
                )
            )
        except FileNotFoundError:
            return ()
        netns = os.fstat(netns_fd)
        netns_literal = os.stat("netns", dir_fd=docker_exec_fd, follow_symlinks=False)
        require(
            stat.S_ISDIR(netns.st_mode)
            and netns.st_uid == 0
            and netns.st_gid == 0
            and (netns.st_dev, netns.st_ino) == (netns_literal.st_dev, netns_literal.st_ino),
            "task network namespace root identity differs",
        )
        names = tuple(sorted(os.listdir(netns_fd)))
        for name in names:
            require(
                TASK_NETNS_ENTRY_RE.fullmatch(name) is not None,
                "task network namespace entry name is invalid",
            )
            value = os.stat(name, dir_fd=netns_fd, follow_symlinks=False)
            require(
                stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_gid == 0,
                f"task network namespace entry identity differs: {name}",
            )
        return names


def build_task_netns_detach_manifest(
    *,
    runtime: RuntimeIdentity,
    state_root: Path,
    control_digest: str,
    stopping_digest: str,
    baseline_digest: str,
    ambient_sources: tuple[AmbientNetnsSource, ...],
    recorded_namespace: object,
    preferred_pids: tuple[int, ...] = (),
) -> dict[str, object]:
    namespace = validate_namespace(recorded_namespace, "recorded supervisor mount namespace")
    raw = read_mountinfo_for_namespace(namespace, preferred_pids=preferred_pids)
    underlying_roster = runtime_netns_entry_roster(runtime)
    if raw is None:
        require(
            not underlying_roster,
            "task network namespace source has no live representative; admin recovery is required",
        )
        targets: tuple[Path, ...] = ()
    else:
        targets = task_netns_mounts(runtime.path, raw)
        require(
            tuple(sorted(target.name for target in targets)) == underlying_roster,
            "task network namespace mount and entry rosters differ",
        )
    entries: list[dict[str, object]] = []
    expected_namespace = mount_namespace_key(namespace)
    for target in sorted(targets):
        anchors = mount_source_anchors(raw, target) if raw is not None else ()
        require(
            len(anchors) == 1,
            "task network namespace must have exactly one source coordinate",
        )
        ambient_targets = ambient_targets_for_anchor(anchors[0], ambient_sources)
        current = stable_global_mount_targets(target, source_anchors=anchors)
        require(
            set(ambient_targets) <= {occurrence_target for _, occurrence_target in current},
            "ambient network namespace target disappeared before detach",
        )
        owned = tuple(occurrence for occurrence in current if occurrence[1] not in ambient_targets)
        require(
            bool(owned)
            and (expected_namespace, str(target)) in owned
            and all(occurrence_target == str(target) for _, occurrence_target in owned),
            "task network namespace occurrence is neither ambient nor the owned target",
        )
        entries.append(
            {
                "target": str(target),
                "fsType": "nsfs",
                "sourceAnchor": mount_source_anchor_document(anchors[0]),
                "ownedOccurrences": [mount_occurrence_document(occurrence) for occurrence in owned],
            }
        )
    return {
        "schema": NETNS_DETACH_SCHEMA,
        "observedAt": utc_now(),
        "bootId": current_boot_id(),
        "stateRoot": str(state_root),
        "runtimeRootIdentity": runtime.json(),
        "rootControlSha256": control_digest,
        "rootStoppingSha256": stopping_digest,
        "rootNetnsBaselineSha256": baseline_digest,
        "mountNamespace": namespace,
        "taskMounts": entries,
    }


def validate_task_netns_detach_manifest(
    value: object,
    *,
    runtime: RuntimeIdentity,
    state_root: Path,
    control_digest: str,
    stopping_digest: str,
    baseline_digest: str,
    ambient_sources: tuple[AmbientNetnsSource, ...],
    recorded_namespace: object,
) -> tuple[TaskNetnsDetachEntry, ...]:
    manifest = exact_keys(
        value,
        {
            "schema",
            "observedAt",
            "bootId",
            "stateRoot",
            "runtimeRootIdentity",
            "rootControlSha256",
            "rootStoppingSha256",
            "rootNetnsBaselineSha256",
            "mountNamespace",
            "taskMounts",
        },
        "task network namespace detach manifest",
    )
    namespace = validate_namespace(recorded_namespace, "recorded supervisor mount namespace")
    require(
        manifest["schema"] == NETNS_DETACH_SCHEMA
        and isinstance(manifest["observedAt"], str)
        and manifest["bootId"] == current_boot_id()
        and manifest["stateRoot"] == str(state_root)
        and manifest["runtimeRootIdentity"] == runtime.json()
        and manifest["rootControlSha256"] == control_digest
        and manifest["rootStoppingSha256"] == stopping_digest
        and manifest["rootNetnsBaselineSha256"] == baseline_digest
        and manifest["mountNamespace"] == namespace
        and isinstance(manifest["taskMounts"], list),
        "task network namespace detach manifest binding differs",
    )
    assert isinstance(manifest["taskMounts"], list)
    require(
        len(manifest["taskMounts"]) <= 4096,
        "task network namespace roster is too large",
    )
    parsed: list[TaskNetnsDetachEntry] = []
    prefix = runtime.path / "docker-exec" / "netns"
    for item in manifest["taskMounts"]:
        entry = exact_keys(
            item,
            {"target", "fsType", "sourceAnchor", "ownedOccurrences"},
            "task network namespace detach entry",
        )
        require(
            isinstance(entry["target"], str),
            "task network namespace detach target is invalid",
        )
        target = Path(entry["target"])
        require(
            target.parent == prefix
            and TASK_NETNS_ENTRY_RE.fullmatch(target.name) is not None
            and entry["fsType"] == "nsfs",
            "task network namespace detach target differs",
        )
        anchor = mount_source_anchor_from_document(entry["sourceAnchor"])
        require(
            isinstance(entry["ownedOccurrences"], list),
            "owned task network namespace occurrence roster is invalid",
        )
        assert isinstance(entry["ownedOccurrences"], list)
        owned = tuple(mount_occurrence_from_document(occurrence) for occurrence in entry["ownedOccurrences"])
        require(
            bool(owned)
            and owned == tuple(sorted(set(owned)))
            and (mount_namespace_key(namespace), str(target)) in owned
            and all(occurrence_target == str(target) for _, occurrence_target in owned),
            "owned task network namespace occurrence roster differs",
        )
        parsed.append(
            (
                target,
                (anchor,),
                ambient_targets_for_anchor(anchor, ambient_sources),
                owned,
            )
        )
    require(
        parsed == sorted(parsed, key=lambda item: str(item[0]))
        and len({target for target, _, _, _ in parsed}) == len(parsed),
        "task network namespace detach roster is not canonical and unique",
    )
    return tuple(parsed)


def ensure_task_netns_detach_manifest(
    *,
    runtime: RuntimeIdentity,
    state_root: Path,
    control_digest: str,
    stopping_digest: str,
    baseline_digest: str,
    ambient_sources: tuple[AmbientNetnsSource, ...],
    recorded_namespace: object,
    preferred_pids: tuple[int, ...] = (),
) -> tuple[str, tuple[TaskNetnsDetachEntry, ...]]:
    value = read_root_manifest(runtime, ROOT_NETNS_DETACH_NAME)
    if value is None:
        value = build_task_netns_detach_manifest(
            runtime=runtime,
            state_root=state_root,
            control_digest=control_digest,
            stopping_digest=stopping_digest,
            baseline_digest=baseline_digest,
            ambient_sources=ambient_sources,
            recorded_namespace=recorded_namespace,
            preferred_pids=preferred_pids,
        )
        digest = write_root_manifest(runtime, ROOT_NETNS_DETACH_NAME, value)
        value = read_root_manifest(runtime, ROOT_NETNS_DETACH_NAME)
        require(value is not None, "task network namespace detach manifest disappeared")
    else:
        digest = canonical_document_digest(value)
    parsed = validate_task_netns_detach_manifest(
        value,
        runtime=runtime,
        state_root=state_root,
        control_digest=control_digest,
        stopping_digest=stopping_digest,
        baseline_digest=baseline_digest,
        ambient_sources=ambient_sources,
        recorded_namespace=recorded_namespace,
    )
    require(
        digest == canonical_document_digest(value),
        "task network namespace digest differs",
    )
    return digest, parsed


def settle_task_netns_detach_manifest(
    *,
    runtime: RuntimeIdentity,
    recorded_namespace: object,
    task_mounts: tuple[TaskNetnsDetachEntry, ...],
    expected_children: set[int],
) -> None:
    namespace = validate_namespace(recorded_namespace, "recorded supervisor mount namespace")
    current_namespace = mount_namespace()
    current_raw = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    current_targets = set(task_netns_mounts(runtime.path, current_raw))
    planned_targets = {target for target, _, _, _ in task_mounts}
    require(
        current_targets <= planned_targets,
        "unplanned task network namespace mount appeared after detach publication",
    )
    for target, anchors, ambient_targets, owned in task_mounts:
        if target in current_targets:
            require(
                current_namespace == namespace,
                "task network namespace source is visible in an unexpected namespace",
            )
            require(
                mount_source_anchors(current_raw, target) == anchors,
                "task network namespace source coordinate changed",
            )
            current = stable_global_mount_targets(target, source_anchors=anchors)
            require(
                set(ambient_targets) <= {item_target for _, item_target in current}
                and all(occurrence[1] in ambient_targets or occurrence in owned for occurrence in current)
                and (mount_namespace_key(namespace), str(target)) in current,
                "task network namespace occurrence differs from its published cutoff",
            )
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
            require_exact_children(expected_children)
        require(
            {occurrence_target for _, occurrence_target in stable_global_mount_targets(target, source_anchors=anchors)}
            == set(ambient_targets),
            "task network namespace targets did not return to their baseline",
        )
    remaining = task_netns_mounts(
        runtime.path,
        Path("/proc/self/mountinfo").read_text(encoding="utf-8"),
    )
    require(not remaining, "task network namespace mount remained after cleanup")
    for target, anchors, ambient_targets, _ in task_mounts:
        require(
            {occurrence_target for _, occurrence_target in stable_global_mount_targets(target, source_anchors=anchors)}
            == set(ambient_targets),
            "task network namespace targets drifted from baseline before deletion",
        )


def _remove_tree_entry(directory_fd: int, name: str) -> None:
    value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    require(value.st_uid == 0, f"runtime cleanup entry owner differs: {name}")
    if stat.S_ISDIR(value.st_mode):
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            child = descriptors.acquire(
                lambda: os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            )
            literal = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            observed = os.fstat(child)
            require(
                (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino),
                f"runtime cleanup directory binding differs: {name}",
            )
            for nested in tuple(sorted(os.listdir(child))):
                _remove_tree_entry(child, nested)
            os.fsync(child)
            literal = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            require(
                (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino),
                f"runtime cleanup directory changed before removal: {name}",
            )
            os.rmdir(name, dir_fd=directory_fd)
    elif stat.S_ISREG(value.st_mode) or stat.S_ISSOCK(value.st_mode) or stat.S_ISLNK(value.st_mode):
        require(hasattr(os, "O_PATH"), "descriptor-only runtime cleanup is unavailable")
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            leaf = descriptors.acquire(
                lambda: os.open(
                    name,
                    os.O_PATH | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            )
            observed = os.fstat(leaf)
            literal = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            require(
                observed.st_uid == 0
                and (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino)
                and stat.S_IFMT(literal.st_mode) == stat.S_IFMT(observed.st_mode),
                f"runtime cleanup leaf binding differs: {name}",
            )
            os.unlink(name, dir_fd=directory_fd)
    else:
        raise SupervisorError(f"runtime cleanup entry type differs: {name}")
    os.fsync(directory_fd)


def reduce_runtime_removal_root(state_root: Path) -> bool:
    path = runtime_removal_root_for(state_root)
    try:
        identity = existing_runtime_identity(
            path,
            path_pattern=RUNTIME_REMOVAL_ROOT_RE,
        )
    except FileNotFoundError:
        return False
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = verify_runtime_root(
            identity,
            custody=descriptors,
            path_pattern=RUNTIME_REMOVAL_ROOT_RE,
        )
        verify_runtime_entries(descriptor)
        require(
            not stable_global_mount_targets(identity.path),
            "runtime root retains a mount",
        )
        for name in tuple(sorted(os.listdir(descriptor))):
            _remove_tree_entry(descriptor, name)
        require(not os.listdir(descriptor), "runtime root did not become empty")
        parent_fd = descriptors.acquire(
            lambda: os.open(
                RUNTIME_PARENT,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        )
        literal = os.stat(identity.path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            (literal.st_dev, literal.st_ino) == (identity.device, identity.inode),
            "runtime root entry changed before removal",
        )
        os.rmdir(identity.path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    return True


def remove_runtime_root(identity: RuntimeIdentity, state_root: Path) -> None:
    require(
        identity.path == runtime_root_for(state_root),
        "runtime removal state path differs",
    )
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = verify_runtime_root(identity, custody=descriptors)
        parent_fd = descriptors.acquire(
            lambda: os.open(
                RUNTIME_PARENT,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        )
        verify_runtime_entries(descriptor)
        require(
            not stable_global_mount_targets(identity.path),
            "runtime root retains a mount",
        )
        removal_path = runtime_removal_root_for(state_root)
        require(
            not path_exists_nofollow(removal_path),
            "runtime removal authority already exists",
        )
        literal = os.stat(identity.path.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            (literal.st_dev, literal.st_ino) == (identity.device, identity.inode),
            "runtime root entry changed before removal publication",
        )
        os.rename(
            identity.path.name,
            removal_path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    require(
        reduce_runtime_removal_root(state_root),
        "runtime removal authority disappeared",
    )


def create_socket_root(path: Path, caller_gid: int) -> SocketPathIdentity:
    require(
        SOCKET_ROOT_RE.fullmatch(str(path)) is not None,
        "Docker API root path is invalid",
    )
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        parent_fd = descriptors.acquire(
            lambda: os.open(
                RUNTIME_PARENT,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        )
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
            descriptor = descriptors.acquire(
                lambda: os.open(
                    path.name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
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
            return SocketPathIdentity(path, observed.st_dev, observed.st_ino, 0, caller_gid, 0o750)
        except BaseException:
            try:
                os.rmdir(path.name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            except OSError:
                pass
            raise


def verify_socket_root(
    identity: SocketPathIdentity,
    caller_gid: int,
    *,
    custody: DescriptorCustody,
) -> int:
    require(
        SOCKET_ROOT_RE.fullmatch(str(identity.path)) is not None,
        "Docker API root path is invalid",
    )
    descriptor = custody.acquire(
        lambda: os.open(
            identity.path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    )
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
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = verify_socket_root(root, caller_gid, custody=descriptors)
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
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        parent_fd = descriptors.acquire(
            lambda: os.open(
                RUNTIME_PARENT,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        )
        descriptor = verify_socket_root(root, caller_gid, custody=descriptors)
        require(
            not stable_global_mount_targets(root.path),
            "Docker API root retains a mount",
        )
        roster = tuple(sorted(os.listdir(descriptor)))
        require(roster in ((), (SOCKET_NAME,)), "Docker API root contains a foreign entry")
        if roster:
            require(hasattr(os, "O_PATH"), "descriptor-only socket cleanup is unavailable")
            socket_fd = descriptors.acquire(
                lambda: os.open(
                    SOCKET_NAME,
                    os.O_PATH | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            )
            observed = os.fstat(socket_fd)
            literal = os.stat(SOCKET_NAME, dir_fd=descriptor, follow_symlinks=False)
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
                )
                and (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino),
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


def classify_recovery_socket(
    root: SocketPathIdentity,
    expected_socket: SocketPathIdentity | None,
    caller_gid: int,
    *,
    absence_authorized: bool,
) -> tuple[bool, SocketPathIdentity | None]:
    try:
        os.stat(root.path, follow_symlinks=False)
    except FileNotFoundError:
        require(
            absence_authorized,
            "Docker API root is absent without durable stopping authority",
        )
        return False, None
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = verify_socket_root(root, caller_gid, custody=descriptors)
        roster = tuple(sorted(os.listdir(descriptor)))
        require(roster in ((), (SOCKET_NAME,)), "Docker API root contains a foreign entry")
    if not roster:
        require(
            absence_authorized or expected_socket is None,
            "Docker API socket is absent without durable stopping authority",
        )
        return True, None
    if expected_socket is not None:
        verify_socket_boundary(root, expected_socket, caller_gid)
        return True, expected_socket
    return True, capture_socket_identity(root, caller_gid)


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
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(
            lambda: os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        )
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
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(
            lambda: os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode,
                dir_fd=runtime_fd,
            )
        )
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        require(
            observed.st_uid == 0 and observed.st_gid == 0 and stat.S_IMODE(observed.st_mode) == mode,
            "runtime file owner or mode differs",
        )
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
        name
        in (
            ROOT_CONTROL_NAME,
            ROOT_READY_NAME,
            ROOT_STOPPING_NAME,
            ROOT_NETNS_BASELINE_NAME,
            ROOT_NETNS_DETACH_NAME,
            ROOT_STOP_NAME,
        ),
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
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as runtime_descriptors:
        runtime_fd = verify_runtime_root(runtime_identity, custody=runtime_descriptors)
        pending_name = _root_manifest_pending(name)
        require(
            not _entry_exists(runtime_fd, name),
            f"root manifest already exists: {name}",
        )
        remove_root_manifest_pending(runtime_fd, name)
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as pending_descriptors:
            descriptor = pending_descriptors.acquire(
                lambda: os.open(
                    pending_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o400,
                    dir_fd=runtime_fd,
                )
            )
            offset = 0
            while offset < len(encoded):
                offset += os.write(descriptor, encoded[offset:])
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        os.replace(pending_name, name, src_dir_fd=runtime_fd, dst_dir_fd=runtime_fd)
        os.fsync(runtime_fd)
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


def legacy_v3_transition_blocked(
    *,
    source_present: bool,
    source_exact: bool,
    control_present: bool,
    archive_present: bool,
    prepared_present: bool,
    terminal_archive_exact: bool,
) -> bool:
    return source_exact or (
        (source_present or control_present or archive_present or prepared_present) and not terminal_archive_exact
    )


def _legacy_v3_digest_from_bound_descriptor(
    descriptor: int,
    literal_reader: Callable[[], os.stat_result],
    *,
    require_terminal_identity: bool,
) -> bool:
    observed = os.fstat(descriptor)
    if not (stat.S_ISREG(observed.st_mode) and 0 < observed.st_size <= 2 * 1024 * 1024):
        return False
    if require_terminal_identity and not (
        observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) == 0o400
        and observed.st_nlink in (1, 2)
    ):
        return False
    raw = _read_fd_all(descriptor, limit=2 * 1024 * 1024)
    after = os.fstat(descriptor)
    literal = literal_reader()
    if not (
        len(raw) == observed.st_size
        and (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_uid,
            after.st_gid,
            stat.S_IMODE(after.st_mode),
            after.st_nlink,
        )
        == (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
            observed.st_nlink,
        )
        and (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino)
    ):
        return False
    return hashlib.sha256(raw).hexdigest() == LEGACY_V3_RECEIPT_SHA256


def _legacy_v3_regular_digest(
    path: Path,
    *,
    require_terminal_identity: bool,
) -> bool:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        try:
            descriptor = descriptors.acquire(lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW))
        except (FileNotFoundError, OSError):
            return False
        try:
            return _legacy_v3_digest_from_bound_descriptor(
                descriptor,
                lambda: os.stat(path, follow_symlinks=False),
                require_terminal_identity=require_terminal_identity,
            )
        except (OSError, SupervisorError):
            return False


def _legacy_v3_regular_digest_at(
    directory_fd: int,
    name: str,
    *,
    require_terminal_identity: bool,
) -> bool:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        try:
            descriptor = descriptors.acquire(
                lambda: os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            )
        except (FileNotFoundError, OSError):
            return False
        try:
            return _legacy_v3_digest_from_bound_descriptor(
                descriptor,
                lambda: os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                ),
                require_terminal_identity=require_terminal_identity,
            )
        except (OSError, SupervisorError):
            return False


def _legacy_v3_entry_exists_at(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def legacy_v3_transition_snapshot(
    evidence_fd: int | None = None,
) -> dict[str, bool]:
    if evidence_fd is None:
        source_present = path_exists_nofollow(LEGACY_V3_LIVE_RECEIPT)
        source_exact = _legacy_v3_regular_digest(
            LEGACY_V3_LIVE_RECEIPT,
            require_terminal_identity=False,
        )
        archive_present = path_exists_nofollow(LEGACY_V3_TERMINAL_ARCHIVE)
        prepared_present = path_exists_nofollow(LEGACY_V3_PREPARED_ARCHIVE)
        terminal_archive_exact = _legacy_v3_regular_digest(
            LEGACY_V3_TERMINAL_ARCHIVE,
            require_terminal_identity=True,
        )
    else:
        source_present = _legacy_v3_entry_exists_at(
            evidence_fd,
            LEGACY_V3_LIVE_RECEIPT.name,
        )
        source_exact = _legacy_v3_regular_digest_at(
            evidence_fd,
            LEGACY_V3_LIVE_RECEIPT.name,
            require_terminal_identity=False,
        )
        archive_present = _legacy_v3_entry_exists_at(
            evidence_fd,
            LEGACY_V3_TERMINAL_ARCHIVE.name,
        )
        prepared_present = _legacy_v3_entry_exists_at(
            evidence_fd,
            LEGACY_V3_PREPARED_ARCHIVE.name,
        )
        terminal_archive_exact = _legacy_v3_regular_digest_at(
            evidence_fd,
            LEGACY_V3_TERMINAL_ARCHIVE.name,
            require_terminal_identity=True,
        )
    return {
        "sourcePresent": source_present,
        "sourceExact": source_exact,
        "controlPresent": path_exists_nofollow(LEGACY_V3_CONTROL_ROOT),
        "archivePresent": archive_present,
        "preparedPresent": prepared_present,
        "terminalArchiveExact": terminal_archive_exact,
    }


def _legacy_v3_snapshot_blocked(snapshot: Mapping[str, bool]) -> bool:
    inconsistent = (snapshot["sourceExact"] and not snapshot["sourcePresent"]) or (
        snapshot["terminalArchiveExact"] and not snapshot["archivePresent"]
    )
    return inconsistent or legacy_v3_transition_blocked(
        source_present=snapshot["sourcePresent"],
        source_exact=snapshot["sourceExact"],
        control_present=snapshot["controlPresent"],
        archive_present=snapshot["archivePresent"],
        prepared_present=snapshot["preparedPresent"],
        terminal_archive_exact=snapshot["terminalArchiveExact"],
    )


def _require_legacy_v3_evidence_binding(
    state_fd: int,
    evidence_fd: int,
) -> None:
    state = os.fstat(state_fd)
    evidence = os.fstat(evidence_fd)
    literal_state = os.stat(LEGACY_V3_STATE_ROOT, follow_symlinks=False)
    literal_evidence = os.stat(
        "evidence",
        dir_fd=state_fd,
        follow_symlinks=False,
    )
    require(
        stat.S_ISDIR(state.st_mode)
        and (state.st_uid, state.st_gid, stat.S_IMODE(state.st_mode)) == (1000, 1000, 0o700)
        and stat.S_ISDIR(evidence.st_mode)
        and (evidence.st_uid, evidence.st_gid, stat.S_IMODE(evidence.st_mode)) == (1000, 1000, 0o700)
        and evidence.st_dev == state.st_dev
        and (literal_state.st_dev, literal_state.st_ino) == (state.st_dev, state.st_ino)
        and (literal_evidence.st_dev, literal_evidence.st_ino) == (evidence.st_dev, evidence.st_ino),
        "legacy v3 state or evidence directory binding differs",
    )


def _require_runtime_lease_custody(lease: RuntimeLease) -> None:
    require(
        lease.path == RUNTIME_PARENT / GLOBAL_LEASE_NAME and lease.parent_fd >= 0 and lease.descriptor >= 0,
        "legacy transition durability requires the shared runtime lease",
    )
    observed = os.fstat(lease.descriptor)
    literal = os.stat(
        lease.path.name,
        dir_fd=lease.parent_fd,
        follow_symlinks=False,
    )
    require(
        stat.S_ISREG(observed.st_mode)
        and observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) == 0o600
        and observed.st_nlink == 1
        and (observed.st_dev, observed.st_ino) == (lease.device, lease.inode) == (literal.st_dev, literal.st_ino),
        "shared runtime lease custody differs",
    )
    try:
        fcntl.flock(lease.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        raise SupervisorError("shared runtime lease custody was lost") from error


def settle_legacy_v3_terminal_archive(lease: RuntimeLease) -> dict[str, bool]:
    _require_runtime_lease_custody(lease)
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        state_fd = descriptors.acquire(
            lambda: os.open(
                LEGACY_V3_STATE_ROOT,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
        )
        evidence_fd = descriptors.acquire(
            lambda: os.open(
                "evidence",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=state_fd,
            )
        )
        _require_legacy_v3_evidence_binding(state_fd, evidence_fd)
        os.fsync(evidence_fd)
        first = legacy_v3_transition_snapshot(evidence_fd)
        second = legacy_v3_transition_snapshot(evidence_fd)
        _require_legacy_v3_evidence_binding(state_fd, evidence_fd)
        require(
            first == second
            and second["archivePresent"]
            and second["terminalArchiveExact"]
            and not _legacy_v3_snapshot_blocked(second),
            "legacy v3 terminal archive changed while completing durability",
        )
        return second


def observe_legacy_v3_transition() -> dict[str, bool]:
    snapshot = legacy_v3_transition_snapshot()
    require(
        not _legacy_v3_snapshot_blocked(snapshot),
        "exact legacy v3 runtime transition is not terminally archived",
    )
    return snapshot


def require_legacy_v3_transition_terminal(*, lease: RuntimeLease) -> None:
    snapshot = observe_legacy_v3_transition()
    if snapshot["terminalArchiveExact"]:
        settle_legacy_v3_terminal_archive(lease)


def require_no_other_task_runtime(
    state_root: Path,
    *,
    lease: RuntimeLease | None = None,
) -> None:
    expected_runtime = runtime_root_for(state_root).name
    expected_removal = runtime_removal_root_for(state_root).name
    expected_socket = socket_root_for(state_root).name
    expected_cgroup = cgroup_path_for(state_root).name
    foreign: list[str] = []
    for parent, pattern, expected in (
        (RUNTIME_PARENT, RUNTIME_ROOT_RE, expected_runtime),
        (RUNTIME_PARENT, RUNTIME_REMOVAL_ROOT_RE, expected_removal),
        (RUNTIME_PARENT, SOCKET_ROOT_RE, expected_socket),
        (CGROUP_PARENT, CGROUP_PATH_RE, expected_cgroup),
    ):
        for name in os.listdir(parent):
            path = parent / name
            if pattern.fullmatch(str(path)) is not None and name != expected:
                foreign.append(str(path))
    require(
        not foreign,
        "another C16b runtime authority exists; use its original STATE_ROOT binding: " + ",".join(sorted(foreign)),
    )
    # Lease-free callers perform only read-only routing (status or proof before
    # acquiring/signaling an already-validated v5 singleton). Every route that
    # can create, remove, or recover runtime state repeats this gate with its
    # held global lease before the first such mutation.
    if lease is None:
        observe_legacy_v3_transition()
    else:
        require_legacy_v3_transition_terminal(lease=lease)
    legacy_tmp = tuple(
        sorted(
            str(Path("/tmp") / name)
            for name in os.listdir("/tmp")
            if LEGACY_TMP_RUNTIME_RE.fullmatch(str(Path("/tmp") / name)) is not None
        )
    )
    require(
        not legacy_tmp,
        "legacy /tmp C16b runtime must be drained under its exact old authority before v5: " + ",".join(legacy_tmp),
    )


def read_root_manifest(runtime_identity: RuntimeIdentity, name: str) -> dict[str, Any] | None:
    require(
        name
        in (
            ROOT_CONTROL_NAME,
            ROOT_READY_NAME,
            ROOT_STOPPING_NAME,
            ROOT_NETNS_BASELINE_NAME,
            ROOT_NETNS_DETACH_NAME,
            ROOT_STOP_NAME,
        ),
        "root manifest name is invalid",
    )
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as runtime_descriptors:
        runtime_fd = verify_runtime_root(runtime_identity, custody=runtime_descriptors)
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
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as manifest_descriptors:
            descriptor = manifest_descriptors.acquire(
                lambda: os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW,
                    dir_fd=runtime_fd,
                )
            )
            first = os.fstat(descriptor)
            require(
                (first.st_dev, first.st_ino) == (value.st_dev, value.st_ino),
                f"root manifest entry changed: {name}",
            )
            raw = _read_fd_all(descriptor, limit=2 * 1024 * 1024)
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


def require_address_pool_available(
    run: Callable[..., subprocess.CompletedProcess[str]],
) -> None:
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
    require(
        operation["outcome"] == expected_outcome,
        "runner storage operation outcome differs",
    )
    require(
        operation["authorityRoot"] == str(AUTHORITY_ROOT),
        "runner storage authority root differs",
    )
    require(
        operation["mountTarget"] == str(MOUNT_TARGET),
        "runner storage mount target differs",
    )
    require(
        operation["mountNamespace"] == f"{expected_namespace['device']}:{expected_namespace['inode']}",
        "runner storage operation namespace differs",
    )
    digest = operation["authorityReceiptSha256"]
    if operation["receipt"] is None:
        require(
            expected_outcome == "deactivated" and allow_unpublished and digest is None,
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
    require(
        receipt["schema"] == STORAGE_RECEIPT_SCHEMA,
        "runner storage receipt schema differs",
    )
    expected_lifecycle_state = "detached" if expected_outcome == "deactivated" else "attached"
    require(
        receipt["lifecycleState"] == expected_lifecycle_state,
        "runner storage receipt lifecycle state differs",
    )
    require(
        receipt["stateRoot"] == str(state_root),
        "runner storage receipt state root differs",
    )
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
    require(
        state_identity["path"] == str(state_root),
        "runner storage state identity path differs",
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
    evidence_identity = exact_keys(
        receipt["evidenceDirectoryIdentity"],
        {"path", "device", "inode", "ownerUid", "ownerGid", "mode"},
        "runner storage evidence identity",
    )
    require(
        evidence_identity["path"] == str(state_root / "evidence")
        and plain_int(evidence_identity["device"], "runner storage evidence device") == state_device
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
    require(
        target["path"] == str(MOUNT_TARGET),
        "runner storage target identity path differs",
    )
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
            isinstance(loop["device"], str) and LOOP_DEVICE_RE.fullmatch(loop["device"]) is not None,
            "runner storage loop device is invalid",
        )
        safe_loop = {
            "device": loop["device"],
            "major": plain_int(loop["major"], "runner storage loop major", positive=True),
            "minor": plain_int(loop["minor"], "runner storage loop minor"),
        }
        require(
            (os.major(target["device"]), os.minor(target["device"])) == (safe_loop["major"], safe_loop["minor"]),
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
        {"pquota", "nodev", "nosuid"} <= set(filesystem["mountOptions"]) and "ro" not in filesystem["mountOptions"],
        "runner storage mount options differ",
    )
    total_bytes = plain_int(filesystem["totalBytes"], "runner storage total bytes", positive=True)
    free_bytes = plain_int(filesystem["freeBytes"], "runner storage free bytes")
    require(free_bytes <= total_bytes, "runner storage free bytes are invalid")
    require(
        isinstance(filesystem["features"], list) and all(isinstance(item, str) for item in filesystem["features"]),
        "runner storage filesystem features are invalid",
    )
    receipt_namespace = validate_namespace(
        receipt["mountNamespace"],
        "runner storage receipt namespace",
    )
    require(
        expected_outcome == "deactivated" or receipt_namespace == expected_namespace,
        "runner storage receipt namespace differs",
    )

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
        plain_int(
            backing["minimumFreeBytes"],
            "runner storage minimum free bytes",
            positive=True,
        )
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
        plain_int(policy["aggregateBytes"], "sandbox aggregate bytes", positive=True) == per_sandbox * maximum,
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
    runtime_lease_fd: int | None,
    allow_unpublished: bool = False,
) -> dict[str, object]:
    outcomes = {
        "activate-private": "activated",
        "observe-private": "observed",
        "deactivate-private": "deactivated",
    }
    require(command in outcomes, "storage helper command is invalid")
    require(
        outcomes[command] == expected_outcome,
        "storage helper outcome authority differs",
    )
    require(
        not allow_unpublished or command == "deactivate-private",
        "unpublished storage policy is invalid for this operation",
    )
    mutating = command in ("activate-private", "deactivate-private")
    require(
        (mutating and runtime_lease_fd is not None and runtime_lease_fd >= 0)
        or (not mutating and runtime_lease_fd is None),
        "runtime lease descriptor policy differs",
    )
    if runtime_lease_fd is not None:
        os.fstat(runtime_lease_fd)
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C.UTF-8",
        "SUDO_UID": str(caller_uid),
        "SUDO_GID": str(caller_gid),
    }
    arguments = [
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
    ]
    pass_fds: tuple[int, ...] = ()
    if runtime_lease_fd is not None:
        arguments.append(str(runtime_lease_fd))
        pass_fds = (runtime_lease_fd,)
    process = subprocess.Popen(
        arguments,
        cwd="/",
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        close_fds=True,
        pass_fds=pass_fds,
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
    return value.replace(r"\040", " ").replace(r"\011", "\t").replace(r"\012", "\n").replace(r"\134", "\\")


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
        require(
            target.parent == prefix,
            "task network namespace mount is nested unexpectedly",
        )
        require(filesystem == "nsfs", "task network namespace mount type differs")
        found.append(target)
    require(len(found) == len(set(found)), "task network namespace mount is duplicated")
    return tuple(sorted(found, key=lambda item: len(item.parts), reverse=True))


def existing_runtime_identity(
    path: Path,
    *,
    recoverable_modes: set[int] = {0o700},
    path_pattern: re.Pattern[str] = RUNTIME_ROOT_RE,
) -> RuntimeIdentity:
    require(path_pattern.fullmatch(str(path)) is not None, "runtime root path is invalid")
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(lambda: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
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
    require(
        (result.uid, result.gid, result.mode) == (0, 0, 0o700),
        "runtime owner or mode differs",
    )
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
    require(
        control["runtimeRoot"] == str(runtime_identity.path),
        "root control runtime path differs",
    )
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
    recorded_process = process_authority["validate_recorded_identity"](control["supervisorProcessIdentity"])
    require(
        recorded_process["mountNamespace"] == namespace,
        "root control process namespace differs",
    )
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
            "netnsBaselineSha256",
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
    require(
        ready["rootControlSha256"] == root_control_digest,
        "root ready control digest differs",
    )
    require(
        isinstance(ready["netnsBaselineSha256"], str) and SHA256_RE.fullmatch(ready["netnsBaselineSha256"]) is not None,
        "root ready ambient netns baseline digest is invalid",
    )
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
    require(
        socket_identity.device == socket_root.device,
        "root ready socket backing differs",
    )
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
    require(
        containerd["root"] == str(AUTHORITY_ROOT / "outer-containerd"),
        "containerd root differs",
    )
    require(
        containerd["address"] == str(runtime_root_for(state_root) / "containerd.sock")
        and isinstance(containerd["version"], str)
        and 0 < len(containerd["version"]) <= 256
        and isinstance(containerd["configSha256"], str)
        and SHA256_RE.fullmatch(containerd["configSha256"]) is not None,
        "root ready containerd authority differs",
    )
    require(
        ready["dataRoot"] == str(AUTHORITY_ROOT / "outer-docker"),
        "Docker data root differs",
    )
    require(
        ready["execRoot"] == str(runtime_root_for(state_root) / "docker-exec"),
        "Docker exec root differs",
    )
    require(
        ready["network"]
        == {
            "defaultBridge": "disabled",
            "addressPool": "172.30.0.0/16",
            "hostFirewallMutation": False,
        },
        "root ready network authority differs",
    )
    require(
        validate_docker_daemon_id(ready["serverId"]) == ready["serverId"],
        "Docker ID differs",
    )
    require(
        isinstance(ready["serverVersion"], str)
        and 0 < len(ready["serverVersion"]) <= 128
        and isinstance(ready["configSha256"], str)
        and SHA256_RE.fullmatch(ready["configSha256"]) is not None,
        "root ready Docker version or config authority differs",
    )
    docker_identity = process_authority["validate_recorded_identity"](ready["dockerProcessIdentity"])
    containerd_identity = process_authority["validate_recorded_identity"](containerd["processIdentity"])
    supervisor_identity = process_authority["validate_recorded_identity"](ready["supervisorProcessIdentity"])
    require(
        docker_identity["parentPid"] == supervisor_identity["pid"]
        and containerd_identity["parentPid"] == supervisor_identity["pid"]
        and docker_identity["mountNamespace"] == ready["mountNamespace"]
        and containerd_identity["mountNamespace"] == ready["mountNamespace"]
        and supervisor_identity["cgroup"] == execution_cgroup_path(ready_cgroup)
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
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def stopping_authority_value(
    *,
    state_root: Path,
    reason: str,
    control_digest: str,
    runtime: RuntimeIdentity,
    cgroup: CgroupIdentity,
    supervisor_identity: dict[str, object],
) -> dict[str, object]:
    require(bool(reason) and len(reason) <= 256, "runtime stopping reason is invalid")
    require(
        SHA256_RE.fullmatch(control_digest) is not None,
        "root control digest is invalid",
    )
    return {
        "schema": STOPPING_SCHEMA,
        "outcome": "stopping",
        "observedAt": utc_now(),
        "bootId": current_boot_id(),
        "stateRoot": str(state_root),
        "reason": reason,
        "rootControlSha256": control_digest,
        "runtimeRootIdentity": runtime.json(),
        "cgroup": cgroup.json(),
        "supervisorProcessIdentity": supervisor_identity,
    }


def validate_stopping_authority(
    value: object,
    *,
    state_root: Path,
    control_digest: str,
    runtime: RuntimeIdentity,
    cgroup: CgroupIdentity,
    supervisor_identity: dict[str, object],
    boot_id: str,
) -> dict[str, object]:
    stopping = exact_keys(
        value,
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
        and isinstance(stopping["observedAt"], str)
        and stopping["bootId"] == boot_id
        and stopping["stateRoot"] == str(state_root)
        and isinstance(stopping["reason"], str)
        and 0 < len(stopping["reason"]) <= 256
        and stopping["rootControlSha256"] == control_digest
        and stopping["runtimeRootIdentity"] == runtime.json()
        and stopping["cgroup"] == cgroup.json()
        and stopping["supervisorProcessIdentity"] == supervisor_identity,
        "root stopping authority differs",
    )
    return stopping


def validate_stop_authority(
    value: object,
    *,
    stopping: dict[str, object],
    state_root: Path,
    runtime: RuntimeIdentity,
    cgroup: CgroupIdentity,
    supervisor_identity: dict[str, object],
    boot_id: str,
    expected_netns_digest: str | None = None,
) -> dict[str, object]:
    stop = exact_keys(
        value,
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
            "netnsDetachSha256",
            "storageProjectionDigest",
            "socketRootRemoved",
            "externalFinalizationRequired",
        },
        "root runtime stop authority",
    )
    netns_digest = stop["netnsDetachSha256"]
    storage_digest = stop["storageProjectionDigest"]
    require(
        stop["schema"] == STOP_SCHEMA
        and stop["outcome"] == "quiesced"
        and isinstance(stop["observedAt"], str)
        and 0 < len(stop["observedAt"]) <= 128
        and stop["bootId"] == boot_id
        and stop["stateRoot"] == str(state_root)
        and stop["reason"] == stopping["reason"]
        and stop["supervisorProcessIdentity"] == supervisor_identity
        and stop["runtimeRootIdentity"] == runtime.json()
        and stop["cgroup"] == cgroup.json()
        and stop["rootStoppingSha256"] == canonical_document_digest(stopping)
        and isinstance(netns_digest, str)
        and SHA256_RE.fullmatch(netns_digest) is not None
        and (expected_netns_digest is None or netns_digest == expected_netns_digest)
        and (
            storage_digest is None
            or (isinstance(storage_digest, str) and SHA256_RE.fullmatch(storage_digest) is not None)
        )
        and stop["socketRootRemoved"] is True
        and stop["externalFinalizationRequired"] is True,
        "root stop authority differs",
    )
    return stop


def _validate_snapshot_prefix(path: Path, expected: bytes) -> None:
    with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
        descriptor = descriptors.acquire(lambda: os.open(path, os.O_RDONLY | os.O_NOFOLLOW))
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
        require(
            expected.startswith(actual),
            f"pre-control snapshot bytes differ: {path.name}",
        )


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
            with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
                descriptor = descriptors.acquire(
                    lambda: os.open(
                        runtime.path,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    )
                )
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
            runtime = RuntimeIdentity(
                runtime.path,
                runtime.device,
                runtime.inode,
                runtime.uid,
                runtime.gid,
                0o700,
            )
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            runtime_fd = verify_runtime_root(runtime, custody=descriptors)
            roster = set(os.listdir(runtime_fd))
            classify_precontrol_roster(roster)
            for name in ("containerd-state", "docker-exec"):
                if name not in roster:
                    continue
                descriptor = descriptors.acquire(
                    lambda: os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=runtime_fd,
                    )
                )
                observed = os.fstat(descriptor)
                require(
                    observed.st_uid == 0
                    and observed.st_gid == 0
                    and stat.S_IMODE(observed.st_mode) in (0o000, 0o700)
                    and not os.listdir(descriptor),
                    f"pre-control directory identity differs: {name}",
                )
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
        remove_runtime_root(runtime, state_root)

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
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            socket_fd = descriptors.acquire(
                lambda: os.open(
                    socket_path,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            )
            parent_fd = descriptors.acquire(
                lambda: os.open(
                    RUNTIME_PARENT,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            )
            require(not os.listdir(socket_fd), "pre-control Docker API root is not empty")
            require(
                not stable_global_mount_targets(socket_path),
                "pre-control Docker API root is mounted",
            )
            os.rmdir(socket_path.name, dir_fd=parent_fd)
            os.fsync(parent_fd)

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
        if state.exists(name):
            state.unlink_regular(name)


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
        self.root_netns_baseline_digest: str | None = None
        self.ambient_netns_sources: tuple[AmbientNetnsSource, ...] | None = None
        self.root_netns_detach_digest: str | None = None
        self.task_netns_detach_manifest: tuple[TaskNetnsDetachEntry, ...] | None = None
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
        require(
            process_arguments_sha256() == expected_digest,
            "supervisor process arguments changed",
        )
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
        require(self.lease is not None, "runtime lifecycle lease is absent")
        runtime_lease_fd = self.lease.descriptor if command in ("activate-private", "deactivate-private") else None
        return invoke_storage_helper(
            helper=self.storage_helper_path,
            command=command,
            state_root=self.state_root,
            caller_uid=self.caller_uid,
            caller_gid=self.caller_gid,
            namespace=self.namespace,
            expected_outcome=outcome,
            expected_children=self.expected_child_pids(),
            runtime_lease_fd=runtime_lease_fd,
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
            existing = read_root_manifest(self.runtime_identity, ROOT_STOPPING_NAME)
            require(existing is not None, "root stopping authority disappeared")
            validate_stopping_authority(
                existing,
                state_root=self.state_root,
                control_digest=self.root_control_digest,
                runtime=self.runtime_identity,
                cgroup=self.cgroup_identity,
                supervisor_identity=self.supervisor_identity,
                boot_id=current_boot_id(),
            )
            return
        value = stopping_authority_value(
            state_root=self.state_root,
            reason=reason,
            control_digest=self.root_control_digest,
            runtime=self.runtime_identity,
            cgroup=self.cgroup_identity,
            supervisor_identity=self.supervisor_identity,
        )
        self.root_stopping_digest = write_root_manifest(
            self.runtime_identity,
            ROOT_STOPPING_NAME,
            value,
        )

    def recover_existing_runtime(self, *, orphaned: bool = False) -> None:
        require(self.state is not None, "state authority is absent")
        require(self.namespace is not None, "recovery mount namespace is absent")
        require(self.lease is not None, "runtime lifecycle lease is absent")
        require_no_other_task_runtime(self.state_root, lease=self.lease)
        runtime_path = runtime_root_for(self.state_root)
        removal_path = runtime_removal_root_for(self.state_root)
        require(
            not (path_exists_nofollow(runtime_path) and path_exists_nofollow(removal_path)),
            "runtime and removal authorities coexist",
        )
        # A crash may leave the atomically renamed removal tree alongside an
        # exact, already emptied cgroup.  Reduce the tree first, then flow
        # through the same absent-runtime reducer that settles those residual
        # boundaries.  This also makes a crash after the final rmdir
        # indistinguishable from the ordinary absent-runtime replay state.
        reduce_runtime_removal_root(self.state_root)
        try:
            runtime = existing_runtime_identity(runtime_path)
        except FileNotFoundError:
            reduce_precontrol_runtime(
                self.state_root,
                self.caller_gid,
                self.precontrol_source_directory,
            )
            if not orphaned:
                remove_user_runtime_projections(writable_state_authority(self.state))
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
            require(
                not orphaned,
                "orphaned pre-control runtime lacks durable caller authority",
            )
            remove_user_runtime_projections(writable_state_authority(self.state))
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
        stopping: dict[str, object] | None = None
        if stopping_value is not None:
            stopping = validate_stopping_authority(
                stopping_value,
                state_root=self.state_root,
                control_digest=root_control_digest,
                runtime=runtime,
                cgroup=validated["cgroup"],
                supervisor_identity=validated["supervisor"],
                boot_id=validated["control"]["bootId"],
            )
        stop_value = read_root_manifest(runtime, ROOT_STOP_NAME)
        stop: dict[str, object] | None = None
        if stop_value is not None:
            require(stopping is not None, "root stop authority lacks stopping authority")
            stop = validate_stop_authority(
                stop_value,
                stopping=stopping,
                state_root=self.state_root,
                runtime=runtime,
                cgroup=validated["cgroup"],
                supervisor_identity=validated["supervisor"],
                boot_id=validated["control"]["bootId"],
            )
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
        if stopping_value is None:
            stopping_value = stopping_authority_value(
                state_root=self.state_root,
                reason="dead_supervisor_recovery",
                control_digest=root_control_digest,
                runtime=runtime,
                cgroup=cgroup,
                supervisor_identity=validated["supervisor"],
            )
            root_stopping_digest = write_root_manifest(
                runtime,
                ROOT_STOPPING_NAME,
                stopping_value,
            )
        else:
            root_stopping_digest = canonical_document_digest(stopping_value)

        socket_root = validated["socketRoot"]
        socket_present, expected_socket = classify_recovery_socket(
            socket_root,
            ready["socket"] if ready is not None else None,
            self.caller_gid,
            absence_authorized=True,
        )
        cgroup_was_populated = cgroup_is_populated(cgroup)
        if cgroup_was_populated:
            freeze_cgroup_and_wait(cgroup, timeout=60)
        frozen_socket_present, frozen_expected_socket = classify_recovery_socket(
            socket_root,
            ready["socket"] if ready is not None else None,
            self.caller_gid,
            absence_authorized=True,
        )
        require(
            socket_present or not frozen_socket_present,
            "Docker API root reappeared after its admitted absent cutpoint",
        )
        if expected_socket is not None and frozen_socket_present:
            require(
                frozen_expected_socket in (None, expected_socket),
                "Docker API socket identity changed before the frozen cutoff",
            )
        socket_present = frozen_socket_present
        expected_socket = frozen_expected_socket

        existing_netns_baseline = read_root_manifest(runtime, ROOT_NETNS_BASELINE_NAME)
        require(
            ready is None or existing_netns_baseline is not None,
            "ready runtime lacks its ambient network namespace baseline",
        )
        netns_baseline_digest, ambient_sources = ensure_netns_baseline_manifest(
            runtime=runtime,
            state_root=self.state_root,
            control_digest=root_control_digest,
            recorded_namespace=validated["control"]["mountNamespace"],
        )
        require(
            ready is None or ready["netnsBaselineSha256"] == netns_baseline_digest,
            "root ready ambient network namespace baseline digest differs",
        )
        existing_netns_detach = read_root_manifest(runtime, ROOT_NETNS_DETACH_NAME)
        require(
            stop is None or existing_netns_detach is not None,
            "root stop authority lacks its task network namespace detach manifest",
        )
        preferred_pids = (
            tuple(identity["pid"] for identity in (ready["docker"], ready["containerd"]) if isinstance(identity, dict))
            if ready is not None
            else ()
        )
        netns_detach_digest, task_mounts = ensure_task_netns_detach_manifest(
            runtime=runtime,
            state_root=self.state_root,
            control_digest=root_control_digest,
            stopping_digest=root_stopping_digest,
            baseline_digest=netns_baseline_digest,
            ambient_sources=ambient_sources,
            recorded_namespace=validated["control"]["mountNamespace"],
            preferred_pids=preferred_pids,
        )
        if stop_value is not None:
            assert stopping is not None
            stop = validate_stop_authority(
                stop_value,
                stopping=stopping,
                state_root=self.state_root,
                runtime=runtime,
                cgroup=cgroup,
                supervisor_identity=validated["supervisor"],
                boot_id=validated["control"]["bootId"],
                expected_netns_digest=netns_detach_digest,
            )

        if cgroup_was_populated or cgroup_is_populated(cgroup):
            kill_cgroup_and_wait(cgroup, timeout=60)
        settle_task_netns_detach_manifest(
            runtime=runtime,
            recorded_namespace=validated["control"]["mountNamespace"],
            task_mounts=task_mounts,
            expected_children=set(),
        )

        if socket_present:
            try:
                os.stat(socket_root.path, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
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
            require(
                stop is None or stop["storageProjectionDigest"] == self.deactivated_storage["projectionDigest"],
                "root stop storage projection digest differs",
            )
        settle_task_netns_detach_manifest(
            runtime=runtime,
            recorded_namespace=validated["control"]["mountNamespace"],
            task_mounts=task_mounts,
            expected_children=set(),
        )
        remove_runtime_root(runtime, self.state_root)
        remove_empty_cgroup(cgroup)
        if not orphaned:
            remove_user_runtime_projections(writable_state_authority(self.state))
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
        self.state = StateAuthority.pending(
            self.state_root,
            self.caller_uid,
            self.caller_gid,
        )
        self.state.acquire()
        self.recover_existing_runtime()
        require(
            not self.state.exists(CONTROL_RECEIPT_NAME) and not self.state.exists(START_RECEIPT_NAME),
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
        self.prepare_netns_baseline()
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
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            runtime_fd = verify_runtime_root(self.runtime_identity, custody=descriptors)
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
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            target_fd = descriptors.acquire(
                lambda: os.open(
                    MOUNT_TARGET,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            )
            target = os.fstat(target_fd)
            require(
                target.st_uid == 0 and target.st_gid == 0 and stat.S_IMODE(target.st_mode) == 0o700,
                "runner storage target owner or mode differs",
            )
            loop = exact_keys(
                self.storage["loop"],
                {"device", "major", "minor"},
                "active runner storage loop",
            )
            require(
                (os.major(target.st_dev), os.minor(target.st_dev)) == (loop["major"], loop["minor"]),
                "runner storage target backing device changed after activation",
            )
            runner_data = target_fd
            inner_fd = descriptors.acquire(
                lambda: os.open(
                    "inner-runner",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=runner_data,
                )
            )
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

        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            authority_fd = descriptors.acquire(
                lambda: os.open(
                    AUTHORITY_ROOT,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
            )
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

        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            runtime_fd = verify_runtime_root(self.runtime_identity, custody=descriptors)
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
            lambda: (
                self.containerd_process is not None
                and self.containerd_process.poll() is None
                and self.containerd_socket is not None
                and self.containerd_socket.is_socket()
            ),
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
            lambda: (
                self.docker_process is not None
                and self.docker_process.poll() is None
                and self.socket_root_identity is not None
                and socket_entry_ready(self.socket_root_identity, self.caller_gid)
            ),
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
        require(
            first_containerd == second_containerd,
            "containerd identity changed during startup",
        )
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
            containerd_identity == self.containerd_identity and docker_identity == self.docker_identity,
            "isolated daemon identity changed before publication",
        )
        verify_socket_boundary(
            self.socket_root_identity,
            self.socket_identity,
            self.caller_gid,
        )
        require_exact_children({self.containerd_process.pid, self.docker_process.pid})

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
            self.containerd_identity is not None and self.docker_identity is not None,
            "daemon identity is absent",
        )
        require(
            self.containerd_process is not None and self.docker_process is not None,
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
            self.root_netns_baseline_digest is not None,
            "ambient network namespace baseline is absent",
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
            "supervisorSourceSha256": verified_supervisor_source_sha256(),
            "processIdentitySourceSha256": PROCESS_IDENTITY_SHA256,
            "storageLifecycleSourceSha256": STORAGE_LIFECYCLE_SHA256,
            "runtimeRoot": str(self.runtime_identity.path),
            "runtimeRootIdentity": self.runtime_identity.json(),
            "rootControlSha256": self.root_control_digest,
            "netnsBaselineSha256": self.root_netns_baseline_digest,
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
                        self.socket_root_identity is not None and self.socket_identity is not None,
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
            arguments = (
                "--config",
                str(self.containerd_config_path),
                "--log-level",
                "info",
            )
            expected_identity = self.containerd_identity
        else:
            raise SupervisorError("unsupported daemon shutdown authority")
        require(hasattr(os, "pidfd_open"), "pidfd process custody is unavailable")
        require(hasattr(signal, "pidfd_send_signal"), "pidfd signal delivery is unavailable")
        with DescriptorCustodyGate() as _descriptor_gate, _descriptor_gate.custody as descriptors:
            pidfd = descriptors.acquire(lambda: os.pidfd_open(process.pid, 0))
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
            require(
                observed_identity == expected_identity,
                f"{name} identity changed before stop",
            )
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired as error:
                raise SupervisorError(f"{name} did not stop within 60 seconds") from error

    def prepare_netns_baseline(self) -> None:
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.namespace is not None, "runtime mount namespace is absent")
        require(self.root_control_digest is not None, "root control authority is absent")
        if self.root_netns_baseline_digest is not None:
            require(
                self.ambient_netns_sources is not None,
                "ambient network namespace baseline is absent",
            )
            return
        digest, sources = ensure_netns_baseline_manifest(
            runtime=self.runtime_identity,
            state_root=self.state_root,
            control_digest=self.root_control_digest,
            recorded_namespace=self.namespace,
        )
        self.root_netns_baseline_digest = digest
        self.ambient_netns_sources = sources

    def prepare_task_netns_detach(self) -> None:
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.namespace is not None, "runtime mount namespace is absent")
        require(self.root_control_digest is not None, "root control authority is absent")
        require(self.root_stopping_digest is not None, "root stopping authority is absent")
        self.prepare_netns_baseline()
        require(
            self.root_netns_baseline_digest is not None and self.ambient_netns_sources is not None,
            "ambient network namespace baseline is absent",
        )
        if self.root_netns_detach_digest is not None:
            require(
                self.task_netns_detach_manifest is not None,
                "task network namespace detach roster is absent",
            )
            return
        digest, task_mounts = ensure_task_netns_detach_manifest(
            runtime=self.runtime_identity,
            state_root=self.state_root,
            control_digest=self.root_control_digest,
            stopping_digest=self.root_stopping_digest,
            baseline_digest=self.root_netns_baseline_digest,
            ambient_sources=self.ambient_netns_sources,
            recorded_namespace=self.namespace,
            preferred_pids=tuple(
                process.pid for process in (self.docker_process, self.containerd_process) if process is not None
            ),
        )
        self.root_netns_detach_digest = digest
        self.task_netns_detach_manifest = task_mounts

    def cleanup_task_netns(self) -> None:
        self.prepare_task_netns_detach()
        require(self.runtime_identity is not None, "runtime identity is absent")
        require(self.namespace is not None, "runtime mount namespace is absent")
        require(
            self.task_netns_detach_manifest is not None,
            "task network namespace detach roster is absent",
        )
        settle_task_netns_detach_manifest(
            runtime=self.runtime_identity,
            recorded_namespace=self.namespace,
            task_mounts=self.task_netns_detach_manifest,
            expected_children=self.expected_child_pids(),
        )

    def try_shutdown(self, reason: str) -> bool:
        require(self.state is not None, "state authority is absent")
        first_attempt = not self.shutdown_started
        self.shutdown_started = True
        try:
            if self.root_stopping_digest is None:
                self.write_shutdown_intent(reason)
            if first_attempt:
                self.write_control_receipt("stopping")
            # Revoke new API admission and durably capture every current nsfs
            # source before either daemon can remove it during shutdown.
            if self.socket_root_identity is not None and not self.socket_root_removed:
                remove_socket_root(
                    self.socket_root_identity,
                    self.socket_identity,
                    self.caller_gid,
                )
                self.socket_root_removed = True
            self.prepare_task_netns_detach()
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
            require(self.runtime_identity is not None, "runtime identity is absent")
            require(self.cgroup_identity is not None, "runtime cgroup identity is absent")
            require(
                self.root_stopping_digest is not None,
                "root stopping authority is absent",
            )
            require(
                self.root_netns_detach_digest is not None,
                "task network namespace detach authority is absent",
            )
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
                    "netnsDetachSha256": self.root_netns_detach_digest,
                    "storageProjectionDigest": (
                        self.deactivated_storage["projectionDigest"] if self.deactivated_storage is not None else None
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
                require(
                    self.supervisor_identity is not None,
                    "supervisor process identity is absent",
                )
                stopping_value = read_root_manifest(
                    self.runtime_identity,
                    ROOT_STOPPING_NAME,
                )
                require(stopping_value is not None, "root stopping authority disappeared")
                stopping = validate_stopping_authority(
                    stopping_value,
                    state_root=self.state_root,
                    control_digest=self.root_control_digest,
                    runtime=self.runtime_identity,
                    cgroup=self.cgroup_identity,
                    supervisor_identity=self.supervisor_identity,
                    boot_id=current_boot_id(),
                )
                value = validate_stop_authority(
                    existing_stop,
                    stopping=stopping,
                    state_root=self.state_root,
                    runtime=self.runtime_identity,
                    cgroup=self.cgroup_identity,
                    supervisor_identity=self.supervisor_identity,
                    boot_id=current_boot_id(),
                    expected_netns_digest=self.root_netns_detach_digest,
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
            print(
                f"isolated runtime shutdown requires retry: {error}",
                file=sys.stderr,
                flush=True,
            )
            return False

    def run(self) -> int:
        primary: BaseException | None = None
        try:
            self.lease = RuntimeLease.pending(self.state_root)
            self.lease.acquire()
            try:
                self.setup()
            except BaseException as error:
                print(
                    f"isolated runtime startup failed: {error}",
                    file=sys.stderr,
                    flush=True,
                )
                if self.state is not None and self.runtime_identity is not None:
                    self.stop_requested = True
                    self.shutdown_reason = "startup_failure"
                    if not self.try_shutdown(self.shutdown_reason):
                        raise SupervisorError("startup recovery requires external cgroup finalization") from error
                raise
            return self.monitor()
        except BaseException as error:
            primary = error
            raise
        finally:
            state = self.state if isinstance(self.state, StateAuthority) else None
            lease = self.lease
            settled = settle_runtime_authorities(
                state=state,
                lease=lease,
                primary=primary,
            )
            if settled:
                self.state = None
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
    if ready is not None:
        validate_ready_netns_baseline(
            runtime=runtime,
            ready=ready,
            state_root=state.path,
            control_digest=canonical_document_digest(control_value),
            recorded_namespace=validated["control"]["mountNamespace"],
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
        and (state_identity["uid"], state_identity["gid"], state_identity["mode"]) == (caller_uid, caller_gid, 0o700)
        and (
            evidence_identity["uid"],
            evidence_identity["gid"],
            evidence_identity["mode"],
        )
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
    if ready is not None:
        validate_ready_netns_baseline(
            runtime=runtime,
            ready=ready,
            state_root=state_root,
            control_digest=canonical_document_digest(control_value),
            recorded_namespace=validated["control"]["mountNamespace"],
        )
    return state, runtime, validated, ready, process_authority


def runtime_status(state_root: Path, caller_uid: int, caller_gid: int) -> dict[str, object]:
    state = StateAuthority.pending(state_root, caller_uid, caller_gid)
    primary: BaseException | None = None
    try:
        state.acquire()
        try:
            require_no_other_task_runtime(state_root)
        except SupervisorError as error:
            return {
                "schema": "ambit.local-daytona-isolated-docker-status/v1",
                "outcome": "blocked",
                "stateRoot": str(state_root),
                "error": str(error),
            }
        if path_exists_nofollow(runtime_removal_root_for(state_root)):
            return {
                "schema": "ambit.local-daytona-isolated-docker-status/v1",
                "outcome": "blocked",
                "stateRoot": str(state_root),
                "error": "runtime removal recovery is pending",
            }
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
        except SupervisorError as error:
            if str(error) != LEGACY_V4_DIAGNOSTIC:
                raise
            return {
                "schema": "ambit.local-daytona-isolated-docker-status/v1",
                "outcome": "blocked",
                "stateRoot": str(state_root),
                "error": str(error),
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
    except BaseException as error:
        primary = error
        raise
    finally:
        settle_runtime_authorities(
            state=state,
            lease=None,
            primary=primary,
        )


def acquire_runtime_lease_until(
    state_root: Path,
    *,
    timeout: float,
    recipient: Callable[[RuntimeLease], None],
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lease = RuntimeLease.pending(state_root)
        recipient(lease)
        try:
            lease.acquire()
            return
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
    state = StateAuthority.pending(state_root, caller_uid, caller_gid)
    lease: RuntimeLease | None = None
    primary: BaseException | None = None

    def publish_lease(candidate: RuntimeLease) -> None:
        nonlocal lease
        lease = candidate

    try:
        state.acquire()
        # Refuse every signal/kill while a second task authority makes the
        # singleton state ambiguous. The global lease prevents a new v5 start
        # after this proof while the admitted target supervisor is active.
        require_no_other_task_runtime(state_root)
        lease = RuntimeLease.pending(state_root)
        try:
            lease.acquire()
        except SupervisorError as error:
            require(str(error) == "runtime lifecycle lease is busy", str(error))
            lease = None
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
                    lease = RuntimeLease.pending(state_root)
                    try:
                        lease.acquire()
                        break
                    except SupervisorError as retry_error:
                        require(
                            str(retry_error) == "runtime lifecycle lease is busy",
                            str(retry_error),
                        )
                        lease = None
                    time.sleep(0.1)
            if lease is not None:
                validated = None
            require(
                lease is not None or (validated is not None and process_authority is not None),
                "live startup did not publish root control before stop timeout",
            )
        if lease is None:
            assert validated is not None and process_authority is not None
            require_no_other_task_runtime(state_root)
            try:
                process_authority["signal_recorded_process"](
                    validated["supervisor"],
                    expected_uid=0,
                    signum=signal.SIGTERM,
                    relax_parent_for_recovery=True,
                    exit_timeout_seconds=720.0,
                )
            except process_authority["ProcessIdentityError"]:
                # A dead supervisor releases the lease. Do not mutate its
                # cgroup while some other holder still owns the global
                # transition; recovery below performs the cgroup kill only
                # after this process acquires that lease and revalidates the
                # root control authority.
                pass
            acquire_runtime_lease_until(
                state_root,
                timeout=60.0,
                recipient=publish_lease,
            )

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
    except BaseException as error:
        primary = error
        raise
    finally:
        settle_runtime_authorities(
            state=state,
            lease=lease,
            primary=primary,
        )


def ensure_orphaned_runtime_stopped(
    state_root: Path,
    caller_uid: int,
    caller_gid: int,
) -> dict[str, object]:
    script_directory = Path(__file__).resolve(strict=True).parent
    runtime_path = runtime_root_for(state_root)
    socket_path = socket_root_for(state_root)
    cgroup_path = cgroup_path_for(state_root)
    require_no_other_task_runtime(state_root)
    if not path_exists_nofollow(runtime_path):
        lease = RuntimeLease.pending(state_root)
        primary: BaseException | None = None
        try:
            lease.acquire()
            require(
                not path_exists_nofollow(runtime_path),
                "orphaned runtime appeared while acquiring the global lease; retry stop",
            )
            require_no_other_task_runtime(state_root, lease=lease)
            reduce_runtime_removal_root(state_root)
            require(
                not path_exists_nofollow(runtime_removal_root_for(state_root)),
                "orphaned runtime removal authority remained",
            )
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
        except BaseException as error:
            primary = error
            raise
        finally:
            settle_runtime_authorities(
                state=None,
                lease=lease,
                primary=primary,
            )
    stored_state, _, validated, _, process_authority = _validated_orphaned_authorities(
        state_root,
        caller_uid,
        caller_gid,
        script_directory,
    )
    lease: RuntimeLease | None = None
    primary = None

    def publish_lease(candidate: RuntimeLease) -> None:
        nonlocal lease
        lease = candidate

    try:
        lease = RuntimeLease.pending(state_root)
        try:
            lease.acquire()
        except SupervisorError as error:
            require(str(error) == "runtime lifecycle lease is busy", str(error))
            lease = None
            require_no_other_task_runtime(state_root)
            try:
                process_authority["signal_recorded_process"](
                    validated["supervisor"],
                    expected_uid=0,
                    signum=signal.SIGTERM,
                    relax_parent_for_recovery=True,
                    exit_timeout_seconds=720.0,
                )
            except process_authority["ProcessIdentityError"]:
                pass
            acquire_runtime_lease_until(
                state_root,
                timeout=60.0,
                recipient=publish_lease,
            )
        stored_state, _, _, _, _ = _validated_orphaned_authorities(
            state_root,
            caller_uid,
            caller_gid,
            script_directory,
        )
        supervisor = RuntimeSupervisor(state_root, caller_uid, caller_gid)
        supervisor.lease = lease
        supervisor.state = stored_state
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
    except BaseException as error:
        primary = error
        raise
    finally:
        settle_runtime_authorities(
            state=None,
            lease=lease,
            primary=primary,
        )


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
    require(
        re.fullmatch(r"[1-9][0-9]*", args.caller_uid) is not None,
        "caller UID is invalid",
    )
    require(re.fullmatch(r"[0-9]+", args.caller_gid) is not None, "caller GID is invalid")
    require_root_credentials()
    require(
        os.environ.get("SUDO_UID") == args.caller_uid and os.environ.get("SUDO_GID") == args.caller_gid,
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
