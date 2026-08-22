from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import re
import select
import signal
import stat
import sys
import time
from pathlib import Path
from typing import Any


class ProcessIdentityError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProcessIdentityError(message)


def _read_at(directory_fd: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 64 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


ARGUMENTS_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RECORDED_PROCESS_FIELDS = {
    "pid",
    "parentPid",
    "procInode",
    "startTimeTicks",
    "executable",
    "argumentsSha256",
    "mountNamespace",
    "cgroup",
}
MAX_RECORDED_IDENTITY_JSON_BYTES = 8 * 1024
MAX_EXECUTABLE_BYTES = 4 * 1024
MAX_PID = (1 << 31) - 1
MAX_UID = (1 << 32) - 1
MAX_KERNEL_IDENTITY = (1 << 64) - 1
MAX_EXIT_WAIT_SECONDS = 900.0


def _plain_int(
    value: Any,
    name: str,
    *,
    positive: bool = False,
    maximum: int | None = None,
) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{name} is invalid")
    _require(value > 0 if positive else value >= 0, f"{name} is invalid")
    if maximum is not None:
        _require(value <= maximum, f"{name} is invalid")
    return value


def _stat_identity(stat_bytes: bytes) -> tuple[int, int]:
    closing = stat_bytes.rfind(b")")
    _require(closing > 0, "process stat record is invalid")
    fields = stat_bytes[closing + 2 :].split()
    _require(
        len(fields) > 19 and fields[1].isdigit() and fields[19].isdigit(),
        "process stat identity is invalid",
    )
    return int(fields[1]), int(fields[19])


def _mount_namespace(directory_fd: int) -> dict[str, int]:
    observed = os.stat("ns/mnt", dir_fd=directory_fd)
    return {"device": observed.st_dev, "inode": observed.st_ino}


def _validate_mount_namespace(value: object) -> dict[str, int]:
    _require(isinstance(value, dict), "mount namespace identity is not an object")
    _require(set(value) == {"device", "inode"}, "mount namespace shape differs")
    device = _plain_int(
        value["device"],
        "mount namespace device",
        maximum=MAX_KERNEL_IDENTITY,
    )
    inode = _plain_int(
        value["inode"],
        "mount namespace inode",
        positive=True,
        maximum=MAX_KERNEL_IDENTITY,
    )
    return {"device": device, "inode": inode}


def _validate_cgroup(value: object) -> str:
    _require(isinstance(value, str), "process cgroup is invalid")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeError as error:
        raise ProcessIdentityError("process cgroup is invalid") from error
    _require(0 < len(encoded) <= 4096, "process cgroup is invalid")
    _require(value.startswith("/") and os.path.normpath(value) == value, "process cgroup is invalid")
    _require(all(0x20 <= byte <= 0x7E for byte in encoded), "process cgroup is invalid")
    return value


def _cgroup(directory_fd: int) -> str:
    records = _read_at(directory_fd, "cgroup").decode("ascii", "strict").splitlines()
    _require(len(records) == 1 and records[0].startswith("0::/"), "process cgroup v2 record differs")
    return _validate_cgroup(records[0][3:])


def verify_process(
    pid: int,
    executable: Path,
    expected_arguments: tuple[str, ...] | None,
    *,
    expected_uid: int,
    expected_arguments_sha256: str | None = None,
    expected_parent_pid: int | None = None,
    expected_mount_namespace: dict[str, int] | None = None,
    expected_cgroup: str | None = None,
) -> dict[str, object]:
    _require(pid > 0, "process id is invalid")
    _require(
        isinstance(expected_uid, int) and not isinstance(expected_uid, bool) and expected_uid >= 0,
        "expected process owner is invalid",
    )
    _require(
        (expected_arguments is None) != (expected_arguments_sha256 is None),
        "exactly one process argument authority is required",
    )
    if expected_arguments_sha256 is not None:
        _require(
            ARGUMENTS_SHA256_RE.fullmatch(expected_arguments_sha256) is not None,
            "expected process argument digest is invalid",
        )
    if expected_parent_pid is not None:
        _require(
            isinstance(expected_parent_pid, int)
            and not isinstance(expected_parent_pid, bool)
            and expected_parent_pid > 0,
            "expected parent process id is invalid",
        )
    if expected_mount_namespace is not None:
        expected_mount_namespace = _validate_mount_namespace(expected_mount_namespace)
    if expected_cgroup is not None:
        expected_cgroup = _validate_cgroup(expected_cgroup)
    expected_executable = executable.resolve(strict=True)
    process_directory = Path("/proc") / str(pid)
    directory_fd = os.open(process_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory_stat = os.fstat(directory_fd)
        _require(stat.S_ISDIR(directory_stat.st_mode), "process directory is invalid")
        first_stat = _read_at(directory_fd, "stat")
        first_parent_pid, first_start_time = _stat_identity(first_stat)
        first_namespace = _mount_namespace(directory_fd)
        first_cgroup = _cgroup(directory_fd)
        actual_executable = Path(os.readlink("exe", dir_fd=directory_fd)).resolve(strict=True)
        _require(actual_executable == expected_executable, "process executable differs")
        executable_identity = actual_executable.stat()
        _require(
            stat.S_ISREG(executable_identity.st_mode)
            and executable_identity.st_uid == 0
            and executable_identity.st_gid == 0
            and stat.S_IMODE(executable_identity.st_mode) & 0o022 == 0,
            "process executable authority differs",
        )
        raw_arguments = _read_at(directory_fd, "cmdline")
        values = raw_arguments.rstrip(b"\0").split(b"\0")
        _require(values and all(values), "process argument vector is invalid")
        arguments = tuple(value.decode("utf-8", "strict") for value in values)
        _require(
            Path(arguments[0]).resolve(strict=True) == expected_executable,
            "process argv[0] differs",
        )
        if expected_arguments is not None:
            _require(arguments[1:] == expected_arguments, "process arguments differ")
        arguments_sha256 = hashlib.sha256(raw_arguments).hexdigest()
        if expected_arguments_sha256 is not None:
            _require(
                arguments_sha256 == expected_arguments_sha256,
                "process argument digest differs",
            )
        status = _read_at(directory_fd, "status").decode("ascii", "strict")
        uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), "")
        uid_fields = uid_line.split()[1:]
        _require(
            len(uid_fields) == 4 and all(value.isdigit() for value in uid_fields),
            "process owner record is invalid",
        )
        _require(
            all(int(value) == expected_uid for value in uid_fields),
            "process owner differs",
        )
        second_namespace = _mount_namespace(directory_fd)
        second_cgroup = _cgroup(directory_fd)
        second_stat = _read_at(directory_fd, "stat")
        second_parent_pid, second_start_time = _stat_identity(second_stat)
        _require(
            (first_parent_pid, first_start_time)
            == (second_parent_pid, second_start_time),
            "process identity changed during proof",
        )
        _require(
            first_namespace == second_namespace,
            "process mount namespace changed during proof",
        )
        _require(first_cgroup == second_cgroup, "process cgroup changed during proof")
        if expected_parent_pid is not None:
            _require(first_parent_pid == expected_parent_pid, "process parent differs")
        if expected_mount_namespace is not None:
            _require(first_namespace == expected_mount_namespace, "process mount namespace differs")
        if expected_cgroup is not None:
            _require(first_cgroup == expected_cgroup, "process cgroup differs")
        return {
            "pid": pid,
            "parentPid": first_parent_pid,
            "procInode": directory_stat.st_ino,
            "startTimeTicks": first_start_time,
            "executable": str(expected_executable),
            "argumentsSha256": arguments_sha256,
            "mountNamespace": first_namespace,
            "cgroup": first_cgroup,
        }
    finally:
        os.close(directory_fd)


def _validate_executable(value: object) -> str:
    _require(isinstance(value, str), "process executable is invalid")
    try:
        encoded = value.encode("ascii", "strict")
    except UnicodeError as error:
        raise ProcessIdentityError("process executable is invalid") from error
    _require(0 < len(encoded) <= MAX_EXECUTABLE_BYTES, "process executable is invalid")
    _require(all(0x20 <= byte <= 0x7E for byte in encoded), "process executable is invalid")
    executable = Path(value)
    _require(executable.is_absolute(), "process executable is not absolute")
    _require(os.path.normpath(value) == value, "process executable is not normalized")
    _require(str(executable.resolve(strict=True)) == value, "process executable is not canonical")
    return value


def validate_recorded_identity(value: object) -> dict[str, object]:
    """Return a sanitized copy of one closed process identity receipt."""

    _require(isinstance(value, dict), "recorded process identity is not an object")
    _require(set(value) == RECORDED_PROCESS_FIELDS, "recorded process identity shape differs")
    arguments_sha256 = value["argumentsSha256"]
    _require(
        isinstance(arguments_sha256, str)
        and ARGUMENTS_SHA256_RE.fullmatch(arguments_sha256) is not None,
        "recorded process argument digest is invalid",
    )
    return {
        "pid": _plain_int(value["pid"], "recorded process id", positive=True, maximum=MAX_PID),
        "parentPid": _plain_int(
            value["parentPid"],
            "recorded parent process id",
            positive=True,
            maximum=MAX_PID,
        ),
        "procInode": _plain_int(
            value["procInode"],
            "recorded process directory inode",
            positive=True,
            maximum=MAX_KERNEL_IDENTITY,
        ),
        "startTimeTicks": _plain_int(
            value["startTimeTicks"],
            "recorded process start time",
            positive=True,
            maximum=MAX_KERNEL_IDENTITY,
        ),
        "executable": _validate_executable(value["executable"]),
        "argumentsSha256": arguments_sha256,
        "mountNamespace": _validate_mount_namespace(value["mountNamespace"]),
        "cgroup": _validate_cgroup(value["cgroup"]),
    }


def _reject_duplicate_object_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        _require(key not in value, "recorded process identity contains a duplicate field")
        value[key] = item
    return value


def _reject_json_constant(_: str) -> object:
    raise ProcessIdentityError("recorded process identity JSON constant is invalid")


def parse_recorded_identity_json(raw: object) -> dict[str, object]:
    _require(isinstance(raw, str), "recorded process identity JSON is invalid")
    try:
        encoded = raw.encode("utf-8", "strict")
        _require(
            0 < len(encoded) <= MAX_RECORDED_IDENTITY_JSON_BYTES,
            "recorded process identity JSON size is invalid",
        )
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeError) as error:
        raise ProcessIdentityError("recorded process identity JSON is invalid") from error
    return validate_recorded_identity(value)


def _validate_expected_uid(expected_uid: object) -> int:
    return _plain_int(expected_uid, "expected process owner", maximum=MAX_UID)


def _validate_recovery_parent_relaxation(value: object) -> bool:
    _require(isinstance(value, bool), "recovery parent relaxation is invalid")
    return value


def _pidfd_has_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLERR | select.POLLHUP)
    return bool(poller.poll(0))


def _validate_exit_timeout(timeout_seconds: object) -> float:
    _require(
        isinstance(timeout_seconds, (int, float))
        and not isinstance(timeout_seconds, bool)
        and math.isfinite(timeout_seconds)
        and 0 < timeout_seconds <= MAX_EXIT_WAIT_SECONDS,
        "process exit wait is invalid",
    )
    return float(timeout_seconds)


def wait_for_pidfd_exit(pidfd: int, timeout_seconds: float) -> None:
    """Wait for pidfd readability until a validated monotonic deadline."""

    _require(isinstance(pidfd, int) and not isinstance(pidfd, bool) and pidfd >= 0, "pidfd is invalid")
    timeout = _validate_exit_timeout(timeout_seconds)
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLERR | select.POLLHUP)
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProcessIdentityError("recorded process did not exit before the bounded deadline")
        try:
            events = poller.poll(max(1, math.ceil(remaining * 1000)))
        except InterruptedError:
            continue
        if events:
            for observed_fd, event_mask in events:
                _require(observed_fd == pidfd, "pidfd exit wait returned a foreign descriptor")
                _require(event_mask & select.POLLNVAL == 0, "pidfd became invalid during exit wait")
                if event_mask & (select.POLLIN | select.POLLHUP):
                    return
            raise ProcessIdentityError("pidfd exit wait failed")


def _prove_recorded_process(
    pidfd: int,
    recorded_identity: dict[str, object],
    *,
    expected_uid: int,
    relax_parent_for_recovery: bool,
) -> dict[str, object]:
    expected_parent_pid = None if relax_parent_for_recovery else recorded_identity["parentPid"]
    try:
        observed = verify_process(
            recorded_identity["pid"],
            Path(recorded_identity["executable"]),
            None,
            expected_uid=expected_uid,
            expected_arguments_sha256=recorded_identity["argumentsSha256"],
            expected_parent_pid=expected_parent_pid,
            expected_mount_namespace=recorded_identity["mountNamespace"],
            expected_cgroup=recorded_identity["cgroup"],
        )
    except OSError as error:
        if isinstance(error, (FileNotFoundError, ProcessLookupError)) or error.errno in (
            errno.ENOENT,
            errno.ESRCH,
        ):
            raise ProcessIdentityError("recorded process exited during identity proof") from error
        raise
    for field in RECORDED_PROCESS_FIELDS:
        if field == "parentPid" and relax_parent_for_recovery:
            continue
        _require(observed[field] == recorded_identity[field], f"recorded process {field} differs")
    _require(not _pidfd_has_exited(pidfd), "recorded process exited during identity proof")
    return observed


def _open_recorded_pidfd(pid: int) -> int:
    try:
        return os.pidfd_open(pid, 0)
    except OSError as error:
        if isinstance(error, ProcessLookupError) or error.errno == errno.ESRCH:
            raise ProcessIdentityError("recorded process exited before pidfd custody") from error
        raise


def verify_recorded_process(
    recorded_identity: object,
    *,
    expected_uid: int,
    relax_parent_for_recovery: bool = False,
) -> dict[str, object]:
    """Prove a full recorded identity under one pidfd lifetime."""

    recorded = validate_recorded_identity(recorded_identity)
    owner = _validate_expected_uid(expected_uid)
    relaxation = _validate_recovery_parent_relaxation(relax_parent_for_recovery)
    _require(hasattr(os, "pidfd_open"), "pidfd process signalling is unavailable")
    pidfd = _open_recorded_pidfd(recorded["pid"])
    try:
        return _prove_recorded_process(
            pidfd,
            recorded,
            expected_uid=owner,
            relax_parent_for_recovery=relaxation,
        )
    finally:
        os.close(pidfd)


def signal_recorded_process(
    recorded_identity: object,
    *,
    expected_uid: int,
    signum: int = signal.SIGTERM,
    relax_parent_for_recovery: bool = False,
    exit_timeout_seconds: float = 10.0,
) -> dict[str, object]:
    """Prove, signal, and observe exit for exactly one recorded process."""

    recorded = validate_recorded_identity(recorded_identity)
    owner = _validate_expected_uid(expected_uid)
    relaxation = _validate_recovery_parent_relaxation(relax_parent_for_recovery)
    timeout = _validate_exit_timeout(exit_timeout_seconds)
    _require(
        isinstance(signum, int)
        and not isinstance(signum, bool)
        and signum in (signal.SIGTERM, signal.SIGKILL),
        "recorded process signal is invalid",
    )
    _require(
        hasattr(signal, "pidfd_send_signal"),
        "pidfd signal delivery is unavailable",
    )
    _require(hasattr(os, "pidfd_open"), "pidfd process signalling is unavailable")
    pidfd = _open_recorded_pidfd(recorded["pid"])
    try:
        observed = _prove_recorded_process(
            pidfd,
            recorded,
            expected_uid=owner,
            relax_parent_for_recovery=relaxation,
        )
        try:
            signal.pidfd_send_signal(pidfd, signum)
        except OSError as error:
            if isinstance(error, ProcessLookupError) or error.errno == errno.ESRCH:
                raise ProcessIdentityError("recorded process exited before signal delivery") from error
            raise
        wait_for_pidfd_exit(pidfd, timeout)
        return observed
    finally:
        os.close(pidfd)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("verify-recorded", "signal-recorded"):
        command = subparsers.add_parser(operation)
        command.add_argument("expected_uid")
        command.add_argument("recorded_identity_json")
        command.add_argument("--relax-parent-for-recovery", action="store_true")
        if operation == "signal-recorded":
            command.add_argument("--signal", choices=("TERM", "KILL"), default="TERM")
            command.add_argument("--timeout-ms", default="10000")
    args = parser.parse_args()
    _require(
        re.fullmatch(r"0|[1-9][0-9]{0,19}", args.expected_uid) is not None,
        "expected owner is invalid",
    )
    expected_uid = _plain_int(
        int(args.expected_uid),
        "expected process owner",
        maximum=MAX_UID,
    )
    recorded = parse_recorded_identity_json(args.recorded_identity_json)
    if args.operation == "signal-recorded":
        _require(
            re.fullmatch(r"[1-9][0-9]{0,5}", args.timeout_ms) is not None,
            "process exit timeout is invalid",
        )
        timeout_ms = int(args.timeout_ms)
        _require(timeout_ms <= int(MAX_EXIT_WAIT_SECONDS * 1000), "process exit timeout is invalid")
        result = signal_recorded_process(
            recorded,
            expected_uid=expected_uid,
            signum={"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}[args.signal],
            relax_parent_for_recovery=args.relax_parent_for_recovery,
            exit_timeout_seconds=timeout_ms / 1000,
        )
    else:
        result = verify_recorded_process(
            recorded,
            expected_uid=expected_uid,
            relax_parent_for_recovery=args.relax_parent_for_recovery,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ProcessIdentityError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(66) from None
