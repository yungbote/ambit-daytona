from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import sys
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


def _validate_mount_namespace(value: dict[str, int]) -> None:
    _require(set(value) == {"device", "inode"}, "mount namespace shape differs")
    _require(
        all(isinstance(item, int) and not isinstance(item, bool) and item >= 0 for item in value.values()),
        "mount namespace identity is invalid",
    )


def verify_process(
    pid: int,
    executable: Path,
    expected_arguments: tuple[str, ...] | None,
    *,
    expected_uid: int,
    expected_arguments_sha256: str | None = None,
    expected_parent_pid: int | None = None,
    expected_mount_namespace: dict[str, int] | None = None,
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
        _validate_mount_namespace(expected_mount_namespace)
    expected_executable = executable.resolve(strict=True)
    process_directory = Path("/proc") / str(pid)
    directory_fd = os.open(process_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory_stat = os.fstat(directory_fd)
        _require(stat.S_ISDIR(directory_stat.st_mode), "process directory is invalid")
        first_stat = _read_at(directory_fd, "stat")
        first_parent_pid, first_start_time = _stat_identity(first_stat)
        first_namespace = _mount_namespace(directory_fd)
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
        real_uid = int(uid_line.split()[1]) if uid_line else -1
        _require(real_uid == expected_uid, "process owner differs")
        second_namespace = _mount_namespace(directory_fd)
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
        if expected_parent_pid is not None:
            _require(first_parent_pid == expected_parent_pid, "process parent differs")
        if expected_mount_namespace is not None:
            _require(first_namespace == expected_mount_namespace, "process mount namespace differs")
        return {
            "pid": pid,
            "parentPid": first_parent_pid,
            "procInode": directory_stat.st_ino,
            "startTimeTicks": first_start_time,
            "executable": str(expected_executable),
            "argumentsSha256": arguments_sha256,
            "mountNamespace": first_namespace,
        }
    finally:
        os.close(directory_fd)


def _plain_int(value: Any, name: str, *, positive: bool = False) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{name} is invalid")
    _require(value > 0 if positive else value >= 0, f"{name} is invalid")
    return value


def signal_exact_process(
    pid: int,
    executable: Path,
    *,
    expected_uid: int,
    expected_arguments_sha256: str,
    expected_parent_pid: int | None = None,
    expected_mount_namespace: dict[str, int] | None = None,
) -> dict[str, object]:
    """Signal the pidfd opened before proof, never a later process reusing PID."""

    _require(isinstance(pid, int) and not isinstance(pid, bool) and pid > 0, "process id is invalid")
    _require(hasattr(os, "pidfd_open"), "pidfd process signalling is unavailable")
    _require(
        hasattr(signal, "pidfd_send_signal"),
        "pidfd signal delivery is unavailable",
    )
    pidfd = os.pidfd_open(pid, 0)
    try:
        identity = verify_process(
            pid,
            executable,
            None,
            expected_uid=expected_uid,
            expected_arguments_sha256=expected_arguments_sha256,
            expected_parent_pid=expected_parent_pid,
            expected_mount_namespace=expected_mount_namespace,
        )
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        return identity
    finally:
        os.close(pidfd)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("verify-digest", "signal-exact"):
        parser = argparse.ArgumentParser()
        parser.add_argument("operation", choices=("verify-digest", "signal-exact"))
        parser.add_argument("pid")
        parser.add_argument("executable", type=Path)
        parser.add_argument("expected_uid")
        parser.add_argument("arguments_sha256")
        parser.add_argument("--parent-pid")
        parser.add_argument("--mount-namespace")
        args = parser.parse_args()
        _require(re.fullmatch(r"[1-9][0-9]*", args.pid) is not None, "process id is invalid")
        _require(re.fullmatch(r"[0-9]+", args.expected_uid) is not None, "expected owner is invalid")
        expected_parent_pid = None
        if args.parent_pid is not None:
            _require(
                re.fullmatch(r"[1-9][0-9]*", args.parent_pid) is not None,
                "expected parent process id is invalid",
            )
            expected_parent_pid = int(args.parent_pid)
        expected_mount_namespace = None
        if args.mount_namespace is not None:
            value = json.loads(args.mount_namespace)
            _require(isinstance(value, dict), "mount namespace identity is not an object")
            expected_mount_namespace = {
                "device": _plain_int(value.get("device"), "mount namespace device"),
                "inode": _plain_int(value.get("inode"), "mount namespace inode", positive=True),
            }
        common = {
            "expected_uid": int(args.expected_uid),
            "expected_arguments_sha256": args.arguments_sha256,
            "expected_parent_pid": expected_parent_pid,
            "expected_mount_namespace": expected_mount_namespace,
        }
        if args.operation == "signal-exact":
            result = signal_exact_process(
                int(args.pid),
                args.executable,
                **common,
            )
        else:
            result = verify_process(
                int(args.pid),
                args.executable,
                None,
                **common,
            )
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("pid")
        parser.add_argument("executable")
        parser.add_argument("config")
        args = parser.parse_args()
        pid_value = args.pid
        executable_value = args.executable
        config_value = args.config
        _require(re.fullmatch(r"[1-9][0-9]*", pid_value) is not None, "process id is invalid")
        executable = Path(executable_value).resolve(strict=True)
        config = Path(config_value).resolve(strict=True)
        if executable.name == "containerd":
            expected_arguments = ("--config", str(config), "--log-level", "info")
        elif executable.name == "dockerd":
            expected_arguments = ("--config-file", str(config))
        else:
            raise ProcessIdentityError("unsupported isolated process executable")
        result = verify_process(int(pid_value), executable, expected_arguments, expected_uid=0)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (ProcessIdentityError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(66) from None
