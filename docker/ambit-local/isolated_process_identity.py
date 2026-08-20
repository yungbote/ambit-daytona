from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path


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


def _start_time(stat_bytes: bytes) -> int:
    closing = stat_bytes.rfind(b")")
    _require(closing > 0, "process stat record is invalid")
    fields = stat_bytes[closing + 2 :].split()
    _require(len(fields) > 19 and fields[19].isdigit(), "process start time is invalid")
    return int(fields[19])


def verify_process(
    pid: int,
    executable: Path,
    expected_arguments: tuple[str, ...],
    *,
    expected_uid: int,
) -> dict[str, object]:
    _require(pid > 0, "process id is invalid")
    expected_executable = executable.resolve(strict=True)
    process_directory = Path("/proc") / str(pid)
    directory_fd = os.open(process_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        directory_stat = os.fstat(directory_fd)
        _require(stat.S_ISDIR(directory_stat.st_mode), "process directory is invalid")
        first_stat = _read_at(directory_fd, "stat")
        actual_executable = Path(os.readlink("exe", dir_fd=directory_fd)).resolve(strict=True)
        _require(actual_executable == expected_executable, "process executable differs")
        _require(actual_executable.stat().st_uid == 0, "process executable is not root-owned")
        raw_arguments = _read_at(directory_fd, "cmdline")
        values = raw_arguments.rstrip(b"\0").split(b"\0")
        _require(values and all(values), "process argument vector is invalid")
        arguments = tuple(value.decode("utf-8", "strict") for value in values)
        _require(Path(arguments[0]).name == expected_executable.name, "process argv[0] differs")
        _require(arguments[1:] == expected_arguments, "process arguments differ")
        status = _read_at(directory_fd, "status").decode("ascii", "strict")
        uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), "")
        real_uid = int(uid_line.split()[1]) if uid_line else -1
        _require(real_uid == expected_uid, "process owner differs")
        second_stat = _read_at(directory_fd, "stat")
        start_time = _start_time(first_stat)
        _require(start_time == _start_time(second_stat), "process identity changed during proof")
        return {
            "pid": pid,
            "procInode": directory_stat.st_ino,
            "startTimeTicks": start_time,
            "executable": str(expected_executable),
            "argumentsSha256": hashlib.sha256(raw_arguments).hexdigest(),
        }
    finally:
        os.close(directory_fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pid")
    parser.add_argument("executable", type=Path)
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    _require(re.fullmatch(r"[1-9][0-9]*", args.pid) is not None, "process id is invalid")
    executable = args.executable.resolve(strict=True)
    config = args.config.resolve(strict=True)
    if executable.name == "containerd":
        expected_arguments = ("--config", str(config), "--log-level", "info")
    elif executable.name == "dockerd":
        expected_arguments = ("--config-file", str(config))
    else:
        raise ProcessIdentityError("unsupported isolated process executable")
    result = verify_process(int(args.pid), executable, expected_arguments, expected_uid=0)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
