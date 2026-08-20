from __future__ import annotations

import argparse
import json
import os
import re
import stat
from pathlib import Path


RUNTIME_ROOT_RE = re.compile(r"^/tmp/ambit-c16b-docker-[0-9a-f]{12}$")
CHILD_DIRECTORIES = ("containerd-state", "docker-exec")


class RuntimeRootError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeRootError(message)


def _open_root(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _identity(fd: int) -> dict[str, int]:
    observed = os.fstat(fd)
    _require(stat.S_ISDIR(observed.st_mode), "runtime root is not a directory")
    _require(observed.st_uid == os.geteuid(), "runtime root owner differs")
    _require(stat.S_IMODE(observed.st_mode) == 0o700, "runtime root mode differs")
    return {
        "device": observed.st_dev,
        "inode": observed.st_ino,
        "uid": observed.st_uid,
        "mode": stat.S_IMODE(observed.st_mode),
    }


def _verify_children(fd: int) -> None:
    observed_names = set(os.listdir(fd))
    allowed = set(CHILD_DIRECTORIES) | {
        "containerd-temp",
        "containerd.sock",
        "containerd.sock.ttrpc",
        "docker.pid",
        "docker.sock",
    }
    _require(observed_names <= allowed, "runtime root contains an unknown entry")
    for name in CHILD_DIRECTORIES:
        observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
        _require(stat.S_ISDIR(observed.st_mode), f"runtime child is not a directory: {name}")
        _require(observed.st_uid == os.geteuid(), f"runtime child owner differs: {name}")
        _require(stat.S_IMODE(observed.st_mode) == 0o700, f"runtime child mode differs: {name}")
    expected_optional_types = {
        "containerd-temp": stat.S_ISDIR,
        "containerd.sock": stat.S_ISSOCK,
        "containerd.sock.ttrpc": stat.S_ISSOCK,
        "docker.pid": stat.S_ISREG,
        "docker.sock": stat.S_ISSOCK,
    }
    for name, expected_type in expected_optional_types.items():
        if name not in observed_names:
            continue
        observed = os.stat(name, dir_fd=fd, follow_symlinks=False)
        _require(expected_type(observed.st_mode), f"runtime entry type differs: {name}")


def create_runtime_root(path: Path) -> dict[str, int]:
    _require(RUNTIME_ROOT_RE.fullmatch(str(path)) is not None, "runtime root path is invalid")
    os.mkdir(path, mode=0o700)
    fd = _open_root(path)
    remove_root = False
    try:
        identity = _identity(fd)
        for name in CHILD_DIRECTORIES:
            os.mkdir(name, mode=0o700, dir_fd=fd)
        _verify_children(fd)
        return identity
    except BaseException:
        for name in reversed(CHILD_DIRECTORIES):
            try:
                os.rmdir(name, dir_fd=fd)
            except FileNotFoundError:
                pass
        remove_root = True
        raise
    finally:
        os.close(fd)
        if remove_root:
            os.rmdir(path)


def verify_runtime_root(path: Path, expected: dict[str, int]) -> dict[str, int]:
    _require(RUNTIME_ROOT_RE.fullmatch(str(path)) is not None, "runtime root path is invalid")
    _require(set(expected) == {"device", "inode", "mode", "uid"}, "runtime identity shape differs")
    fd = _open_root(path)
    try:
        observed = _identity(fd)
        _require(observed == expected, "runtime root identity changed")
        _verify_children(fd)
        return observed
    finally:
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("create", "verify"))
    parser.add_argument("runtime_root", type=Path)
    parser.add_argument("--expected")
    args = parser.parse_args()
    if args.operation == "create":
        if args.expected is not None:
            raise RuntimeRootError("create does not accept an expected identity")
        result = create_runtime_root(args.runtime_root)
    else:
        if args.expected is None:
            raise RuntimeRootError("verify requires an expected identity")
        value = json.loads(args.expected)
        _require(isinstance(value, dict), "expected runtime identity is not an object")
        result = verify_runtime_root(args.runtime_root, value)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
