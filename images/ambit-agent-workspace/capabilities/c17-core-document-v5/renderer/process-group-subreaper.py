#!/opt/ambit/runtime-pack/core-document-v5/bin/ambit-structural-python
"""Run one bounded child invocation under an exact descendant reaper."""

from __future__ import annotations

import ctypes
import os
import signal
import sys
import time
from pathlib import Path


PR_SET_PDEATHSIG = 1
PR_SET_CHILD_SUBREAPER = 36
TERMINATION_GRACE_SECONDS = 0.25
LIBC = ctypes.CDLL(None, use_errno=True)


def prctl(option: int, value: int) -> None:
    if LIBC.prctl(option, value, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def process_snapshot() -> dict[int, tuple[int, int]]:
    processes: dict[int, tuple[int, int]] = {}
    for entry in os.scandir("/proc"):
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            text = Path(entry.path, "stat").read_text(encoding="ascii")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        close = text.rfind(")")
        if close < 0:
            raise RuntimeError("process stat identity is malformed")
        fields = text[close + 2 :].split()
        if len(fields) < 3:
            raise RuntimeError("process stat identity is truncated")
        processes[pid] = (int(fields[1]), int(fields[2]))
    return processes


def related_processes(process_group: int) -> tuple[int, ...]:
    root = os.getpid()
    processes = process_snapshot()
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, (parent, _group) in processes.items():
            if pid == root or pid in descendants:
                continue
            if parent == root or parent in descendants:
                descendants.add(pid)
                changed = True
    group_members = {
        pid for pid, (_parent, group) in processes.items()
        if pid != root and group == process_group
    }
    return tuple(sorted(descendants | group_members))


def reap_children(primary_pid: int, primary_status: int | None) -> int | None:
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return primary_status
        if pid == 0:
            return primary_status
        if pid == primary_pid:
            primary_status = status


def exit_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    raise RuntimeError("primary process has no terminal wait status")


def main() -> int:
    if len(sys.argv) < 2 or not os.path.isabs(sys.argv[1]):
        raise RuntimeError("expected one absolute executable and its arguments")
    executable = sys.argv[1]
    arguments = [executable, *sys.argv[2:]]
    prctl(PR_SET_CHILD_SUBREAPER, 1)
    prctl(PR_SET_PDEATHSIG, signal.SIGKILL)

    terminating_at: float | None = None

    def begin_termination(_signum: int, _frame: object) -> None:
        nonlocal terminating_at
        if terminating_at is None:
            terminating_at = time.monotonic()

    signal.signal(signal.SIGTERM, begin_termination)
    signal.signal(signal.SIGINT, begin_termination)

    subreaper_pid = os.getpid()
    primary_pid = os.fork()
    if primary_pid == 0:
        try:
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
            if os.getppid() != subreaper_pid:
                os.kill(os.getpid(), signal.SIGTERM)
            os.execve(executable, arguments, dict(os.environ))
        except BaseException as error:
            os.write(2, f"Bounded child exec failed: {error}\n".encode("utf-8", "replace"))
            os._exit(127)

    process_group = os.getpgrp()
    if process_group != os.getpid():
        raise RuntimeError("subreaper is not the process-group leader")
    primary_status: int | None = None
    forced = False
    while True:
        primary_status = reap_children(primary_pid, primary_status)
        members = related_processes(process_group)
        if primary_status is not None and not members:
            return exit_code(primary_status)
        if (
            terminating_at is not None
            and not forced
            and time.monotonic() - terminating_at >= TERMINATION_GRACE_SECONDS
        ):
            forced = True
        if forced:
            for pid in members:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        time.sleep(0.01)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Bounded child subreaper failed: {error}", file=sys.stderr, flush=True)
        raise SystemExit(70)
