from __future__ import annotations

import math
import os
import resource
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


MAXIMUM_LOG_BYTES = 16 * 1024 * 1024
MAXIMUM_CHILD_FILE_BYTES = 512 * 1024 * 1024
PROCESS_POLL_SECONDS = 0.05


@dataclass(frozen=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessFailure(RuntimeError):
    def __init__(self, result: ProcessResult) -> None:
        super().__init__(f"bounded child exited {result.returncode}: {result.argv[0]}")
        self.result = result


class ProcessDeadlineExceeded(TimeoutError):
    """A bounded child failed to quiesce before the exact request deadline."""


def _limits(remaining: float) -> None:
    cpu_seconds = max(1, math.ceil(remaining))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAXIMUM_CHILD_FILE_BYTES, MAXIMUM_CHILD_FILE_BYTES),
    )
    # Sandboxed multi-process browsers legitimately fan out descriptors across
    # their broker, renderers, trace, fonts, and local service. Keep a finite
    # per-process ceiling without imposing a single-process-sized 256 limit.
    resource.setrlimit(resource.RLIMIT_NOFILE, (4_096, 4_096))


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            process.wait(timeout=0)
            return
        time.sleep(PROCESS_POLL_SECONDS)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            process.wait(timeout=0)
            return
        time.sleep(PROCESS_POLL_SECONDS)
    raise ProcessDeadlineExceeded("bounded child process group did not quiesce")


def run_bounded(
    argv: list[str],
    *,
    deadline: float,
    cwd: Path,
    environment: dict[str, str],
    check: bool = True,
) -> ProcessResult:
    if not argv or any(not isinstance(value, str) or "\x00" in value for value in argv):
        raise ValueError("bounded process argv is invalid")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProcessDeadlineExceeded
    with tempfile.TemporaryFile(dir=cwd) as stdout_file, tempfile.TemporaryFile(
        dir=cwd
    ) as stderr_file:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            close_fds=True,
            start_new_session=True,
            preexec_fn=lambda: _limits(remaining),
        )
        log_limit_exceeded = False
        try:
            while process.poll() is None:
                if (
                    os.fstat(stdout_file.fileno()).st_size > MAXIMUM_LOG_BYTES
                    or os.fstat(stderr_file.fileno()).st_size > MAXIMUM_LOG_BYTES
                ):
                    log_limit_exceeded = True
                    _terminate(process)
                    break
                if time.monotonic() >= deadline:
                    _terminate(process)
                    raise ProcessDeadlineExceeded
                time.sleep(
                    min(PROCESS_POLL_SECONDS, max(0.0, deadline - time.monotonic()))
                )
        except BaseException:
            _terminate(process)
            raise
        stdout_file.seek(0)
        stderr_file.seek(0)
        result = ProcessResult(
            argv=tuple(argv),
            returncode=process.returncode,
            stdout=stdout_file.read(MAXIMUM_LOG_BYTES + 1),
            stderr=stderr_file.read(MAXIMUM_LOG_BYTES + 1),
        )
    if (
        log_limit_exceeded
        or len(result.stdout) > MAXIMUM_LOG_BYTES
        or len(result.stderr) > MAXIMUM_LOG_BYTES
    ):
        raise ProcessFailure(
            ProcessResult(result.argv, 153, result.stdout[:MAXIMUM_LOG_BYTES], result.stderr[:MAXIMUM_LOG_BYTES])
        )
    if check and result.returncode != 0:
        raise ProcessFailure(result)
    return result
