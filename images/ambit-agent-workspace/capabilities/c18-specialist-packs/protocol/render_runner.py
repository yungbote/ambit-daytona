from __future__ import annotations

import ctypes
import errno
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import NamedTuple
from typing import Any

from framed_render import (
    FRAME_SCHEMA,
    INTERFACE_REF,
    MAXIMUM_RESPONSE_BYTES,
    MAXIMUM_RESPONSE_FILES,
    RAW_CHUNK_BYTES,
    CanonicalFrameWriter,
    FramedRenderCancelled,
    FramedRenderError,
    FramedRequestCollector,
    admit_cancel_frame,
    decode_line,
    exact_nonce,
    read_line,
    response_file_chunk,
    response_file_start,
)
from public_preview import (
    PublicPreviewError,
    create_preview,
    encode_preview,
    parse_preview_bytes,
)
from render_command import (
    EVIDENCE_MEDIA_TYPE,
    MAXIMUM_COMMAND_BYTES,
    RenderCommandError,
    canonical_bytes,
    create_check_evidence,
    create_result,
    instant_now,
    pack_check_names,
    parse_check_evidence_bytes,
    parse_request_bytes,
    parse_result_bytes,
    sha256_bytes,
)
from render_policy import require_request_policy


READ_CHUNK_BYTES = 1024 * 1024
MAXIMUM_EVIDENCE_ARTIFACT_BYTES = 512 * 1024 * 1024
RESULT_MEDIA_TYPE = "application/vnd.ambit.c18-specialist-render-command-result+json"
TASK_SCRATCH_ROOT = Path("/tmp/ambit-task")
PRIVATE_ROOT_CLEANUP = "completed"
TERMINAL_SELECTION = "helper-selected"
FACT_KEY_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")
FACT_KEY_UNSAFE = re.compile(r"[^a-z0-9]+")


def _prepare_task_scratch_root() -> None:
    try:
        TASK_SCRATCH_ROOT.mkdir(mode=0o700)
    except FileExistsError:
        pass
    descriptor = os.open(
        TASK_SCRATCH_ROOT,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.getuid()
            or metadata.st_gid != os.getgid()
        ):
            raise RenderCommandError("provider task scratch authority is invalid")
    finally:
        os.close(descriptor)


class CommandCancelled(RuntimeError):
    """The host cancelled a valid in-flight render request."""


class CommandDeadlineExceeded(RuntimeError):
    """The exact request deadline elapsed before settlement."""


class ResultPublicationFailure(RuntimeError):
    """A terminal result could not be published atomically for host reconciliation."""


class AdapterFailure(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        check: str | None = None,
        observations: dict[str, Any] | None = None,
        outcome: str = "failed",
    ) -> None:
        super().__init__(message)
        self.code = code
        self.public_message = message
        self.check = check
        self.observations = observations or {}
        self.outcome = outcome


class SemanticJobRoots(NamedTuple):
    job: Path
    inputs: Path
    outputs: Path
    ancestor_identities: tuple[tuple[Path, int, int], ...]
    job_fd: int
    inputs_fd: int
    outputs_fd: int


class FramedOutputFile(NamedTuple):
    ordinal: int
    role: str
    path: str
    media_type: str
    byte_length: int
    digest: str
    descriptor: int
    identity: tuple[int, int, int, int, int, int]


class FramedControlAdmission:
    def __init__(self, stream: Any, nonce: str) -> None:
        self._stream = stream
        self._nonce = exact_nonce(nonce)
        self._lock = threading.Lock()
        self._closed = False
        self._error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._watch,
            name="ambit-specialist-framed-control",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def _watch(self) -> None:
        try:
            frame = read_line(self._stream)
            value = decode_line(frame)
            admit_cancel_frame(value, self._nonce)
            failure: BaseException = CommandCancelled()
        except BaseException as error:
            failure = error
        if not self._offer(failure):
            return
        os.kill(os.getpid(), signal.SIGUSR1)

    def _offer(self, failure: BaseException) -> bool:
        with self._lock:
            if self._closed:
                return False
            self._error = failure
            return True

    def offer_line(self, line: bytes) -> bool:
        try:
            value = decode_line(line)
            admit_cancel_frame(value, self._nonce)
            failure: BaseException = CommandCancelled()
        except BaseException as error:
            failure = error
        return self._offer(failure)

    def raise_pending(self) -> None:
        with self._lock:
            failure = self._error
        if failure is not None:
            raise failure

    def select_terminal(self) -> None:
        with self._lock:
            if self._error is not None:
                raise self._error
            self._closed = True

    def abandon(self) -> None:
        with self._lock:
            self._closed = True


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


SYS_OPENAT2 = 437
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
OPENAT2_RESOLVE = (
    RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH
)
LIBC = ctypes.CDLL(None, use_errno=True)
def _directory_identity(path: Path) -> tuple[int, int]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RenderCommandError("semantic job directory is not real")
    return (metadata.st_dev, metadata.st_ino)


def _reprove_semantic_roots(roots: SemanticJobRoots) -> None:
    for path, expected_device, expected_inode in roots.ancestor_identities:
        if _directory_identity(path) != (expected_device, expected_inode):
            raise RenderCommandError("semantic job ancestor identity changed")
    for descriptor, path in (
        (roots.job_fd, roots.job),
        (roots.inputs_fd, roots.inputs),
        (roots.outputs_fd, roots.outputs),
    ):
        metadata = os.fstat(descriptor)
        expected = next(
            (identity for identity in roots.ancestor_identities if identity[0] == path),
            None,
        )
        if (
            expected is None
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != expected[1:]
        ):
            raise RenderCommandError("semantic job directory descriptor changed")


def _open_beneath(directory_fd: int, relative: str, flags: int) -> int:
    if (
        not isinstance(relative, str)
        or not relative
        or relative.startswith("/")
        or "\0" in relative
        or PurePosixPath(relative).as_posix() != relative
        or any(part in {"", ".", ".."} for part in PurePosixPath(relative).parts)
    ):
        raise RenderCommandError("descriptor-relative path is not canonical")
    how = OpenHow(
        flags=flags | getattr(os, "O_CLOEXEC", 0),
        mode=0,
        resolve=OPENAT2_RESOLVE,
    )
    descriptor = LIBC.syscall(
        SYS_OPENAT2,
        directory_fd,
        relative.encode("utf-8"),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if descriptor < 0:
        failure = ctypes.get_errno()
        if failure in {errno.ENOSYS, errno.EINVAL}:
            raise RenderCommandError("openat2 semantic containment is unavailable")
        raise OSError(failure, os.strerror(failure), relative)
    return int(descriptor)


def _capture_directory_chain(root: Path) -> tuple[tuple[Path, int, int], ...]:
    current = Path("/")
    paths = [current]
    for part in root.parts[1:]:
        current /= part
        paths.append(current)
    identities: list[tuple[Path, int, int]] = []
    for path in paths:
        device, inode = _directory_identity(path)
        identities.append((path, device, inode))
    return tuple(identities)


def _open_exact_directory(path: Path, expected: tuple[int, int]) -> int:
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != expected
    ):
        os.close(descriptor)
        raise RenderCommandError("semantic job directory changed while opening")
    return descriptor


def _semantic_job_roots(job_root: str) -> SemanticJobRoots:
    root = Path(job_root)
    if not root.is_absolute() or str(root) != job_root:
        raise RenderCommandError("semantic job root is not exact")
    inputs = root / "inputs"
    outputs = root / "outputs"
    identities = _capture_directory_chain(outputs)
    input_identity = _directory_identity(inputs)
    if not any(path == inputs for path, _device, _inode in identities):
        identities = (*identities, (inputs, *input_identity))
    identity_map = {path: (device, inode) for path, device, inode in identities}
    job_fd = _open_exact_directory(root, identity_map[root])
    try:
        inputs_fd = _open_beneath(
            job_fd,
            "inputs",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            outputs_fd = _open_beneath(
                job_fd,
                "outputs",
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
        except BaseException:
            os.close(inputs_fd)
            raise
    except BaseException:
        os.close(job_fd)
        raise
    roots = SemanticJobRoots(
        root,
        inputs,
        outputs,
        tuple(identities),
        job_fd,
        inputs_fd,
        outputs_fd,
    )
    _reprove_semantic_roots(roots)
    return roots


def _close_semantic_job_roots(roots: SemanticJobRoots) -> None:
    for descriptor in (roots.outputs_fd, roots.inputs_fd, roots.job_fd):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _job_root_from_request_argument(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or "\\" in value
        or "//" in value
        or PurePosixPath(value).as_posix() != value
        or any(part in {"", ".", ".."} for part in PurePosixPath(value).parts)
    ):
        raise RenderCommandError("request argument is not one exact absolute path")
    if value.startswith("/ambit/inputs/"):
        return "/ambit"
    raise RenderCommandError(
        "product renders require the provider-owned framed interface"
    )


def _deadline_monotonic(deadline_at: str) -> float:
    deadline = datetime.fromisoformat(deadline_at.replace("Z", "+00:00"))
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    if remaining <= 0:
        raise CommandDeadlineExceeded
    return time.monotonic() + remaining


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise CommandDeadlineExceeded


def _zone_relative(value: str, zone: str) -> str:
    prefix = zone + "/"
    if not value.startswith(prefix) or len(value) == len(prefix):
        raise RenderCommandError(f"protocol path escapes the {zone} zone")
    return value[len(prefix) :]


def _read_exact_regular_file(
    directory_fd: int,
    relative: str,
    *,
    minimum_bytes: int,
    maximum_bytes: int,
    expected_bytes: int | None = None,
) -> bytes:
    descriptor = _open_beneath(directory_fd, relative, os.O_RDONLY)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < minimum_bytes
            or before.st_size > maximum_bytes
            or (expected_bytes is not None and before.st_size != expected_bytes)
        ):
            raise RenderCommandError(
                "authority input is not one exact bounded regular file"
            )
        chunks: list[bytes] = []
        copied = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes - copied + 1))
            if not chunk:
                break
            copied += len(chunk)
            if copied > maximum_bytes:
                raise RenderCommandError("authority input exceeded its byte bound")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if copied != before.st_size or identity_before != identity_after:
            raise RenderCommandError("authority input identity changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _copy_exact_source(
    request: dict[str, Any],
    destination: Path,
    deadline: float,
    roots: SemanticJobRoots,
) -> None:
    _check_deadline(deadline)
    _reprove_semantic_roots(roots)
    descriptor = _open_beneath(
        roots.inputs_fd,
        _zone_relative(request["source"]["path"], "inputs"),
        os.O_RDONLY,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != request["source"]["byteLength"]
        ):
            raise RenderCommandError("source is not one exact regular file")
        digest = hashlib.sha256()
        copied = 0
        with destination.open("xb") as output:
            os.chmod(destination, 0o400)
            while True:
                _check_deadline(deadline)
                chunk = os.read(descriptor, READ_CHUNK_BYTES)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > request["source"]["byteLength"]:
                    raise RenderCommandError("source exceeded its declared bytes")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            copied != request["source"]["byteLength"]
            or "sha256:" + digest.hexdigest() != request["source"]["digest"]
            or before_identity != after_identity
        ):
            raise RenderCommandError("source bytes or identity differ")
    finally:
        os.close(descriptor)


def _private_semantic_roots(root: Path) -> SemanticJobRoots:
    if root.exists():
        raise RenderCommandError("private semantic root already exists")
    root.mkdir(mode=0o700)
    (root / "inputs").mkdir(mode=0o700)
    (root / "outputs").mkdir(mode=0o700)
    if any((root / "inputs").iterdir()) or any((root / "outputs").iterdir()):
        raise RenderCommandError("private semantic zones are not empty")
    return _semantic_job_roots(str(root))


def _admit_streamed_source(
    request: dict[str, Any],
    roots: SemanticJobRoots,
    temporary_leaf: str,
    *,
    byte_length: int,
    digest: str,
) -> None:
    if (
        request["source"]["byteLength"] != byte_length
        or request["source"]["digest"] != digest
    ):
        raise RenderCommandError("streamed source identity differs from the request")
    source_relative = request["source"]["path"]
    parent_fd, leaf = _zone_parent_descriptor(source_relative, roots, "inputs")
    try:
        if not _target_is_absent(parent_fd, leaf):
            raise RenderCommandError("private source target already exists")
        temporary_fd = _open_beneath(roots.inputs_fd, temporary_leaf, os.O_RDONLY)
        try:
            metadata = os.fstat(temporary_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size != byte_length
            ):
                raise RenderCommandError("streamed source is not one exact regular file")
        finally:
            os.close(temporary_fd)
        os.link(
            temporary_leaf,
            leaf,
            src_dir_fd=roots.inputs_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary_leaf, dir_fd=roots.inputs_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    admitted = _open_beneath(
        roots.inputs_fd,
        _zone_relative(source_relative, "inputs"),
        os.O_RDONLY,
    )
    try:
        metadata = os.fstat(admitted)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != byte_length
        ):
            raise RenderCommandError("streamed source admission did not settle exactly")
    finally:
        os.close(admitted)


def _zone_parent_descriptor(
    value: str,
    roots: SemanticJobRoots,
    zone: str,
) -> tuple[int, str]:
    relative = _zone_relative(value, zone)
    parts = PurePosixPath(relative).parts
    if not parts:
        raise RenderCommandError(f"{zone} target has no filename")
    root_fd = roots.outputs_fd if zone == "outputs" else roots.inputs_fd
    current_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            if part in {"", ".", ".."}:
                raise RenderCommandError("output parent path is invalid")
            try:
                os.mkdir(part, mode=0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            child_fd = _open_beneath(
                current_fd,
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            os.close(current_fd)
            current_fd = child_fd
        return current_fd, parts[-1]
    except BaseException:
        os.close(current_fd)
        raise


def _output_parent_descriptor(
    value: str,
    roots: SemanticJobRoots,
) -> tuple[int, str]:
    return _zone_parent_descriptor(value, roots, "outputs")


def _target_is_absent(parent_fd: int, leaf: str) -> bool:
    try:
        os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def _output_target_exists(value: str, roots: SemanticJobRoots) -> bool:
    parent_fd, leaf = _output_parent_descriptor(value, roots)
    try:
        return not _target_is_absent(parent_fd, leaf)
    finally:
        os.close(parent_fd)


def _temporary_output(parent_fd: int, leaf: str) -> tuple[int, str]:
    for _attempt in range(8):
        temporary = f".{leaf}.{secrets.token_hex(16)}"
        try:
            return (
                os.open(
                    temporary,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o400,
                    dir_fd=parent_fd,
                ),
                temporary,
            )
        except FileExistsError:
            continue
    raise RenderCommandError("output temporary filename allocation failed")


def _atomic_publish(value: str, payload: bytes, roots: SemanticJobRoots) -> None:
    _reprove_semantic_roots(roots)
    parent_fd, leaf = _output_parent_descriptor(value, roots)
    temporary: str | None = None
    try:
        if not _target_is_absent(parent_fd, leaf):
            raise RenderCommandError("output target already exists")
        descriptor, temporary = _temporary_output(parent_fd, leaf)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.link(
            temporary,
            leaf,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        os.fsync(parent_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def _atomic_publish_file(
    source: Path,
    target: str,
    scratch: Path,
    roots: SemanticJobRoots,
) -> dict[str, Any]:
    source = source.resolve(strict=True)
    try:
        source.relative_to(scratch.resolve(strict=True))
    except ValueError as error:
        raise RenderCommandError("evidence artifact escapes task scratch") from error
    metadata = source.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size < 1
        or metadata.st_size > MAXIMUM_EVIDENCE_ARTIFACT_BYTES
    ):
        raise RenderCommandError("evidence artifact is not a bounded regular file")
    _reprove_semantic_roots(roots)
    parent_fd, leaf = _output_parent_descriptor(target, roots)
    temporary: str | None = None
    digest = hashlib.sha256()
    copied = 0
    try:
        if not _target_is_absent(parent_fd, leaf):
            raise RenderCommandError("evidence artifact target already exists")
        descriptor, temporary = _temporary_output(parent_fd, leaf)
        with source.open("rb") as input_file, os.fdopen(descriptor, "wb", closefd=True) as output:
            while chunk := input_file.read(READ_CHUNK_BYTES):
                copied += len(chunk)
                if copied > MAXIMUM_EVIDENCE_ARTIFACT_BYTES:
                    raise RenderCommandError("evidence artifact exceeded its byte bound")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = source.lstat()
        if (
            after.st_dev,
            after.st_ino,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ):
            raise RenderCommandError("evidence artifact changed during custody copy")
        os.link(
            temporary,
            leaf,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        os.fsync(parent_fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
    return {
        "byteLength": copied,
        "digest": "sha256:" + digest.hexdigest(),
    }


def _load_executor(pack_root: Path, facet: str | None) -> dict[str, str]:
    lock_path = pack_root / "executor.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    facets = lock.get("facets") if isinstance(lock, dict) else None
    if (
        not isinstance(lock, dict)
        or set(lock) != {"digest", "facets", "ref", "schema", "transport"}
        or lock["schema"] != "ambit.c18-specialist-render-executor-lock/v2"
        or not isinstance(facets, list)
        or not facets
        or not all(isinstance(value, str) for value in facets)
        or (facet is not None and facet not in facets)
        or not isinstance(lock["ref"], str)
        or not isinstance(lock["digest"], str)
        or lock["transport"] != _load_interface(pack_root)
    ):
        raise RenderCommandError("executor lock does not own the request facet")
    body = {
        key: lock[key]
        for key in ("facets", "ref", "schema", "transport")
    }
    if (
        facets != sorted(set(facets))
        or lock["digest"] != sha256_bytes(canonical_bytes(body))
    ):
        raise RenderCommandError("executor lock identity is forged")
    return {"ref": lock["ref"], "digest": lock["digest"]}


def _load_interface(pack_root: Path) -> dict[str, str]:
    path = pack_root / "protocol/specialist-render-interface.lock.json"
    lock = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(lock, dict)
        or set(lock) != {"contract", "digest", "schema", "state"}
        or lock["schema"] != "ambit.runtime-interface-lock/v1"
        or lock["state"] != "candidate-ready"
        or not isinstance(lock["contract"], dict)
        or lock["contract"].get("interfaceRef") != INTERFACE_REF
        or lock["contract"].get("frameSchema") != FRAME_SCHEMA
        or lock["digest"] != sha256_bytes(canonical_bytes(lock["contract"]))
    ):
        raise RenderCommandError("specialist framed interface lock is invalid")
    return {"ref": INTERFACE_REF, "digest": lock["digest"]}


def _process_identity() -> dict[str, object]:
    value = Path("/proc/self/stat").read_text(encoding="utf-8")
    close = value.rfind(")")
    fields = value[close + 2 :].strip().split(" ")
    if close < 0 or len(fields) <= 19 or not fields[19].isdigit() or fields[19] == "0":
        raise RenderCommandError("specialist helper process identity is invalid")
    return {"pid": os.getpid(), "startTicks": fields[19]}


def _load_adapter(pack_root: Path) -> ModuleType:
    path = pack_root / "runtime/adapter.py"
    specification = importlib.util.spec_from_file_location("ambit_specialist_adapter", path)
    if specification is None or specification.loader is None:
        raise RenderCommandError("specialist adapter cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    if not callable(getattr(module, "render_validate", None)):
        raise RenderCommandError("specialist adapter has no render_validate entrypoint")
    return module


def _evidence_relative_path(request: dict[str, Any], index: int, check: str) -> str:
    result_parent = Path(request["output"]["resultPath"]).parent
    return (result_parent / "evidence" / f"{index:03d}-{check}.json").as_posix()


def _fact_key(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RenderCommandError("adapter fact key is invalid")
    snake = FACT_KEY_BOUNDARY.sub("_", value).lower()
    normalized = FACT_KEY_UNSAFE.sub("_", snake).strip("_")
    if not normalized or len(normalized) > 128:
        raise RenderCommandError("adapter fact key exceeds its canonical bound")
    return normalized


def _fact_value(value: object) -> str:
    try:
        encoded = canonical_bytes(value)
    except RenderCommandError:
        raise
    text = encoded.decode("utf-8")
    if text.endswith("\n"):
        text = text[:-1]
    if isinstance(value, str):
        text = value
    if not text or len(text) > 256 or len(text.encode("utf-8")) > 1_024:
        return sha256_bytes(encoded)
    return text


def _adapter_proofs(
    request: dict[str, Any],
    observations: object,
    evidence_artifacts: object,
) -> dict[str, dict[str, Any]]:
    requested_checks = pack_check_names(request)
    if not isinstance(observations, dict) or sorted(observations) != requested_checks:
        raise RenderCommandError("adapter checks differ from the exact request policy")
    proofs: dict[str, dict[str, Any]] = {}
    for check in requested_checks:
        observation = observations[check]
        if not isinstance(observation, dict) or observation.get("check") != check:
            raise RenderCommandError("adapter observation identity is invalid")
        facts: dict[str, str] = {}
        for raw_key, raw_value in observation.items():
            if raw_key == "check":
                continue
            key = _fact_key(raw_key)
            if key in facts:
                raise RenderCommandError("adapter fact keys collide after canonicalization")
            facts[key] = _fact_value(raw_value)
        proofs[check] = {"facts": facts, "artifacts": []}

    if not isinstance(evidence_artifacts, list) or len(evidence_artifacts) > 64:
        raise RenderCommandError("adapter evidence artifact roster is invalid")
    names: set[str] = set()
    for raw in evidence_artifacts:
        if not isinstance(raw, dict) or set(raw) != {
            "check",
            "mediaType",
            "name",
            "sourcePath",
        }:
            raise RenderCommandError("adapter evidence artifact shape is invalid")
        check = raw["check"]
        name = raw["name"]
        if check not in proofs or not isinstance(name, str) or name in names:
            raise RenderCommandError("adapter evidence artifact ownership is invalid")
        names.add(name)
        proofs[check]["artifacts"].append(
            {
                "mediaType": raw["mediaType"],
                "name": name,
                "sourcePath": raw["sourcePath"],
            }
        )
    for proof in proofs.values():
        proof["facts"] = dict(sorted(proof["facts"].items()))
        proof["artifacts"].sort(key=lambda item: item["name"])
    return proofs


def _write_evidence(
    request: dict[str, Any],
    executor: dict[str, str],
    proofs: dict[str, dict[str, Any]],
    scratch: Path,
    roots: SemanticJobRoots,
    *,
    outcomes: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    outcomes = outcomes or {check: "passed" for check in proofs}
    checks: list[dict[str, Any]] = []
    artifact_cache: dict[tuple[str, str], dict[str, Any]] = {}
    result_parent = Path(request["output"]["resultPath"]).parent
    for index, check in enumerate(sorted(proofs), start=1):
        proof = proofs[check]
        if not isinstance(proof, dict) or set(proof) != {"artifacts", "facts"}:
            raise RenderCommandError("adapter check proof shape is invalid")
        raw_facts = proof["facts"]
        raw_artifacts = proof["artifacts"]
        if not isinstance(raw_facts, dict) or not isinstance(raw_artifacts, list):
            raise RenderCommandError("adapter check proof fields are invalid")
        facts = [
            {"key": key, "value": raw_facts[key]}
            for key in sorted(raw_facts)
        ]
        artifacts: list[dict[str, Any]] = []
        for raw in raw_artifacts:
            if not isinstance(raw, dict) or set(raw) != {"mediaType", "name", "sourcePath"}:
                raise RenderCommandError("adapter artifact proof shape is invalid")
            name = raw["name"]
            if (
                not isinstance(name, str)
                or Path(name).name != name
                or not name
                or name.endswith(".sock")
            ):
                raise RenderCommandError("adapter artifact filename is unsafe")
            source_path = Path(raw["sourcePath"])
            relative = (result_parent / "artifacts" / name).as_posix()
            cache_key = (str(source_path.resolve(strict=True)), relative)
            descriptor = artifact_cache.get(cache_key)
            if descriptor is None:
                identity = _atomic_publish_file(
                    source_path, relative, scratch, roots
                )
                descriptor = {
                    "path": relative,
                    "mediaType": raw["mediaType"],
                    **identity,
                }
                artifact_cache[cache_key] = descriptor
            artifacts.append(descriptor)
        artifacts.sort(key=lambda item: item["path"])
        evidence = create_check_evidence(
            request,
            executor,
            check,
            outcomes[check],
            facts,
            artifacts,
        )
        payload = canonical_bytes(evidence)
        relative = _evidence_relative_path(request, index, check)
        _atomic_publish(relative, payload, roots)
        checks.append(
            {
                "check": check,
                "outcome": outcomes[check],
                "evidence": {
                    "path": relative,
                    "mediaType": EVIDENCE_MEDIA_TYPE,
                    "byteLength": len(payload),
                    "digest": sha256_bytes(payload),
                },
            }
        )
    return checks


def _settle_result(
    request: dict[str, Any],
    result_path: str,
    executor: dict[str, str],
    started_at: str,
    roots: SemanticJobRoots,
    *,
    outcome: str,
    checks: list[dict[str, Any]],
    preview: dict[str, Any] | None,
    failure: dict[str, str] | None,
) -> dict[str, Any]:
    result = create_result(
        request,
        {
            "outcome": outcome,
            "execution": {
                "executorRevision": executor,
                "startedAt": started_at,
                "completedAt": instant_now(),
            },
            "preview": preview,
            "checks": checks,
            "failure": failure,
        },
    )
    _atomic_publish(result_path, canonical_bytes(result), roots)
    return result


def _settle_or_unknown(
    *args: Any,
    private_errors: bool = True,
    **kwargs: Any,
) -> bool:
    try:
        _settle_result(*args, **kwargs)
        return True
    except Exception:
        if private_errors:
            print(
                "ambit-specialist-render: terminal result publication failed; host reconciliation required",
                file=sys.stderr,
            )
        return False


def _hold_output_file(
    roots: SemanticJobRoots,
    *,
    ordinal: int,
    role: str,
    path: str,
    media_type: str,
    maximum_bytes: int,
    expected_bytes: int | None = None,
    expected_digest: str | None = None,
    retain_bytes: bool = False,
) -> tuple[FramedOutputFile, bytes | None]:
    _reprove_semantic_roots(roots)
    descriptor = _open_beneath(
        roots.outputs_fd,
        _zone_relative(path, "outputs"),
        os.O_RDONLY,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum_bytes
            or (expected_bytes is not None and before.st_size != expected_bytes)
        ):
            raise RenderCommandError("framed response file is not exact and bounded")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        copied = 0
        while chunk := os.read(descriptor, min(READ_CHUNK_BYTES, maximum_bytes - copied + 1)):
            copied += len(chunk)
            if copied > maximum_bytes:
                raise RenderCommandError("framed response file exceeded its bound")
            digest.update(chunk)
            if retain_bytes:
                chunks.append(chunk)
        observed_digest = "sha256:" + digest.hexdigest()
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        if (
            copied != before.st_size
            or identity
            != (
                after.st_dev,
                after.st_ino,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or (expected_digest is not None and observed_digest != expected_digest)
        ):
            raise RenderCommandError("framed response file identity changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return (
            FramedOutputFile(
                ordinal,
                role,
                path,
                media_type,
                copied,
                observed_digest,
                descriptor,
                identity,
            ),
            b"".join(chunks) if retain_bytes else None,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _framed_output_roster(
    request: dict[str, Any],
    executor: dict[str, str],
    roots: SemanticJobRoots,
) -> tuple[dict[str, Any], list[FramedOutputFile]]:
    projected_count = 0
    projected_bytes = 0

    def admit(byte_length: int) -> int:
        nonlocal projected_count, projected_bytes
        if (
            not isinstance(byte_length, int)
            or isinstance(byte_length, bool)
            or byte_length < 1
            or projected_count + 1 > MAXIMUM_RESPONSE_FILES
            or projected_bytes + byte_length > MAXIMUM_RESPONSE_BYTES
        ):
            raise RenderCommandError("framed response aggregate exceeds its bound")
        projected_count += 1
        projected_bytes += byte_length
        return MAXIMUM_RESPONSE_BYTES - (projected_bytes - byte_length)

    result_file, result_bytes = _hold_output_file(
        roots,
        ordinal=1,
        role="result",
        path=request["output"]["resultPath"],
        media_type=RESULT_MEDIA_TYPE,
        maximum_bytes=MAXIMUM_COMMAND_BYTES,
        retain_bytes=True,
    )
    admit(result_file.byte_length)
    files = [result_file]
    try:
        if result_bytes is None:
            raise RenderCommandError("framed result bytes are absent")
        result = parse_result_bytes(request, result_bytes)
        if result["execution"]["executorRevision"] != executor:
            raise RenderCommandError("framed result executor identity differs")
        seen = {result_file.path}
        deferred_artifacts: dict[str, tuple[str, int, str]] = {}
        preview_descriptor = result["preview"]
        if preview_descriptor is not None:
            path = preview_descriptor["path"]
            if path in seen:
                raise RenderCommandError("framed output path is duplicated")
            remaining = admit(preview_descriptor["byteLength"])
            preview_file, preview_bytes = _hold_output_file(
                roots,
                ordinal=len(files) + 1,
                role="preview",
                path=path,
                media_type=preview_descriptor["mediaType"],
                maximum_bytes=min(
                    request["output"]["maximumPreviewBytes"],
                    remaining,
                ),
                expected_bytes=preview_descriptor["byteLength"],
                expected_digest=preview_descriptor["bytesDigest"],
                retain_bytes=True,
            )
            if preview_bytes is None:
                raise RenderCommandError("framed preview bytes are absent")
            preview = parse_preview_bytes(preview_bytes)
            if preview["digest"] != preview_descriptor["envelopeDigest"]:
                raise RenderCommandError("framed preview envelope identity differs")
            files.append(preview_file)
            seen.add(path)
        for check in result["checks"]:
            evidence_descriptor = check["evidence"]
            if evidence_descriptor is None:
                continue
            path = evidence_descriptor["path"]
            if path in seen:
                raise RenderCommandError("framed output path is duplicated")
            remaining = admit(evidence_descriptor["byteLength"])
            evidence_file, evidence_bytes = _hold_output_file(
                roots,
                ordinal=len(files) + 1,
                role="evidence",
                path=path,
                media_type=evidence_descriptor["mediaType"],
                maximum_bytes=min(MAXIMUM_COMMAND_BYTES, remaining),
                expected_bytes=evidence_descriptor["byteLength"],
                expected_digest=evidence_descriptor["digest"],
                retain_bytes=True,
            )
            if evidence_bytes is None:
                raise RenderCommandError("framed evidence bytes are absent")
            evidence = parse_check_evidence_bytes(evidence_bytes)
            if (
                evidence["check"] != check["check"]
                or evidence["executorRevision"] != executor
                or evidence["request"]["digest"] != request["digest"]
                or evidence["request"]["sourceDigest"]
                != request["source"]["digest"]
            ):
                raise RenderCommandError("framed evidence identity differs")
            files.append(evidence_file)
            seen.add(path)
            for artifact in evidence["artifacts"]:
                artifact_path = artifact["path"]
                identity = (
                    artifact["mediaType"],
                    artifact["byteLength"],
                    artifact["digest"],
                )
                existing = deferred_artifacts.get(artifact_path)
                if existing is not None and existing != identity:
                    raise RenderCommandError("framed artifact identity conflicts")
                deferred_artifacts[artifact_path] = identity
        for path in sorted(deferred_artifacts):
            if path in seen:
                raise RenderCommandError("framed output path is duplicated")
            media_type, byte_length, digest = deferred_artifacts[path]
            remaining = admit(byte_length)
            artifact_file, _payload = _hold_output_file(
                roots,
                ordinal=len(files) + 1,
                role="artifact",
                path=path,
                media_type=media_type,
                maximum_bytes=min(MAXIMUM_EVIDENCE_ARTIFACT_BYTES, remaining),
                expected_bytes=byte_length,
                expected_digest=digest,
            )
            files.append(artifact_file)
            seen.add(path)
        if len(files) != projected_count or sum(
            value.byte_length for value in files
        ) != projected_bytes:
            raise RenderCommandError("framed response aggregate exceeds its bound")
        return result, files
    except BaseException:
        for value in files:
            try:
                os.close(value.descriptor)
            except OSError:
                pass
        raise


def _close_framed_output_files(files: list[FramedOutputFile]) -> None:
    for value in files:
        try:
            os.close(value.descriptor)
        except OSError:
            pass


def _stream_framed_output_files(
    writer: CanonicalFrameWriter,
    nonce: str,
    files: list[FramedOutputFile],
    roots: SemanticJobRoots,
) -> None:
    _reprove_semantic_roots(roots)
    for value in files:
        writer.write(
            response_file_start(
                nonce=nonce,
                ordinal=value.ordinal,
                role=value.role,
                path=value.path,
                media_type=value.media_type,
                byte_length=value.byte_length,
                digest=value.digest,
            )
        )
        digest = hashlib.sha256()
        copied = 0
        chunk_index = 0
        while chunk := os.read(value.descriptor, RAW_CHUNK_BYTES):
            copied += len(chunk)
            digest.update(chunk)
            writer.write(
                response_file_chunk(
                    nonce=nonce,
                    ordinal=value.ordinal,
                    chunk_index=chunk_index,
                    payload=chunk,
                )
            )
            chunk_index += 1
        after = os.fstat(value.descriptor)
        if (
            copied != value.byte_length
            or "sha256:" + digest.hexdigest() != value.digest
            or value.identity
            != (
                after.st_dev,
                after.st_ino,
                after.st_nlink,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise RenderCommandError("framed response file changed while streaming")
    _reprove_semantic_roots(roots)


def _render(
    pack_root: Path,
    request: dict[str, Any],
    result_path: str,
    executor: dict[str, str],
    started_at: str,
    roots: SemanticJobRoots,
) -> int:
    deadline = _deadline_monotonic(request["deadlineAt"])
    adapter = _load_adapter(pack_root)

    with tempfile.TemporaryDirectory(
        prefix="ambit-specialist-render-",
        dir=TASK_SCRATCH_ROOT,
    ) as temporary:
        local_source = Path(temporary) / ("source" + Path(request["source"]["path"]).suffix)
        _copy_exact_source(request, local_source, deadline, roots)
        _check_deadline(deadline)
        rendered = adapter.render_validate(
            request=request,
            source_path=local_source,
            scratch=Path(temporary),
            deadline=deadline,
        )
        if not isinstance(rendered, dict) or set(rendered) != {
            "evidenceArtifacts",
            "facts",
            "limitations",
            "observations",
            "summary",
            "title",
            "views",
        }:
            raise RenderCommandError("specialist adapter result shape is invalid")
        proofs = _adapter_proofs(
            request,
            rendered["observations"],
            rendered["evidenceArtifacts"],
        )
        checks = _write_evidence(
            request, executor, proofs, Path(temporary), roots
        )
        _check_deadline(deadline)
        image_pixels = 0
        for view in rendered["views"]:
            if isinstance(view, dict) and view.get("kind") == "image":
                width = view.get("width")
                height = view.get("height")
                if not isinstance(width, int) or not isinstance(height, int):
                    raise RenderCommandError("adapter image geometry is invalid")
                pixels = width * height
                if pixels > request["output"]["maximumImagePixels"]:
                    raise RenderCommandError("adapter image exceeds the request pixel bound")
                image_pixels += pixels
        if image_pixels > request["output"]["maximumAggregateImagePixels"]:
            raise RenderCommandError("adapter images exceed the aggregate request pixel bound")
        preview_envelope = create_preview(
            {
                "facet": request["facet"],
                "title": rendered["title"],
                "summary": rendered["summary"],
                "views": rendered["views"],
                "facts": rendered["facts"],
                "validation": [
                    {
                        "check": item["check"],
                        "label": item["label"],
                        "status": "passed",
                    }
                    for item in request["packRequiredChecks"]
                ],
                "limitations": rendered["limitations"],
            }
        )
        preview_bytes = encode_preview(preview_envelope)
        if len(preview_bytes) > request["output"]["maximumPreviewBytes"]:
            raise RenderCommandError("preview exceeds the request byte limit")
        _atomic_publish(request["output"]["previewPath"], preview_bytes, roots)
        _check_deadline(deadline)
        try:
            _settle_result(
                request,
                result_path,
                executor,
                started_at,
                roots,
                outcome="succeeded",
                checks=checks,
                preview={
                    "path": request["output"]["previewPath"],
                    "mediaType": request["output"]["previewMediaType"],
                    "byteLength": len(preview_bytes),
                    "bytesDigest": sha256_bytes(preview_bytes),
                    "envelopeDigest": preview_envelope["digest"],
                },
                failure=None,
            )
        except Exception as error:
            raise ResultPublicationFailure from error
    return 0


def _execute_and_settle(
    pack_root: Path,
    request: dict[str, Any],
    executor: dict[str, str],
    roots: SemanticJobRoots,
    *,
    private_errors: bool,
) -> int:
    result_path = request["output"]["resultPath"]
    started_at = instant_now()
    try:
        return _render(
            pack_root,
            request,
            result_path,
            executor,
            started_at,
            roots,
        )
    except ResultPublicationFailure:
        if private_errors:
            print(
                "ambit-specialist-render: terminal result publication failed; host reconciliation required",
                file=sys.stderr,
            )
        return 70
    except CommandCancelled:
        if not private_errors and _output_target_exists(result_path, roots):
            # A framed success result is still private, not a host commit. An
            # exact cancel that wins before the terminal frame discards it.
            raise
        settled = _settle_or_unknown(
            request,
            result_path,
            executor,
            started_at,
            roots,
            outcome="cancelled",
            checks=[],
            preview=None,
            failure={"code": "cancelled", "message": "The specialist render was cancelled."},
            private_errors=private_errors,
        )
        return 130 if settled else 70
    except CommandDeadlineExceeded:
        settled = _settle_or_unknown(
            request,
            result_path,
            executor,
            started_at,
            roots,
            outcome="failed",
            checks=[],
            preview=None,
            failure={
                "code": "deadline_exceeded",
                "message": "The specialist render deadline elapsed.",
            },
            private_errors=private_errors,
        )
        return 124 if settled else 70
    except AdapterFailure as error:
        bound_check = (
            error.check
            if error.check is not None and error.check in pack_check_names(request)
            else None
        )
        if bound_check is None:
            checks = []
        elif error.outcome == "blocked":
            checks = [{"check": bound_check, "outcome": "blocked", "evidence": None}]
        else:
            failure_proof = {
                bound_check: {
                    "facts": {"failure": "observed"},
                    "artifacts": [],
                }
            }
            with tempfile.TemporaryDirectory(
                prefix="ambit-specialist-failure-",
                dir=TASK_SCRATCH_ROOT,
            ) as failure_scratch:
                checks = _write_evidence(
                    request,
                    executor,
                    failure_proof,
                    Path(failure_scratch),
                    roots,
                    outcomes={bound_check: "failed"},
                )
        settled = _settle_or_unknown(
            request,
            result_path,
            executor,
            started_at,
            roots,
            outcome="failed",
            checks=checks,
            preview=None,
            failure={"code": error.code, "message": error.public_message},
            private_errors=private_errors,
        )
        return 1 if settled else 70
    except FramedRenderError:
        raise
    except Exception as error:
        if private_errors:
            private_detail = (
                str(error)
                if isinstance(error, (PublicPreviewError, RenderCommandError))
                else type(error).__name__
            )
            print(
                "ambit-specialist-render: private failure " f"{private_detail}",
                file=sys.stderr,
            )
        settled = _settle_or_unknown(
            request,
            result_path,
            executor,
            started_at,
            roots,
            outcome="failed",
            checks=[],
            preview=None,
            failure={
                "code": "renderer_failed",
                "message": "The specialist renderer failed before producing a safe preview.",
            },
            private_errors=private_errors,
        )
        return 1 if settled else 70


def _file_main(pack_root: Path, request_argument: str, result_argument: str) -> int:
    roots: SemanticJobRoots | None = None
    try:
        job_root = _job_root_from_request_argument(request_argument)
        roots = _semantic_job_roots(job_root)
        relative_request = PurePosixPath(request_argument).relative_to(
            PurePosixPath(job_root)
        ).as_posix()
        request_bytes = _read_exact_regular_file(
            roots.inputs_fd,
            _zone_relative(relative_request, "inputs"),
            minimum_bytes=1,
            maximum_bytes=MAXIMUM_COMMAND_BYTES,
        )
        request = parse_request_bytes(request_bytes)
        require_request_policy(request)
        if request["jobRoot"] != job_root:
            raise RenderCommandError("request semantic root differs from its argv")
        if request_argument != f"{job_root}/{request['requestPath']}":
            raise RenderCommandError(
                "request argument differs from the exact request identity"
            )
        result_path = request["output"]["resultPath"]
        if result_argument != f"{job_root}/{result_path}":
            raise RenderCommandError("result argument differs from the exact request")
    except (OSError, RenderCommandError) as error:
        if roots is not None:
            _close_semantic_job_roots(roots)
        print(f"ambit-specialist-render: invalid request: {error}", file=sys.stderr)
        return 64

    try:
        executor = _load_executor(pack_root, request["facet"])
    except (OSError, json.JSONDecodeError, RenderCommandError) as error:
        _close_semantic_job_roots(roots)
        print(
            f"ambit-specialist-render: executor identity unavailable: {error}",
            file=sys.stderr,
        )
        return 70

    def cancel(_signum: int, _frame: Any) -> None:
        raise CommandCancelled

    signal.signal(signal.SIGINT, cancel)
    signal.signal(signal.SIGTERM, cancel)
    try:
        return _execute_and_settle(
            pack_root,
            request,
            executor,
            roots,
            private_errors=True,
        )
    finally:
        _close_semantic_job_roots(roots)


def _result_exit_matches(result: dict[str, Any], exit_code: int) -> bool:
    if result["outcome"] == "succeeded":
        return exit_code == 0
    if result["outcome"] == "cancelled":
        return exit_code == 130
    if result["outcome"] != "failed" or result["failure"] is None:
        return False
    if result["failure"]["code"] == "deadline_exceeded":
        return exit_code == 124
    return exit_code == 1


def _framed_main(
    pack_root: Path,
    nonce: str,
    input_stream: Any,
    output_stream: Any,
) -> int:
    nonce = exact_nonce(nonce)
    writer = CanonicalFrameWriter(output_stream)
    process_identity = _process_identity()
    interface = _load_interface(pack_root)
    executor = _load_executor(pack_root, None)
    writer.write(
        {
            "schema": FRAME_SCHEMA,
            "kind": "ready",
            "nonce": nonce,
            "chunkBytes": RAW_CHUNK_BYTES,
            "cancellationExitCode": 130,
            "interface": interface,
            "executorRevision": executor,
            "executable": str(pack_root / "bin/ambit-specialist-render"),
            "processIdentity": process_identity,
        },
        aggregate=False,
    )

    previous_signals = {
        name: signal.getsignal(name)
        for name in (signal.SIGINT, signal.SIGTERM, signal.SIGUSR1)
    }
    control: FramedControlAdmission | None = None
    files: list[FramedOutputFile] = []
    private_root_path: Path | None = None
    cleanup_started = False

    def external_abort(_signum: int, _frame: Any) -> None:
        raise FramedRenderError("provider terminated the framed helper")

    def control_abort(_signum: int, _frame: Any) -> None:
        if cleanup_started:
            return
        if control is None:
            raise FramedRenderError("framed control interrupted before admission")
        control.raise_pending()

    signal.signal(signal.SIGINT, external_abort)
    signal.signal(signal.SIGTERM, external_abort)
    signal.signal(signal.SIGUSR1, control_abort)
    try:
        with tempfile.TemporaryDirectory(
            prefix="ambit-specialist-framed-",
            dir=TASK_SCRATCH_ROOT,
        ) as temporary:
            private_root_path = Path(temporary)
            roots = _private_semantic_roots(Path(temporary) / "job")
            temporary_source = f".transport-source-{nonce}"
            request_sink = io.BytesIO()
            source_descriptor = os.open(
                temporary_source,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o400,
                dir_fd=roots.inputs_fd,
            )
            try:
                with os.fdopen(source_descriptor, "wb", closefd=True) as source_sink:
                    collector = FramedRequestCollector(
                        nonce,
                        request_sink,
                        source_sink,
                    )
                    collected = None
                    while collected is None:
                        collected = collector.accept(read_line(input_stream))
                    source_sink.flush()
                    os.fsync(source_sink.fileno())
                request_bytes = request_sink.getvalue()
                if (
                    len(request_bytes) != collected.request_bytes
                    or sha256_bytes(request_bytes) != collected.request_sha256
                ):
                    raise RenderCommandError("streamed request bytes differ")
                request = parse_request_bytes(request_bytes)
                require_request_policy(request)
                if request["jobRoot"] == "/ambit":
                    raise RenderCommandError(
                        "the framed interface is reserved for product render authority"
                    )
                executor = _load_executor(pack_root, request["facet"])
                _admit_streamed_source(
                    request,
                    roots,
                    temporary_source,
                    byte_length=collected.source_bytes,
                    digest=collected.source_sha256,
                )
                control = FramedControlAdmission(input_stream, nonce)
                control.start()
                exit_code = _execute_and_settle(
                    pack_root,
                    request,
                    executor,
                    roots,
                    private_errors=False,
                )
                if exit_code == 130:
                    raise CommandCancelled
                control.raise_pending()
                if exit_code not in {0, 1, 124}:
                    raise ResultPublicationFailure
                result, files = _framed_output_roster(
                    request,
                    executor,
                    roots,
                )
                if not _result_exit_matches(result, exit_code):
                    raise RenderCommandError("framed result and helper exit differ")
                writer.write(
                    {
                        "schema": FRAME_SCHEMA,
                        "kind": "response_start",
                        "nonce": nonce,
                        "outcome": result["outcome"],
                        "exitCode": exit_code,
                        "request": {
                            "digest": request["digest"],
                            "jobRef": request["jobRef"],
                            "jobRoot": request["jobRoot"],
                        },
                        "resultDigest": result["digest"],
                        "executorRevision": executor,
                        "fileCount": len(files),
                        "totalBytes": sum(value.byte_length for value in files),
                    }
                )
                _stream_framed_output_files(writer, nonce, files, roots)
                control.raise_pending()
                # Terminal selection is the cancellation linearization point.
                # Once selected, a late cancel cannot interrupt cleanup or
                # cause a false cleanup-completed cancellation receipt.
                control.select_terminal()
                response = {
                    "outcome": result["outcome"],
                    "exitCode": exit_code,
                    "request": {
                        "digest": request["digest"],
                        "jobRef": request["jobRef"],
                        "jobRoot": request["jobRoot"],
                    },
                    "resultDigest": result["digest"],
                    "executorRevision": executor,
                    "fileCount": len(files),
                    "totalBytes": sum(value.byte_length for value in files),
                }
            finally:
                cleanup_started = True
                _close_framed_output_files(files)
                files = []
                _close_semantic_job_roots(roots)
        if control is None or private_root_path is None or private_root_path.exists():
            raise FramedRenderError("framed control admission was not established")
        writer.write(
            {
                "schema": FRAME_SCHEMA,
                "kind": "response_end",
                "nonce": nonce,
                **response,
                "frameCount": writer.frame_count,
                "streamSha256": writer.stream_sha256,
                "processIdentity": process_identity,
                "privateRootCleanup": PRIVATE_ROOT_CLEANUP,
                "terminalSelection": TERMINAL_SELECTION,
            },
            aggregate=False,
        )
        return int(response["exitCode"])
    except (CommandCancelled, FramedRenderCancelled):
        if private_root_path is None or private_root_path.exists():
            return 70
        try:
            if control is not None:
                control.select_terminal()
        except CommandCancelled:
            pass
        writer.write(
            {
                "schema": FRAME_SCHEMA,
                "kind": "cancelled",
                "nonce": nonce,
                "outcome": "cancelled",
                "exitCode": 130,
                "executorRevision": executor,
                "processIdentity": process_identity,
                "privateRootCleanup": PRIVATE_ROOT_CLEANUP,
                "terminalSelection": TERMINAL_SELECTION,
            },
            aggregate=False,
        )
        return 130
    except BaseException:
        return 70
    finally:
        _close_framed_output_files(files)
        if control is not None:
            control.abandon()
        for name, handler in previous_signals.items():
            signal.signal(name, handler)


def main(pack_root: Path, argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        _prepare_task_scratch_root()
    except (OSError, RenderCommandError):
        return 70
    if (
        len(arguments) == 3
        and arguments[0] == "--framed-jsonl"
        and arguments[1] == "--nonce"
    ):
        try:
            return _framed_main(
                pack_root,
                arguments[2],
                sys.stdin.buffer,
                sys.stdout.buffer,
            )
        except BaseException:
            return 70
    if (
        len(arguments) == 4
        and arguments[0] == "--request"
        and arguments[2] == "--result"
    ):
        return _file_main(pack_root, arguments[1], arguments[3])
    print(
        "ambit-specialist-render: expected framed product authority "
        "or /ambit conformance arguments",
        file=sys.stderr,
    )
    return 64
