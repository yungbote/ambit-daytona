from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import re
import secrets
import signal
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import NamedTuple
from typing import Any

from public_preview import PublicPreviewError, create_preview, encode_preview
from render_command import (
    EVIDENCE_MEDIA_TYPE,
    MAXIMUM_COMMAND_BYTES,
    RenderCommandError,
    canonical_bytes,
    create_check_evidence,
    create_result,
    instant_now,
    pack_check_names,
    parse_request_bytes,
    sha256_bytes,
)
from render_policy import require_request_policy


READ_CHUNK_BYTES = 1024 * 1024
MAXIMUM_EVIDENCE_ARTIFACT_BYTES = 512 * 1024 * 1024
FACT_KEY_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")
FACT_KEY_UNSAFE = re.compile(r"[^a-z0-9]+")


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
PRODUCT_REQUEST_PATH = re.compile(
    r"^(?P<root>/workspace/\.ambit/render-jobs/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})/inputs/"
    r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
)


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
    match = PRODUCT_REQUEST_PATH.fullmatch(value)
    if match is None:
        raise RenderCommandError("request argument is outside a policy-admitted job root")
    return match.group("root")


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


def _output_parent_descriptor(
    value: str,
    roots: SemanticJobRoots,
) -> tuple[int, str]:
    relative = _zone_relative(value, "outputs")
    parts = PurePosixPath(relative).parts
    if not parts:
        raise RenderCommandError("output target has no filename")
    current_fd = os.dup(roots.outputs_fd)
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


def _target_is_absent(parent_fd: int, leaf: str) -> bool:
    try:
        os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


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


def _load_executor(pack_root: Path, facet: str) -> dict[str, str]:
    lock_path = pack_root / "executor.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    facets = lock.get("facets") if isinstance(lock, dict) else None
    if (
        not isinstance(lock, dict)
        or set(lock) != {"digest", "facets", "ref", "schema"}
        or lock["schema"] != "ambit.c18-specialist-render-executor-lock/v1"
        or not isinstance(facets, list)
        or not facets
        or not all(isinstance(value, str) for value in facets)
        or facet not in facets
        or not isinstance(lock["ref"], str)
        or not isinstance(lock["digest"], str)
    ):
        raise RenderCommandError("executor lock does not own the request facet")
    body = {key: lock[key] for key in ("facets", "ref", "schema")}
    if (
        facets != sorted(set(facets))
        or lock["digest"] != sha256_bytes(canonical_bytes(body))
    ):
        raise RenderCommandError("executor lock identity is forged")
    return {"ref": lock["ref"], "digest": lock["digest"]}


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


def _settle_or_unknown(*args: Any, **kwargs: Any) -> bool:
    try:
        _settle_result(*args, **kwargs)
        return True
    except Exception:
        print(
            "ambit-specialist-render: terminal result publication failed; host reconciliation required",
            file=sys.stderr,
        )
        return False


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

    with tempfile.TemporaryDirectory(prefix="ambit-specialist-render-", dir="/tmp") as temporary:
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--request", required=True)
    parser.add_argument("--result", required=True)
    return parser


def main(pack_root: Path, argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    roots: SemanticJobRoots | None = None
    try:
        job_root = _job_root_from_request_argument(arguments.request)
        roots = _semantic_job_roots(job_root)
        relative_request = PurePosixPath(arguments.request).relative_to(
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
        if arguments.request != f"{job_root}/{request['requestPath']}":
            raise RenderCommandError(
                "request argument differs from the exact request identity"
            )
        result_path = request["output"]["resultPath"]
        if arguments.result != f"{job_root}/{result_path}":
            raise RenderCommandError("result argument differs from the exact request")
    except (OSError, RenderCommandError) as error:
        if roots is not None:
            _close_semantic_job_roots(roots)
        print(f"ambit-specialist-render: invalid request: {error}", file=sys.stderr)
        return 64

    started_at = instant_now()
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
        return _render(
            pack_root, request, result_path, executor, started_at, roots
        )
    except ResultPublicationFailure:
        print(
            "ambit-specialist-render: terminal result publication failed; host reconciliation required",
            file=sys.stderr,
        )
        return 70
    except CommandCancelled:
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
            failure={"code": "deadline_exceeded", "message": "The specialist render deadline elapsed."},
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
                prefix="ambit-specialist-failure-", dir="/tmp"
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
        )
        return 1 if settled else 70
    except Exception as error:
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
        )
        return 1 if settled else 70
    finally:
        _close_semantic_job_roots(roots)
