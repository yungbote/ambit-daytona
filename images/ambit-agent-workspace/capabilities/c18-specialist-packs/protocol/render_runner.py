from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import signal
import stat
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
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


AMBIT_ROOT = Path("/ambit")
INPUT_ROOT = AMBIT_ROOT / "inputs"
OUTPUT_ROOT = AMBIT_ROOT / "outputs"
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


def _deadline_monotonic(deadline_at: str) -> float:
    deadline = datetime.fromisoformat(deadline_at.replace("Z", "+00:00"))
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    if remaining <= 0:
        raise CommandDeadlineExceeded
    return time.monotonic() + remaining


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise CommandDeadlineExceeded


def _absolute_protocol_path(value: str, zone: Path) -> Path:
    target = AMBIT_ROOT / value
    try:
        target.relative_to(zone)
    except ValueError as error:
        raise RenderCommandError(f"protocol path escapes {zone}") from error
    return target


def _require_nonsymlink_chain(path: Path, root: Path, *, final_may_be_absent: bool) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise RenderCommandError("path escapes its semantic root") from error
    current = root
    root_status = root.lstat()
    if not stat.S_ISDIR(root_status.st_mode) or stat.S_ISLNK(root_status.st_mode):
        raise RenderCommandError("semantic root is not a real directory")
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if final_may_be_absent:
                return
            raise RenderCommandError("protocol path component is absent")
        if stat.S_ISLNK(metadata.st_mode):
            raise RenderCommandError("protocol path contains a symlink")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise RenderCommandError("protocol path parent is not a directory")


def _copy_exact_source(request: dict[str, Any], destination: Path, deadline: float) -> None:
    source = _absolute_protocol_path(request["source"]["path"], INPUT_ROOT)
    _require_nonsymlink_chain(source, INPUT_ROOT, final_may_be_absent=False)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != request["source"]["byteLength"]:
            raise RenderCommandError("source is not the exact bounded regular file")
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
                    raise RenderCommandError("source grew beyond its declared byte length")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        after = os.fstat(descriptor)
        identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if (
            copied != request["source"]["byteLength"]
            or "sha256:" + digest.hexdigest() != request["source"]["digest"]
            or identity_before != identity_after
        ):
            raise RenderCommandError("source bytes or identity differ from the request")
    finally:
        os.close(descriptor)


def _make_output_directory(path: Path) -> None:
    try:
        relative = path.relative_to(OUTPUT_ROOT)
    except ValueError as error:
        raise RenderCommandError("output directory escapes its semantic root") from error
    current = OUTPUT_ROOT
    _require_nonsymlink_chain(OUTPUT_ROOT, OUTPUT_ROOT, final_may_be_absent=False)
    for part in relative.parts:
        current /= part
        try:
            os.mkdir(current, mode=0o700)
        except FileExistsError:
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise RenderCommandError("output parent is not a real directory")


def _atomic_publish(path: Path, payload: bytes) -> None:
    _make_output_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise RenderCommandError("output target already exists")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o400)
        os.link(temporary, path, follow_symlinks=False)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_publish_file(source: Path, target: Path, scratch: Path) -> dict[str, Any]:
    source = source.resolve(strict=True)
    try:
        source.relative_to(scratch.resolve(strict=True))
    except ValueError as error:
        raise RenderCommandError("evidence artifact escapes task scratch") from error
    metadata = source.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > MAXIMUM_EVIDENCE_ARTIFACT_BYTES
    ):
        raise RenderCommandError("evidence artifact is not a bounded regular file")
    _make_output_directory(target.parent)
    if target.exists() or target.is_symlink():
        raise RenderCommandError("evidence artifact target already exists")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    copied = 0
    try:
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
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        ):
            raise RenderCommandError("evidence artifact changed during custody copy")
        os.chmod(temporary, 0o400)
        os.link(temporary, target, follow_symlinks=False)
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
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
                target = _absolute_protocol_path(relative, OUTPUT_ROOT)
                identity = _atomic_publish_file(source_path, target, scratch)
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
        target = _absolute_protocol_path(relative, OUTPUT_ROOT)
        _atomic_publish(target, payload)
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
    result_path: Path,
    executor: dict[str, str],
    started_at: str,
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
    _atomic_publish(result_path, canonical_bytes(result))
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
    result_path: Path,
    executor: dict[str, str],
    started_at: str,
) -> int:
    deadline = _deadline_monotonic(request["deadlineAt"])
    adapter = _load_adapter(pack_root)

    with tempfile.TemporaryDirectory(prefix="ambit-specialist-render-", dir="/tmp") as temporary:
        local_source = Path(temporary) / ("source" + Path(request["source"]["path"]).suffix)
        _copy_exact_source(request, local_source, deadline)
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
        checks = _write_evidence(request, executor, proofs, Path(temporary))
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
        preview_path = _absolute_protocol_path(request["output"]["previewPath"], OUTPUT_ROOT)
        _atomic_publish(preview_path, preview_bytes)
        _check_deadline(deadline)
        try:
            _settle_result(
                request,
                result_path,
                executor,
                started_at,
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
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    return parser


def main(pack_root: Path, argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        _require_nonsymlink_chain(arguments.request, INPUT_ROOT, final_may_be_absent=False)
        request_metadata = arguments.request.lstat()
        if (
            not stat.S_ISREG(request_metadata.st_mode)
            or request_metadata.st_size < 1
            or request_metadata.st_size > MAXIMUM_COMMAND_BYTES
        ):
            raise RenderCommandError("request file is not a bounded regular file")
        request_bytes = arguments.request.read_bytes()
        request = parse_request_bytes(request_bytes)
        require_request_policy(request)
        result_path = _absolute_protocol_path(request["output"]["resultPath"], OUTPUT_ROOT)
        if arguments.result != result_path:
            raise RenderCommandError("result argument differs from the exact request")
        _require_nonsymlink_chain(result_path.parent, OUTPUT_ROOT, final_may_be_absent=True)
    except (OSError, RenderCommandError) as error:
        print(f"ambit-specialist-render: invalid request: {error}", file=sys.stderr)
        return 64

    started_at = instant_now()
    try:
        executor = _load_executor(pack_root, request["facet"])
    except (OSError, json.JSONDecodeError, RenderCommandError) as error:
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
        return _render(pack_root, request, result_path, executor, started_at)
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
                    outcomes={bound_check: "failed"},
                )
        settled = _settle_or_unknown(
            request,
            result_path,
            executor,
            started_at,
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
            outcome="failed",
            checks=[],
            preview=None,
            failure={
                "code": "renderer_failed",
                "message": "The specialist renderer failed before producing a safe preview.",
            },
        )
        return 1 if settled else 70
