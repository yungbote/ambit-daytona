from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, BinaryIO, Iterable, Iterator


FRAME_SCHEMA = "ambit.runtime-interface/specialist-render-jsonl@1"
INTERFACE_REF = "ambit.runtime-interface/specialist-render@1"
RAW_CHUNK_BYTES = 49_152
MAXIMUM_FRAME_LINE_BYTES = 70_000
MAXIMUM_REQUEST_BYTES = 2 * 1024 * 1024
MAXIMUM_SOURCE_BYTES = 512 * 1024 * 1024
MAXIMUM_RESPONSE_FILES = 128
MAXIMUM_RESPONSE_BYTES = 512 * 1024 * 1024
NONCE = re.compile(r"^[0-9a-f]{32}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
MEDIA_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$"
)
ROLE = frozenset({"artifact", "evidence", "preview", "result"})


class FramedRenderError(ValueError):
    """A C18 framed-render peer violated the exact transport contract."""


class FramedRenderCancelled(RuntimeError):
    """The exact nonce-bound transport peer cancelled before success commit."""


@dataclass(frozen=True)
class CollectedRequest:
    request_bytes: int
    request_sha256: str
    source_bytes: int
    source_sha256: str


@dataclass(frozen=True)
class CollectedResponseFile:
    ordinal: int
    role: str
    path: str
    media_type: str
    payload: bytes
    digest: str


@dataclass(frozen=True)
class CollectedResponse:
    terminal: dict[str, Any]
    files: tuple[CollectedResponseFile, ...]


def _require(condition: object, message: str) -> None:
    if not condition:
        raise FramedRenderError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as error:
        raise FramedRenderError("framed value is not strict JSON") from error


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def exact_nonce(value: object) -> str:
    _require(isinstance(value, str) and NONCE.fullmatch(value), "framed nonce is invalid")
    return value


def exact_digest(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and SHA256.fullmatch(value),
        f"{label} is not an exact SHA-256",
    )
    return value


def _exact_record(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == fields, f"{label} fields are invalid")
    return value


def _positive_integer(value: object, label: str, maximum: int) -> int:
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= maximum,
        f"{label} exceeds its bound",
    )
    return value


def _nonnegative_integer(value: object, label: str, maximum: int) -> int:
    _require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= maximum,
        f"{label} exceeds its bound",
    )
    return value


def chunk_count(byte_length: int) -> int:
    return (byte_length + RAW_CHUNK_BYTES - 1) // RAW_CHUNK_BYTES


def frame_line(value: object) -> bytes:
    encoded = canonical_bytes(value) + b"\n"
    _require(len(encoded) <= MAXIMUM_FRAME_LINE_BYTES, "framed line exceeds its byte bound")
    return encoded


def decode_line(value: bytes) -> dict[str, Any]:
    _require(
        isinstance(value, bytes)
        and 0 < len(value) <= MAXIMUM_FRAME_LINE_BYTES
        and b"\r" not in value
        and b"\n" not in value,
        "framed line delimiter or size is invalid",
    )

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise FramedRenderError("framed line contains a duplicate JSON key")
            result[key] = item
        return result

    try:
        text = value.decode("utf-8", errors="strict")
        parsed = json.loads(text, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FramedRenderError("framed line is not exact UTF-8 JSON") from error
    _require(isinstance(parsed, dict), "framed line is not an object")
    _require(canonical_bytes(parsed) == value, "framed line is not canonical JSON")
    return parsed


def read_line(stream: BinaryIO) -> bytes:
    value = stream.readline(MAXIMUM_FRAME_LINE_BYTES + 2)
    _require(value != b"", "framed transport closed before request completion")
    _require(value.endswith(b"\n"), "framed transport line has no LF terminator")
    line = value[:-1]
    _require(
        len(value) <= MAXIMUM_FRAME_LINE_BYTES,
        "framed transport line exceeds its byte bound",
    )
    return line


def _decode_payload(value: object, expected_bytes: int) -> bytes:
    _require(isinstance(value, str) and value, "framed payload is not base64")
    _require(
        len(value) <= ((RAW_CHUNK_BYTES + 2) // 3) * 4,
        "framed base64 exceeds its bound",
    )
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise FramedRenderError("framed payload is not canonical base64") from error
    _require(
        len(decoded) == expected_bytes
        and base64.b64encode(decoded).decode("ascii") == value,
        "framed payload is not canonical base64",
    )
    return decoded


def _pinned(value: object, label: str) -> dict[str, str]:
    record = _exact_record(value, {"digest", "ref"}, label)
    _require(
        isinstance(record["ref"], str)
        and 0 < len(record["ref"]) <= 512
        and (":" in record["ref"] or "@" in record["ref"]),
        f"{label} ref is invalid",
    )
    return {
        "ref": record["ref"],
        "digest": exact_digest(record["digest"], f"{label} digest"),
    }


def _process_identity(value: object) -> dict[str, object]:
    record = _exact_record(value, {"pid", "startTicks"}, "process identity")
    pid = _positive_integer(record["pid"], "process pid", 2**31 - 1)
    _require(
        isinstance(record["startTicks"], str)
        and record["startTicks"].isdigit()
        and record["startTicks"] != "0",
        "process start ticks are invalid",
    )
    return {"pid": pid, "startTicks": record["startTicks"]}


def _request_identity(value: object) -> dict[str, str]:
    record = _exact_record(value, {"digest", "jobRef", "jobRoot"}, "request identity")
    _require(
        isinstance(record["jobRef"], str)
        and record["jobRef"].startswith("ambit://artifact-render-jobs/")
        and isinstance(record["jobRoot"], str)
        and record["jobRoot"].startswith("/workspace/.ambit/render-jobs/"),
        "response request identity is invalid",
    )
    return {
        "digest": exact_digest(record["digest"], "response request digest"),
        "jobRef": record["jobRef"],
        "jobRoot": record["jobRoot"],
    }


def _safe_response_path(value: object) -> str:
    _require(
        isinstance(value, str)
        and len(value.encode("utf-8")) <= 128
        and value.startswith("outputs/")
        and PurePosixPath(value).as_posix() == value
        and "\\" not in value
        and ":" not in value
        and all(part not in {"", ".", ".."} for part in PurePosixPath(value).parts),
        "response path is invalid",
    )
    return value


def _media_type(value: object) -> str:
    _require(
        isinstance(value, str)
        and MEDIA_TYPE.fullmatch(value)
        and 0 < len(value) <= 128,
        "response media type is invalid",
    )
    return value


class FramedResponseCollector:
    def __init__(
        self,
        *,
        nonce: str,
        interface: dict[str, str],
        executor: dict[str, str],
        executable: str,
        request: dict[str, str],
        provider_process_identity: dict[str, object] | None = None,
    ) -> None:
        self._nonce = exact_nonce(nonce)
        self._interface = _pinned(interface, "expected interface")
        self._executor = _pinned(executor, "expected executor")
        _require(
            isinstance(executable, str) and executable.startswith("/opt/ambit/runtime-pack/"),
            "expected executable is invalid",
        )
        self._executable = executable
        self._request = _request_identity(request)
        self._provider_process = (
            None
            if provider_process_identity is None
            else _process_identity(provider_process_identity)
        )
        self._process: dict[str, object] | None = None
        self._ready: dict[str, Any] | None = None
        self._state = "ready"
        self._response_start: dict[str, Any] | None = None
        self._current: dict[str, Any] | None = None
        self._files: list[CollectedResponseFile] = []
        self._paths: set[str] = set()
        self._stream_digest = hashlib.sha256()
        self._frame_count = 0
        self._declared_file_count = 0
        self._declared_total_bytes = 0
        self._projected_bytes = 0
        self._last_role: str | None = None

    @property
    def ready_frame(self) -> dict[str, Any]:
        _require(self._ready is not None, "framed ready has not been admitted")
        return dict(self._ready)

    def accept(self, line: bytes) -> CollectedResponse | None:
        _require(self._state != "complete", "framed response has data after terminal")
        frame = decode_line(line)
        if self._state == "ready":
            self._accept_ready(frame)
            return None
        kind = frame.get("kind")
        if kind == "cancelled":
            return self._accept_cancelled(frame)
        if kind == "response_start":
            self._accept_response_start(frame, line)
            return None
        if kind == "file_start":
            self._accept_file_start(frame, line)
            return None
        if kind == "file_chunk":
            self._accept_file_chunk(frame, line)
            return None
        if kind == "response_end":
            return self._accept_response_end(frame)
        raise FramedRenderError("framed response kind or order is invalid")

    def _accept_ready(self, value: object) -> None:
        frame = _exact_record(
            value,
            {
                "cancellationExitCode",
                "chunkBytes",
                "executable",
                "executorRevision",
                "interface",
                "kind",
                "nonce",
                "processIdentity",
                "schema",
            },
            "ready",
        )
        process = _process_identity(frame["processIdentity"])
        _require(
            frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "ready"
            and frame["nonce"] == self._nonce
            and frame["chunkBytes"] == RAW_CHUNK_BYTES
            and frame["cancellationExitCode"] == 130
            and _pinned(frame["interface"], "ready interface") == self._interface
            and _pinned(frame["executorRevision"], "ready executor") == self._executor
            and frame["executable"] == self._executable
            and (
                self._provider_process is None
                or process == self._provider_process
            ),
            "ready identity differs",
        )
        self._process = process
        self._ready = frame
        self._state = "response"

    def _record_stream_frame(self, line: bytes) -> None:
        self._stream_digest.update(line + b"\n")
        self._frame_count += 1

    def _accept_response_start(self, value: object, line: bytes) -> None:
        frame = _exact_record(
            value,
            {
                "executorRevision",
                "exitCode",
                "fileCount",
                "kind",
                "nonce",
                "outcome",
                "request",
                "resultDigest",
                "schema",
                "totalBytes",
            },
            "response_start",
        )
        file_count = _positive_integer(
            frame["fileCount"], "response file count", MAXIMUM_RESPONSE_FILES
        )
        total_bytes = _positive_integer(
            frame["totalBytes"], "response total bytes", MAXIMUM_RESPONSE_BYTES
        )
        outcome = frame["outcome"]
        exit_code = frame["exitCode"]
        _require(
            self._response_start is None
            and self._current is None
            and not self._files
            and frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "response_start"
            and frame["nonce"] == self._nonce
            and _pinned(frame["executorRevision"], "response executor")
            == self._executor
            and _request_identity(frame["request"]) == self._request
            and exact_digest(frame["resultDigest"], "response result digest")
            and (
                (outcome == "succeeded" and exit_code == 0)
                or (outcome == "failed" and exit_code in {1, 124})
            ),
            "response_start identity or order differs",
        )
        self._declared_file_count = file_count
        self._declared_total_bytes = total_bytes
        self._response_start = frame
        self._record_stream_frame(line)

    def _accept_file_start(self, value: object, line: bytes) -> None:
        frame = _exact_record(
            value,
            {
                "byteLength",
                "chunkBytes",
                "chunkCount",
                "kind",
                "mediaType",
                "nonce",
                "ordinal",
                "path",
                "role",
                "schema",
                "sha256",
            },
            "file_start",
        )
        ordinal = _positive_integer(
            frame["ordinal"], "response file ordinal", MAXIMUM_RESPONSE_FILES
        )
        byte_length = _positive_integer(
            frame["byteLength"], "response file bytes", MAXIMUM_RESPONSE_BYTES
        )
        chunk_total = _positive_integer(
            frame["chunkCount"],
            "response file chunk count",
            chunk_count(MAXIMUM_RESPONSE_BYTES),
        )
        path = _safe_response_path(frame["path"])
        role = frame["role"]
        _require(role in ROLE, "response file role is invalid")
        if ordinal == 1:
            role_order = role == "result"
        elif role == "preview":
            role_order = self._last_role == "result"
        elif role == "evidence":
            role_order = self._last_role in {"result", "preview", "evidence"}
        else:
            role_order = role == "artifact" and self._last_role in {
                "result",
                "preview",
                "evidence",
                "artifact",
            }
        _require(
            self._response_start is not None
            and self._current is None
            and ordinal == len(self._files) + 1
            and ordinal <= self._declared_file_count
            and path not in self._paths
            and role_order
            and frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "file_start"
            and frame["nonce"] == self._nonce
            and frame["chunkBytes"] == RAW_CHUNK_BYTES
            and chunk_total == chunk_count(byte_length)
            and self._projected_bytes + byte_length <= self._declared_total_bytes,
            "file_start identity, order, or bounds differ",
        )
        self._projected_bytes += byte_length
        self._paths.add(path)
        self._last_role = role
        self._current = {
            "ordinal": ordinal,
            "role": role,
            "path": path,
            "mediaType": _media_type(frame["mediaType"]),
            "byteLength": byte_length,
            "sha256": exact_digest(frame["sha256"], "response file digest"),
            "chunkCount": chunk_total,
            "next": 0,
            "payload": bytearray(),
        }
        self._record_stream_frame(line)

    def _accept_file_chunk(self, value: object, line: bytes) -> None:
        frame = _exact_record(
            value,
            {
                "base64",
                "bytes",
                "chunkIndex",
                "kind",
                "nonce",
                "ordinal",
                "schema",
                "sha256",
            },
            "file_chunk",
        )
        current = self._current
        _require(current is not None, "file_chunk has no active file")
        index = _nonnegative_integer(
            frame["chunkIndex"], "response chunk index", current["chunkCount"]
        )
        remaining = current["byteLength"] - current["next"] * RAW_CHUNK_BYTES
        expected_bytes = min(RAW_CHUNK_BYTES, remaining)
        claimed_bytes = _positive_integer(
            frame["bytes"], "response chunk bytes", RAW_CHUNK_BYTES
        )
        _require(
            frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "file_chunk"
            and frame["nonce"] == self._nonce
            and frame["ordinal"] == current["ordinal"]
            and index == current["next"]
            and index < current["chunkCount"]
            and claimed_bytes == expected_bytes,
            "file_chunk identity, order, or bounds differ",
        )
        payload = _decode_payload(frame["base64"], claimed_bytes)
        _require(
            sha256_bytes(payload)
            == exact_digest(frame["sha256"], "response chunk digest"),
            "response chunk digest differs",
        )
        current["payload"].extend(payload)
        current["next"] += 1
        if current["next"] == current["chunkCount"]:
            body = bytes(current["payload"])
            _require(
                len(body) == current["byteLength"]
                and sha256_bytes(body) == current["sha256"],
                "response file aggregate differs",
            )
            self._files.append(
                CollectedResponseFile(
                    ordinal=current["ordinal"],
                    role=current["role"],
                    path=current["path"],
                    media_type=current["mediaType"],
                    payload=body,
                    digest=current["sha256"],
                )
            )
            self._current = None
        self._record_stream_frame(line)

    def _accept_response_end(self, value: object) -> CollectedResponse:
        frame = _exact_record(
            value,
            {
                "executorRevision",
                "exitCode",
                "fileCount",
                "frameCount",
                "kind",
                "nonce",
                "outcome",
                "privateRootCleanup",
                "processIdentity",
                "request",
                "resultDigest",
                "schema",
                "streamSha256",
                "terminalSelection",
                "totalBytes",
            },
            "response_end",
        )
        start = self._response_start
        shared = (
            "executorRevision",
            "exitCode",
            "fileCount",
            "outcome",
            "request",
            "resultDigest",
            "totalBytes",
        )
        _require(
            start is not None
            and self._current is None
            and frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "response_end"
            and frame["nonce"] == self._nonce
            and all(frame[key] == start[key] for key in shared)
            and frame["frameCount"] == self._frame_count
            and frame["streamSha256"]
            == "sha256:" + self._stream_digest.hexdigest()
            and _process_identity(frame["processIdentity"]) == self._process
            and frame["privateRootCleanup"] == "completed"
            and frame["terminalSelection"] == "helper-selected"
            and len(self._files) == self._declared_file_count
            and self._projected_bytes == self._declared_total_bytes
            and sum(len(item.payload) for item in self._files)
            == self._declared_total_bytes,
            "response_end identity or aggregate differs",
        )
        self._state = "complete"
        return CollectedResponse(frame, tuple(self._files))

    def _accept_cancelled(self, value: object) -> CollectedResponse:
        frame = _exact_record(
            value,
            {
                "executorRevision",
                "exitCode",
                "kind",
                "nonce",
                "outcome",
                "privateRootCleanup",
                "processIdentity",
                "schema",
                "terminalSelection",
            },
            "cancelled",
        )
        _require(
            frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "cancelled"
            and frame["nonce"] == self._nonce
            and frame["outcome"] == "cancelled"
            and frame["exitCode"] == 130
            and _pinned(frame["executorRevision"], "cancelled executor")
            == self._executor
            and _process_identity(frame["processIdentity"]) == self._process
            and frame["privateRootCleanup"] == "completed"
            and frame["terminalSelection"] == "helper-selected",
            "cancelled terminal identity differs",
        )
        self._state = "complete"
        return CollectedResponse(frame, tuple())


class FramedRequestCollector:
    def __init__(self, nonce: str, request_sink: BinaryIO, source_sink: BinaryIO) -> None:
        self._nonce = exact_nonce(nonce)
        self._request_sink = request_sink
        self._source_sink = source_sink
        self._request_digest = hashlib.sha256()
        self._source_digest = hashlib.sha256()
        self._state = "start"
        self._request_bytes = 0
        self._source_bytes = 0
        self._request_sha256 = ""
        self._source_sha256 = ""
        self._request_chunks = 0
        self._source_chunks = 0
        self._next_request = 0
        self._next_source = 0

    def accept(self, line: bytes) -> CollectedRequest | None:
        _require(self._state != "complete", "framed request has data after request_end")
        frame = decode_line(line)
        if frame.get("kind") == "cancel":
            admit_cancel_frame(frame, self._nonce)
            raise FramedRenderCancelled
        if self._state == "start":
            self._accept_start(frame)
            return None
        if frame.get("kind") == "request_chunk":
            self._accept_chunk(frame, request=True)
            return None
        if frame.get("kind") == "source_chunk":
            self._accept_chunk(frame, request=False)
            return None
        if frame.get("kind") == "request_end":
            return self._accept_end(frame)
        raise FramedRenderError("framed request kind or order is invalid")

    def _accept_start(self, value: object) -> None:
        frame = _exact_record(
            value,
            {
                "chunkBytes",
                "kind",
                "nonce",
                "requestBytes",
                "requestChunkCount",
                "requestSha256",
                "schema",
                "sourceBytes",
                "sourceChunkCount",
                "sourceSha256",
            },
            "request_start",
        )
        request_bytes = _positive_integer(
            frame["requestBytes"], "framed request bytes", MAXIMUM_REQUEST_BYTES
        )
        source_bytes = _positive_integer(
            frame["sourceBytes"], "framed source bytes", MAXIMUM_SOURCE_BYTES
        )
        request_chunks = _positive_integer(
            frame["requestChunkCount"],
            "framed request chunk count",
            chunk_count(MAXIMUM_REQUEST_BYTES),
        )
        source_chunks = _positive_integer(
            frame["sourceChunkCount"],
            "framed source chunk count",
            chunk_count(MAXIMUM_SOURCE_BYTES),
        )
        _require(
            frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "request_start"
            and frame["nonce"] == self._nonce
            and frame["chunkBytes"] == RAW_CHUNK_BYTES
            and request_chunks == chunk_count(request_bytes)
            and source_chunks == chunk_count(source_bytes),
            "request_start identity or bounds are invalid",
        )
        self._request_bytes = request_bytes
        self._source_bytes = source_bytes
        self._request_sha256 = exact_digest(frame["requestSha256"], "request digest")
        self._source_sha256 = exact_digest(frame["sourceSha256"], "source digest")
        self._request_chunks = request_chunks
        self._source_chunks = source_chunks
        self._state = "request"

    def _accept_chunk(self, value: object, *, request: bool) -> None:
        kind = "request_chunk" if request else "source_chunk"
        frame = _exact_record(
            value,
            {"base64", "bytes", "index", "kind", "nonce", "schema", "sha256"},
            kind,
        )
        expected_state = "request" if request else "source"
        if not request and self._state == "request" and self._next_request == self._request_chunks:
            self._state = "source"
        _require(self._state == expected_state, f"{kind} order is invalid")
        next_index = self._next_request if request else self._next_source
        total_chunks = self._request_chunks if request else self._source_chunks
        total_bytes = self._request_bytes if request else self._source_bytes
        index = _nonnegative_integer(frame["index"], f"{kind} index", total_chunks)
        remaining = total_bytes - next_index * RAW_CHUNK_BYTES
        expected_bytes = min(RAW_CHUNK_BYTES, remaining)
        claimed_bytes = _positive_integer(frame["bytes"], f"{kind} bytes", RAW_CHUNK_BYTES)
        _require(
            frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == kind
            and frame["nonce"] == self._nonce
            and index == next_index
            and index < total_chunks
            and claimed_bytes == expected_bytes,
            f"{kind} identity, order, or bounds are invalid",
        )
        decoded = _decode_payload(frame["base64"], claimed_bytes)
        _require(
            sha256_bytes(decoded) == exact_digest(frame["sha256"], f"{kind} digest"),
            f"{kind} digest differs",
        )
        if request:
            self._request_sink.write(decoded)
            self._request_digest.update(decoded)
            self._next_request += 1
        else:
            self._source_sink.write(decoded)
            self._source_digest.update(decoded)
            self._next_source += 1

    def _accept_end(self, value: object) -> CollectedRequest:
        frame = _exact_record(
            value,
            {
                "kind",
                "nonce",
                "requestBytes",
                "requestChunkCount",
                "requestSha256",
                "schema",
                "sourceBytes",
                "sourceChunkCount",
                "sourceSha256",
            },
            "request_end",
        )
        _require(
            self._state in {"request", "source"}
            and frame["schema"] == FRAME_SCHEMA
            and frame["kind"] == "request_end"
            and frame["nonce"] == self._nonce
            and frame["requestBytes"] == self._request_bytes
            and frame["requestSha256"] == self._request_sha256
            and frame["requestChunkCount"] == self._request_chunks
            and frame["sourceBytes"] == self._source_bytes
            and frame["sourceSha256"] == self._source_sha256
            and frame["sourceChunkCount"] == self._source_chunks
            and self._next_request == self._request_chunks
            and self._next_source == self._source_chunks,
            "request_end aggregate or order is invalid",
        )
        observed_request = "sha256:" + self._request_digest.hexdigest()
        observed_source = "sha256:" + self._source_digest.hexdigest()
        _require(
            observed_request == self._request_sha256
            and observed_source == self._source_sha256,
            "framed request aggregate digest differs",
        )
        self._request_sink.flush()
        self._source_sink.flush()
        self._state = "complete"
        return CollectedRequest(
            request_bytes=self._request_bytes,
            request_sha256=observed_request,
            source_bytes=self._source_bytes,
            source_sha256=observed_source,
        )


def admit_cancel_frame(value: object, nonce: str) -> None:
    frame = _exact_record(value, {"kind", "nonce", "schema"}, "cancel")
    _require(
        frame == {"schema": FRAME_SCHEMA, "kind": "cancel", "nonce": exact_nonce(nonce)},
        "cancel frame identity differs",
    )


def payload_frames(kind: str, nonce: str, payload: bytes) -> Iterator[dict[str, object]]:
    _require(kind in {"request_chunk", "source_chunk"}, "request payload kind is invalid")
    exact_nonce(nonce)
    _positive_integer(len(payload), "request payload bytes", MAXIMUM_SOURCE_BYTES)
    for index in range(chunk_count(len(payload))):
        chunk = payload[index * RAW_CHUNK_BYTES : (index + 1) * RAW_CHUNK_BYTES]
        yield {
            "schema": FRAME_SCHEMA,
            "kind": kind,
            "nonce": nonce,
            "index": index,
            "bytes": len(chunk),
            "sha256": sha256_bytes(chunk),
            "base64": base64.b64encode(chunk).decode("ascii"),
        }


def request_frames(nonce: str, request: bytes, source: bytes) -> Iterator[dict[str, object]]:
    exact_nonce(nonce)
    _positive_integer(len(request), "request bytes", MAXIMUM_REQUEST_BYTES)
    _positive_integer(len(source), "source bytes", MAXIMUM_SOURCE_BYTES)
    request_digest = sha256_bytes(request)
    source_digest = sha256_bytes(source)
    request_chunks = chunk_count(len(request))
    source_chunks = chunk_count(len(source))
    yield {
        "schema": FRAME_SCHEMA,
        "kind": "request_start",
        "nonce": nonce,
        "chunkBytes": RAW_CHUNK_BYTES,
        "requestBytes": len(request),
        "requestSha256": request_digest,
        "requestChunkCount": request_chunks,
        "sourceBytes": len(source),
        "sourceSha256": source_digest,
        "sourceChunkCount": source_chunks,
    }
    yield from payload_frames("request_chunk", nonce, request)
    yield from payload_frames("source_chunk", nonce, source)
    yield {
        "schema": FRAME_SCHEMA,
        "kind": "request_end",
        "nonce": nonce,
        "requestBytes": len(request),
        "requestSha256": request_digest,
        "requestChunkCount": request_chunks,
        "sourceBytes": len(source),
        "sourceSha256": source_digest,
        "sourceChunkCount": source_chunks,
    }


class CanonicalFrameWriter:
    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._digest = hashlib.sha256()
        self._frame_count = 0

    @property
    def frame_count(self) -> int:
        return self._frame_count

    @property
    def stream_sha256(self) -> str:
        return "sha256:" + self._digest.copy().hexdigest()

    def write(self, value: object, *, aggregate: bool = True) -> bytes:
        line = frame_line(value)
        self._stream.write(line)
        self._stream.flush()
        if aggregate:
            self._digest.update(line)
            self._frame_count += 1
        return line


def response_file_start(
    *,
    nonce: str,
    ordinal: int,
    role: str,
    path: str,
    media_type: str,
    byte_length: int,
    digest: str,
) -> dict[str, object]:
    exact_nonce(nonce)
    _positive_integer(ordinal, "response file ordinal", MAXIMUM_RESPONSE_FILES)
    _require(role in ROLE, "response file role is invalid")
    path = _safe_response_path(path)
    media_type = _media_type(media_type)
    _positive_integer(byte_length, "response file bytes", MAXIMUM_RESPONSE_BYTES)
    return {
        "schema": FRAME_SCHEMA,
        "kind": "file_start",
        "nonce": nonce,
        "ordinal": ordinal,
        "role": role,
        "path": path,
        "mediaType": media_type,
        "byteLength": byte_length,
        "sha256": exact_digest(digest, "response file digest"),
        "chunkBytes": RAW_CHUNK_BYTES,
        "chunkCount": chunk_count(byte_length),
    }


def response_file_chunk(
    *, nonce: str, ordinal: int, chunk_index: int, payload: bytes
) -> dict[str, object]:
    exact_nonce(nonce)
    _positive_integer(ordinal, "response file ordinal", MAXIMUM_RESPONSE_FILES)
    _nonnegative_integer(chunk_index, "response chunk index", chunk_count(MAXIMUM_RESPONSE_BYTES))
    _positive_integer(len(payload), "response chunk bytes", RAW_CHUNK_BYTES)
    return {
        "schema": FRAME_SCHEMA,
        "kind": "file_chunk",
        "nonce": nonce,
        "ordinal": ordinal,
        "chunkIndex": chunk_index,
        "bytes": len(payload),
        "sha256": sha256_bytes(payload),
        "base64": base64.b64encode(payload).decode("ascii"),
    }


def encoded_lines(values: Iterable[object]) -> bytes:
    return b"".join(frame_line(value) for value in values)
