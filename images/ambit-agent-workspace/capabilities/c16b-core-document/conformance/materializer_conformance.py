from __future__ import annotations

import errno
import hashlib
import json
import os
import pty
import select
import stat
import struct
import subprocess
import sys
import threading
import time
import tty
from dataclasses import dataclass
from pathlib import Path


HELPER = Path("/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize")
WORKSPACE = Path("/workspace")
OUTPUT = Path(sys.argv[1]).resolve()
MAXIMUM_BYTES = 33_554_432
MAXIMUM_CHUNK = 65_536
MAXIMUM_PRE_READY = 65_536
HELPER_SHA256 = f"sha256:{hashlib.sha256(HELPER.read_bytes()).hexdigest()}"
MAGICS = {
    "ready": b"AMATRDY1",
    "request": b"AMATREQ1",
    "header_ack": b"AMATHDR1",
    "data": b"AMATDAT1",
    "data_ack": b"AMATACK1",
    "end": b"AMATEND1",
    "result": b"AMATRES1",
    "error": b"AMATERR1",
}


@dataclass(frozen=True)
class FramedResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def frame_header(
    relative_path: str,
    payload: bytes,
    *,
    mode: int = 0o444,
    operation: str = "create_or_verify",
    expected_sha256: str | None = None,
    expected_helper_sha256: str | None = None,
    expected_bytes: int | None = None,
) -> bytes:
    return canonical(
        {
            "expectedBytes": len(payload) if expected_bytes is None else expected_bytes,
            "expectedHelperSha256": expected_helper_sha256 or HELPER_SHA256,
            "expectedSha256": expected_sha256 or digest(payload),
            "mode": mode,
            "operation": operation,
            "relativePath": relative_path,
            "version": 1,
            "workspaceRoot": "/workspace",
        }
    )


class Session:
    def __init__(self, *, output_prefix: bytes = b"") -> None:
        self.nonce = os.urandom(32)
        master, slave = pty.openpty()
        tty.setraw(slave)
        nonce_hex = self.nonce.hex()
        prefix_command = ""
        if output_prefix:
            assert set(output_prefix) == {ord("P")}
            prefix_command = f"printf '%0.sP' $(seq 1 {len(output_prefix)}) && "
        bootstrap = (
            f"{prefix_command}stty raw -echo && exec {HELPER} --framed-stream-v1 "
            f"--ready-nonce {nonce_hex}"
        )
        self.process = subprocess.Popen(
            ["/bin/sh", "-c", bootstrap],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        os.close(slave)
        self.fd = master
        try:
            self._accept_ready()
        except BaseException:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.close()
            raise

    @staticmethod
    def _write_fd(fd: int, payload: bytes) -> None:
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            assert written > 0
            offset += written

    def write(self, payload: bytes) -> None:
        self._write_fd(self.fd, payload)

    def read_exact(self, length: int, timeout: float = 10.0) -> bytes:
        deadline = time.monotonic() + timeout
        result = bytearray()
        while len(result) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out after {len(result)} of {length} bytes")
            readable, _, _ = select.select([self.fd], [], [], remaining)
            if not readable:
                raise TimeoutError(f"timed out after {len(result)} of {length} bytes")
            try:
                chunk = os.read(self.fd, length - len(result))
            except OSError as error:
                if error.errno == errno.EIO:
                    raise EOFError("PTY closed") from error
                raise
            if not chunk:
                raise EOFError("PTY closed")
            result.extend(chunk)
        return bytes(result)

    def _accept_ready(self) -> None:
        expected = MAGICS["ready"] + self.nonce
        observed = bytearray()
        while len(observed) < MAXIMUM_PRE_READY + len(expected):
            observed.extend(self.read_exact(1))
            if observed.endswith(expected):
                prefix = observed[: -len(expected)]
                assert len(prefix) <= MAXIMUM_PRE_READY
                return
        raise AssertionError("READY frame not found within bounded pre-ready output")

    def response_from_magic(self, magic: bytes) -> FramedResult:
        assert magic in (MAGICS["result"], MAGICS["error"]), magic
        length = struct.unpack(">I", self.read_exact(4))[0]
        assert 1 <= length <= 4096
        payload = self.read_exact(length)
        status = self.process.wait(timeout=10)
        self.close()
        if magic == MAGICS["result"]:
            return FramedResult(status, payload, b"")
        return FramedResult(status, b"", payload)

    def reattach(self) -> None:
        replacement = os.dup(self.fd)
        os.close(self.fd)
        self.fd = replacement

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def invoke(
    relative_path: str,
    payload: bytes,
    *,
    mode: int = 0o444,
    operation: str = "create_or_verify",
    expected_sha256: str | None = None,
    expected_helper_sha256: str | None = None,
    expected_bytes: int | None = None,
    header_split: int | None = None,
    chunk_split: bool = False,
    trailing: bytes = b"",
    output_prefix: bytes = b"",
    reattach: bool = False,
    inspect_after_bytes: int | None = None,
) -> FramedResult:
    session = Session(output_prefix=output_prefix)
    header = frame_header(
        relative_path,
        payload,
        mode=mode,
        operation=operation,
        expected_sha256=expected_sha256,
        expected_helper_sha256=expected_helper_sha256,
        expected_bytes=expected_bytes,
    )
    request = MAGICS["request"] + struct.pack(">I", len(header)) + header
    if header_split is None:
        session.write(request)
    else:
        session.write(request[:header_split])
        time.sleep(0.001)
        session.write(request[header_split:])
    first_magic = session.read_exact(8)
    if first_magic == MAGICS["error"]:
        return session.response_from_magic(first_magic)
    assert first_magic == MAGICS["header_ack"]
    assert session.read_exact(32) == hashlib.sha256(header).digest()
    if reattach:
        session.reattach()

    cumulative = 0
    for offset in range(0, len(payload), MAXIMUM_CHUNK):
        chunk = payload[offset : offset + MAXIMUM_CHUNK]
        data_frame = MAGICS["data"] + struct.pack(">I", len(chunk)) + chunk
        if chunk_split and len(chunk) > 1:
            split_at = 12 + len(chunk) // 2
            session.write(data_frame[:split_at])
            readable, _, _ = select.select([session.fd], [], [], 0.02)
            assert not readable, "helper ACKed a partial DATA frame"
            session.write(data_frame[split_at:])
        else:
            session.write(data_frame)
        ack_magic = session.read_exact(8)
        if ack_magic == MAGICS["error"]:
            return session.response_from_magic(ack_magic)
        assert ack_magic == MAGICS["data_ack"]
        cumulative += len(chunk)
        assert struct.unpack(">Q", session.read_exact(8))[0] == cumulative
        if inspect_after_bytes is not None and cumulative >= inspect_after_bytes:
            marker = payload[:48]
            assert marker not in Path(f"/proc/{session.process.pid}/cmdline").read_bytes()
            assert marker not in Path(f"/proc/{session.process.pid}/environ").read_bytes()
            assert not (WORKSPACE / relative_path).exists()
            inspect_after_bytes = None

    declared_sha = expected_sha256 or digest(payload)
    raw_digest = bytes.fromhex(declared_sha.removeprefix("sha256:"))
    end = MAGICS["end"] + struct.pack(">Q", len(payload) if expected_bytes is None else expected_bytes) + raw_digest
    session.write(end + trailing)
    return session.response_from_magic(session.read_exact(8))


def assert_success(
    result: FramedResult,
    *,
    relative_path: str,
    payload: bytes,
    mode: int,
    operation: str,
    outcome: str,
) -> dict[str, object]:
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert result.stderr == b""
    receipt = json.loads(result.stdout)
    assert result.stdout == canonical(receipt)
    expected_body = {
        "bytes": len(payload),
        "helperSha256": HELPER_SHA256,
        "kind": "ambit_atomic_materialization_receipt",
        "mode": mode,
        "operation": operation,
        "outcome": outcome,
        "relativePath": relative_path,
        "sha256": digest(payload),
        "version": 1,
    }
    body = {key: value for key, value in receipt.items() if key != "receiptRef"}
    assert body == expected_body
    body_digest = hashlib.sha256(canonical(expected_body)).hexdigest()
    assert receipt["receiptRef"] == f"atomic-materialization-receipt:sha256:{body_digest}"
    return receipt


def assert_failure(result: FramedResult, expected_exit: int) -> dict[str, object]:
    assert result.returncode == expected_exit, (result.returncode, result.stdout, result.stderr)
    assert result.stdout == b""
    receipt = json.loads(result.stderr)
    assert result.stderr == canonical(receipt)
    assert list(receipt) == ["code", "kind", "relativePath", "version"]
    assert receipt["kind"] == "ambit_atomic_materialization_error"
    assert receipt["version"] == 1
    assert b"/workspace" not in result.stderr
    return receipt


def ensure_file(relative_path: str, payload: bytes, mode: int) -> None:
    target = WORKSPACE / relative_path
    assert target.is_file() and not target.is_symlink()
    assert target.read_bytes() == payload
    assert stat.S_IMODE(target.stat().st_mode) == mode


WORKSPACE.mkdir(mode=0o755, exist_ok=True)
assert HELPER.is_file() and stat.S_IMODE(HELPER.stat().st_mode) == 0o555
cases: list[str] = []

primary_path = "artifacts/reports/project-brief.docx"
primary_payload = bytes(range(256)) * 4
for operation, outcome in (
    ("create_or_verify", "created"),
    ("create_or_verify", "already_identical"),
    ("verify_only", "already_identical"),
):
    result = invoke(primary_path, primary_payload, operation=operation, output_prefix=b"P" * 1024)
    assert_success(
        result,
        relative_path=primary_path,
        payload=primary_payload,
        mode=0o444,
        operation=operation,
        outcome=outcome,
    )
ensure_file(primary_path, primary_payload, 0o444)
cases.extend(["all_256_raw_byte_values", "create_and_idempotent_verify", "bounded_pre_ready_discard"])

try:
    Session(output_prefix=b"P" * (MAXIMUM_PRE_READY + 1))
except AssertionError:
    pass
else:
    raise AssertionError("pre-READY output beyond the frozen bound was accepted")
cases.append("over_bound_pre_ready_output_rejected")

empty_path = "artifacts/empty.bin"
empty = invoke(empty_path, b"")
assert_success(empty, relative_path=empty_path, payload=b"", mode=0o444, operation="create_or_verify", outcome="created")
ensure_file(empty_path, b"", 0o444)
one_path = "artifacts/one.bin"
one = invoke(one_path, b"\x04", reattach=True)
assert_success(one, relative_path=one_path, payload=b"\x04", mode=0o444, operation="create_or_verify", outcome="created")
cases.extend(["zero_and_one_byte_frames", "same_session_fd_reattach"])

missing_verify = invoke("verify-only/missing.bin", b"missing", operation="verify_only")
assert assert_failure(missing_verify, 4)["code"] == "existing_mismatch"
assert not (WORKSPACE / "verify-only").exists()
safe_create = invoke("verify-only/missing.bin", b"missing", operation="create_or_verify")
assert_success(safe_create, relative_path="verify-only/missing.bin", payload=b"missing", mode=0o444, operation="create_or_verify", outcome="created")
ensure_file("verify-only/missing.bin", b"missing", 0o444)
mismatch = invoke(primary_path, b"different")
assert_failure(mismatch, 4)
assert (WORKSPACE / primary_path).read_bytes() == primary_payload
attacker_file = WORKSPACE / "attacker-owned.bin"
attacker_file.write_bytes(b"attacker-owned")
attacker_file.chmod(0o444)
assert_failure(invoke("attacker-owned.bin", b"replacement"), 4)
assert attacker_file.read_bytes() == b"attacker-owned"
bad_digest = invoke("rejected/input.bin", b"payload", expected_sha256=f"sha256:{'0' * 64}")
assert_failure(bad_digest, 3)
bad_helper = invoke("rejected/helper.bin", b"payload", expected_helper_sha256=f"sha256:{'0' * 64}")
assert_failure(bad_helper, 4)
assert not (WORKSPACE / "rejected").exists()
invalid_path = invoke("../outside.bin", b"unsafe")
assert assert_failure(invalid_path, 2)["relativePath"] is None
cases.extend(["missing_verify_then_safe_create_reconciliation", "mismatch_no_overwrite_or_attacker_deletion", "input_and_helper_preflight", "unsafe_path_denial"])

unicode_path = "unicode/<>&\u2028-artifact.bin"
unicode_payload = b"canonical-json"
unicode_result = invoke(unicode_path, unicode_payload, mode=0o555)
assert_success(unicode_result, relative_path=unicode_path, payload=unicode_payload, mode=0o555, operation="create_or_verify", outcome="created")
ensure_file(unicode_path, unicode_payload, 0o555)
cases.append("backend_strict_canonical_utf8_json")

outside_root = OUTPUT / "materializer-outside"
outside_root.mkdir(mode=0o755)
outside_final = outside_root / "sentinel"
outside_final.write_bytes(b"outside-sentinel")
(WORKSPACE / "symlink-parent").symlink_to(outside_root, target_is_directory=True)
assert_failure(invoke("symlink-parent/escape.bin", b"escape"), 4)
final_parent = WORKSPACE / "final-symlink"
final_parent.mkdir()
(final_parent / "artifact.bin").symlink_to(outside_final)
assert_failure(invoke("final-symlink/artifact.bin", b"escape"), 4)
hardlink_parent = WORKSPACE / "hardlink"
hardlink_parent.mkdir()
hardlink_source = hardlink_parent / "source.bin"
hardlink_source.write_bytes(b"hardlink")
hardlink_source.chmod(0o444)
os.link(hardlink_source, hardlink_parent / "artifact.bin")
assert_failure(invoke("hardlink/artifact.bin", b"hardlink"), 4)
assert outside_final.read_bytes() == b"outside-sentinel"
assert not (outside_root / "escape.bin").exists()
cases.extend(["parent_and_final_symlink_denial", "hardlink_denial"])

race_path = "parent-race/artifact.bin"
race_payload = b"parent-race-content"
race_created = invoke(race_path, race_payload)
assert_success(race_created, relative_path=race_path, payload=race_payload, mode=0o444, operation="create_or_verify", outcome="created")
race_entry = WORKSPACE / "parent-race"
race_saved = WORKSPACE / "parent-race-saved"
race_outside = outside_root / "parent-race"
race_outside.mkdir()
stop_parent_race = threading.Event()


def swap_parent() -> None:
    while not stop_parent_race.is_set():
        try:
            if race_entry.exists() and not race_entry.is_symlink():
                race_entry.rename(race_saved)
            if not race_entry.exists() and not race_entry.is_symlink():
                race_entry.symlink_to(race_outside, target_is_directory=True)
            if race_entry.is_symlink():
                race_entry.unlink()
            if race_saved.exists() and not race_entry.exists():
                race_saved.rename(race_entry)
        except (FileExistsError, FileNotFoundError):
            pass


parent_thread = threading.Thread(target=swap_parent, daemon=True)
parent_thread.start()
parent_race_statuses: list[int] = []
for index in range(20):
    operation = "verify_only" if index % 2 else "create_or_verify"
    result = invoke(race_path, race_payload, operation=operation)
    assert result.returncode in (0, 4), (result.returncode, result.stderr)
    parent_race_statuses.append(result.returncode)
    if result.returncode == 0:
        assert_success(result, relative_path=race_path, payload=race_payload, mode=0o444, operation=operation, outcome="already_identical")
    else:
        assert assert_failure(result, 4)["code"] in ("path_race", "unsafe_path")
stop_parent_race.set()
parent_thread.join(timeout=5)
if race_entry.is_symlink():
    race_entry.unlink()
if race_saved.exists():
    assert not race_entry.exists()
    race_saved.rename(race_entry)
ensure_file(race_path, race_payload, 0o444)
assert not any(race_outside.iterdir())
assert 4 in parent_race_statuses
cases.append("concurrent_parent_move_symlink_reproof")

final_race_parent = WORKSPACE / "final-race"
final_race_parent.mkdir()
final_race_leaf = final_race_parent / "artifact.bin"
stop_final_race = threading.Event()


def swap_final() -> None:
    while not stop_final_race.is_set():
        try:
            final_race_leaf.symlink_to(outside_final)
        except FileExistsError:
            if final_race_leaf.is_symlink():
                final_race_leaf.unlink()
            else:
                return


final_thread = threading.Thread(target=swap_final, daemon=True)
final_thread.start()
final_race_payload = b"final-race-content"
final_race_result = invoke("final-race/artifact.bin", final_race_payload)
assert final_race_result.returncode in (0, 4), (final_race_result.returncode, final_race_result.stderr)
stop_final_race.set()
final_thread.join(timeout=5)
if final_race_leaf.is_symlink():
    final_race_leaf.unlink()
if final_race_result.returncode == 0:
    assert_success(final_race_result, relative_path="final-race/artifact.bin", payload=final_race_payload, mode=0o444, operation="create_or_verify", outcome="created")
    ensure_file("final-race/artifact.bin", final_race_payload, 0o444)
else:
    assert assert_failure(final_race_result, 4)["code"] in ("path_race", "unsafe_path")
assert outside_final.read_bytes() == b"outside-sentinel"
cases.append("concurrent_final_symlink_swap_no_escape")

split_payload = b"S"
split_path = "framing/every-header-split.bin"
created_split = invoke(split_path, split_payload)
assert_success(created_split, relative_path=split_path, payload=split_payload, mode=0o444, operation="create_or_verify", outcome="created")
split_header = frame_header(split_path, split_payload, operation="verify_only")
split_request_length = 12 + len(split_header)
for split_at in range(1, split_request_length):
    split_result = invoke(split_path, split_payload, operation="verify_only", header_split=split_at)
    assert_success(split_result, relative_path=split_path, payload=split_payload, mode=0o444, operation="verify_only", outcome="already_identical")
cases.append("every_request_header_byte_split")

slow_path = "framing/slow-chunk.bin"
slow_payload = bytes(range(256)) * 300
slow = invoke(slow_path, slow_payload, chunk_split=True)
assert_success(slow, relative_path=slow_path, payload=slow_payload, mode=0o444, operation="create_or_verify", outcome="created")
cases.append("ack_gated_slow_chunk_backpressure")

extra_path = "framing/extra.bin"
extra = invoke(extra_path, b"exact", trailing=b"unexpected")
assert_failure(extra, 3)
assert not (WORKSPACE / extra_path).exists()
cases.append("coalesced_post_end_bytes_rejected")

out_of_order_session = Session()
out_header = frame_header("framing/out-of-order.bin", b"x")
out_of_order_session.write(MAGICS["request"] + struct.pack(">I", len(out_header)) + out_header)
assert out_of_order_session.read_exact(8) == MAGICS["header_ack"]
assert out_of_order_session.read_exact(32) == hashlib.sha256(out_header).digest()
out_of_order_session.write(MAGICS["end"] + struct.pack(">Q", 1) + hashlib.sha256(b"x").digest())
out_of_order = out_of_order_session.response_from_magic(out_of_order_session.read_exact(8))
assert_failure(out_of_order, 3)
assert not (WORKSPACE / "framing/out-of-order.bin").exists()
cases.append("out_of_order_end_rejected")

unknown_path = "framing/outcome-unknown.bin"
unknown_payload = b"committed-before-response-loss"
unknown_session = Session()
unknown_header = frame_header(unknown_path, unknown_payload)
unknown_session.write(MAGICS["request"] + struct.pack(">I", len(unknown_header)) + unknown_header)
assert unknown_session.read_exact(8) == MAGICS["header_ack"]
assert unknown_session.read_exact(32) == hashlib.sha256(unknown_header).digest()
unknown_session.write(MAGICS["data"] + struct.pack(">I", len(unknown_payload)) + unknown_payload)
assert unknown_session.read_exact(8) == MAGICS["data_ack"]
assert struct.unpack(">Q", unknown_session.read_exact(8))[0] == len(unknown_payload)
unknown_session.write(MAGICS["end"] + struct.pack(">Q", len(unknown_payload)) + hashlib.sha256(unknown_payload).digest())
os.close(unknown_session.fd)
unknown_session.fd = -1
assert unknown_session.process.wait(timeout=10) == 5
reconciled = invoke(unknown_path, unknown_payload, operation="verify_only")
assert_success(reconciled, relative_path=unknown_path, payload=unknown_payload, mode=0o444, operation="verify_only", outcome="already_identical")
ensure_file(unknown_path, unknown_payload, 0o444)
cases.append("lost_response_reconciled_new_verify_only_no_replay")

truncated_session = Session()
truncated_header = frame_header("framing/truncated.bin", b"truncated")
truncated_session.write(MAGICS["request"] + struct.pack(">I", len(truncated_header)) + truncated_header)
assert truncated_session.read_exact(8) == MAGICS["header_ack"]
truncated_session.read_exact(32)
truncated_session.write(MAGICS["data"] + struct.pack(">I", 9) + b"half")
os.close(truncated_session.fd)
truncated_session.fd = -1
assert truncated_session.process.wait(timeout=10) == 3
assert not (WORKSPACE / "framing/truncated.bin").exists()
cases.append("truncated_abort_no_mutation")

transport_path = "transport/max-channel.bin"
marker = b"AMBIT_PAYLOAD_NOT_IN_ARGV_ENV_OR_STAGING_01234567"
transport_payload = marker + b"M" * (MAXIMUM_BYTES - len(marker))
transport = invoke(
    transport_path,
    transport_payload,
    inspect_after_bytes=MAXIMUM_BYTES // 2,
)
assert_success(transport, relative_path=transport_path, payload=transport_payload, mode=0o444, operation="create_or_verify", outcome="created")
ensure_file(transport_path, transport_payload, 0o444)
cases.append("full_32mib_framed_pty_no_argv_env_staging")

(OUTPUT / "materializer-receipt.json").write_text(
    json.dumps(
        {
            "schema": "ambit.atomic-materializer-conformance.v1",
            "outcome": "passed",
            "helperPath": str(HELPER),
            "helperSha256": HELPER_SHA256,
            "maximumBytes": MAXIMUM_BYTES,
            "maximumChunkBytes": MAXIMUM_CHUNK,
            "maximumPreReadyBytes": MAXIMUM_PRE_READY,
            "protocolDigest": "sha256:1274e0bb27dfb15d9d7564d71fc02a7117631b405de73d84f39defb415a5f7ad",
            "publication": "O_TMPFILE_linkat_AT_EMPTY_PATH_no_replace",
            "workspaceRoot": "/workspace",
            "reconnect": "never_replay_reconcile_with_new_verify_only",
            "cases": cases,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
