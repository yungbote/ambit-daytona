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
import time
import tty
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


HELPER = Path("/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize")
WORKSPACE = Path("/workspace")
OUTPUT = Path(sys.argv[1]).resolve()
MAXIMUM_BYTES = 33_554_432
MAXIMUM_CHUNK = 65_536
MAXIMUM_PRE_READY = 65_536
TREE_DIRECTORY_MODE = 0o555
TREE_MAGIC = b"AMATTRE1"
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


def tree_archive(files: list[tuple[str, int, bytes]]) -> bytes:
    ordered = sorted(files, key=lambda entry: entry[0].encode("utf-8"))
    payload = bytearray(TREE_MAGIC + struct.pack(">I", len(ordered)))
    previous = b""
    for relative_path, mode, content in ordered:
        encoded_path = relative_path.encode("utf-8")
        assert encoded_path > previous
        assert mode in (0o444, 0o555)
        previous = encoded_path
        payload.extend(struct.pack(">I", len(encoded_path)))
        payload.extend(encoded_path)
        payload.extend(struct.pack(">I", mode))
        payload.extend(struct.pack(">Q", len(content)))
        payload.extend(hashlib.sha256(content).digest())
        payload.extend(content)
    return bytes(payload)


def frame_header(
    relative_path: str,
    payload: bytes,
    *,
    mode: int = 0o444,
    operation: str = "create_or_verify",
    expected_sha256: str | None = None,
    expected_helper_sha256: str | None = None,
    expected_bytes: int | None = None,
    artifact_kind: str = "file",
    expected_entry_count: int = 0,
) -> bytes:
    header = {
        "expectedBytes": len(payload) if expected_bytes is None else expected_bytes,
        "expectedHelperSha256": expected_helper_sha256 or HELPER_SHA256,
        "expectedSha256": expected_sha256 or digest(payload),
        "mode": mode,
        "operation": operation,
        "relativePath": relative_path,
        "version": 1,
        "workspaceRoot": "/workspace",
    }
    if artifact_kind == "tree":
        header.update(
            {
                "artifactKind": "tree",
                "expectedEntryCount": expected_entry_count,
                "version": 2,
            }
        )
    else:
        assert artifact_kind == "file" and expected_entry_count == 0
    return canonical(header)


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
    after_end: Callable[[Session], None] | None = None,
    artifact_kind: str = "file",
    expected_entry_count: int = 0,
    stop_after_end: bool = False,
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
        artifact_kind=artifact_kind,
        expected_entry_count=expected_entry_count,
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
    if after_end is not None:
        try:
            after_end(session)
        except BaseException:
            session.process.kill()
            session.process.wait(timeout=5)
            session.close()
            raise
    if stop_after_end:
        status = session.process.wait(timeout=10)
        session.close()
        return FramedResult(status, b"", b"")
    return session.response_from_magic(session.read_exact(8))


def assert_success(
    result: FramedResult,
    *,
    relative_path: str,
    payload: bytes,
    mode: int,
    operation: str,
    outcome: str,
    artifact_kind: str = "file",
    expected_entry_count: int = 0,
) -> dict[str, object]:
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
    assert result.stderr == b""
    receipt = json.loads(result.stdout)
    assert result.stdout == canonical(receipt)
    expected_body: dict[str, object] = {
        "bytes": len(payload),
        "helperSha256": HELPER_SHA256,
        "kind": (
            "ambit_atomic_tree_materialization_receipt"
            if artifact_kind == "tree"
            else "ambit_atomic_materialization_receipt"
        ),
        "mode": mode,
        "operation": operation,
        "outcome": outcome,
        "relativePath": relative_path,
        "sha256": digest(payload),
        "version": 1,
    }
    if artifact_kind == "tree":
        expected_body["entries"] = expected_entry_count
    else:
        assert expected_entry_count == 0
    body = {key: value for key, value in receipt.items() if key != "receiptRef"}
    assert body == expected_body
    body_digest = hashlib.sha256(canonical(expected_body)).hexdigest()
    receipt_prefix = (
        "atomic-tree-materialization-receipt"
        if artifact_kind == "tree"
        else "atomic-materialization-receipt"
    )
    assert receipt["receiptRef"] == f"{receipt_prefix}:sha256:{body_digest}"
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
missing_verify_receipt = assert_failure(missing_verify, 4)
assert missing_verify_receipt["code"] == "existing_mismatch", missing_verify_receipt
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

def wait_for_open_inode(session: Session, expected: os.stat_result) -> None:
    deadline = time.monotonic() + 10
    process_fd_root = Path(f"/proc/{session.process.pid}/fd")
    while time.monotonic() < deadline:
        try:
            descriptors = list(process_fd_root.iterdir())
        except FileNotFoundError:
            break
        for descriptor in descriptors:
            try:
                observed = descriptor.stat()
            except (FileNotFoundError, PermissionError):
                continue
            if observed.st_dev == expected.st_dev and observed.st_ino == expected.st_ino:
                return
        time.sleep(0.0001)
    raise AssertionError(
        f"helper did not pin expected inode {expected.st_dev}:{expected.st_ino} before response"
    )


race_path = "parent-race/artifact.bin"
race_marker = b"AMBIT_PARENT_RACE_PINNED_DIRFD_0123456789"
race_payload = race_marker + b"R" * (MAXIMUM_BYTES - len(race_marker))
race_created = invoke(race_path, race_payload)
assert_success(race_created, relative_path=race_path, payload=race_payload, mode=0o444, operation="create_or_verify", outcome="created")
race_entry = WORKSPACE / "parent-race"
race_saved = WORKSPACE / "parent-race-saved"
race_outside = outside_root / "parent-race"
race_outside.mkdir()


def move_parent_after_pin(session: Session) -> None:
    wait_for_open_inode(session, race_entry.stat())
    race_entry.rename(race_saved)
    race_entry.symlink_to(race_outside, target_is_directory=True)


parent_race_result = invoke(
    race_path,
    race_payload,
    operation="verify_only",
    after_end=move_parent_after_pin,
)
assert assert_failure(parent_race_result, 4)["code"] in ("path_race", "unsafe_path")
assert race_entry.is_symlink()
assert (race_saved / "artifact.bin").read_bytes() == race_payload
race_entry.unlink()
race_saved.rename(race_entry)
reconciled_parent_race = invoke(race_path, race_payload, operation="verify_only")
assert_success(reconciled_parent_race, relative_path=race_path, payload=race_payload, mode=0o444, operation="verify_only", outcome="already_identical")
ensure_file(race_path, race_payload, 0o444)
assert not any(race_outside.iterdir())
cases.append("concurrent_parent_move_after_dirfd_pin_reproof")

race_leaf = WORKSPACE / race_path
race_leaf_saved = race_entry / "artifact-saved.bin"


def move_final_after_pin(session: Session) -> None:
    wait_for_open_inode(session, race_leaf.stat())
    race_leaf.rename(race_leaf_saved)
    race_leaf.symlink_to(outside_final)


final_race_result = invoke(
    race_path,
    race_payload,
    operation="verify_only",
    after_end=move_final_after_pin,
)
assert assert_failure(final_race_result, 4)["code"] in ("path_race", "unsafe_path")
assert race_leaf.is_symlink()
assert race_leaf_saved.read_bytes() == race_payload
race_leaf.unlink()
race_leaf_saved.rename(race_leaf)
reconciled_final_race = invoke(race_path, race_payload, operation="verify_only")
assert_success(reconciled_final_race, relative_path=race_path, payload=race_payload, mode=0o444, operation="verify_only", outcome="already_identical")
ensure_file(race_path, race_payload, 0o444)
assert outside_final.read_bytes() == b"outside-sentinel"
assert not any(race_outside.iterdir())
cases.append("concurrent_final_symlink_swap_after_file_pin_reproof")

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
unknown_target = WORKSPACE / unknown_path
publication_deadline = time.monotonic() + 10
while not unknown_target.exists() and time.monotonic() < publication_deadline:
    time.sleep(0.001)
ensure_file(unknown_path, unknown_payload, 0o444)
os.close(unknown_session.fd)
unknown_session.fd = -1
unknown_process_status = unknown_session.process.wait(timeout=10)
# The exact inode is published before response loss. Depending on whether the
# helper wins the final response-write race, it exits successfully (0) or with
# an I/O failure (5). Input-truncation exit 3 remains rejected: that is a
# different, not-yet-committed case. The caller still treats the Action as
# outcome-unknown and only a new verify_only Action may reconcile custody.
assert unknown_process_status in (0, 5), unknown_process_status
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

tree_parent = WORKSPACE / "trees"
tree_parent.mkdir(mode=0o755)
tree_files = [
    (
        f"files/{index:04d}.bin",
        0o444,
        hashlib.sha256(str(index).encode()).digest() * 128,
    )
    for index in range(4096)
]
tree_payload = tree_archive(tree_files)
tree_path = "trees/provider-crash"
tree_stage = tree_parent / ".ambit-tree-stage-v1"
tree_prep = tree_parent / ".ambit-tree-stage-prep-v1"
tree_target = WORKSPACE / tree_path
tree_crash_observation: dict[str, int] = {}


def kill_after_positive_tree_prefix(session: Session) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert not tree_target.exists(), "tree published before crash injection"
        if tree_stage.is_dir():
            staged_bytes = sum(
                child.stat().st_size
                for child in tree_stage.rglob("*")
                if child.is_file()
            )
            if staged_bytes > 0:
                tree_crash_observation["stagedBytes"] = staged_bytes
                session.process.kill()
                return
        time.sleep(0.0005)
    raise AssertionError("tree stage did not expose a positive crash prefix")


crashed_tree = invoke(
    tree_path,
    tree_payload,
    mode=TREE_DIRECTORY_MODE,
    artifact_kind="tree",
    expected_entry_count=len(tree_files),
    after_end=kill_after_positive_tree_prefix,
    stop_after_end=True,
)
assert crashed_tree.returncode < 0, crashed_tree
assert tree_crash_observation["stagedBytes"] > 0
assert tree_stage.is_dir() and not tree_target.exists()
recoverable_tree = invoke(
    tree_path,
    tree_payload,
    mode=TREE_DIRECTORY_MODE,
    operation="verify_only",
    artifact_kind="tree",
    expected_entry_count=len(tree_files),
)
assert_success(
    recoverable_tree,
    relative_path=tree_path,
    payload=tree_payload,
    mode=TREE_DIRECTORY_MODE,
    operation="verify_only",
    outcome="recoverable_stage",
    artifact_kind="tree",
    expected_entry_count=len(tree_files),
)
resumed_tree = invoke(
    tree_path,
    tree_payload,
    mode=TREE_DIRECTORY_MODE,
    artifact_kind="tree",
    expected_entry_count=len(tree_files),
)
assert_success(
    resumed_tree,
    relative_path=tree_path,
    payload=tree_payload,
    mode=TREE_DIRECTORY_MODE,
    operation="create_or_verify",
    outcome="created",
    artifact_kind="tree",
    expected_entry_count=len(tree_files),
)
verified_tree = invoke(
    tree_path,
    tree_payload,
    mode=TREE_DIRECTORY_MODE,
    operation="verify_only",
    artifact_kind="tree",
    expected_entry_count=len(tree_files),
)
assert_success(
    verified_tree,
    relative_path=tree_path,
    payload=tree_payload,
    mode=TREE_DIRECTORY_MODE,
    operation="verify_only",
    outcome="already_identical",
    artifact_kind="tree",
    expected_entry_count=len(tree_files),
)
assert len(list((tree_target / "files").iterdir())) == len(tree_files)
assert not tree_stage.exists() and not tree_prep.exists()
expected_tree_intent = hashlib.sha256(
    ("ambit-atomic-tree-intent/v1\n" + tree_path + "\n" + digest(tree_payload)).encode()
).digest()
assert os.getxattr(tree_target, "user.ambit.tree-intent-v1") == expected_tree_intent
workspace_mount = next(
    line.rstrip("\n")
    for line in Path("/proc/self/mountinfo").read_text().splitlines()
    if len(line.split()) > 4 and line.split()[4] == "/workspace"
)
cases.extend(
    [
        "tree_closed_world_4096_files",
        "tree_sigkill_positive_prefix_recovery",
        "tree_user_xattr_actual_filesystem",
        "tree_renameat2_noreplace_actual_filesystem",
    ]
)

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
            "schema": "ambit.atomic-materializer-conformance.v2",
            "outcome": "passed",
            "helperPath": str(HELPER),
            "helperSha256": HELPER_SHA256,
            "maximumBytes": MAXIMUM_BYTES,
            "maximumChunkBytes": MAXIMUM_CHUNK,
            "maximumPreReadyBytes": MAXIMUM_PRE_READY,
            "protocolDigest": "sha256:1274e0bb27dfb15d9d7564d71fc02a7117631b405de73d84f39defb415a5f7ad",
            "treeProtocolDigest": "sha256:2c3e58eedfa0d268c9844c038baa49d2f896c4f42de783a5d3ee1762d5828e4d",
            "publication": "O_TMPFILE_linkat_AT_EMPTY_PATH_no_replace",
            "treePublication": "complete_staged_tree_renameat2_RENAME_NOREPLACE",
            "treeCrashStagedBytes": tree_crash_observation["stagedBytes"],
            "treeEntryCount": len(tree_files),
            "workspaceMountInfo": workspace_mount,
            "workspaceRoot": "/workspace",
            "reconnect": "never_replay_reconcile_with_new_verify_only",
            "postEndLostResponseProcessStatus": unknown_process_status,
            "cases": cases,
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
