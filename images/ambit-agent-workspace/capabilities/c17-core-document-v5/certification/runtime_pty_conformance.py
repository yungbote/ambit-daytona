#!/usr/bin/env python3
"""Exercise the exact document renderer through a real Docker PTY."""

from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import secrets
import select
import signal
import subprocess
import termios
import time
import tty
from pathlib import Path
from typing import Any


SCHEMA = "ambit.runtime-interface/docx-paginated-render-jsonl@1"
CHUNK_BYTES = 49_152
MAXIMUM_LINE_BYTES = 70_000
QUIESCENCE = "all-render-process-groups-settled-and-private-roots-removed"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def line(value: Any) -> bytes:
    encoded = canonical_bytes(value) + b"\n"
    if len(encoded) > MAXIMUM_LINE_BYTES:
        raise ValueError("conformance frame exceeds the interface line bound")
    return encoded


def sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def request_lines(document: bytes, nonce: str) -> list[bytes]:
    document_digest = sha256(document)
    chunk_count = (len(document) + CHUNK_BYTES - 1) // CHUNK_BYTES
    lineage = {
        "schemaRef": "ambit.backend-contract/runtime-component-lineage@conformance",
        "ref": "runtime-component-lineage:real-pty-conformance",
        "digest": f"sha256:{'1' * 64}",
        "canonicalBytesSha256": f"sha256:{'2' * 64}",
    }
    frames = [
        {
            "schema": SCHEMA,
            "kind": "request_start",
            "nonce": nonce,
            "backendLineage": lineage,
            "documentBytes": len(document),
            "documentSha256": document_digest,
            "chunkBytes": CHUNK_BYTES,
            "chunkCount": chunk_count,
        }
    ]
    for index in range(chunk_count):
        body = document[index * CHUNK_BYTES : (index + 1) * CHUNK_BYTES]
        frames.append(
            {
                "schema": SCHEMA,
                "kind": "document_chunk",
                "nonce": nonce,
                "index": index,
                "bytes": len(body),
                "sha256": sha256(body),
                "base64": base64.b64encode(body).decode("ascii"),
            }
        )
    frames.append(
        {
            "schema": SCHEMA,
            "kind": "request_end",
            "nonce": nonce,
            "documentBytes": len(document),
            "documentSha256": document_digest,
            "chunkCount": chunk_count,
        }
    )
    return [line(frame) for frame in frames]


class PtyProcess:
    def __init__(self, image: str, nonce: str, name: str) -> None:
        master, slave = os.openpty()
        tty.setraw(master)
        tty.setraw(slave)
        attributes = termios.tcgetattr(slave)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attributes)
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "-t",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--tmpfs",
            "/workspace:rw,noexec,nosuid,nodev,size=800m,uid=1000,gid=1000,mode=0700",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700",
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            "stty raw -echo -onlcr && exec "
            "/opt/ambit/runtime-pack/core-document-v5/bin/ambit-render-document "
            f"--framed-jsonl --nonce {nonce}",
        ]
        self.master = master
        self.pending = bytearray()
        self.process = subprocess.Popen(
            command,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
        )
        os.close(slave)
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def write(self, value: bytes, timeout: float = 10.0) -> None:
        cursor = 0
        deadline = time.monotonic() + timeout
        while cursor < len(value):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("PTY input write timed out")
            _, writable, _ = select.select([], [self.master], [], remaining)
            if not writable:
                continue
            cursor += os.write(self.master, value[cursor:])

    def _read(self, timeout: float) -> bool:
        readable, _, _ = select.select([self.master], [], [], timeout)
        if not readable:
            return False
        try:
            chunk = os.read(self.master, 65_536)
        except OSError as error:
            if error.errno == errno.EIO:
                return False
            raise
        if not chunk:
            return False
        self.pending.extend(chunk)
        if len(self.pending) > MAXIMUM_LINE_BYTES * 2:
            raise ValueError("PTY conformance buffer exceeded the protocol bound")
        return True

    def read_line(self, timeout: float = 30.0) -> bytes | None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                newline = self.pending.index(0x0A)
            except ValueError:
                newline = -1
            if newline >= 0:
                value = bytes(self.pending[:newline])
                del self.pending[: newline + 1]
                return value
            if len(self.pending) > MAXIMUM_LINE_BYTES:
                raise ValueError("PTY response line exceeded the protocol bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            if not self._read(remaining) and self.process.poll() is not None:
                if self.pending:
                    raise ValueError("PTY response ended with a partial frame")
                return None

    def wait(self, timeout: float = 30.0) -> int:
        return self.process.wait(timeout=timeout)

    def close(self) -> None:
        try:
            os.close(self.master)
        except OSError:
            pass

    def terminate(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.close()


def decode_frame(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAXIMUM_LINE_BYTES or b"\r" in raw:
        raise ValueError("PTY frame delimiters or bounds are invalid")
    value = json.loads(raw.decode("utf-8"))
    if canonical_bytes(value) != raw or not isinstance(value, dict):
        raise ValueError("PTY frame is not exact canonical UTF-8 JSON")
    return value


def read_ready(process: PtyProcess, nonce: str, interface_digest: str) -> None:
    raw = process.read_line(30)
    if raw is None:
        raise RuntimeError("renderer omitted its ready frame")
    ready = decode_frame(raw)
    if (
        ready.get("schema") != SCHEMA
        or ready.get("kind") != "ready"
        or ready.get("nonce") != nonce
        or ready.get("cancellationExitCode") != 130
        or ready.get("chunkBytes") != CHUNK_BYTES
        or ready.get("interface", {}).get("digest") != interface_digest
    ):
        raise ValueError("renderer ready identity differs")


def validate_success(lines: list[bytes], nonce: str) -> None:
    frames = [decode_frame(raw) for raw in lines]
    if not frames or frames[-1].get("kind") != "response_end":
        raise ValueError("successful PTY run omitted response_end")
    terminal = frames[-1]
    preceding = lines[:-1]
    if (
        terminal.get("nonce") != nonce
        or terminal.get("outcome") != "passed"
        or terminal.get("exitCode") != 0
        or terminal.get("frameCount") != len(preceding)
        or terminal.get("streamSha256")
        != sha256(b"".join(raw + b"\n" for raw in preceding))
    ):
        raise ValueError("successful PTY terminal aggregate differs")
    page_roster: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    manifest = bytearray()
    manifest_start: dict[str, Any] | None = None
    for frame in frames[:-1]:
        if frame.get("nonce") != nonce or frame.get("schema") != SCHEMA:
            raise ValueError("PTY response nonce or schema differs")
        kind = frame.get("kind")
        if kind == "page_start":
            if current is not None:
                raise ValueError("PTY page frames overlap")
            current = {"evidence": frame["page"], "chunks": bytearray(), "next": 0}
        elif kind == "page_chunk":
            if (
                current is None
                or frame.get("chunkIndex") != current["next"]
                or frame.get("pageIndex") != current["evidence"]["index"]
            ):
                raise ValueError("PTY page chunk order differs")
            body = base64.b64decode(frame["base64"], validate=True)
            if len(body) != frame.get("bytes") or sha256(body) != frame.get("sha256"):
                raise ValueError("PTY page chunk evidence differs")
            current["chunks"].extend(body)
            current["next"] += 1
            if current["next"] == (
                current["evidence"]["bytes"] + CHUNK_BYTES - 1
            ) // CHUNK_BYTES:
                body = bytes(current["chunks"])
                if (
                    len(body) != current["evidence"]["bytes"]
                    or sha256(body) != current["evidence"]["sha256"]
                ):
                    raise ValueError("PTY page aggregate differs")
                page_roster.append(current["evidence"])
                current = None
        elif kind == "manifest_start":
            if current is not None or manifest_start is not None:
                raise ValueError("PTY manifest order differs")
            manifest_start = frame
        elif kind == "manifest_chunk":
            if (
                manifest_start is None
                or frame.get("chunkIndex")
                != (len(manifest) + CHUNK_BYTES - 1) // CHUNK_BYTES
            ):
                raise ValueError("PTY manifest chunk precedes its start")
            body = base64.b64decode(frame["base64"], validate=True)
            if len(body) != frame.get("bytes") or sha256(body) != frame.get("sha256"):
                raise ValueError("PTY manifest chunk evidence differs")
            manifest.extend(body)
        else:
            raise ValueError(f"unexpected PTY success frame: {kind}")
    if current is not None or manifest_start is None:
        raise ValueError("PTY success stream is structurally incomplete")
    manifest_value = json.loads(bytes(manifest).decode("utf-8"))
    if bytes(manifest) != canonical_bytes(manifest_value) + b"\n":
        raise ValueError("PTY manifest bytes are not canonical")
    manifest_digest = manifest_value.get("manifestDigest")
    manifest_ref = manifest_value.get("manifestRef")
    manifest_body = {
        key: value
        for key, value in manifest_value.items()
        if key not in {"manifestDigest", "manifestRef"}
    }
    if (
        len(manifest) != manifest_start.get("bytes")
        or sha256(bytes(manifest)) != manifest_start.get("sha256")
        or manifest_value.get("pages") != page_roster
        or manifest_digest != sha256(canonical_bytes(manifest_body))
        or manifest_ref != f"runtime-paginated-render-manifest:{manifest_digest}"
        or manifest_digest != terminal.get("manifestDigest")
        or terminal.get("manifestBytes") != len(manifest)
        or terminal.get("manifestSha256") != sha256(bytes(manifest))
        or len(page_roster) != terminal.get("pageCount")
        or sum(page["bytes"] for page in page_roster)
        != terminal.get("totalOutputBytes")
    ):
        raise ValueError("PTY manifest or terminal evidence differs")


def run_case(
    *,
    image: str,
    document: bytes,
    interface_digest: str,
    mode: str,
) -> dict[str, Any]:
    nonce = secrets.token_hex(16)
    name = f"ambit-c17-pty-{mode}-{secrets.token_hex(4)}"
    process = PtyProcess(image, nonce, name)
    lines: list[bytes] = []
    try:
        read_ready(process, nonce, interface_digest)
        if mode == "error":
            process.write(b" " + line({"schema": SCHEMA, "kind": "cancel", "nonce": nonce}))
        else:
            for encoded in request_lines(document, nonce):
                process.write(encoded)
            if mode in {"cancel", "backpressure"}:
                if mode == "backpressure":
                    time.sleep(1.0)
                process.write(line({"schema": SCHEMA, "kind": "cancel", "nonce": nonce}))
        while True:
            raw = process.read_line(180)
            if raw is None:
                break
            lines.append(raw)
            decode_frame(raw)
        code = process.wait(30)
        if mode == "success":
            if code != 0:
                raise ValueError(f"successful PTY render exited {code}")
            validate_success(lines, nonce)
        elif mode == "cancel":
            frames = [decode_frame(raw) for raw in lines]
            if (
                code != 130
                or not frames
                or frames[-1].get("kind") != "cancelled"
                or any(frame.get("kind") == "response_end" for frame in frames)
            ):
                raise ValueError("explicit PTY cancellation did not have one exact terminal")
            terminal = frames[-1]
            if terminal != {
                "schema": SCHEMA,
                "kind": "cancelled",
                "nonce": nonce,
                "outcome": "cancelled",
                "exitCode": 130,
                "quiescence": QUIESCENCE,
            }:
                raise ValueError("explicit PTY cancellation terminal differs")
        elif mode == "error":
            if code != 1 or lines or process.pending:
                raise ValueError("invalid PTY input did not fail silently and closed")
        else:
            if any(decode_frame(raw).get("kind") == "response_end" for raw in lines):
                raise ValueError("backpressured cancellation emitted a success terminal")
            if code not in {1, 130}:
                raise ValueError("backpressured cancellation exit is not fail-closed")
            if code == 130:
                terminals = [decode_frame(raw) for raw in lines if decode_frame(raw).get("kind") == "cancelled"]
                if len(terminals) != 1 or terminals[0].get("quiescence") != QUIESCENCE:
                    raise ValueError("typed backpressure cancellation lacks quiescence")
        return {
            "mode": mode,
            "exitCode": code,
            "frameCount": len(lines),
            "terminalKind": decode_frame(lines[-1]).get("kind") if lines else None,
        }
    finally:
        process.terminate()
        deadline = time.monotonic() + 2
        while True:
            residue = subprocess.run(
                ["docker", "inspect", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if residue.returncode != 0 or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        if residue.returncode == 0:
            subprocess.run(
                ["docker", "rm", "-f", name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            raise RuntimeError(f"PTY conformance container remained: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--document", type=Path, required=True)
    parser.add_argument("--interface-digest", required=True)
    parser.add_argument(
        "--mode",
        choices=("all", "backpressure", "cancel", "error", "success"),
        default="all",
    )
    args = parser.parse_args()
    document = args.document.read_bytes()
    if not document:
        raise ValueError("PTY conformance document is empty")
    modes = (
        ("success", "cancel", "error", "backpressure")
        if args.mode == "all"
        else (args.mode,)
    )
    results = [
        run_case(
            image=args.image,
            document=document,
            interface_digest=args.interface_digest,
            mode=mode,
        )
        for mode in modes
    ]
    print(
        json.dumps(
            {
                "schema": "ambit.runtime-pack-document-real-pty-conformance/v1",
                "outcome": "passed",
                "image": args.image,
                "interfaceDigest": args.interface_digest,
                "results": results,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
