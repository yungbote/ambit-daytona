#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import secrets
import select
import signal
import subprocess
import sys
import termios
import time
import tty
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT / "protocol"))

from framed_render import (  # noqa: E402
    FRAME_SCHEMA,
    MAXIMUM_FRAME_LINE_BYTES,
    FramedResponseCollector,
    encoded_lines,
    frame_line,
    request_frames,
    sha256_bytes,
)
from public_preview import parse_preview_bytes  # noqa: E402
from render_command import (  # noqa: E402
    PREVIEW_MEDIA_TYPE,
    canonical_bytes,
    create_request,
    parse_check_evidence_bytes,
    parse_result_bytes,
)
from render_policy import POLICY_MATRIX  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def exact_policy(facet: str, media_type: str) -> dict[str, Any]:
    values = [
        entry
        for entry in POLICY_MATRIX["entries"]
        if entry["facet"] == facet and entry["sourceMediaType"] == media_type
    ]
    if len(values) != 1:
        raise ValueError("framed conformance policy is not unique")
    return values[0]


class PtyProcess:
    def __init__(
        self,
        *,
        image: str,
        pack: str,
        nonce: str,
        name: str,
        job_root: str,
        hostile: bool,
        seccomp: bytes,
    ) -> None:
        master, slave = os.openpty()
        tty.setraw(master)
        tty.setraw(slave)
        attributes = termios.tcgetattr(slave)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attributes)
        helper = f"/opt/ambit/runtime-pack/{pack}/bin/ambit-specialist-render"
        if hostile:
            prelude = (
                f"mkdir -p {job_root}/inputs {job_root}/outputs/render; "
                f"printf forged > {job_root}/inputs/request.json; "
                f"printf forged > {job_root}/inputs/source.bin; "
                f"printf forged > {job_root}/outputs/render/result.json; "
                f"(while :; do rm -f {job_root}/outputs/render/result.json "
                f"{job_root}/outputs/render/preview.json; "
                f"printf replaced > {job_root}/outputs/render/result.json; "
                "sleep 0.01; done) "
                ">/dev/null 2>&1 & "
            )
        else:
            prelude = ""
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
            "--pids-limit",
            "1024" if pack == "web-browser" else "512",
            "--memory",
            "6g" if pack == "web-browser" else "4g",
            "--cpus",
            "4",
            "--tmpfs",
            "/workspace:rw,noexec,nosuid,nodev,size=1g,uid=1000,gid=1000,mode=0700",
            "--tmpfs",
            "/tmp/ambit-task:rw,noexec,nosuid,nodev,size=2g,uid=1000,gid=1000,mode=0700",
        ]
        if pack == "web-browser":
            command.extend(["--shm-size", "1g"])
        seccomp_descriptor = os.memfd_create(
            "ambit-specialist-seccomp",
            flags=os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
        )
        os.write(seccomp_descriptor, seccomp)
        os.lseek(seccomp_descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(
            seccomp_descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE,
        )
        command.extend(
            ["--security-opt", f"seccomp=/proc/self/fd/{seccomp_descriptor}"]
        )
        command.extend(
            [
                "--entrypoint",
                "/bin/sh",
                image,
                "-c",
                prelude
                + "stty raw -echo -onlcr && exec "
                + helper
                + f" --framed-jsonl --nonce {nonce}",
            ]
        )
        self.command = command
        self.name = name
        self.master = master
        self.pending = bytearray()
        try:
            self.process = subprocess.Popen(
                command,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                close_fds=True,
                pass_fds=(seccomp_descriptor,),
            )
        finally:
            os.close(seccomp_descriptor)
        os.close(slave)
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def write(self, value: bytes, timeout: float = 30.0) -> None:
        cursor = 0
        deadline = time.monotonic() + timeout
        while cursor < len(value):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("framed PTY write timed out")
            _, writable, _ = select.select([], [self.master], [], remaining)
            if writable:
                cursor += os.write(self.master, value[cursor:])

    def read_line(self, timeout: float = 180.0) -> bytes | None:
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
            if len(self.pending) > MAXIMUM_FRAME_LINE_BYTES:
                raise ValueError("framed PTY response line exceeded its bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            readable, _, _ = select.select([self.master], [], [], remaining)
            if not readable:
                continue
            try:
                chunk = os.read(self.master, 65_536)
            except OSError as error:
                if error.errno == errno.EIO:
                    if self.pending:
                        raise ValueError("framed PTY ended with a partial line")
                    return None
                raise
            if not chunk:
                return None
            self.pending.extend(chunk)

    def wait(self, timeout: float = 30.0) -> int:
        return self.process.wait(timeout=timeout)

    def provider_launch_observation(self, timeout: float = 30.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        inspection: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            completed = subprocess.run(
                ["docker", "container", "inspect", self.name],
                capture_output=True,
                check=False,
            )
            if completed.returncode == 0:
                values = json.loads(completed.stdout)
                if isinstance(values, list) and len(values) == 1:
                    inspection = values[0]
                    if inspection.get("State", {}).get("Pid", 0) > 0:
                        break
            time.sleep(0.05)
        if inspection is None:
            raise RuntimeError("provider container inspection was unavailable")
        host_pid = inspection["State"]["Pid"]
        stat_text = Path(f"/proc/{host_pid}/stat").read_text(encoding="utf-8")
        close = stat_text.rfind(")")
        fields = stat_text[close + 2 :].strip().split(" ")
        start_ticks = fields[19]
        status = Path(f"/proc/{host_pid}/status").read_text(encoding="utf-8")
        namespace_pids = next(
            line.split()[1:] for line in status.splitlines() if line.startswith("NSpid:")
        )
        if namespace_pids[-1] != "1":
            raise RuntimeError("provider helper is not namespace PID 1")
        host = inspection.get("HostConfig", {})
        config = inspection.get("Config", {})
        if (
            host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("CapDrop") != ["ALL"]
            or "no-new-privileges" not in host.get("SecurityOpt", [])
            or config.get("Tty") is not True
            or config.get("OpenStdin") is not True
            or "/workspace" not in host.get("Tmpfs", {})
            or "/tmp/ambit-task" not in host.get("Tmpfs", {})
        ):
            raise RuntimeError("provider launch isolation differs")
        return {
            "imageId": inspection["Image"],
            "containerId": inspection["Id"],
            "hostPid": host_pid,
            "processIdentity": {"pid": 1, "startTicks": start_ticks},
            "mountNamespace": os.readlink(f"/proc/{host_pid}/ns/mnt"),
            "processNamespace": os.readlink(f"/proc/{host_pid}/ns/pid"),
            "networkMode": host["NetworkMode"],
            "readonlyRootfs": host["ReadonlyRootfs"],
            "capDrop": host["CapDrop"],
            "securityOpt": host["SecurityOpt"],
            "tmpfs": host["Tmpfs"],
        }

    def terminate(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        try:
            os.close(self.master)
        except OSError:
            pass


def request_for(
    *,
    pack: str,
    facet: str,
    media_type: str,
    source: bytes,
    source_name: str,
    job_id: str,
) -> dict[str, Any]:
    policy = exact_policy(facet, media_type)
    pack_lock = SOURCE_ROOT / pack / "pack.lock.json"
    job_root = f"/workspace/.ambit/render-jobs/{job_id}"
    return create_request(
        {
            "jobRef": f"ambit://artifact-render-jobs/{job_id}",
            "jobRoot": job_root,
            "requestPath": "inputs/request.json",
            "facet": facet,
            "source": {
                "path": f"inputs/{source_name}",
                "ref": "ambit://artifact-revisions/framed-runtime-conformance",
                "digest": sha256_bytes(source),
                "byteLength": len(source),
                "mediaType": media_type,
                "schemaUri": policy["requiredSchemaUri"],
            },
            "renderer": {
                key: policy[key]
                for key in (
                    "executablePath",
                    "rendererRef",
                    "validationPolicyRef",
                    "representation",
                    "renderMode",
                )
            },
            "runtime": {
                "workspaceExecutionManifest": {
                    "ref": "workspace-execution-manifest:sha256:" + "1" * 64,
                    "digest": "sha256:" + "2" * 64,
                },
                "profileRevision": {
                    "ref": "ambit.workspace-runtime/c18-framed-conformance@1",
                    "digest": "sha256:" + "3" * 64,
                },
                "packRevisions": [
                    {
                        "ref": str(policy["executorPackRevisionRef"]),
                        "digest": sha256_file(pack_lock),
                    }
                ],
            },
            "packRequiredChecks": policy["checkLabels"],
            "output": {
                "jobOutputRoot": "outputs/render",
                "previewPath": "outputs/render/preview.json",
                "resultPath": "outputs/render/result.json",
                "previewMediaType": PREVIEW_MEDIA_TYPE,
                "maximumPreviewBytes": 8 * 1024 * 1024,
                "maximumImagePixels": 8 * 1024 * 1024,
                "maximumAggregateImagePixels": 32 * 1024 * 1024,
            },
            "deadlineAt": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }
    )


def verify_semantic_response(
    request: dict[str, Any],
    terminal: dict[str, Any],
    collected_files: tuple[Any, ...],
) -> dict[str, bytes]:
    if terminal["kind"] == "cancelled":
        if collected_files:
            raise ValueError("cancelled response retained partial files")
        return {}
    files = {item.path: item.payload for item in collected_files}
    if len(files) != len(collected_files):
        raise ValueError("framed response file path is duplicated")
    result_path = request["output"]["resultPath"]
    result = parse_result_bytes(request, files[result_path])
    if result["digest"] != terminal["resultDigest"]:
        raise ValueError("framed terminal result digest differs")
    expected: list[tuple[str, str, str, int, str]] = [
        (
            "result",
            result_path,
            "application/vnd.ambit.c18-specialist-render-command-result+json",
            len(files[result_path]),
            sha256_bytes(files[result_path]),
        )
    ]
    if result["preview"] is not None:
        descriptor = result["preview"]
        payload = files[descriptor["path"]]
        if (
            len(payload) != descriptor["byteLength"]
            or sha256_bytes(payload) != descriptor["bytesDigest"]
            or parse_preview_bytes(payload)["digest"] != descriptor["envelopeDigest"]
        ):
            raise ValueError("framed preview identity differs")
        expected.append(
            (
                "preview",
                descriptor["path"],
                descriptor["mediaType"],
                descriptor["byteLength"],
                descriptor["bytesDigest"],
            )
        )
    artifacts: dict[str, tuple[str, int, str]] = {}
    for check in result["checks"]:
        descriptor = check["evidence"]
        if descriptor is None:
            continue
        payload = files[descriptor["path"]]
        if (
            len(payload) != descriptor["byteLength"]
            or sha256_bytes(payload) != descriptor["digest"]
        ):
            raise ValueError("framed evidence bytes differ")
        evidence = parse_check_evidence_bytes(payload)
        expected.append(
            (
                "evidence",
                descriptor["path"],
                descriptor["mediaType"],
                descriptor["byteLength"],
                descriptor["digest"],
            )
        )
        for artifact in evidence["artifacts"]:
            identity = (
                artifact["mediaType"],
                artifact["byteLength"],
                artifact["digest"],
            )
            current = artifacts.get(artifact["path"])
            if current is not None and current != identity:
                raise ValueError("framed artifact identity conflicts")
            artifacts[artifact["path"]] = identity
    for path in sorted(artifacts):
        media_type, byte_length, digest = artifacts[path]
        payload = files[path]
        if len(payload) != byte_length or sha256_bytes(payload) != digest:
            raise ValueError("framed artifact bytes differ")
        expected.append(("artifact", path, media_type, byte_length, digest))
    observed = [
        (item.role, item.path, item.media_type, len(item.payload), item.digest)
        for item in collected_files
    ]
    if observed != expected:
        raise ValueError("framed response contains missing, extra, or reordered files")
    return files


def run_case(args: argparse.Namespace, mode: str) -> dict[str, Any]:
    source = args.source.read_bytes()
    nonce = secrets.token_hex(16)
    job_id = str(uuid.uuid4())
    request = request_for(
        pack=args.pack,
        facet=args.facet,
        media_type=args.media_type,
        source=source,
        source_name="source" + args.source.suffix,
        job_id=job_id,
    )
    interface = json.loads(
        (SOURCE_ROOT / "protocol/specialist-render-interface.lock.json").read_text()
    )
    executor = json.loads((SOURCE_ROOT / args.pack / "executor.lock.json").read_text())
    image = subprocess.run(
        ["docker", "image", "inspect", args.image],
        capture_output=True,
        check=True,
    )
    image_values = json.loads(image.stdout)
    if (
        not isinstance(image_values, list)
        or len(image_values) != 1
        or image_values[0].get("Id") != args.image_config_digest
    ):
        raise ValueError("provider image config digest differs")
    if args.seccomp is None:
        raise ValueError("framed conformance requires exact provider seccomp")
    seccomp_bytes = args.seccomp.read_bytes()
    seccomp_digest = sha256_bytes(seccomp_bytes)
    expected_seccomp = json.loads(
        (SOURCE_ROOT / "web-browser/locks/toolchain.lock.json").read_text()
    )["sandbox"]["conformanceSeccompProfile"]["renderedSha256"]
    if seccomp_digest != expected_seccomp:
        raise ValueError("framed provider seccomp digest differs")
    name = f"ambit-c18-framed-{mode}-{secrets.token_hex(4)}"
    process = PtyProcess(
        image=args.image_config_digest,
        pack=args.pack,
        nonce=nonce,
        name=name,
        job_root=request["jobRoot"],
        hostile=mode == "hostile",
        seccomp=seccomp_bytes,
    )
    try:
        launch = process.provider_launch_observation()
        if launch["imageId"] != args.image_config_digest:
            raise ValueError("provider launched a different image config")
        collector = FramedResponseCollector(
            nonce=nonce,
            interface={
                "ref": interface["contract"]["interfaceRef"],
                "digest": interface["digest"],
            },
            executor={"ref": executor["ref"], "digest": executor["digest"]},
            executable=f"/opt/ambit/runtime-pack/{args.pack}/bin/ambit-specialist-render",
            request={
                "digest": request["digest"],
                "jobRef": request["jobRef"],
                "jobRoot": request["jobRoot"],
            },
            provider_process_identity=launch["processIdentity"],
        )
        raw = process.read_line(30)
        if raw is None:
            raise RuntimeError("framed helper omitted ready")
        collector.accept(raw)
        ready = collector.ready_frame
        process.write(
            encoded_lines(request_frames(nonce, canonical_bytes(request), source))
        )
        if mode == "cancel":
            process.write(
                frame_line(
                    {"schema": FRAME_SCHEMA, "kind": "cancel", "nonce": nonce}
                )
            )
        collected = None
        while collected is None:
            raw = process.read_line(300)
            if raw is None:
                raise RuntimeError("framed helper omitted terminal response")
            collected = collector.accept(raw)
        terminal = collected.terminal
        files = verify_semantic_response(request, terminal, collected.files)
        if process.read_line(30) is not None:
            raise ValueError("framed helper emitted data after its terminal frame")
        exit_code = process.wait(30)
        if exit_code != terminal["exitCode"]:
            raise ValueError("framed terminal and helper exit differ")
        absent = subprocess.run(
            ["docker", "container", "inspect", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode != 0
        if not absent:
            raise RuntimeError("framed provider container did not quiesce")
        return {
            "schema": "ambit.runtime-provider-specialist-render-receipt/v1",
            "outcome": "passed",
            "mode": mode,
            "image": args.image,
            "imageConfigDigest": args.image_config_digest,
            "pack": args.pack,
            "facet": args.facet,
            "mediaType": args.media_type,
            "nonce": nonce,
            "interface": {
                "ref": interface["contract"]["interfaceRef"],
                "digest": interface["digest"],
            },
            "executorRevision": ready["executorRevision"],
            "processIdentity": ready["processIdentity"],
            "executable": ready["executable"],
            "request": {
                "digest": request["digest"],
                "jobRef": request["jobRef"],
                "jobRoot": request["jobRoot"],
            },
            "terminal": terminal,
            "helperExitCode": exit_code,
            "fileDigests": {
                path: sha256_bytes(payload) for path, payload in sorted(files.items())
            },
            "providerQuiescence": {
                "schema": "ambit.runtime-provider-quiescence-receipt/v1",
                "containerName": name,
                "containerAbsent": absent,
                "launch": launch,
            },
            "seccompDigest": seccomp_digest,
            "launchArgv": process.command,
        }
    finally:
        process.terminate()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument(
        "--image-config-digest",
        required=True,
        dest="image_config_digest",
    )
    parser.add_argument(
        "--pack",
        required=True,
        choices=("data-research", "office-authoring", "pdf-ocr", "web-browser"),
    )
    parser.add_argument("--facet", required=True)
    parser.add_argument("--media-type", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--seccomp", type=Path)
    parser.add_argument("--mode", choices=("success", "hostile", "cancel"), default="success")
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = run_case(args, args.mode)
        args.receipt.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"framed-runtime-conformance: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
