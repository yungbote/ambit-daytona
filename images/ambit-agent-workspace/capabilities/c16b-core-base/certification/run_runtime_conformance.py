from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class RuntimeConformanceError(RuntimeError):
    """The exact image did not pass the hardened runtime matrix."""


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def run(image: str, script_path: Path, output: Path) -> dict[str, object]:
    script = script_path.resolve(strict=True).read_bytes()
    if not script.startswith(b"#!/bin/sh\n"):
        raise RuntimeConformanceError("conformance script is not exact POSIX shell")
    inspect_process = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if inspect_process.returncode != 0:
        raise RuntimeConformanceError("candidate image is absent")
    inspect_values = json.loads(inspect_process.stdout)
    if not isinstance(inspect_values, list) or len(inspect_values) != 1:
        raise RuntimeConformanceError("candidate image inspect is ambiguous")
    inspect = inspect_values[0]
    if not isinstance(inspect, dict):
        raise RuntimeConformanceError("candidate image inspect is invalid")

    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    positive = _execute(_command(image), script)
    if positive["exitCode"] != 0:
        raise RuntimeConformanceError("positive hardened runtime failed")
    positive_value = json.loads(str(positive["stdout"]))
    if (
        not isinstance(positive_value, dict)
        or positive_value.get("schema") != "ambit.runtime-core-base-conformance/v2"
        or positive_value.get("outcome") != "passed"
    ):
        raise RuntimeConformanceError("positive runtime receipt is invalid")
    _write(output / "positive.stdout", str(positive["stdout"]).encode())
    _write(output / "positive.stderr", str(positive["stderr"]).encode())

    cases = [
        ("root-user", _command(image, user="0:0"), 10),
        ("supplementary-group", _command(image, groups=["1234"]), 13),
        ("no-new-privileges", _command(image, no_new_privileges=False), 24),
        ("network-host", _command(image, network="host"), 25),
        ("writable-root", _command(image, read_only=False), 28),
        ("added-capability", _command(image, added_capability="CHOWN"), 23),
        ("extra-innocuous-environment", _command(image, environment=["AMBIT_TEST_ONLY=1"]), 14),
    ]
    for name in (
        "SSH_AUTH_SOCK",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AWS_ACCESS_KEY_ID",
        "DATABASE_URL",
        "GITHUB_PAT",
        "OPENAI_KEY",
    ):
        cases.append(
            (
                f"credential-environment-{name.lower().replace('_', '-')}",
                _command(image, environment=[f"{name}=non-secret-negative-fixture"]),
                14,
            )
        )

    with tempfile.TemporaryDirectory(prefix="ambit-core-socket-") as directory:
        socket_path = Path(directory) / "agent.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(os.fspath(socket_path))
            listener.listen(1)
            stat = socket_path.stat()
            if stat.st_uid != os.getuid() or not socket_path.is_socket():
                raise RuntimeConformanceError("alternate host socket is not same-uid")
            mount = f"type=bind,src={socket_path},dst=/agent.sock,readonly"
            cases.extend(
                [
                    ("alternate-host-socket", _command(image, mounts=[mount]), 26),
                    (
                        "alternate-host-socket-with-environment",
                        _command(
                            image,
                            mounts=[mount],
                            environment=["SSH_AUTH_SOCK=/agent.sock"],
                        ),
                        14,
                    ),
                ]
            )
            negatives = _run_negatives(cases, script, output)
        finally:
            listener.close()

    receipt = {
        "schema": "ambit.runtime-core-base-runtime-matrix/v1",
        "image": {
            "requestedRef": image,
            "imageId": inspect.get("Id"),
            "repoDigests": inspect.get("RepoDigests") or [],
            "repoTags": inspect.get("RepoTags") or [],
            "user": (inspect.get("Config") or {}).get("User"),
            "labels": (inspect.get("Config") or {}).get("Labels") or {},
        },
        "scriptSha256": sha256(script),
        "positive": positive,
        "negativeCases": negatives,
        "sameUidAlternateSocket": True,
        "outcome": "passed",
    }
    rendered = canonical_json(receipt)
    _write(output / "runtime-matrix.json", rendered)
    return {**receipt, "receiptSha256": sha256(rendered)}


def _run_negatives(
    cases: list[tuple[str, list[str], int]],
    script: bytes,
    output: Path,
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for name, command, expected_exit in cases:
        result = _execute(command, script)
        if result["exitCode"] != expected_exit:
            raise RuntimeConformanceError(
                f"negative {name} exited {result['exitCode']}, expected {expected_exit}"
            )
        if not str(result["stderr"]).startswith("core-conformance:"):
            raise RuntimeConformanceError(f"negative {name} was not rejected by conformance")
        _write(output / f"negative-{name}.stdout", str(result["stdout"]).encode())
        _write(output / f"negative-{name}.stderr", str(result["stderr"]).encode())
        results.append({"name": name, "expectedExitCode": expected_exit, **result})
    return results


def _execute(command: list[str], script: bytes) -> dict[str, object]:
    process = subprocess.run(
        command,
        input=script,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "argv": command,
        "exitCode": process.returncode,
        "stdout": process.stdout.decode("utf-8", "strict"),
        "stdoutSha256": sha256(process.stdout),
        "stderr": process.stderr.decode("utf-8", "strict"),
        "stderrSha256": sha256(process.stderr),
    }


def _command(
    image: str,
    *,
    network: str = "none",
    read_only: bool = True,
    no_new_privileges: bool = True,
    user: str | None = None,
    groups: list[str] | None = None,
    added_capability: str | None = None,
    environment: list[str] | None = None,
    mounts: list[str] | None = None,
) -> list[str]:
    command = ["docker", "run", "--rm", "-i", "--network", network]
    if read_only:
        command.append("--read-only")
    command.extend(["--cap-drop", "ALL"])
    if added_capability:
        command.extend(["--cap-add", added_capability])
    if no_new_privileges:
        command.extend(["--security-opt", "no-new-privileges"])
    command.extend(
        [
            "--tmpfs",
            "/workspace:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700",
        ]
    )
    if user:
        command.extend(["--user", user])
    for group in groups or []:
        command.extend(["--group-add", group])
    for value in environment or []:
        command.extend(["--env", value])
    for mount in mounts or []:
        command.extend(["--mount", mount])
    command.extend(["--entrypoint", "/bin/sh", image, "-s"])
    return command


def _write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--script", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.image, args.script, args.output), indent=2, sort_keys=True))
    except (OSError, RuntimeConformanceError, UnicodeError, json.JSONDecodeError) as error:
        print(f"runtime-conformance: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
