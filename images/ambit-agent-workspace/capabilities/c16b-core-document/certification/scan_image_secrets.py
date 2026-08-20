from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


CONTENT_PATTERNS = {
    "pem_private_key": re.compile(
        rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\r\n]+"
        rb"[A-Za-z0-9+/=\r\n]{64,16384}"
        rb"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    ),
    "aws_access_key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "github_token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{24,}"),
    "openai_api_key": re.compile(rb"sk-[A-Za-z0-9_-]{32,}"),
    "google_service_account_private_key": re.compile(rb'"private_key"\s*:\s*"-----BEGIN'),
}
SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:\.env(?:\.[^/]*)?|credentials?|id_(?:rsa|dsa|ecdsa|ed25519)|[^/]*private[^/]*\.pem|secrets?)(?:$|/)",
    flags=re.IGNORECASE,
)
SENSITIVE_ENV = re.compile(r"(?:api[_-]?key|password|private[_-]?key|secret|token)", flags=re.IGNORECASE)
SENSITIVE_ASSIGNMENT = re.compile(
    rb"(?i)(?:api[_-]?key|password|private[_-]?key|secret|token)\s*=\s*[^\s\"']{8,}"
)
CHUNK_BYTES = 1024 * 1024
OVERLAP_BYTES = 256


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_stream(stream: BinaryIO) -> tuple[int, set[str]]:
    examined = 0
    previous = b""
    findings: set[str] = set()
    while True:
        chunk = stream.read(CHUNK_BYTES)
        if not chunk:
            break
        examined += len(chunk)
        window = previous + chunk
        for name, pattern in CONTENT_PATTERNS.items():
            if pattern.search(window):
                findings.add(name)
        previous = window[-OVERLAP_BYTES:]
    return examined, findings


def nonempty_secret_value(value: object) -> bool:
    if value is None or value is False:
        return False
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


def scan_sensitive_config_keys(value: object, path: str, findings: list[dict[str, str]]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if SENSITIVE_ENV.search(str(key)) and nonempty_secret_value(item):
                findings.append({"kind": "sensitive_config_key", "path": child_path})
            scan_sensitive_config_keys(item, child_path, findings)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            scan_sensitive_config_keys(item, f"{path}[{index}]", findings)


parser = argparse.ArgumentParser()
parser.add_argument("image_tar", type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()

image_tar = args.image_tar.resolve()
findings: list[dict[str, str]] = []
examined_files = 0
examined_bytes = 0
layer_count = 0

with tarfile.open(image_tar, "r:*") as outer:
    manifest_member = outer.getmember("manifest.json")
    manifest_stream = outer.extractfile(manifest_member)
    if manifest_stream is None:
        raise ValueError("docker image archive has no readable manifest")
    manifest = json.load(manifest_stream)
    if not isinstance(manifest, list) or len(manifest) != 1:
        raise ValueError("docker image archive must contain exactly one image")
    image = manifest[0]
    config_name = image.get("Config")
    layers = image.get("Layers")
    if not isinstance(config_name, str) or not isinstance(layers, list) or not layers:
        raise ValueError("docker image archive manifest is incomplete")
    config_stream = outer.extractfile(config_name)
    if config_stream is None:
        raise ValueError("docker image archive config is unreadable")
    config_payload = config_stream.read()
    config = json.loads(config_payload)
    scan_sensitive_config_keys(config, "config", findings)
    for kind, pattern in CONTENT_PATTERNS.items():
        if pattern.search(config_payload):
            findings.append({"kind": kind, "path": "config.json"})
    environment = config.get("config", {}).get("Env", []) or []
    for entry in environment:
        if not isinstance(entry, str) or "=" not in entry:
            raise ValueError("image config contains malformed environment entry")
        name, value = entry.split("=", 1)
        if value and SENSITIVE_ENV.search(name):
            findings.append({"kind": "sensitive_environment", "path": name})
    history = config.get("history", []) or []
    for index, item in enumerate(history):
        created_by = str(item.get("created_by", "")).encode()
        for kind, pattern in CONTENT_PATTERNS.items():
            if pattern.search(created_by):
                findings.append({"kind": kind, "path": f"config.history[{index}]"})
        if SENSITIVE_ASSIGNMENT.search(created_by):
            findings.append({"kind": "sensitive_history_assignment", "path": f"config.history[{index}]"})

    for layer_name in layers:
        if not isinstance(layer_name, str):
            raise ValueError("docker image archive layer name is invalid")
        layer_member = outer.getmember(layer_name)
        layer_stream = outer.extractfile(layer_member)
        if layer_stream is None:
            raise ValueError(f"docker image layer is unreadable: {layer_name}")
        layer_count += 1
        with tarfile.open(fileobj=layer_stream, mode="r|*") as layer:
            for member in layer:
                path = str(PurePosixPath(member.name))
                if member.isfile() and SENSITIVE_PATH.search(path):
                    findings.append({"kind": "sensitive_path", "path": path, "layer": layer_name})
                if not member.isfile():
                    continue
                payload = layer.extractfile(member)
                if payload is None:
                    raise ValueError(f"regular layer file is unreadable: {path}")
                examined_files += 1
                size, content_findings = scan_stream(payload)
                examined_bytes += size
                for kind in sorted(content_findings):
                    findings.append({"kind": kind, "path": path, "layer": layer_name})

receipt = {
    "schema": "ambit.runtime-pack-image-secret-scan/v1",
    "outcome": "passed" if not findings else "failed",
    "input": {
        "path": image_tar.name,
        "bytes": image_tar.stat().st_size,
        "sha256": sha256(image_tar),
        "configSha256": hashlib.sha256(config_payload).hexdigest(),
    },
    "coverage": {
        "layers": layer_count,
        "regularFiles": examined_files,
        "regularFileBytes": examined_bytes,
        "patterns": sorted(CONTENT_PATTERNS),
        "sensitivePathPolicy": SENSITIVE_PATH.pattern,
    },
    "findings": sorted(findings, key=lambda item: tuple(sorted(item.items()))),
}
args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
if findings:
    raise SystemExit(2)
