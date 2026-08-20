from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path


LINE_RE = re.compile(r"^([0-9a-f]{64})  /helper-input/([A-Za-z0-9][A-Za-z0-9._-]*)$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


parser = argparse.ArgumentParser()
parser.add_argument("--manifest", required=True, type=Path)
parser.add_argument("--helper-root", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()

if args.helper_root.is_symlink():
    raise ValueError("helper root must not be a symlink")
root = args.helper_root.resolve(strict=True)
if not root.is_dir():
    raise ValueError("helper root is not a directory")
lines = args.manifest.read_text().splitlines()
if not lines:
    raise ValueError("helper input manifest is empty")

entries: list[dict[str, object]] = []
names: list[str] = []
for line_number, line in enumerate(lines, start=1):
    match = LINE_RE.fullmatch(line)
    if match is None:
        raise ValueError(f"helper input manifest line {line_number} has an unsafe or noncanonical path")
    expected, name = match.groups()
    names.append(name)
    path = root / name
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"helper input is not a no-follow regular file: {name}")
    actual = sha256(path)
    if actual != expected:
        raise ValueError(f"helper input digest mismatch: {name}")
    entries.append({"name": name, "bytes": metadata.st_size, "sha256": actual})

if names != sorted(set(names)):
    raise ValueError("helper input manifest paths must be sorted and unique")
actual_names = sorted(item.name for item in os.scandir(root))
if actual_names != names:
    raise ValueError(f"helper archive file roster differs from manifest: {actual_names!r}")

manifest_payload = args.manifest.read_bytes()
receipt = {
    "schema": "ambit.runtime-pack-helper-input-verification/v1",
    "outcome": "passed",
    "manifest": {
        "name": args.manifest.name,
        "bytes": len(manifest_payload),
        "sha256": hashlib.sha256(manifest_payload).hexdigest(),
    },
    "fileCount": len(entries),
    "files": entries,
}
args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
