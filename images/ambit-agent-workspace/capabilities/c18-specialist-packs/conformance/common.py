from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def canonical_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def runtime_guard(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("\t")
        if not separator or not key or key in values:
            raise ValueError("runtime guard receipt is malformed")
        values[key] = value
    expected = {
        "cap_eff": "0000000000000000",
        "gid": "1000",
        "network": "none",
        "no_new_privileges": "1",
        "root_filesystem": "read_only",
        "runtime_installers": "absent",
        "uid": "1000",
        "user": "daytona",
    }
    for key, value in expected.items():
        if values.get(key) != value:
            raise ValueError(f"runtime guard field {key!r} is invalid")
    if not values.get("pack"):
        raise ValueError("runtime guard pack is absent")
    return values


def file_receipts(root: Path) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"output symlink is forbidden: {path}")
        if path.is_file():
            receipts.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )
    return receipts
