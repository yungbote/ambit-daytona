from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

try:
    from .verify_source_contracts import verify as verify_source_contracts
except ImportError:
    from verify_source_contracts import verify as verify_source_contracts


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one object")
    return value


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return all(
        getattr(left, field) == getattr(right, field)
        for field in (
            "st_ctime_ns",
            "st_dev",
            "st_gid",
            "st_ino",
            "st_mode",
            "st_mtime_ns",
            "st_nlink",
            "st_size",
            "st_uid",
        )
    )


def verify_exact_file(path: Path, *, expected_bytes: int, expected_sha256: str) -> None:
    if not path.is_absolute():
        raise ValueError("offline input path must be absolute")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o222
            or before.st_size != expected_bytes
        ):
            raise ValueError(f"offline input is not exact and immutable: {path.name}")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        if observed != expected_bytes or not _same_identity(before, after):
            raise ValueError(f"offline input changed while reading: {path.name}")
        if f"sha256:{digest.hexdigest()}" != expected_sha256:
            raise ValueError(f"offline input digest differs: {path.name}")
    finally:
        os.close(descriptor)


def audit(pack_root: Path, input_root: Path) -> dict[str, Any]:
    pack_root = pack_root.resolve(strict=True)
    verify_source_contracts(pack_root)
    if not input_root.is_absolute() or input_root.is_symlink():
        raise ValueError("offline input root must be one absolute real directory")
    input_metadata = input_root.stat()
    if not stat.S_ISDIR(input_metadata.st_mode):
        raise ValueError("offline input root is not a directory")
    lock = _read_json(pack_root / "locks/offline-build-input.lock.json")
    verified: list[dict[str, Any]] = []
    missing: list[str] = []
    exact_artifacts = [*lock["publicArtifacts"], *lock["frozenEvidence"]]
    for artifact in exact_artifacts:
        path = input_root / artifact["path"]
        if not path.exists():
            missing.append(artifact["path"])
            continue
        verify_exact_file(
            path,
            expected_bytes=artifact["bytes"],
            expected_sha256=artifact["sha256"],
        )
        verified.append(
            {
                "path": artifact["path"],
                "bytes": artifact["bytes"],
                "sha256": artifact["sha256"],
            }
        )
    expected_public = {artifact["path"] for artifact in lock["publicArtifacts"]}
    observed_public: set[str] = set()
    public_root = input_root / "public"
    if public_root.exists():
        for directory, names, filenames in os.walk(public_root, followlinks=False):
            directory_path = Path(directory)
            for name in names:
                if (directory_path / name).is_symlink():
                    raise ValueError("offline public input contains a symlink directory")
            for name in filenames:
                path = directory_path / name
                if path.is_symlink() or not path.is_file():
                    raise ValueError("offline public input contains an unsafe file")
                observed_public.add(path.relative_to(input_root).as_posix())
    extras = sorted(observed_public - expected_public)
    if extras:
        raise ValueError(f"offline public input contains extra files: {extras}")
    missing.extend(lock["requiredUnfrozenEvidence"])
    ready = lock["state"] == "ready" and not missing
    return {
        "schema": "ambit.runtime-pack-offline-input-audit/v1",
        "outcome": "ready" if ready else "unavailable",
        "networkOperations": "none",
        "verifiedPublicArtifacts": verified,
        "missing": sorted(missing),
        "sourceState": lock["state"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pack-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    result = audit(args.pack_root, args.input_root)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if args.require_ready and result["outcome"] != "ready":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
