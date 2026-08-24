from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any


class SharedFontClosureError(ValueError):
    """The exact shared font set cannot be derived into a target closure."""


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SharedFontClosureError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def atomic_write(path: Path, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def derive(
    source_lock_path: Path,
    target_lock_path: Path,
    font_set_path: Path,
    target_installed_path: Path,
) -> tuple[dict[str, Any], bytes, bytes]:
    source = load_json(source_lock_path)
    target = load_json(target_lock_path)
    font_set = load_json(font_set_path)
    for field in ("baseImage", "platform", "schema", "signaturePolicy", "snapshots"):
        if source.get(field) != target.get(field):
            raise SharedFontClosureError(f"source and target {field} differ")
    packages = font_set.get("packages")
    if (
        not isinstance(packages, list)
        or not packages
        or not all(isinstance(package, str) and package for package in packages)
        or packages != sorted(set(packages))
    ):
        raise SharedFontClosureError("font package roster is invalid")
    desired = set(packages)
    source_entries = archive_index(source.get("archives"), "source")
    missing = desired - set(source_entries)
    if missing:
        raise SharedFontClosureError(f"font archives are absent: {sorted(missing)!r}")
    target_entries = archive_index(target.get("archives"), "target")
    by_filename = filename_index(target_entries.values(), "target")
    for package in sorted(desired):
        entry = source_entries[package]
        previous = by_filename.setdefault(entry["localFilename"], entry)
        if previous != entry:
            raise SharedFontClosureError("font archive collides with target closure")
    archives = [by_filename[key] for key in sorted(by_filename)]
    installed_lines_before = target_installed_path.read_text(
        encoding="utf-8"
    ).splitlines()
    if (
        not installed_lines_before
        or installed_lines_before != sorted(set(installed_lines_before))
        or not all(installed_lines_before)
    ):
        raise SharedFontClosureError("target installed closure is not sorted and unique")
    installed = set(installed_lines_before)
    installed.update(desired)
    installed_lines = sorted(installed)
    installed_payload = ("\n".join(installed_lines) + "\n").encode("utf-8")
    graph = [
        {
            "package": entry["package"],
            "version": entry["version"],
            "architecture": entry["architecture"],
            "sha256": entry["sha256"],
        }
        for entry in archives
    ]
    result = {
        **target,
        "requestedPackages": sorted(
            set(target.get("requestedPackages", [])) | desired
        ),
        "archiveCount": len(archives),
        "transitiveGraphDigest": "sha256:"
        + hashlib.sha256(canonical_bytes(graph)).hexdigest(),
        "archives": archives,
        "installedClosure": {
            "entryCount": len(installed_lines),
            "sha256": "sha256:" + hashlib.sha256(installed_payload).hexdigest(),
        },
    }
    manifest = "".join(
        f"{entry['sha256'].removeprefix('sha256:')}  debian/{entry['localFilename']}\n"
        for entry in archives
    ).encode("utf-8")
    return result, installed_payload, manifest


def archive_index(value: object, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise SharedFontClosureError(f"{label} archive roster is invalid")
    result: dict[str, dict[str, Any]] = {}
    for entry in value:
        if not isinstance(entry, dict):
            raise SharedFontClosureError(f"{label} archive entry is invalid")
        try:
            identity = f"{entry['package']}={entry['version']}"
            filename = entry["localFilename"]
        except KeyError as error:
            raise SharedFontClosureError(
                f"{label} archive entry omits {error.args[0]}"
            ) from error
        if (
            not isinstance(entry["package"], str)
            or not entry["package"]
            or not isinstance(entry["version"], str)
            or not entry["version"]
            or not isinstance(filename, str)
            or not filename
        ):
            raise SharedFontClosureError(f"{label} archive identity is invalid")
        if identity in result:
            raise SharedFontClosureError(f"{label} archive identity is duplicated")
        result[identity] = entry
    filename_index(result.values(), label)
    return result


def filename_index(
    entries: Iterable[dict[str, Any]], label: str
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for entry in entries:
        filename = entry["localFilename"]
        if filename in result:
            raise SharedFontClosureError(f"{label} archive filename is duplicated")
        result[filename] = entry
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-lock", required=True, type=Path)
    parser.add_argument("--source-deb-directory", required=True, type=Path)
    parser.add_argument("--target-lock", required=True, type=Path)
    parser.add_argument("--target-installed", required=True, type=Path)
    parser.add_argument("--target-manifest", required=True, type=Path)
    parser.add_argument("--target-deb-directory", required=True, type=Path)
    parser.add_argument("--font-set", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        lock, installed, manifest = derive(
            args.source_lock,
            args.target_lock,
            args.font_set,
            args.target_installed,
        )
        if not args.write:
            if (
                load_json(args.target_lock) != lock
                or args.target_installed.read_bytes() != installed
                or args.target_manifest.read_bytes() != manifest
            ):
                raise SharedFontClosureError("target font closure drifted")
            return 0
        atomic_write(
            args.target_lock,
            json.dumps(lock, indent=2, sort_keys=True).encode() + b"\n",
        )
        atomic_write(args.target_installed, installed)
        atomic_write(args.target_manifest, manifest)
        entries = filename_index(lock["archives"], "derived")
        source_entries = archive_index(
            load_json(args.source_lock)["archives"], "source"
        )
        for package in load_json(args.font_set)["packages"]:
            entry = source_entries[package]
            source = args.source_deb_directory / entry["localFilename"]
            target = args.target_deb_directory / entry["localFilename"]
            if target.exists():
                if file_sha256(target) != entry["sha256"].removeprefix("sha256:"):
                    raise SharedFontClosureError("existing target font archive differs")
            else:
                shutil.copyfile(source, target)
                os.chmod(target, 0o444)
            if file_sha256(target) != entries[target.name]["sha256"].removeprefix("sha256:"):
                raise SharedFontClosureError("copied target font archive differs")
    except (OSError, json.JSONDecodeError, SharedFontClosureError) as error:
        print(f"shared-font-closure: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
