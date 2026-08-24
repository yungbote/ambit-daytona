from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path
from typing import Any


PACKS = {
    "data-research": "ambit.runtime-pack/data-research@1",
    "office-authoring": "ambit.runtime-pack/office-authoring@1",
    "pdf-ocr": "ambit.runtime-pack/pdf-ocr@1",
    "web-browser": "ambit.runtime-pack/web-browser@1",
}
INPUT_MANIFESTS = {
    "data-research": ("debian-archives.sha256", "python-wheels.sha256"),
    "office-authoring": ("debian-archives.sha256", "python-wheels.sha256"),
    "pdf-ocr": ("debian-archives.sha256", "python-wheels.sha256"),
    "web-browser": ("npm-archives.sha256",),
}
MANIFEST_LINE = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<path>[^\n]+)$")
SHARED_SOURCE_ROOTS = (
    "build",
    "conformance",
    "policy",
    "protocol",
)


class PackBundleError(ValueError):
    """The reusable offline pack material is not a closed canonical bundle."""


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            result.update(chunk)
    return "sha256:" + result.hexdigest()


def _load_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PackBundleError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def _entry(path: Path, relative: str, scope: str) -> dict[str, object]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise PackBundleError(f"bundle input is not a regular file: {scope}/{relative}")
    normalized_mode = 0o555 if scope == "source" and metadata.st_mode & 0o111 else 0o444
    return {
        "scope": scope,
        "path": relative,
        "bytes": metadata.st_size,
        "mode": normalized_mode,
        "sha256": file_digest(path),
    }


def _source_paths(root: Path, pack_id: str) -> list[Path]:
    values: list[Path] = []
    for relative in SHARED_SOURCE_ROOTS:
        values.extend(path for path in (root / relative).rglob("*") if path.is_file())
    values.extend(path for path in (root / pack_id).rglob("*") if path.is_file())
    for relative in ("pack-set.lock.json", "source-contracts.sha256"):
        values.append(root / relative)
    unique = {path.relative_to(root).as_posix(): path for path in values}
    return [unique[key] for key in sorted(unique)]


def _input_paths(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise PackBundleError("external input root is not a real directory")
    paths: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PackBundleError("external input contains a symlink")
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            paths.append(path)
        elif not stat.S_ISDIR(metadata.st_mode):
            raise PackBundleError("external input contains a special file")
    if not paths:
        raise PackBundleError("external input bundle is empty")
    return paths


def _entries(
    source_root: Path, input_root: Path, pack_id: str
) -> tuple[list[dict[str, object]], int, int]:
    if pack_id not in PACKS:
        raise PackBundleError("pack ID is invalid")
    source_root = source_root.resolve(strict=True)
    input_root = input_root.resolve(strict=True)
    source_entries = [
        _entry(path, path.relative_to(source_root).as_posix(), "source")
        for path in _source_paths(source_root, pack_id)
    ]
    input_entries = [
        _entry(path, path.relative_to(input_root).as_posix(), "external")
        for path in _input_paths(input_root)
    ]
    entries = sorted([*source_entries, *input_entries], key=lambda item: (item["scope"], item["path"]))
    if len({(item["scope"], item["path"]) for item in entries}) != len(entries):
        raise PackBundleError("bundle material path is duplicated")
    expected_external: list[tuple[str, str]] = []
    for manifest_name in INPUT_MANIFESTS[pack_id]:
        manifest = source_root / pack_id / "locks" / manifest_name
        for line in manifest.read_text(encoding="utf-8").splitlines():
            match = MANIFEST_LINE.fullmatch(line)
            if match is None:
                raise PackBundleError("pack input manifest line is invalid")
            expected_external.append(
                (match.group("path"), "sha256:" + match.group("digest"))
            )
    expected_external.sort()
    actual_external = sorted(
        (str(entry["path"]), str(entry["sha256"])) for entry in input_entries
    )
    if actual_external != expected_external:
        raise PackBundleError("external input set differs from the exact pack locks")
    return entries, len(source_entries), len(input_entries)


def write_artifact(
    source_root: Path, input_root: Path, pack_id: str, artifact_path: Path
) -> dict[str, object]:
    source_root = source_root.resolve(strict=True)
    input_root = input_root.resolve(strict=True)
    entries, _source_count, _external_count = _entries(
        source_root, input_root, pack_id
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(artifact_path, flags, 0o400)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            with tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT) as archive:
                for entry in entries:
                    scope = str(entry["scope"])
                    relative = str(entry["path"])
                    source = (source_root if scope == "source" else input_root) / relative
                    info = tarfile.TarInfo(f"{scope}/{relative}")
                    info.size = int(entry["bytes"])
                    info.mode = int(entry["mode"])
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    with source.open("rb") as payload:
                        archive.addfile(info, payload)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            artifact_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return verify_artifact(artifact_path, entries)


def verify_artifact(
    artifact_path: Path, entries: list[dict[str, object]]
) -> dict[str, object]:
    expected_names = [f"{entry['scope']}/{entry['path']}" for entry in entries]
    with tarfile.open(artifact_path, mode="r:") as archive:
        members = archive.getmembers()
        if [member.name for member in members] != expected_names:
            raise PackBundleError("offline pack artifact entry roster differs")
        for member, entry in zip(members, entries, strict=True):
            if (
                not member.isfile()
                or member.uid != 0
                or member.gid != 0
                or member.uname != ""
                or member.gname != ""
                or member.mtime != 0
                or member.mode != int(entry["mode"])
                or member.size != int(entry["bytes"])
            ):
                raise PackBundleError("offline pack artifact metadata differs")
            stream = archive.extractfile(member)
            if stream is None:
                raise PackBundleError("offline pack artifact payload is absent")
            actual = hashlib.sha256()
            while chunk := stream.read(1024 * 1024):
                actual.update(chunk)
            if "sha256:" + actual.hexdigest() != entry["sha256"]:
                raise PackBundleError("offline pack artifact payload differs")
    return {
        "mediaType": "application/vnd.ambit.c18-offline-pack-bundle+tar",
        "byteLength": artifact_path.stat().st_size,
        "digest": file_digest(artifact_path),
        "entryCount": len(entries),
    }


def build_manifest(
    source_root: Path,
    input_root: Path,
    pack_id: str,
    artifact_path: Path,
) -> dict[str, object]:
    if pack_id not in PACKS:
        raise PackBundleError("pack ID is invalid")
    source_root = source_root.resolve(strict=True)
    input_root = input_root.resolve(strict=True)
    pack = _load_json(source_root / pack_id / "pack.lock.json")
    toolchain = _load_json(source_root / pack_id / "locks/toolchain.lock.json")
    if pack.get("packRevisionRef") != PACKS[pack_id] or toolchain.get("packRef") != PACKS[pack_id]:
        raise PackBundleError("pack source identity differs")
    entries, source_count, external_count = _entries(
        source_root, input_root, pack_id
    )
    artifact = verify_artifact(artifact_path, entries)
    base_image = toolchain.get("baseImage")
    if pack_id == "web-browser":
        base_image = toolchain.get("browserSourceImage", {}).get("image")
    if not isinstance(base_image, str) or "@sha256:" not in base_image:
        raise PackBundleError("pack base image is not immutable")
    body = {
        "schema": "ambit.c18-offline-pack-bundle/v1",
        "packRevisionRef": PACKS[pack_id],
        "platform": "linux/amd64",
        "baseImage": base_image,
        "sourceSetDigest": file_digest(source_root / "source-contracts.sha256"),
        "installerDigest": file_digest(
            source_root
            / "build"
            / ("install-web-pack.sh" if pack_id == "web-browser" else "install-debian-python-pack.sh")
        ),
        "artifact": artifact,
        "entryCount": len(entries),
        "sourceEntryCount": source_count,
        "externalEntryCount": external_count,
        "entryBytes": sum(int(item["bytes"]) for item in entries),
        "entryTreeDigest": digest(entries),
        "entries": entries,
    }
    return {**body, "bundleDigest": digest(body)}


def verify_manifest(
    source_root: Path,
    input_root: Path,
    pack_id: str,
    artifact_path: Path,
    manifest: object,
) -> dict[str, object]:
    expected = build_manifest(source_root, input_root, pack_id, artifact_path)
    if manifest != expected:
        raise PackBundleError("offline pack bundle manifest differs from exact materials")
    return expected


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--pack", required=True, choices=sorted(PACKS))
    parser.add_argument("--artifact-output", required=True, type=Path)
    parser.add_argument("--manifest-output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify:
            manifest = _load_json(args.manifest_output)
            verify_manifest(
                args.source_root,
                args.input_root,
                args.pack,
                args.artifact_output,
                manifest,
            )
        else:
            artifact = write_artifact(
                args.source_root,
                args.input_root,
                args.pack,
                args.artifact_output,
            )
            manifest = build_manifest(
                args.source_root,
                args.input_root,
                args.pack,
                args.artifact_output,
            )
            if manifest["artifact"] != artifact:
                raise PackBundleError("artifact identity changed before manifest seal")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(args.manifest_output, flags, 0o400)
            with os.fdopen(descriptor, "wb") as output:
                output.write(json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
                output.flush()
                os.fsync(output.fileno())
    except (OSError, PackBundleError, json.JSONDecodeError) as error:
        print(f"pack-bundle: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
