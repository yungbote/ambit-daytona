from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


SHA256_LINE = re.compile(
    r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/\[\]-]*)$"
)
LINK_LINE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._/-]*) -> ([A-Za-z0-9][A-Za-z0-9._-]*)$"
)


def _read_exact_immutable(
    path: Path,
    *,
    expected_bytes: int,
    expected_sha256: str,
) -> bytes:
    if not path.is_absolute():
        raise ValueError("structural archive path must be absolute")
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
            raise ValueError("structural archive is not one exact immutable file")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
            digest.update(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
        identity = (
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
        if observed != expected_bytes or any(
            getattr(before, field) != getattr(after, field) for field in identity
        ):
            raise ValueError("structural archive changed while reading")
        if f"sha256:{digest.hexdigest()}" != expected_sha256:
            raise ValueError("structural archive raw SHA-256 differs")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_file_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = SHA256_LINE.fullmatch(line)
        if match is None:
            raise ValueError("structural file manifest is noncanonical")
        digest, name = match.groups()
        if name in entries:
            raise ValueError("structural file manifest contains a duplicate")
        entries[name] = digest
    if list(entries) != sorted(entries):
        raise ValueError("structural file manifest is not sorted")
    return entries


def read_link_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = LINK_LINE.fullmatch(line)
        if match is None:
            raise ValueError("structural link manifest is noncanonical")
        name, target = match.groups()
        if name in entries:
            raise ValueError("structural link manifest contains a duplicate")
        entries[name] = target
    if list(entries) != sorted(entries):
        raise ValueError("structural link manifest is not sorted")
    return entries


def read_tree_manifest(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        if (
            not isinstance(value, dict)
            or json.dumps(value, sort_keys=True, separators=(",", ":")) != line
        ):
            raise ValueError("structural tree manifest is noncanonical")
        kind = value.get("type")
        expected = {
            "directory": {"mode", "path", "type"},
            "file": {"bytes", "mode", "path", "sha256", "type"},
            "symlink": {"mode", "path", "target", "type"},
        }.get(kind)
        if expected is None or set(value) != expected:
            raise ValueError("structural tree manifest entry fields differ")
        if value["path"] != ".":
            _canonical_name(value["path"])
        entries.append(value)
    paths = [entry["path"] for entry in entries]
    if not paths or paths[0] != "." or paths[1:] != sorted(set(paths[1:])):
        raise ValueError("structural tree manifest order differs")
    return entries


def _canonical_name(value: str) -> str:
    name = value.removeprefix("./")
    pure = PurePosixPath(name)
    if (
        not name
        or pure.is_absolute()
        or ".." in pure.parts
        or "\\" in name
        or any(ord(character) <= 0x1F or ord(character) == 0x7F for character in name)
    ):
        raise ValueError("structural archive contains an unsafe path")
    return name


def verify_archive_bytes(
    archive: bytes,
    *,
    lock: dict[str, Any],
    file_manifest: dict[str, str],
    link_manifest: dict[str, str],
    tree_manifest: list[dict[str, Any]],
) -> dict[str, Any]:
    observed_files: dict[str, str] = {}
    observed_links: dict[str, str] = {}
    observed_directories: set[str] = set()
    member_names: list[str] = []
    regular_bytes = 0
    root_seen = False
    observed_tree: list[dict[str, Any]] = []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        for member in source.getmembers():
            if member.name in {".", "./"}:
                if (
                    root_seen
                    or not member.isdir()
                    or member.uid != 0
                    or member.gid != 0
                    or member.mtime != lock["sourceDateEpoch"]
                    or member.mode & 0o022
                    or member.pax_headers
                ):
                    raise ValueError("structural archive root member differs")
                root_seen = True
                observed_tree.append(
                    {"mode": f"{member.mode:04o}", "path": ".", "type": "directory"}
                )
                continue
            name = _canonical_name(member.name)
            if name in member_names:
                raise ValueError("structural archive contains a duplicate member")
            member_names.append(name)
            if member.uid != 0 or member.gid != 0:
                raise ValueError("structural archive owner differs")
            if member.mtime != lock["sourceDateEpoch"]:
                raise ValueError("structural archive timestamp differs")
            if set(member.pax_headers) - {"path"} or (
                "path" in member.pax_headers
                and _canonical_name(member.pax_headers["path"]) != name
            ):
                raise ValueError("structural archive PAX metadata differs")
            if member.issparse():
                raise ValueError("structural archive sparse members are forbidden")
            if member.isdir():
                if member.mode & 0o022:
                    raise ValueError("structural archive contains a writable member")
                observed_directories.add(name)
                observed_tree.append(
                    {
                        "mode": f"{member.mode:04o}",
                        "path": name,
                        "type": "directory",
                    }
                )
                continue
            if member.issym():
                target = member.linkname
                target_path = PurePosixPath(target)
                if target_path.is_absolute() or ".." in target_path.parts or "/" in target:
                    raise ValueError("structural archive symlink target is unsafe")
                observed_links[name] = target
                observed_tree.append(
                    {
                        "mode": f"{member.mode:04o}",
                        "path": name,
                        "target": target,
                        "type": "symlink",
                    }
                )
                continue
            if not member.isreg():
                raise ValueError("structural archive contains a special member")
            if member.mode & 0o022:
                raise ValueError("structural archive contains a writable member")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("structural archive file bytes are unavailable")
            digest = hashlib.sha256()
            observed_size = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                observed_size += len(chunk)
            if observed_size != member.size:
                raise ValueError("structural archive file size differs")
            regular_bytes += observed_size
            file_digest = digest.hexdigest()
            observed_files[name] = file_digest
            observed_tree.append(
                {
                    "bytes": observed_size,
                    "mode": f"{member.mode:04o}",
                    "path": name,
                    "sha256": file_digest,
                    "type": "file",
                }
            )
    if observed_tree != tree_manifest:
        raise ValueError("structural archive type, order, mode, or size roster differs")
    if observed_files != file_manifest:
        raise ValueError("structural archive regular-file roster differs")
    if observed_links != link_manifest:
        raise ValueError("structural archive symlink roster differs")
    if not root_seen or len(observed_directories) + 1 != lock["directoryCount"]:
        raise ValueError("structural archive directory count differs")
    if regular_bytes != lock["extractedRegularBytes"]:
        raise ValueError("structural archive extracted byte count differs")
    return {
        "schema": "ambit.runtime-pack-structural-archive-verification/v1",
        "outcome": "passed",
        "archiveSha256": lock["sha256"],
        "archiveBytes": lock["bytes"],
        "regularFileCount": len(observed_files),
        "symlinkCount": len(observed_links),
        "directoryCount": len(observed_directories) + 1,
        "extractedRegularBytes": regular_bytes,
    }


def verify(
    pack_root: Path,
    archive_path: Path,
    independent_expected_raw_sha256: str,
) -> dict[str, Any]:
    lock = json.loads(
        (pack_root / "locks/structural-compatibility-input.lock.json").read_text(
            encoding="utf-8"
        )
    )["structuralRuntimeArchive"]
    if independent_expected_raw_sha256 != lock["sha256"]:
        raise ValueError("independent structural archive SHA-256 differs from source lock")
    archive = _read_exact_immutable(
        archive_path,
        expected_bytes=lock["bytes"],
        expected_sha256=independent_expected_raw_sha256,
    )
    return verify_archive_bytes(
        archive,
        lock=lock,
        file_manifest=read_file_manifest(
            pack_root / "locks/structural-runtime-files.sha256"
        ),
        link_manifest=read_link_manifest(
            pack_root / "locks/structural-runtime-links.txt"
        ),
        tree_manifest=read_tree_manifest(
            pack_root / "locks/structural-runtime-tree.jsonl"
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pack-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--expected-raw-sha256", required=True)
    args = parser.parse_args()
    receipt = verify(args.pack_root, args.archive, args.expected_raw_sha256)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
