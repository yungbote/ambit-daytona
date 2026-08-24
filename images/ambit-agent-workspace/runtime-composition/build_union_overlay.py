from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


SAFE_PATH = re.compile(r"^[^\x00-\x1f\x7f]+$")


class UnionOverlayBuildError(RuntimeError):
    """The selected runtime roots do not form one closed additive overlay."""


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def build(
    core_root: Path,
    target_root: Path,
    output: Path,
    protected_paths: list[str],
    timestamp: int,
) -> dict[str, object]:
    core_root = core_root.resolve(strict=True)
    target_root = target_root.resolve(strict=True)
    if core_root == target_root:
        raise UnionOverlayBuildError("core and target roots must be distinct")
    if output.exists() or output.is_symlink():
        raise UnionOverlayBuildError("overlay output already exists")
    protected = _protected_paths(protected_paths)
    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or timestamp <= 0:
        raise UnionOverlayBuildError("overlay timestamp is invalid")
    core = _root_manifest(core_root)
    target = _root_manifest(target_root)

    missing_protected = sorted(path for path in protected if path not in core)
    if missing_protected:
        raise UnionOverlayBuildError(
            f"protected core paths are absent: {missing_protected!r}"
        )
    for path in protected:
        if path in target and target[path] != core[path]:
            raise UnionOverlayBuildError(f"protected core path changed: /{path}")

    selected = {
        path
        for path, entry in target.items()
        if core.get(path) != entry
    }
    # A hardlink relationship is identity, not an optimization. If one member
    # differs, every member must enter the same overlay so COPY cannot split the
    # target inode group across the core and overlay layers.
    target_groups = _hardlink_groups(target)
    for paths in target_groups.values():
        if any(path in selected for path in paths):
            selected.update(paths)
    for path in tuple(selected):
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            relative = parent.as_posix()
            if relative in target:
                selected.add(relative)
            parent = parent.parent

    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    overlay_root = output / "overlay"
    overlay_root.mkdir(mode=0o700)
    _materialize_overlay(target_root, target, selected, overlay_root, timestamp)
    overlay = _root_manifest(overlay_root)
    expected_overlay = {path: target[path] for path in sorted(selected)}
    if overlay != expected_overlay:
        raise UnionOverlayBuildError("materialized overlay differs from its target")

    composed = dict(core)
    composed.update(target)
    # Core-only entries are intentionally retained. A pack may add or replace
    # admitted paths, but removing core authority requires a new core artifact.
    if any(composed[path] != core[path] for path in protected):
        raise UnionOverlayBuildError("composed overlay changed protected core state")

    core_manifest = _manifest_bytes(core)
    target_manifest = _manifest_bytes(target)
    overlay_manifest = _manifest_bytes(overlay)
    composed_manifest = _manifest_bytes(composed)
    _write(output / "core-root-manifest.jsonl", core_manifest)
    _write(output / "target-root-manifest.jsonl", target_manifest)
    _write(output / "overlay-entry-manifest.jsonl", overlay_manifest)
    _write(output / "composed-root-manifest.jsonl", composed_manifest)

    overwritten = sorted(path for path in selected if path in core)
    receipt = {
        "schema": "ambit.runtime-union-overlay-build-receipt/v1",
        "composition": "additive-core-plus-one-closed-overlay",
        "coreRootManifestSha256": sha256(core_manifest),
        "targetRootManifestSha256": sha256(target_manifest),
        "overlayEntryManifestSha256": sha256(overlay_manifest),
        "composedRootManifestSha256": sha256(composed_manifest),
        "coreEntryCount": len(core),
        "targetEntryCount": len(target),
        "overlayEntryCount": len(overlay),
        "coreOnlyEntryCount": len(set(core) - set(target)),
        "overwrittenCorePathCount": len(overwritten),
        "overwrittenCorePathsSha256": sha256(
            ("\n".join(overwritten) + ("\n" if overwritten else "")).encode()
        ),
        "protectedCorePaths": ["/" + path for path in protected],
        "protectedCorePathsOutcome": "passed",
        "deletions": "forbidden-and-not-applied",
        "hardlinkTopology": "exact-within-selected-overlay",
        "specialFiles": "forbidden",
        "xattrsOnOverlayEntries": "forbidden",
        "normalizedTimestamp": timestamp,
        "lastWriterWins": False,
        "installPasses": 1,
        "prunePasses": 1,
        "outcome": "passed",
    }
    rendered = canonical_json(receipt)
    _write(output / "overlay-build-receipt.json", rendered)
    return {**receipt, "receiptSha256": sha256(rendered)}


def _protected_paths(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if not value.startswith("/"):
            raise UnionOverlayBuildError("protected path must be absolute")
        relative = _safe_relative(value.removeprefix("/"))
        result.append(relative)
    if not result or result != sorted(set(result)):
        raise UnionOverlayBuildError("protected paths must be sorted and unique")
    return result


def _root_manifest(root: Path) -> dict[str, dict[str, Any]]:
    manifest: dict[str, dict[str, Any]] = {}

    def visit(directory: Path, prefix: PurePosixPath) -> None:
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: os.fsencode(entry.name))
        for child in children:
            relative = _safe_relative((prefix / child.name).as_posix())
            observed = child.stat(follow_symlinks=False)
            mode = stat.S_IMODE(observed.st_mode)
            common: dict[str, Any] = {
                "path": relative,
                "mode": f"{mode:04o}",
                "uid": observed.st_uid,
                "gid": observed.st_gid,
            }
            path = Path(child.path)
            if stat.S_ISDIR(observed.st_mode):
                value = {**common, "kind": "directory"}
                manifest[relative] = value
                visit(path, PurePosixPath(relative))
            elif stat.S_ISREG(observed.st_mode):
                xattrs = _xattrs(path, follow_symlinks=False)
                value = {
                    **common,
                    "kind": "file",
                    "bytes": observed.st_size,
                    "sha256": _read_regular(path, observed),
                    "hardlinkIdentity": f"{observed.st_dev}:{observed.st_ino}",
                    "linkCount": observed.st_nlink,
                    "xattrs": xattrs,
                }
                manifest[relative] = value
            elif stat.S_ISLNK(observed.st_mode):
                target = os.readlink(path)
                if not target or "\x00" in target:
                    raise UnionOverlayBuildError(f"unsafe symlink target: {relative}")
                manifest[relative] = {
                    **common,
                    "kind": "symlink",
                    "target": target,
                    "xattrs": _xattrs(path, follow_symlinks=False),
                }
            else:
                raise UnionOverlayBuildError(
                    f"special runtime entry is forbidden: {relative}"
                )

    visit(root, PurePosixPath("."))
    groups = _hardlink_groups(manifest)
    for paths in groups.values():
        identity = "\n".join(paths)
        for path in paths:
            manifest[path]["hardlinkIdentity"] = identity
    for entry in manifest.values():
        if entry.get("kind") == "file" and entry.get("linkCount") == 1:
            entry["hardlinkIdentity"] = entry["path"]
    return {path: manifest[path] for path in sorted(manifest)}


def _hardlink_groups(
    manifest: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for path, entry in manifest.items():
        if entry.get("kind") != "file" or entry.get("linkCount", 0) < 2:
            continue
        identity = str(entry["hardlinkIdentity"])
        groups.setdefault(identity, []).append(path)
    return {identity: sorted(paths) for identity, paths in groups.items()}


def _materialize_overlay(
    target_root: Path,
    target: dict[str, dict[str, Any]],
    selected: set[str],
    output: Path,
    timestamp: int,
) -> None:
    directories = [
        path for path in sorted(selected) if target[path]["kind"] == "directory"
    ]
    for relative in directories:
        destination = output / relative
        destination.mkdir(parents=True, exist_ok=True)

    linked: dict[str, Path] = {}
    for relative in sorted(selected):
        entry = target[relative]
        if entry["kind"] == "directory":
            continue
        source = target_root / relative
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if entry["kind"] == "symlink":
            if entry.get("xattrs"):
                raise UnionOverlayBuildError(
                    f"overlay xattrs are forbidden: {entry['path']}"
                )
            os.symlink(os.readlink(source), destination)
            os.chown(destination, int(entry["uid"]), int(entry["gid"]), follow_symlinks=False)
            os.utime(
                destination,
                (timestamp, timestamp),
                follow_symlinks=False,
            )
            continue
        identity = str(entry["hardlinkIdentity"])
        existing = linked.get(identity)
        if existing is not None:
            os.link(existing, destination, follow_symlinks=False)
        else:
            _copy_regular(source, destination, entry, timestamp)
            linked[identity] = destination

    for relative in sorted(directories, key=lambda value: (value.count("/"), value), reverse=True):
        _apply_metadata(
            output / relative,
            target[relative],
            timestamp,
            follow_symlinks=False,
        )


def _copy_regular(
    source: Path,
    destination: Path,
    expected: dict[str, Any],
    timestamp: int,
) -> None:
    source_descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(source_descriptor)
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            int(str(expected["mode"]), 8),
        )
        try:
            digest = hashlib.sha256()
            observed = 0
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                observed += len(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    view = view[written:]
            os.fsync(destination_descriptor)
            after = os.fstat(source_descriptor)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or before.st_size != after.st_size
                or observed != expected["bytes"]
                or "sha256:" + digest.hexdigest() != expected["sha256"]
            ):
                raise UnionOverlayBuildError(
                    f"source changed while copying: {expected['path']}"
                )
        finally:
            os.close(destination_descriptor)
    finally:
        os.close(source_descriptor)
    _apply_metadata(destination, expected, timestamp, follow_symlinks=False)


def _apply_metadata(
    path: Path,
    entry: dict[str, Any],
    timestamp: int,
    *,
    follow_symlinks: bool,
) -> None:
    if entry.get("xattrs"):
        raise UnionOverlayBuildError(f"overlay xattrs are forbidden: {entry['path']}")
    os.chown(path, int(entry["uid"]), int(entry["gid"]), follow_symlinks=follow_symlinks)
    if entry["kind"] != "symlink":
        os.chmod(path, int(str(entry["mode"]), 8), follow_symlinks=follow_symlinks)
    os.utime(path, (timestamp, timestamp), follow_symlinks=follow_symlinks)


def _read_regular(path: Path, expected: os.stat_result) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != expected.st_dev
            or before.st_ino != expected.st_ino
            or before.st_size != expected.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or observed != before.st_size
        ):
            raise UnionOverlayBuildError(f"regular file changed while read: {path}")
        return "sha256:" + digest.hexdigest()
    finally:
        os.close(descriptor)


def _xattrs(path: Path, *, follow_symlinks: bool) -> dict[str, str]:
    try:
        names = sorted(os.listxattr(path, follow_symlinks=follow_symlinks))
    except OSError as error:
        raise UnionOverlayBuildError(f"cannot inspect xattrs: {path}") from error
    return {
        name: os.getxattr(path, name, follow_symlinks=follow_symlinks).hex()
        for name in names
    }


def _manifest_bytes(manifest: dict[str, dict[str, Any]]) -> bytes:
    return b"".join(canonical_json(manifest[path]) for path in sorted(manifest))


def _safe_relative(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
        or "." in path.parts
        or not SAFE_PATH.fullmatch(value)
    ):
        raise UnionOverlayBuildError(f"unsafe runtime path: {value!r}")
    return value


def _write(path: Path, value: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-root", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--protected-path", action="append", default=[])
    parser.add_argument("--timestamp", required=True, type=int)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                build(
                    args.core_root,
                    args.target_root,
                    args.output,
                    args.protected_path,
                    args.timestamp,
                ),
                indent=2,
                sort_keys=True,
            )
        )
    except (OSError, UnionOverlayBuildError, json.JSONDecodeError) as error:
        print(f"union-overlay-build: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
