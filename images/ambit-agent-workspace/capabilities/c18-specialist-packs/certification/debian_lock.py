from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import re
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "ambit.c18-debian-binary-closure-lock/v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PLATFORM = "linux/amd64"
DEFAULT_BASE_IMAGE = (
    "docker.io/library/debian@sha256:"
    "38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16"
)
SNAPSHOTS = {
    "debian": {
        "url": "https://snapshot.debian.org/archive/debian/20260802T202614Z/",
        "inReleaseSha256": "sha256:98b25b5cd185c59d34aa6e4c3e9b5b8f01bbe9d104fe2dcfbcd30dc0a14a59ed",
    },
    "debian-security": {
        "url": "https://snapshot.debian.org/archive/debian-security/20260802T121235Z/",
        "inReleaseSha256": "sha256:c5b38b54765337d3f141385c5cd7b5ef2dd64557c44b519bd079c5ac8f40b369",
    },
}


class DebianLockError(ValueError):
    """A Debian binary closure is not exactly replayable."""


@dataclass(frozen=True)
class PackageIndexRecord:
    repository: str
    package: str
    version: str
    architecture: str
    filename: str
    bytes: int
    sha256: str


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _paragraphs(lines: Iterable[str]) -> Iterable[dict[str, str]]:
    fields: dict[str, str] = {}
    current: str | None = None
    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if not line:
            if fields:
                yield fields
                fields = {}
                current = None
            continue
        if line.startswith((" ", "\t")):
            if current is None:
                raise DebianLockError("Debian index contains an orphan continuation line")
            fields[current] += "\n" + line[1:]
            continue
        if ": " not in line:
            raise DebianLockError("Debian index contains a malformed field")
        current, value = line.split(": ", 1)
        if current in fields:
            raise DebianLockError(f"Debian index contains duplicate field {current!r}")
        fields[current] = value
    if fields:
        yield fields


def read_package_index(path: Path, repository: str) -> list[PackageIndexRecord]:
    if repository not in SNAPSHOTS:
        raise DebianLockError(f"unknown repository {repository!r}")
    if not path.is_file() or path.is_symlink():
        raise DebianLockError(f"package index must be one regular file: {path}")
    try:
        with lzma.open(path, mode="rt", encoding="utf-8") as source:
            records = list(_paragraphs(source))
    except (lzma.LZMAError, UnicodeDecodeError) as error:
        raise DebianLockError(f"package index {path} is invalid") from error
    result: list[PackageIndexRecord] = []
    for record in records:
        if not {"Package", "Version", "Architecture", "Filename", "Size", "SHA256"}.issubset(record):
            continue
        try:
            size = int(record["Size"])
        except ValueError as error:
            raise DebianLockError("package index size is invalid") from error
        sha256 = record["SHA256"]
        if size <= 0 or not SHA256_PATTERN.fullmatch(sha256):
            raise DebianLockError("package index digest or size is invalid")
        result.append(
            PackageIndexRecord(
                repository=repository,
                package=record["Package"],
                version=record["Version"],
                architecture=record["Architecture"],
                filename=record["Filename"],
                bytes=size,
                sha256=sha256,
            )
        )
    return result


def _ar_members(payload: bytes) -> dict[str, bytes]:
    if not payload.startswith(b"!<arch>\n"):
        raise DebianLockError("Debian archive is not an ar container")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(payload):
        if offset + 60 > len(payload):
            raise DebianLockError("Debian ar header is truncated")
        header = payload[offset : offset + 60]
        offset += 60
        if header[58:60] != b"`\n":
            raise DebianLockError("Debian ar member header is invalid")
        try:
            name = header[:16].decode("ascii").strip().rstrip("/")
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise DebianLockError("Debian ar member metadata is invalid") from error
        if not name or name in members or size < 0 or offset + size > len(payload):
            raise DebianLockError("Debian ar member roster is invalid")
        members[name] = payload[offset : offset + size]
        offset += size + (size % 2)
    if offset != len(payload):
        raise DebianLockError("Debian ar trailing bytes are invalid")
    return members


def _deb_identity(path: Path) -> tuple[str, str, str]:
    if not path.is_file() or path.is_symlink() or path.suffix != ".deb":
        raise DebianLockError(f"Debian archive must be one regular .deb: {path}")
    members = _ar_members(path.read_bytes())
    if members.get("debian-binary") != b"2.0\n":
        raise DebianLockError(f"Debian archive version is invalid: {path.name!r}")
    control_members = [
        (name, payload)
        for name, payload in members.items()
        if name.startswith("control.tar")
    ]
    if len(control_members) != 1:
        raise DebianLockError(f"Debian archive control member is ambiguous: {path.name!r}")
    try:
        with tarfile.open(fileobj=io.BytesIO(control_members[0][1]), mode="r:*") as archive:
            controls = [
                member
                for member in archive.getmembers()
                if member.name.lstrip("./") == "control" and member.isfile()
            ]
            if len(controls) != 1:
                raise DebianLockError(
                    f"Debian archive must contain exactly one control file: {path.name!r}"
                )
            source = archive.extractfile(controls[0])
            if source is None:
                raise DebianLockError(f"Debian archive control file is unreadable: {path.name!r}")
            control = source.read().decode("utf-8")
    except (tarfile.TarError, UnicodeDecodeError) as error:
        raise DebianLockError(f"Debian archive control member is invalid: {path.name!r}") from error
    paragraphs = list(_paragraphs(control.splitlines(keepends=True)))
    if len(paragraphs) != 1:
        raise DebianLockError(f"Debian archive control paragraph is invalid: {path.name!r}")
    fields = paragraphs[0]
    values = tuple(fields.get(field, "") for field in ("Package", "Version", "Architecture"))
    if not all(values):
        raise DebianLockError(f"Debian archive identity is incomplete: {path.name!r}")
    return values


def _load_closure(path: Path) -> list[str]:
    if not path.is_file() or path.is_symlink():
        raise DebianLockError("installed dpkg closure must be one regular file")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines != sorted(set(lines)):
        raise DebianLockError("installed dpkg closure must be nonempty, sorted, and unique")
    if any("=" not in line or line.startswith("=") or line.endswith("=") for line in lines):
        raise DebianLockError("installed dpkg closure contains an invalid entry")
    return lines


def build_lock(
    deb_directory: Path,
    *,
    pack_ref: str,
    requested_packages: list[str],
    installed_closure: Path,
    package_indexes: list[tuple[Path, str]],
    base_image: str = DEFAULT_BASE_IMAGE,
) -> dict[str, object]:
    if "@sha256:" not in base_image or not SHA256_PATTERN.fullmatch(
        base_image.rsplit("@sha256:", 1)[1]
    ):
        raise DebianLockError("base image must use an immutable sha256 reference")
    if not deb_directory.is_dir() or deb_directory.is_symlink():
        raise DebianLockError("Debian archive directory must be one real directory")
    unexpected = sorted(
        path.name
        for path in deb_directory.iterdir()
        if not path.is_file() or path.suffix != ".deb" or path.is_symlink()
    )
    if unexpected:
        raise DebianLockError(f"Debian archive directory has unexpected entries: {unexpected!r}")
    index_records = [
        record
        for path, repository in package_indexes
        for record in read_package_index(path, repository)
    ]
    archive_entries: list[dict[str, object]] = []
    identities: set[tuple[str, str, str]] = set()
    for path in sorted(deb_directory.iterdir(), key=lambda item: item.name):
        package, version, architecture = _deb_identity(path)
        identity = (package, version, architecture)
        if identity in identities:
            raise DebianLockError(f"duplicate Debian archive identity: {identity!r}")
        identities.add(identity)
        size = path.stat().st_size
        digest = _sha256(path)
        matches = [
            record
            for record in index_records
            if (record.package, record.version, record.architecture, record.bytes, record.sha256)
            == (package, version, architecture, size, digest)
        ]
        if not matches:
            raise DebianLockError(
                f"archive {path.name!r} does not resolve to a signed package index record"
            )
        signed_locations = sorted(
            (
                {"repository": match.repository, "repositoryPath": match.filename}
                for match in matches
            ),
            key=lambda value: (value["repository"], value["repositoryPath"]),
        )
        if len(signed_locations) != len(
            {(value["repository"], value["repositoryPath"]) for value in signed_locations}
        ):
            raise DebianLockError(f"archive {path.name!r} has duplicate signed locations")
        archive_entries.append(
            {
                "localFilename": path.name,
                "package": package,
                "version": version,
                "architecture": architecture,
                "signedLocations": signed_locations,
                "bytes": size,
                "sha256": f"sha256:{digest}",
            }
        )
    if not archive_entries:
        raise DebianLockError("Debian archive closure cannot be empty")

    requested = sorted(set(requested_packages))
    requested_identities = {
        f"{entry['package']}={entry['version']}" for entry in archive_entries
    }
    missing = sorted(set(requested) - requested_identities)
    if missing:
        raise DebianLockError(f"requested packages are absent: {missing!r}")
    closure = _load_closure(installed_closure)
    graph_digest = hashlib.sha256(
        _canonical_bytes(
            [
                {
                    "package": entry["package"],
                    "version": entry["version"],
                    "architecture": entry["architecture"],
                    "sha256": entry["sha256"],
                }
                for entry in archive_entries
            ]
        )
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "packRef": pack_ref,
        "platform": PLATFORM,
        "baseImage": base_image,
        "snapshots": SNAPSHOTS,
        "signaturePolicy": {
            "inReleaseVerification": "required-external-input",
            "trustedKeyring": "debian-archive-keyring-2025.1",
            "checkValidUntil": False,
            "exception": "immutable-snapshot-and-exact-inrelease-digests",
        },
        "resolution": {
            "installRecommends": False,
            "mode": "offline-dpkg-replay",
            "installScripts": "package-maintainer-scripts-captured-during-image-build",
            "runtimePackageManager": "absent",
        },
        "requestedPackages": requested,
        "archiveCount": len(archive_entries),
        "transitiveGraphDigest": f"sha256:{graph_digest}",
        "archives": archive_entries,
        "installedClosure": {
            "entryCount": len(closure),
            "sha256": f"sha256:{_sha256(installed_closure)}",
        },
    }


def _load_unique_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DebianLockError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise DebianLockError(f"invalid JSON in {path}: {error}") from error


def verify_lock(
    lock_path: Path,
    deb_directory: Path,
    installed_closure: Path,
    package_indexes: list[tuple[Path, str]],
) -> dict[str, object]:
    lock = _load_unique_json(lock_path)
    if not isinstance(lock, dict) or lock.get("schema") != SCHEMA:
        raise DebianLockError("Debian lock schema is invalid")
    rebuilt = build_lock(
        deb_directory,
        pack_ref=str(lock.get("packRef")),
        requested_packages=list(lock.get("requestedPackages") or []),
        installed_closure=installed_closure,
        package_indexes=package_indexes,
        base_image=str(lock.get("baseImage")),
    )
    if rebuilt != lock:
        raise DebianLockError("Debian archive closure does not reproduce the lock")
    return rebuilt


def _index_arguments(values: list[str]) -> list[tuple[Path, str]]:
    result: list[tuple[Path, str]] = []
    for value in values:
        repository, separator, path = value.partition("=")
        if not separator or repository not in SNAPSHOTS or not path:
            raise DebianLockError(f"invalid --package-index value: {value!r}")
        result.append((Path(path), repository))
    if {repository for _, repository in result} != set(SNAPSHOTS):
        raise DebianLockError("both exact Debian snapshot indexes are required")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("freeze", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--deb-directory", required=True, type=Path)
        command.add_argument("--installed-closure", required=True, type=Path)
        command.add_argument("--package-index", action="append", default=[])
        if name == "freeze":
            command.add_argument("--output", required=True, type=Path)
            command.add_argument("--pack-ref", required=True)
            command.add_argument("--requested", action="append", default=[])
            command.add_argument("--base-image", default=DEFAULT_BASE_IMAGE)
        else:
            command.add_argument("--lock", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        indexes = _index_arguments(args.package_index)
        if args.command == "freeze":
            lock = build_lock(
                args.deb_directory,
                pack_ref=args.pack_ref,
                requested_packages=args.requested,
                installed_closure=args.installed_closure,
                package_indexes=indexes,
                base_image=args.base_image,
            )
            args.output.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
        else:
            verify_lock(args.lock, args.deb_directory, args.installed_closure, indexes)
    except (OSError, DebianLockError) as error:
        print(f"debian-lock: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
