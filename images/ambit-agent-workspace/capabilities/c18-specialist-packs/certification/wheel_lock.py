from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "ambit.c18-python-wheel-lock/v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
WHEEL_PATTERN = re.compile(
    r"^(?P<distribution>.+)-(?P<version>[^-]+)-(?P<python>[^-]+)-"
    r"(?P<abi>[^-]+)-(?P<platform>[^-]+)\.whl$"
)


class WheelLockError(ValueError):
    """A wheel set is not a closed, reproducible input."""


@dataclass(frozen=True)
class WheelIdentity:
    filename: str
    distribution: str
    version: str
    python_tag: str
    abi_tag: str
    platform_tag: str
    bytes: int
    sha256: str

    def as_json(self) -> dict[str, object]:
        return {
            "filename": self.filename,
            "distribution": self.distribution,
            "version": self.version,
            "pythonTag": self.python_tag,
            "abiTag": self.abi_tag,
            "platformTag": self.platform_tag,
            "bytes": self.bytes,
            "sha256": f"sha256:{self.sha256}",
        }


def _canonical_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _metadata_identity(
    path: Path,
    *,
    expected_distribution: str,
    expected_version: str,
) -> tuple[str, str]:
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.namelist()
            unsafe = [
                member
                for member in members
                if member.startswith("/")
                or ".." in PurePosixPath(member).parts
                or "\\" in member
            ]
            if unsafe:
                raise WheelLockError(
                    f"wheel {path.name!r} contains unsafe members: {unsafe[:3]!r}"
                )
            metadata_members = [
                member
                for member in members
                if member.endswith(".dist-info/METADATA")
                and len(PurePosixPath(member).parts) == 2
            ]
            if not metadata_members:
                raise WheelLockError(
                    f"wheel {path.name!r} must contain top-level distribution METADATA"
                )
            metadata_documents = [
                archive.read(member).decode("utf-8") for member in metadata_members
            ]
    except zipfile.BadZipFile as error:
        raise WheelLockError(f"wheel {path.name!r} is not a valid ZIP archive") from error

    identities: list[tuple[str, str]] = []
    for metadata in metadata_documents:
        fields: dict[str, str] = {}
        for line in metadata.splitlines():
            if not line:
                break
            if ": " not in line:
                continue
            name, value = line.split(": ", 1)
            if name in {"Name", "Version"} and name not in fields:
                fields[name] = value
        if set(fields) == {"Name", "Version"}:
            identities.append((_canonical_distribution(fields["Name"]), fields["Version"]))
    matches = [
        identity
        for identity in identities
        if identity == (expected_distribution, expected_version)
    ]
    if len(matches) != 1:
        raise WheelLockError(
            f"wheel {path.name!r} must contain exactly one matching top-level METADATA identity"
        )
    return matches[0]


def inspect_wheel(path: Path) -> WheelIdentity:
    if not path.is_file() or path.is_symlink():
        raise WheelLockError(f"wheel input must be one regular file: {path}")
    match = WHEEL_PATTERN.fullmatch(path.name)
    if not match:
        raise WheelLockError(f"invalid or non-wheel input filename: {path.name!r}")
    filename_distribution = _canonical_distribution(match.group("distribution"))
    filename_version = match.group("version")
    metadata_distribution, metadata_version = _metadata_identity(
        path,
        expected_distribution=filename_distribution,
        expected_version=filename_version,
    )
    if (metadata_distribution, metadata_version) != (
        filename_distribution,
        filename_version,
    ):
        raise WheelLockError(
            f"wheel filename and METADATA identity disagree for {path.name!r}"
        )
    return WheelIdentity(
        filename=path.name,
        distribution=metadata_distribution,
        version=metadata_version,
        python_tag=match.group("python"),
        abi_tag=match.group("abi"),
        platform_tag=match.group("platform"),
        bytes=path.stat().st_size,
        sha256=_sha256(path),
    )


def build_lock(
    wheel_directory: Path,
    *,
    pack_ref: str,
    python_version: str,
    platform: str,
    direct_requirements: list[str],
) -> dict[str, object]:
    if not wheel_directory.is_dir() or wheel_directory.is_symlink():
        raise WheelLockError("wheel directory must be one real directory")
    unexpected = sorted(
        path.name
        for path in wheel_directory.iterdir()
        if not path.is_file() or path.suffix != ".whl" or path.is_symlink()
    )
    if unexpected:
        raise WheelLockError(f"wheel directory contains unexpected entries: {unexpected!r}")
    wheels = sorted(
        (inspect_wheel(path) for path in wheel_directory.iterdir()),
        key=lambda wheel: (wheel.distribution, wheel.version, wheel.filename),
    )
    if not wheels:
        raise WheelLockError("wheel set cannot be empty")
    identities = [(wheel.distribution, wheel.version) for wheel in wheels]
    if len(identities) != len(set(identities)):
        raise WheelLockError("wheel set contains duplicate distribution/version identities")

    normalized_direct = sorted({_canonical_distribution(value) for value in direct_requirements})
    locked_distributions = {wheel.distribution for wheel in wheels}
    missing_direct = sorted(set(normalized_direct) - locked_distributions)
    if missing_direct:
        raise WheelLockError(
            f"direct requirements are absent from the resolved wheel set: {missing_direct!r}"
        )

    wheel_entries = [wheel.as_json() for wheel in wheels]
    graph_digest = hashlib.sha256(
        canonical_bytes(
            [
                {
                    "distribution": wheel.distribution,
                    "version": wheel.version,
                    "sha256": f"sha256:{wheel.sha256}",
                }
                for wheel in wheels
            ]
        )
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "packRef": pack_ref,
        "pythonVersion": python_version,
        "platform": platform,
        "resolver": "pip-download-only-binary-require-hashes",
        "installScripts": "forbidden",
        "runtimeInstaller": "absent",
        "directRequirements": normalized_direct,
        "resolvedDistributionCount": len(wheels),
        "transitiveGraphDigest": f"sha256:{graph_digest}",
        "wheels": wheel_entries,
    }


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def write_lock(path: Path, lock: dict[str, object]) -> None:
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_unique_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise WheelLockError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise WheelLockError(f"invalid JSON in {path}: {error}") from error


def verify_lock(lock_path: Path, wheel_directory: Path) -> dict[str, object]:
    lock = _load_unique_json(lock_path)
    if not isinstance(lock, dict) or lock.get("schema") != SCHEMA:
        raise WheelLockError("wheel lock schema is invalid")
    required_keys = {
        "schema",
        "packRef",
        "pythonVersion",
        "platform",
        "resolver",
        "installScripts",
        "runtimeInstaller",
        "directRequirements",
        "resolvedDistributionCount",
        "transitiveGraphDigest",
        "wheels",
    }
    if set(lock) != required_keys:
        raise WheelLockError("wheel lock has missing or extra top-level keys")
    if lock["resolver"] != "pip-download-only-binary-require-hashes":
        raise WheelLockError("wheel resolver boundary is invalid")
    if lock["installScripts"] != "forbidden" or lock["runtimeInstaller"] != "absent":
        raise WheelLockError("wheel install/runtime-installer policy is invalid")
    if not isinstance(lock["directRequirements"], list) or not all(
        isinstance(item, str) for item in lock["directRequirements"]
    ):
        raise WheelLockError("direct requirement roster is invalid")
    rebuilt = build_lock(
        wheel_directory,
        pack_ref=str(lock["packRef"]),
        python_version=str(lock["pythonVersion"]),
        platform=str(lock["platform"]),
        direct_requirements=list(lock["directRequirements"]),
    )
    if rebuilt != lock:
        raise WheelLockError("wheel directory does not reproduce the committed lock")
    return rebuilt


def requirements_from_lock(lock_path: Path) -> str:
    lock = _load_unique_json(lock_path)
    if not isinstance(lock, dict) or lock.get("schema") != SCHEMA:
        raise WheelLockError("wheel lock schema is invalid")
    wheels = lock.get("wheels")
    if not isinstance(wheels, list) or not wheels:
        raise WheelLockError("wheel lock has no resolved wheels")
    lines: list[str] = []
    identities: set[tuple[str, str]] = set()
    for index, raw in enumerate(wheels):
        if not isinstance(raw, dict):
            raise WheelLockError(f"wheel lock entry {index} is invalid")
        distribution = raw.get("distribution")
        version = raw.get("version")
        digest = raw.get("sha256")
        if (
            not isinstance(distribution, str)
            or distribution != _canonical_distribution(distribution)
            or not isinstance(version, str)
            or not version
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or not SHA256_PATTERN.fullmatch(digest.removeprefix("sha256:"))
        ):
            raise WheelLockError(f"wheel lock entry {index} identity is invalid")
        identity = (distribution, version)
        if identity in identities:
            raise WheelLockError("wheel lock contains a duplicate requirement identity")
        identities.add(identity)
        lines.append(f"{distribution}=={version} --hash={digest}")
    return "\n".join(lines) + "\n"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--wheel-directory", required=True, type=Path)
    freeze.add_argument("--output", required=True, type=Path)
    freeze.add_argument("--pack-ref", required=True)
    freeze.add_argument("--python-version", required=True)
    freeze.add_argument("--platform", required=True)
    freeze.add_argument("--direct", action="append", default=[])
    verify = subparsers.add_parser("verify")
    verify.add_argument("--wheel-directory", required=True, type=Path)
    verify.add_argument("--lock", required=True, type=Path)
    requirements = subparsers.add_parser("requirements")
    requirements.add_argument("--lock", required=True, type=Path)
    requirements.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "freeze":
            write_lock(
                args.output,
                build_lock(
                    args.wheel_directory,
                    pack_ref=args.pack_ref,
                    python_version=args.python_version,
                    platform=args.platform,
                    direct_requirements=args.direct,
                ),
            )
        elif args.command == "verify":
            verify_lock(args.lock, args.wheel_directory)
        else:
            args.output.write_text(requirements_from_lock(args.lock), encoding="utf-8")
    except (OSError, WheelLockError) as error:
        print(f"wheel-lock: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
