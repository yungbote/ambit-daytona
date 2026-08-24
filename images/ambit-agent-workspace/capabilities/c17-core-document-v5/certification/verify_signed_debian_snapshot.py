#!/usr/bin/env python3
"""Verify the frozen Debian runtime closure from signed snapshot metadata.

This verifier does not download or install anything. It proves that the
checked-in binary/source/font/copyright locks are the exact deterministic
outputs of the preserved snapshot inputs supplied by ``--input-root``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import re
import subprocess
from collections.abc import Iterable
from pathlib import Path


PACKAGES = ("debian-Packages.xz", "security-Packages.xz")
SOURCES = ("debian-Sources.xz", "security-Sources.xz")
INDEX_ORIGINS = {
    "debian": (
        "debian-InRelease",
        "debian-Packages.xz",
        "debian-Sources.xz",
        "main/binary-amd64/Packages.xz",
        "main/source/Sources.xz",
    ),
    "security": (
        "security-InRelease",
        "security-Packages.xz",
        "security-Sources.xz",
        "main/binary-amd64/Packages.xz",
        "main/source/Sources.xz",
    ),
}
EXPECTED_INDEX_SIGNERS = {
    "debian-InRelease": frozenset(
        {
            "4CB50190207B4758A3F73A796ED0E7B82643E131",
            "B8E5F13176D2A7A75220028078DBA3BC47EF2265",
            "41587F7DB8C774BCCF131416762F67A0B2C39DE4",
        }
    ),
    "security-InRelease": frozenset(
        {
            "B0CAB9266E8C3929798B3EEEBDE6D2B9216EC7A8",
            "89C87ACEA5DD6B8E6A7068808E9F831205B4BA95",
        }
    ),
}
EXPECTED_REQUESTED_PACKAGES = {
    "fonts-noto-cjk": "1:20240730+repack1-1",
    "fonts-noto-core": "20201225-2",
    "fonts-noto-mono": "20201225-2",
    "libreoffice-writer-nogui": "4:25.2.3-2+deb13u6",
}
REPRODUCED_OUTPUTS = (
    "copyright-files.sha256",
    "copyright-links.txt",
    "dpkg-audit.txt",
    "font-files.sha256",
    "fontconfig-noto-mono-substitutions.tsv",
    "fontconfig-noto-sans-substitutions.tsv",
    "fontconfig-noto-serif-substitutions.tsv",
    "fontconfig-roster.tsv",
    "libreoffice-version.txt",
    "runtime-dpkg.lock",
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require_regular(path: Path) -> Path:
    metadata = path.lstat()
    if not metadata.st_mode or not path.is_file() or path.is_symlink():
        raise ValueError(f"expected one regular no-follow input: {path}")
    return path


def parse_manifest(path: Path, *, digest_manifest: bool) -> dict[str, str | int]:
    output: dict[str, str | int] = {}
    for line in require_regular(path).read_text(encoding="utf-8").splitlines():
        pieces = line.split("  ", 1)
        if len(pieces) != 2 or not pieces[0] or not pieces[1]:
            raise ValueError(f"invalid manifest row in {path.name}")
        raw_value, name = pieces
        if name in output:
            raise ValueError(f"duplicate manifest path in {path.name}: {name}")
        if digest_manifest:
            if not re.fullmatch(r"[0-9a-f]{64}", raw_value):
                raise ValueError(f"invalid digest in {path.name}")
            output[name] = raw_value
        else:
            if not raw_value.isascii() or not raw_value.isdecimal():
                raise ValueError(f"invalid byte count in {path.name}")
            output[name] = int(raw_value)
    return output


def require_roster(
    root: Path,
    digests: dict[str, str | int],
    sizes: dict[str, str | int],
    *,
    prefix: str,
) -> list[Path]:
    if digests.keys() != sizes.keys():
        raise ValueError(f"{prefix} digest and byte rosters differ")
    paths: list[Path] = []
    for name in digests:
        if not name.startswith(prefix):
            raise ValueError(f"manifest path escaped {prefix}: {name}")
        path = require_regular(root / name.removeprefix(prefix))
        if path.stat().st_size != sizes[name]:
            raise ValueError(f"byte count differs for {name}")
        if digest(path) != digests[name]:
            raise ValueError(f"digest differs for {name}")
        paths.append(path)
    return paths


def control_records(text: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    field: str | None = None
    for line in [*text.splitlines(), ""]:
        if not line:
            if current:
                records.append(current)
                current = {}
                field = None
            continue
        if line[0] in " \t":
            if field is None:
                raise ValueError("orphan Debian control continuation")
            current[field] += "\n" + line[1:]
            continue
        if ":" not in line:
            raise ValueError("malformed Debian control field")
        field, value = line.split(":", 1)
        if field in current:
            raise ValueError(f"duplicate Debian control field: {field}")
        current[field] = value.lstrip()
    return records


def signed_cleartext(path: Path) -> str:
    lines = require_regular(path).read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "-----BEGIN PGP SIGNED MESSAGE-----":
        raise ValueError(f"{path.name} is not a clear-signed message")
    try:
        body_start = lines.index("") + 1
        signature_start = lines.index("-----BEGIN PGP SIGNATURE-----", body_start)
    except ValueError as error:
        raise ValueError(f"{path.name} clear-sign framing is invalid") from error
    body = [line[2:] if line.startswith("- ") else line for line in lines[body_start:signature_start]]
    return "\n".join(body) + "\n"


def valid_signers(in_release: Path, keyring: Path) -> frozenset[str]:
    result = subprocess.run(
        [
            "gpgv",
            "--status-fd=1",
            "--keyring",
            str(keyring),
            str(in_release),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    signers = {
        pieces[2]
        for line in result.stdout.splitlines()
        if (pieces := line.split())[:2] == ["[GNUPG:]", "VALIDSIG"]
    }
    if not signers:
        raise ValueError(f"{in_release.name} has no valid signer")
    return frozenset(signers)


def release_sha256(text: str) -> dict[str, tuple[str, int]]:
    fields = control_records(text)
    if len(fields) != 1 or "SHA256" not in fields[0]:
        raise ValueError("signed Release has no unique SHA256 field")
    output: dict[str, tuple[str, int]] = {}
    for line in fields[0]["SHA256"].splitlines():
        if not line:
            continue
        value, size, name = line.split()
        if not re.fullmatch(r"[0-9a-f]{64}", value) or not size.isdecimal():
            raise ValueError("signed Release SHA256 row is invalid")
        output[name] = (value, int(size))
    return output


def source_pair(record: dict[str, str]) -> tuple[str, str]:
    raw = record.get("Source", record["Package"])
    match = re.fullmatch(r"([^ ]+)(?: \(([^)]+)\))?", raw)
    if match is None:
        raise ValueError(f"invalid binary Source field: {raw}")
    return match.group(1), match.group(2) or record["Version"]


def source_roster(record: dict[str, str]) -> tuple[tuple[str, int, str, str], ...]:
    directory = record["Directory"]
    rows = []
    for line in record["Checksums-Sha256"].splitlines():
        if not line:
            continue
        value, size, name = line.split()
        rows.append((value, int(size), name, directory))
    return tuple(rows)


def normalized_sha_output(path: Path) -> str:
    return require_regular(path).read_text(encoding="utf-8").replace("  /", "  ")


def require_text(path: Path, expected: str) -> None:
    actual = require_regular(path).read_text(encoding="utf-8")
    if actual != expected:
        raise ValueError(f"tracked lock differs from reproduced output: {path.name}")


def package_index(indexes: Path) -> dict[str, list[dict[str, str]]]:
    output: dict[str, list[dict[str, str]]] = {}
    for name in PACKAGES:
        data = lzma.decompress(require_regular(indexes / name).read_bytes()).decode("utf-8")
        for record in control_records(data):
            if "SHA256" in record:
                output.setdefault(record["SHA256"], []).append(record)
    return output


def package_identity_index(
    records: dict[str, list[dict[str, str]]],
) -> dict[tuple[str, str, str], list[dict[str, str]]]:
    output: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for candidates in records.values():
        for record in candidates:
            key = (record["Package"], record["Version"], record["Architecture"])
            output.setdefault(key, []).append(record)
    return output


def source_index(indexes: Path) -> dict[tuple[str, str], list[dict[str, str]]]:
    output: dict[tuple[str, str], list[dict[str, str]]] = {}
    for name in SOURCES:
        data = lzma.decompress(require_regular(indexes / name).read_bytes()).decode("utf-8")
        for record in control_records(data):
            output.setdefault((record["Package"], record["Version"]), []).append(record)
    return output


def verify(input_root: Path, pack_root: Path) -> dict[str, int | str]:
    locks = pack_root / "locks"
    indexes = input_root / "indexes"
    keyring = require_regular(indexes / "debian-archive-keyring.gpg")
    index_digests = parse_manifest(locks / "debian-index-artifacts.sha256", digest_manifest=True)
    index_sizes = parse_manifest(locks / "debian-index-artifacts.bytes", digest_manifest=False)
    require_roster(indexes, index_digests, index_sizes, prefix="debian/indexes/")
    if digest(keyring) != "506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017":
        raise ValueError("the Debian archive keyring differs from the pinned base image")
    require_text(indexes / "debian-archive-keyring.version", "debian-archive-keyring=2025.1\n")

    for (
        in_release_name,
        packages_name,
        sources_name,
        packages_ref,
        sources_ref,
    ) in INDEX_ORIGINS.values():
        in_release = indexes / in_release_name
        if valid_signers(in_release, keyring) != EXPECTED_INDEX_SIGNERS[in_release_name]:
            raise ValueError(f"{in_release_name} signer roster differs")
        signed = release_sha256(signed_cleartext(in_release))
        for local_name, signed_name in ((packages_name, packages_ref), (sources_name, sources_ref)):
            local = require_regular(indexes / local_name)
            if signed.get(signed_name) != (digest(local), local.stat().st_size):
                raise ValueError(f"{local_name} is not the exact signed index")

    runtime_digests = parse_manifest(locks / "debian-runtime-debs.sha256", digest_manifest=True)
    runtime_sizes = parse_manifest(locks / "debian-runtime-debs.bytes", digest_manifest=False)
    runtime_paths = require_roster(
        input_root / "debs-source", runtime_digests, runtime_sizes, prefix="runtime-debs/"
    )
    actual_runtime_names = {path.name for path in (input_root / "debs-source").glob("*.deb")}
    if actual_runtime_names != {path.name for path in runtime_paths}:
        raise ValueError("the runtime package directory contains an unlocked package")

    binaries = package_index(indexes)
    selected_pairs: set[tuple[str, str]] = set()
    selected_packages: dict[str, str] = {}
    for path in runtime_paths:
        candidates = [
            record
            for record in binaries.get(digest(path), [])
            if int(record["Size"]) == path.stat().st_size
        ]
        if not candidates:
            raise ValueError(f"runtime package is absent from the signed indexes: {path.name}")
        pairs = {source_pair(record) for record in candidates}
        if len(pairs) != 1:
            raise ValueError(f"runtime package has ambiguous source authority: {path.name}")
        selected_pairs.update(pairs)
        identities = {(record["Package"], record["Version"]) for record in candidates}
        if len(identities) != 1:
            raise ValueError(f"runtime package has ambiguous binary identity: {path.name}")
        package, version = next(iter(identities))
        selected_packages[package] = version
    for package, version in EXPECTED_REQUESTED_PACKAGES.items():
        if selected_packages.get(package) != version:
            raise ValueError(f"requested package is missing or substituted: {package}")

    identities = package_identity_index(binaries)
    runtime_lock_lines = require_regular(locks / "debian-runtime-dpkg.lock").read_text(
        encoding="utf-8"
    ).splitlines()
    for line in runtime_lock_lines:
        package_arch, version = line.split("=", 1)
        if ":" in package_arch:
            package, architecture = package_arch.rsplit(":", 1)
        else:
            package, architecture = package_arch, "all"
        candidates = identities.get((package, version, architecture), [])
        if not candidates and architecture == "all":
            candidates = identities.get((package, version, "amd64"), [])
        if not candidates:
            raise ValueError(f"installed package is absent from signed indexes: {line}")
        pairs = {source_pair(record) for record in candidates}
        if len(pairs) != 1:
            raise ValueError(f"installed package has ambiguous source authority: {line}")
        selected_pairs.update(pairs)

    sources = source_index(indexes)
    source_digests = parse_manifest(locks / "debian-source-artifacts.sha256", digest_manifest=True)
    source_sizes = parse_manifest(locks / "debian-source-artifacts.bytes", digest_manifest=False)
    expected_sources: dict[str, tuple[str, int]] = {}
    for pair in sorted(selected_pairs):
        candidates = sources.get(pair, [])
        if not candidates:
            raise ValueError(f"source package is absent from signed indexes: {pair}")
        rosters = [source_roster(record) for record in candidates]
        artifact_rosters = {
            tuple((value, size, name) for value, size, name, _ in roster)
            for roster in rosters
        }
        if len(artifact_rosters) != 1:
            raise ValueError(f"source package has ambiguous artifact authority: {pair}")
        matching_rosters = [
            roster
            for roster in rosters
            if all(
                source_digests.get(f"debian/sources/{directory}/{name}") == value
                and source_sizes.get(f"debian/sources/{directory}/{name}") == size
                for value, size, name, directory in roster
            )
        ]
        if len(matching_rosters) != 1:
            raise ValueError(f"source transport alias is not exact: {pair}")
        for value, size, name, directory in matching_rosters[0]:
            path = f"debian/sources/{directory}/{name}"
            prior = expected_sources.setdefault(path, (value, size))
            if prior != (value, size):
                raise ValueError(f"source artifact path collides: {path}")
    if source_digests.keys() != expected_sources.keys() or source_sizes.keys() != expected_sources.keys():
        raise ValueError("tracked source closure differs from the signed binary source closure")
    for name, (value, size) in expected_sources.items():
        if source_digests[name] != value or source_sizes[name] != size:
            raise ValueError(f"tracked source identity differs: {name}")
    source_paths = require_roster(
        input_root / "source-files", source_digests, source_sizes, prefix="debian/sources/"
    )
    actual_source_files = {path.relative_to(input_root / "source-files").as_posix() for path in (input_root / "source-files").rglob("*") if path.is_file()}
    if actual_source_files != {path.relative_to(input_root / "source-files").as_posix() for path in source_paths}:
        raise ValueError("the source directory contains an unlocked artifact")

    first = input_root / "generated-one"
    second = input_root / "generated-two"
    for name in REPRODUCED_OUTPUTS:
        if require_regular(first / name).read_bytes() != require_regular(second / name).read_bytes():
            raise ValueError(f"offline installation output is not reproducible: {name}")
    if (second / "dpkg-audit.txt").read_bytes():
        raise ValueError("offline installed package closure is not configured")
    require_text(second / "libreoffice-version.txt", "LibreOffice 25.2.3.2 520(Build:2)\n\n")
    require_text(locks / "debian-runtime-dpkg.lock", (second / "runtime-dpkg.lock").read_text(encoding="utf-8"))
    require_text(locks / "debian-copyright-files.sha256", normalized_sha_output(second / "copyright-files.sha256"))
    require_text(locks / "font-files.sha256", normalized_sha_output(second / "font-files.sha256"))
    require_text(locks / "fontconfig-roster.tsv", (second / "fontconfig-roster.tsv").read_text(encoding="utf-8"))
    require_text(locks / "package-copyright.tsv", (second / "package-copyright.tsv").read_text(encoding="utf-8"))
    require_text(locks / "font-package-ownership.tsv", (second / "font-package-ownership.tsv").read_text(encoding="utf-8"))

    return {
        "schema": "ambit.signed-debian-snapshot-verification/v1",
        "runtimeDebs": len(runtime_paths),
        "installedPackages": len(runtime_lock_lines),
        "sourcePackages": len(selected_pairs),
        "sourceArtifacts": len(source_paths),
        "fontFiles": len((second / "font-files.sha256").read_text(encoding="utf-8").splitlines()),
        "reproducedInstallations": 2,
        "outcome": "passed",
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--pack-root", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(verify(args.input_root.resolve(), args.pack_root.resolve()), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
