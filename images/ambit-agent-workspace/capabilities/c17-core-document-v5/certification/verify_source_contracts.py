from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA512 = re.compile(r"^sha512:[0-9a-f]{128}$")
SOURCE_CONTRACT_LINE = re.compile(r"^([0-9a-f]{64})  ([a-z0-9][a-z0-9./-]*)$")
SOURCE_CONTRACT_PATHS = (
    "locks/base-oci.lock.json",
    "locks/capture-helper-input.lock.json",
    "locks/debian-input.lock.json",
    "locks/pdfjs-input.lock.json",
    "policy/license-policy.json",
    "policy/render-policy.json",
    "policy/runtime-policy.json",
    "toolchain-manifest.json",
)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = child
    return value


def _read(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream, object_pairs_hook=_pairs)
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def _keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} fields differ: {sorted(value)}")


def _expect(value: Any, expected: Any, label: str) -> None:
    if value != expected:
        raise ValueError(f"{label} differs")


def _sha256(value: Any, label: str) -> None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} is not an exact SHA-256")


def _sha512(value: Any, label: str) -> None:
    if not isinstance(value, str) or SHA512.fullmatch(value) is None:
        raise ValueError(f"{label} is not an exact SHA-512")


def _verify_source_manifest(root: Path) -> None:
    manifest = root / "certification/source-contracts.sha256"
    lines = manifest.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    for line in lines:
        match = SOURCE_CONTRACT_LINE.fullmatch(line)
        if match is None:
            raise ValueError("source contract manifest is noncanonical")
        entries.append((match.group(2), match.group(1)))
    if tuple(path for path, _ in entries) != SOURCE_CONTRACT_PATHS:
        raise ValueError("source contract manifest path roster differs")
    for relative, expected in entries:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"source contract is not a regular file: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"source contract digest differs: {relative}")


def verify(root: Path, *, require_ready: bool = False) -> dict[str, Any]:
    root = root.resolve(strict=True)
    base = _read(root / "locks/base-oci.lock.json")
    debian = _read(root / "locks/debian-input.lock.json")
    pdfjs = _read(root / "locks/pdfjs-input.lock.json")
    helper = _read(root / "locks/capture-helper-input.lock.json")
    toolchain = _read(root / "toolchain-manifest.json")
    runtime = _read(root / "policy/runtime-policy.json")
    render = _read(root / "policy/render-policy.json")
    license_policy = _read(root / "policy/license-policy.json")

    _keys(
        base,
        {
            "schema",
            "sourceTag",
            "index",
            "platform",
            "configCreatedAt",
            "debuerreotypeVersion",
        },
        "base lock",
    )
    _expect(base["schema"], "ambit.runtime-pack-base-oci-lock/v1", "base schema")
    _expect(
        base["index"]["reference"],
        (
            "docker.io/library/debian@sha256:"
            "3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
        ),
        "base reference",
    )
    _sha256(base["index"]["digest"], "base index digest")
    if not str(base["index"]["reference"]).endswith(f"@{base['index']['digest']}"):
        raise ValueError("base reference does not bind the index digest")
    _expect(base["platform"]["os"], "linux", "base platform OS")
    _expect(base["platform"]["architecture"], "amd64", "base architecture")
    _sha256(base["platform"]["manifestDigest"], "base platform manifest")
    _sha256(base["platform"]["configDigest"], "base config")
    if len(base["platform"]["layers"]) != 1:
        raise ValueError("base layer roster must be exact")
    _sha256(base["platform"]["layers"][0]["digest"], "base layer")

    _expect(debian["schema"], "ambit.runtime-pack-debian-input-lock/v1", "Debian schema")
    _expect(debian["platform"], "linux/amd64", "Debian platform")
    _expect(
        debian["requestedPackages"],
        [
            "fonts-noto-cjk=1:20240730+repack1-1",
            "fonts-noto-core=20201225-2",
            "libreoffice-writer-nogui=4:25.2.3-2+deb13u6",
        ],
        "Debian requested package roster",
    )
    _expect(debian["signaturePolicy"]["verifyInRelease"], True, "Debian signatures")
    _expect(debian["resolution"]["state"], "unavailable", "Debian closure state")
    if len(debian["archives"]) != 2:
        raise ValueError("Debian archive roster must contain exactly two archives")
    for archive in debian["archives"]:
        _sha256(archive["inRelease"]["sha256"], f"{archive['name']} InRelease")
        if not archive["snapshot"].startswith("https://snapshot.debian.org/archive/"):
            raise ValueError("Debian snapshot must use the official immutable archive")

    _expect(pdfjs["schema"], "ambit.runtime-pack-pdfjs-input-lock/v1", "PDF.js schema")
    _expect(pdfjs["package"], "pdfjs-dist", "PDF.js package")
    _expect(pdfjs["version"], "6.2.108", "PDF.js version")
    _sha256(pdfjs["archive"]["sha256"], "PDF.js archive")
    _sha512(pdfjs["archive"]["sha512"], "PDF.js archive SHA-512")
    _expect(pdfjs["execution"]["state"], "unavailable", "PDF.js execution state")
    _expect(pdfjs["extractedRoster"]["state"], "unavailable", "PDF.js roster state")
    if "standard_fonts" not in pdfjs["excludedRoots"]:
        raise ValueError("unreviewed PDF.js standard fonts must remain excluded")
    if any("node_modules" in item for item in pdfjs["retainedStaticRoots"]):
        raise ValueError("PDF.js static roster must not smuggle a Node dependency tree")

    _expect(
        helper["schema"],
        "ambit.runtime-pack-external-capture-helper-input-lock/v1",
        "capture helper schema",
    )
    _expect(helper["state"], "unavailable", "capture helper state")
    _expect(helper["license"]["packageLicenseField"], "UNLICENSED", "helper license")
    _expect(
        helper["requiredExternalAuthority"]["downgrade"],
        "forbidden",
        "helper signature downgrade",
    )
    if any(
        key in helper
        for key in (
            "archiveSha256",
            "expectedRawSha256",
            "signatureSha256",
            "publisherKeySha256",
        )
    ):
        raise ValueError("unavailable helper lock must not contain self-minted pins")
    _expect(
        helper["archiveAdmission"]["hashRawBytesBeforeParsing"],
        True,
        "helper raw-byte admission order",
    )
    _expect(
        helper["archiveAdmission"]["selfDescribedDigestsGrantAuthority"],
        False,
        "helper self-description authority",
    )

    _expect(toolchain["schema"], "ambit.runtime-pack-toolchain/v3", "toolchain schema")
    _expect(toolchain["pack"], "ambit.runtime-pack/core-document@5", "pack ref")
    _expect(toolchain["state"], "unavailable", "toolchain state")
    _expect(toolchain["platform"], {"os": "linux", "architecture": "amd64"}, "platform")
    _expect(toolchain["pdfjs"]["runtimeNode"], "absent", "runtime Node")
    _expect(toolchain["pdfjs"]["runtimeNpm"], "absent", "runtime npm")
    _expect(toolchain["pdfjs"]["nativeCanvas"], "unavailable", "native Canvas")
    _expect(toolchain["activation"], "forbidden", "activation")
    if len(toolchain["knownBlockers"]) != len(set(toolchain["knownBlockers"])):
        raise ValueError("toolchain blockers must be unique")

    _expect(runtime["runtimeUid"], 1000, "runtime UID")
    _expect(runtime["rootEscalation"], "denied", "root escalation")
    _expect(runtime["rootFilesystem"], "read-only", "root filesystem")
    _expect(runtime["network"], "provider-enforced-none", "runtime network")
    _expect(runtime["runtimePackageInstallers"], "absent", "runtime installers")
    _expect(render["pdfjs"]["popplerFallback"], "forbidden", "Poppler fallback")
    _expect(render["pdfjs"]["executionState"], "unavailable", "render execution")
    _expect(render["canonicalArtifactBoundary"], "external-commit-only", "commit boundary")
    _expect(render["renderOutputGrantsCanonicalAuthority"], False, "render authority")
    _expect(license_policy["state"], "unavailable", "license policy state")
    _expect(
        license_policy["nativeCanvas"]["disposition"],
        "unavailable",
        "native Canvas license closure",
    )
    _expect(
        license_policy["promotionWithoutCompleteInventory"],
        "forbidden",
        "license promotion",
    )

    _verify_source_manifest(root)

    unavailable = {
        "toolchain": toolchain["state"],
        "debianClosure": debian["resolution"]["state"],
        "pdfjsExecution": pdfjs["execution"]["state"],
        "pdfjsRoster": pdfjs["extractedRoster"]["state"],
        "captureHelper": helper["state"],
        "fonts": toolchain["fonts"]["state"],
        "licenses": license_policy["state"],
        "renderExecution": render["pdfjs"]["executionState"],
    }
    if require_ready:
        raise ValueError(f"core-document@5 is unavailable: {unavailable}")
    return {
        "schema": "ambit.runtime-pack-source-contract-verification/v1",
        "outcome": "passed",
        "availability": unavailable,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    result = verify(args.root, require_ready=args.require_ready)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
