from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^[0-9a-f]{40}$")
MANIFEST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\[\]-]*$")
LINK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = child
    return value


def _read_json(path: Path) -> dict[str, Any]:
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


def _git_object(value: Any, label: str) -> None:
    if not isinstance(value, str) or GIT_OBJECT.fullmatch(value) is None:
        raise ValueError(f"{label} is not an exact Git object")


def _raw_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _canonical_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or MANIFEST_NAME.fullmatch(value) is None:
        raise ValueError(f"{label} is not canonical")
    pure = PurePosixPath(value)
    if pure.is_absolute() or ".." in pure.parts or "\\" in value:
        raise ValueError(f"{label} is unsafe")
    return value


def _read_sha_manifest(path: Path, *, label: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            digest, name = line.split("  ", 1)
        except ValueError as error:
            raise ValueError(f"{label} is noncanonical") from error
        if RAW_SHA256.fullmatch(digest) is None:
            raise ValueError(f"{label} digest is invalid")
        _canonical_path(name, f"{label} path")
        if name in entries:
            raise ValueError(f"{label} contains a duplicate")
        entries[name] = digest
    if list(entries) != sorted(entries):
        raise ValueError(f"{label} is not sorted")
    return entries


def _read_link_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            name, target = line.split(" -> ", 1)
        except ValueError as error:
            raise ValueError("structural link manifest is noncanonical") from error
        if LINK_NAME.fullmatch(name) is None or LINK_NAME.fullmatch(target) is None:
            raise ValueError("structural link manifest is noncanonical")
        _canonical_path(name, "structural link path")
        target_path = PurePosixPath(target)
        if target_path.is_absolute() or ".." in target_path.parts or "/" in target:
            raise ValueError("structural link target is unsafe")
        if name in entries:
            raise ValueError("structural link manifest contains a duplicate")
        entries[name] = target
    if list(entries) != sorted(entries):
        raise ValueError("structural link manifest is not sorted")
    return entries


def _read_tree_manifest(path: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        value = json.loads(line, object_pairs_hook=_pairs)
        if (
            not isinstance(value, dict)
            or json.dumps(value, sort_keys=True, separators=(",", ":")) != line
        ):
            raise ValueError("structural tree manifest is noncanonical")
        expected = {
            "directory": {"mode", "path", "type"},
            "file": {"bytes", "mode", "path", "sha256", "type"},
            "symlink": {"mode", "path", "target", "type"},
        }.get(value.get("type"))
        if expected is None or set(value) != expected:
            raise ValueError("structural tree manifest fields differ")
        if value["path"] != ".":
            _canonical_path(value["path"], "structural tree path")
        if not isinstance(value["mode"], str) or re.fullmatch(r"0[0-7]{3}", value["mode"]) is None:
            raise ValueError("structural tree mode is invalid")
        if value["type"] == "file":
            if not isinstance(value["bytes"], int) or value["bytes"] < 0:
                raise ValueError("structural tree file size is invalid")
            if RAW_SHA256.fullmatch(value["sha256"]) is None:
                raise ValueError("structural tree file digest is invalid")
        elif value["type"] == "symlink":
            target = value["target"]
            if not isinstance(target, str) or LINK_NAME.fullmatch(target) is None:
                raise ValueError("structural tree symlink target is invalid")
            pure_target = PurePosixPath(target)
            if pure_target.is_absolute() or ".." in pure_target.parts or "/" in target:
                raise ValueError("structural tree symlink target is unsafe")
        entries.append(value)
    paths = [entry["path"] for entry in entries]
    if not paths or paths[0] != "." or paths[1:] != sorted(set(paths[1:])):
        raise ValueError("structural tree manifest order differs")
    return entries


def _verify_manifest_rosters(root: Path, archive: dict[str, Any]) -> None:
    file_path = root / "locks/structural-runtime-files.sha256"
    link_path = root / "locks/structural-runtime-links.txt"
    tree_path = root / "locks/structural-runtime-tree.jsonl"
    loaded_elf_path = root / "locks/structural-runtime-loaded-elf.sha256"

    files = _read_sha_manifest(file_path, label="structural file manifest")
    links = _read_link_manifest(link_path)
    tree = _read_tree_manifest(tree_path)
    loaded_elf = _read_sha_manifest(
        loaded_elf_path,
        label="structural loaded-ELF manifest",
    )

    _expect(len(files), archive["regularFileCount"], "structural file count")
    _expect(len(links), archive["symlinkCount"], "structural symlink count")
    _expect(len(tree), archive["treeManifest"]["entries"], "structural tree count")
    _expect(
        sum(entry["type"] == "directory" for entry in tree),
        archive["directoryCount"],
        "structural directory count",
    )
    _expect(
        sum(entry.get("bytes", 0) for entry in tree if entry["type"] == "file"),
        archive["extractedRegularBytes"],
        "structural extracted bytes",
    )
    _expect(
        {
            entry["path"]: entry["sha256"]
            for entry in tree
            if entry["type"] == "file"
        },
        files,
        "structural tree/file roster",
    )
    _expect(
        {
            entry["path"]: entry["target"]
            for entry in tree
            if entry["type"] == "symlink"
        },
        links,
        "structural tree/link roster",
    )
    _expect(
        _raw_digest(file_path),
        archive["fileManifest"]["sha256"],
        "structural file manifest digest",
    )
    _expect(
        _raw_digest(link_path),
        archive["linkManifest"]["sha256"],
        "structural link manifest digest",
    )
    _expect(
        _raw_digest(tree_path),
        archive["treeManifest"]["sha256"],
        "structural tree manifest digest",
    )
    _expect(len(loaded_elf), 37, "structural loaded-ELF count")


def _verify_conformance(root: Path, lock: dict[str, Any]) -> dict[str, Any]:
    path = root / "locks/structural-runtime-conformance.json"
    receipt = _read_json(path)
    _expect(_raw_digest(path), lock["sha256"], "structural conformance digest")
    _keys(
        receipt,
        {
            "debianBase",
            "documentConformance",
            "environment",
            "loadedElfConformance",
            "materializerConformance",
            "network",
            "notProved",
            "observed",
            "outcome",
            "platform",
            "schema",
            "scope",
            "sourceCandidate",
            "structuralArchive",
        },
        "structural conformance",
    )
    _expect(
        receipt["schema"],
        "ambit.runtime-pack-structural-compatibility-conformance/v1",
        "structural conformance schema",
    )
    _expect(receipt["outcome"], "passed", "structural conformance outcome")
    _expect(receipt["network"], "none", "structural conformance network")
    _expect(receipt["platform"], "linux/amd64", "structural conformance platform")
    _expect(
        receipt["structuralArchive"],
        {
            "bytes": 68464640,
            "reproducibleCopiesCompared": 2,
            "sha256": "sha256:89f4f0fdcb0376e5079922a3bfb6dcc3a0262ab5a0e2449813f2b658ea94641c",
        },
        "structural conformance archive",
    )
    _expect(
        receipt["notProved"],
        [
            "publisher-authenticated-structural-archive",
            "complete-wheel-source-and-license-closure",
            "complete-native-library-source-and-license-closure",
            "real-daytona-xfs-materializer-conformance",
            "runtime-vulnerability-policy-pass",
            "final-image-composition",
        ],
        "structural conformance open gaps",
    )
    return receipt


def _verify_external_manifests(
    root: Path,
    expected: list[dict[str, Any]],
) -> None:
    expected_hashes = [
        f"{entry['sha256'].removeprefix('sha256:')}  {entry['path']}"
        for entry in expected
    ]
    expected_bytes = [f"{entry['bytes']}  {entry['path']}" for entry in expected]
    observed_hashes = (
        root / "locks/offline-frozen-evidence.sha256"
    ).read_text(encoding="utf-8").splitlines()
    observed_bytes = (
        root / "locks/offline-frozen-evidence.bytes"
    ).read_text(encoding="utf-8").splitlines()
    _expect(observed_hashes, expected_hashes, "offline frozen SHA roster")
    _expect(observed_bytes, expected_bytes, "offline frozen byte roster")


def verify(root: Path, offline: dict[str, Any]) -> dict[str, Any]:
    structural = _read_json(root / "locks/structural-compatibility-input.lock.json")
    _keys(
        structural,
        {
            "atomicMaterializer",
            "composition",
            "debianCompatibilityConformance",
            "missing",
            "python",
            "schema",
            "sourceCandidate",
            "state",
            "structuralRuntimeArchive",
            "wheels",
        },
        "structural compatibility lock",
    )
    _expect(
        structural["schema"],
        "ambit.runtime-pack-structural-compatibility-input-lock/v1",
        "structural compatibility schema",
    )
    _expect(structural["state"], "candidate-ready", "structural compatibility state")
    _expect(
        structural["composition"],
        "external-curated-files-not-oci-layer-inheritance",
        "structural composition",
    )

    source = structural["sourceCandidate"]
    _keys(
        source,
        {
            "daytonaRevision",
            "ociConfigDigest",
            "ociIndexDigest",
            "ociManifestDigest",
            "pack",
            "sourcePackTree",
        },
        "structural source candidate",
    )
    _expect(source["pack"], "ambit.runtime-pack/core-document@4", "structural source pack")
    _git_object(source["daytonaRevision"], "structural source revision")
    _git_object(source["sourcePackTree"], "structural source tree")
    for key in ("ociConfigDigest", "ociIndexDigest", "ociManifestDigest"):
        _sha256(source[key], f"structural source {key}")

    archive = structural["structuralRuntimeArchive"]
    _keys(
        archive,
        {
            "bytes",
            "directoryCount",
            "extractedRegularBytes",
            "fileManifest",
            "format",
            "linkManifest",
            "path",
            "regularFileCount",
            "sha256",
            "sourceDateEpoch",
            "symlinkCount",
            "treeManifest",
        },
        "structural runtime archive",
    )
    _expect(
        archive["path"],
        "structural/core-document-v4-structural-runtime.tar",
        "structural archive path",
    )
    _expect(
        archive["format"],
        "canonical-sorted-posix-pax-tar",
        "structural archive format",
    )
    _expect(archive["sourceDateEpoch"], 1787380799, "structural archive epoch")
    _expect(archive["bytes"], 68464640, "structural archive bytes")
    _expect(
        archive["sha256"],
        "sha256:89f4f0fdcb0376e5079922a3bfb6dcc3a0262ab5a0e2449813f2b658ea94641c",
        "structural archive digest",
    )
    for key, expected_path in (
        ("fileManifest", "structural-runtime-files.sha256"),
        ("linkManifest", "structural-runtime-links.txt"),
        ("treeManifest", "structural-runtime-tree.jsonl"),
    ):
        expected_keys = {"path", "sha256"}
        if key == "treeManifest":
            expected_keys.add("entries")
        _keys(archive[key], expected_keys, f"structural {key}")
        _expect(archive[key]["path"], expected_path, f"structural {key} path")
        _sha256(archive[key]["sha256"], f"structural {key} digest")
    _verify_manifest_rosters(root, archive)

    python = structural["python"]
    _keys(
        python,
        {
            "binary",
            "dynamicSonames",
            "license",
            "privateElfRuntime",
            "sharedLibrary",
            "version",
        },
        "structural Python",
    )
    _expect(python["version"], "3.14.7", "structural Python version")
    for label in ("binary", "sharedLibrary", "license"):
        _keys(python[label], {"bytes", "path", "sha256"}, f"structural Python {label}")
        _sha256(python[label]["sha256"], f"structural Python {label} digest")
    private_elf = python["privateElfRuntime"]
    _keys(
        private_elf,
        {"glibc", "globalLdLibraryPath", "invocation", "loadedObjectManifest", "loader"},
        "structural private ELF runtime",
    )
    _expect(private_elf["globalLdLibraryPath"], "forbidden", "global loader path")
    for label in ("loader", "glibc"):
        _keys(private_elf[label], {"bytes", "path", "sha256"}, f"private ELF {label}")
        _sha256(private_elf[label]["sha256"], f"private ELF {label} digest")
    _keys(
        private_elf["loadedObjectManifest"],
        {"count", "path", "sha256"},
        "private ELF manifest",
    )
    _expect(private_elf["loadedObjectManifest"]["count"], 37, "private ELF count")
    _expect(
        _raw_digest(root / "locks/structural-runtime-loaded-elf.sha256"),
        private_elf["loadedObjectManifest"]["sha256"],
        "private ELF manifest digest",
    )

    wheels = structural["wheels"]
    _keys(wheels, {"installed", "originalArchiveRoster", "requirementsLockSha256"}, "structural wheels")
    _expect(wheels["originalArchiveRoster"], "unavailable", "original wheel roster")
    _sha256(wheels["requirementsLockSha256"], "structural requirement lock")
    _expect(
        [(entry["name"], entry["version"]) for entry in wheels["installed"]],
        [
            ("cobble", "0.1.4"),
            ("lxml", "6.1.2"),
            ("mammoth", "1.12.1"),
            ("python-docx", "1.2.0"),
            ("typing-extensions", "4.16.0"),
        ],
        "structural wheel roster",
    )
    for entry in wheels["installed"]:
        _keys(entry, {"license", "name", "version"}, "structural wheel")

    materializer = structural["atomicMaterializer"]
    _keys(
        materializer,
        {"binary", "interfaces", "license", "publisherAuthentication", "sourceArchive"},
        "structural atomic materializer",
    )
    _expect(
        materializer["publisherAuthentication"],
        "unavailable",
        "materializer publisher authentication",
    )
    for label in ("sourceArchive", "binary"):
        required = {"bytes", "path", "sha256"}
        if label == "sourceArchive":
            required |= {"backendRevision", "backendTree"}
        _keys(materializer[label], required, f"materializer {label}")
        _sha256(materializer[label]["sha256"], f"materializer {label} digest")
    _git_object(materializer["sourceArchive"]["backendRevision"], "materializer backend revision")
    _git_object(materializer["sourceArchive"]["backendTree"], "materializer backend tree")
    _keys(
        materializer["license"],
        {"licenseLockSha256", "noticeSha256", "packageLicenseField", "spdxExpression"},
        "materializer license",
    )
    _expect(materializer["license"]["packageLicenseField"], "UNLICENSED", "materializer package license")
    _expect(materializer["license"]["spdxExpression"], "LicenseRef-Ambit-Proprietary", "materializer SPDX")
    _sha256(materializer["license"]["licenseLockSha256"], "materializer license lock")
    _sha256(materializer["license"]["noticeSha256"], "materializer notice")
    if len(materializer["interfaces"]) != 2:
        raise ValueError("materializer interface roster differs")
    for interface in materializer["interfaces"]:
        _keys(interface, {"digest", "ref"}, "materializer interface")
        _sha256(interface["digest"], "materializer interface digest")

    conformance_lock = structural["debianCompatibilityConformance"]
    _keys(conformance_lock, {"outcome", "path", "sha256"}, "structural conformance lock")
    _expect(conformance_lock["outcome"], "passed", "structural conformance lock outcome")
    receipt = _verify_conformance(root, conformance_lock)

    required_gaps = {
        "independently-published-structural-runtime-archive",
        "exact-original-wheel-archive-roster",
        "complete-wheel-source-and-license-archive-roster",
        "complete-native-library-source-license-and-vulnerability-closure",
        "publisher-authenticated-materializer-source-and-binary",
        "real-daytona-xfs-materializer-conformance",
    }
    if set(structural["missing"]) != required_gaps:
        raise ValueError("structural compatibility gap roster differs")

    expected_frozen = [
        {
            "path": archive["path"],
            "bytes": archive["bytes"],
            "sha256": archive["sha256"],
        },
        {
            "path": "structural/conformance/artifact-receipt.json",
            "bytes": receipt["documentConformance"]["receiptBytes"],
            "sha256": receipt["documentConformance"]["receiptSha256"],
        },
        {
            "path": "structural/conformance/artifact_conformance.py",
            "bytes": 20297,
            "sha256": receipt["documentConformance"]["sourceSha256"],
        },
        {
            "path": "structural/conformance/materializer-receipt.json",
            "bytes": receipt["materializerConformance"]["receiptBytes"],
            "sha256": receipt["materializerConformance"]["receiptSha256"],
        },
        {
            "path": "structural/conformance/materializer_conformance.py",
            "bytes": 30016,
            "sha256": receipt["materializerConformance"]["sourceSha256"],
        },
    ]
    _expect(offline["frozenEvidence"], expected_frozen, "offline frozen evidence")
    _verify_external_manifests(root, expected_frozen)

    return {
        "state": structural["state"],
        "atomicMaterializerState": materializer["publisherAuthentication"],
        "frozenEvidenceCount": len(expected_frozen),
    }
