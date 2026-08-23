from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA512 = re.compile(r"^sha512:[0-9a-f]{128}$")
SOURCE_CONTRACT_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9./_-]*)$")
SOURCE_CONTRACT_PATHS = (
    "Dockerfile",
    "certification/audit_offline_inputs.py",
    "locks/backend-lineage-input.lock.json",
    "locks/base-oci.lock.json",
    "locks/canvas-input.lock.json",
    "locks/capture-helper-input.lock.json",
    "locks/debian-input.lock.json",
    "locks/node-input.lock.json",
    "locks/offline-build-input.lock.json",
    "locks/offline-public-artifacts.bytes",
    "locks/offline-public-artifacts.sha256",
    "locks/pdfjs-input.lock.json",
    "locks/pdfjs-static-files.sha256",
    "policy/license-policy.json",
    "policy/render-policy.json",
    "policy/runtime-policy.json",
    "renderer/ambit-render-pages.mjs",
    "renderer/pdfjs-page-renderer.mjs",
    "renderer/render-contracts.mjs",
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
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("source contract manifest must be a regular file")
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


def _verify_pdfjs_roster(root: Path, lock: dict[str, Any]) -> None:
    path = root / "locks/pdfjs-static-files.sha256"
    lines = path.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    pattern = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$")
    for line in lines:
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError("PDF.js static-file roster is noncanonical")
        entries.append((match.group(2), match.group(1)))
    names = [name for name, _ in entries]
    if names != sorted(set(names)) or len(names) != lock["fileCount"]:
        raise ValueError("PDF.js static-file roster paths differ")
    required = {
        "LICENSE",
        "cmaps/LICENSE",
        "iccs/LICENSE",
        "legacy/build/pdf.mjs",
        "legacy/build/pdf.worker.mjs",
        "wasm/LICENSE_JBIG2",
        "wasm/LICENSE_OPENJPEG",
        "wasm/LICENSE_PDFJS_JBIG2",
        "wasm/LICENSE_PDFJS_OPENJPEG",
        "wasm/LICENSE_PDFJS_QCMS",
        "wasm/LICENSE_QCMS",
    }
    if not required.issubset(names):
        raise ValueError("PDF.js static-file roster omits required runtime licenses")
    if any(
        name.startswith("standard_fonts/") or "quickjs-eval" in name
        for name in names
    ):
        raise ValueError("PDF.js static-file roster retains excluded resources")
    digest = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    _expect(digest, lock["lockSha256"], "PDF.js static-file roster digest")


def _verify_offline_public_manifests(
    root: Path,
    artifacts: list[dict[str, Any]],
) -> None:
    expected_hashes = [
        f"{artifact['sha256'].removeprefix('sha256:')}  {artifact['path']}"
        for artifact in artifacts
    ]
    expected_bytes = [
        f"{artifact['bytes']}  {artifact['path']}" for artifact in artifacts
    ]
    observed_hashes = (
        root / "locks/offline-public-artifacts.sha256"
    ).read_text(encoding="utf-8").splitlines()
    observed_bytes = (
        root / "locks/offline-public-artifacts.bytes"
    ).read_text(encoding="utf-8").splitlines()
    _expect(observed_hashes, expected_hashes, "offline public SHA roster")
    _expect(observed_bytes, expected_bytes, "offline public byte roster")


def _verify(root: Path, *, require_ready: bool = False) -> dict[str, Any]:
    root = root.resolve(strict=True)
    _verify_source_manifest(root)
    backend_lineage = _read(root / "locks/backend-lineage-input.lock.json")
    base = _read(root / "locks/base-oci.lock.json")
    canvas = _read(root / "locks/canvas-input.lock.json")
    debian = _read(root / "locks/debian-input.lock.json")
    node = _read(root / "locks/node-input.lock.json")
    offline = _read(root / "locks/offline-build-input.lock.json")
    pdfjs = _read(root / "locks/pdfjs-input.lock.json")
    helper = _read(root / "locks/capture-helper-input.lock.json")
    toolchain = _read(root / "toolchain-manifest.json")
    runtime = _read(root / "policy/runtime-policy.json")
    render = _read(root / "policy/render-policy.json")
    license_policy = _read(root / "policy/license-policy.json")

    _keys(
        backend_lineage,
        {
            "expectedBackendCommit",
            "expectedBackendSchemaRef",
            "forbidden",
            "interpretation",
            "ownership",
            "producer",
            "requiredCrossRepositoryEvidence",
            "requiredEnvelopeFields",
            "schema",
            "state",
        },
        "external backend lineage lock",
    )
    _expect(
        backend_lineage["schema"],
        "ambit.runtime-pack-external-backend-lineage-input-lock/v1",
        "external backend lineage schema",
    )
    _expect(backend_lineage["state"], "unavailable", "backend lineage state")
    _expect(
        backend_lineage["interpretation"],
        "opaque-canonical-byte-envelope-only",
        "backend lineage interpretation",
    )
    _expect(
        backend_lineage["requiredEnvelopeFields"],
        ["schemaRef", "ref", "digest", "canonicalBytesSha256"],
        "backend lineage envelope",
    )
    _expect(
        backend_lineage["expectedBackendCommit"],
        "unavailable",
        "backend lineage commit",
    )
    _expect(
        backend_lineage["expectedBackendSchemaRef"],
        "unavailable",
        "backend lineage schema ref",
    )

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
    _keys(base["index"], {"digest", "mediaType", "reference"}, "base index")
    _keys(
        base["platform"],
        {"architecture", "configDigest", "layers", "manifestDigest", "os"},
        "base platform",
    )
    _expect(
        base["index"]["reference"],
        (
            "docker.io/library/debian@sha256:"
            "3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
        ),
        "base reference",
    )
    _sha256(base["index"]["digest"], "base index digest")
    _expect(
        base["index"]["digest"],
        "sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258",
        "base index digest",
    )
    if not str(base["index"]["reference"]).endswith(f"@{base['index']['digest']}"):
        raise ValueError("base reference does not bind the index digest")
    _expect(base["platform"]["os"], "linux", "base platform OS")
    _expect(base["platform"]["architecture"], "amd64", "base architecture")
    _sha256(base["platform"]["manifestDigest"], "base platform manifest")
    _sha256(base["platform"]["configDigest"], "base config")
    _expect(
        base["platform"]["manifestDigest"],
        "sha256:38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16",
        "base platform manifest",
    )
    _expect(
        base["platform"]["configDigest"],
        "sha256:cb1aeeeb4fff439fcbc763f5b313a1f00b39d03f45d2d4be0c52cf14928b297e",
        "base config",
    )
    if len(base["platform"]["layers"]) != 1:
        raise ValueError("base layer roster must be exact")
    _keys(
        base["platform"]["layers"][0],
        {"digest", "mediaType", "size"},
        "base layer",
    )
    _sha256(base["platform"]["layers"][0]["digest"], "base layer")
    _expect(
        base["platform"]["layers"][0]["digest"],
        "sha256:26c307b5e35a59ce911f5fde5b9458120ec8734e831ea2da5649a9ad14abfd3d",
        "base layer",
    )

    _keys(
        node,
        {
            "binary",
            "missing",
            "releaseAuthority",
            "removedRuntimePaths",
            "retainedRuntimePaths",
            "runtimeAbi",
            "schema",
            "source",
            "state",
            "version",
        },
        "Node lock",
    )
    _keys(
        node["source"],
        {
            "archiveBytes",
            "archiveSha256",
            "archiveUrl",
            "commit",
            "repository",
            "tag",
            "tagObject",
        },
        "Node source",
    )
    _keys(
        node["binary"],
        {
            "archiveBytes",
            "archiveSha256",
            "archiveUrl",
            "licensePath",
            "licenseSha256",
            "nodeBytes",
            "nodePath",
            "nodeSha256",
            "platform",
        },
        "Node binary",
    )
    _keys(
        node["releaseAuthority"],
        {
            "shasumsBytes",
            "shasumsSha256",
            "shasumsUrl",
            "signatureBytes",
            "signatureSha256",
            "signatureUrl",
            "signerFingerprint",
            "verificationState",
        },
        "Node release authority",
    )
    _keys(
        node["runtimeAbi"],
        {"dynamicLibraries", "modules", "napi", "openssl", "uv", "v8"},
        "Node runtime ABI",
    )
    _expect(node["schema"], "ambit.runtime-pack-node-input-lock/v1", "Node schema")
    _expect(node["state"], "unavailable", "Node state")
    _expect(node["version"], "24.19.0", "Node version")
    for key in ("archiveSha256",):
        _sha256(node["source"][key], f"Node source {key}")
    for key in ("archiveSha256", "licenseSha256", "nodeSha256"):
        _sha256(node["binary"][key], f"Node binary {key}")
    for key in ("shasumsSha256", "signatureSha256"):
        _sha256(node["releaseAuthority"][key], f"Node release {key}")
    _expect(
        node["releaseAuthority"]["verificationState"],
        "unavailable",
        "Node release signature state",
    )
    _expect(node["runtimeAbi"]["modules"], "137", "Node module ABI")
    _expect(node["runtimeAbi"]["napi"], "10", "Node N-API")
    _expect(
        node["source"]["archiveSha256"],
        "sha256:f6d95e10a0431ee1067fc6aabe9f762908b4716dd35324e1ddb4b1466b76659f",
        "Node source archive pin",
    )
    _expect(
        node["binary"]["archiveSha256"],
        "sha256:14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647",
        "Node binary archive pin",
    )
    _expect(
        node["binary"]["nodeSha256"],
        "sha256:bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12",
        "Node binary pin",
    )
    _expect(
        node["binary"]["licenseSha256"],
        "sha256:148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5",
        "Node license pin",
    )
    _expect(
        node["releaseAuthority"]["shasumsSha256"],
        "sha256:be0629ee2bcd8e40bb856abdd3407f0762101b76bd60a36b8867f637733631c0",
        "Node SHASUMS pin",
    )
    _expect(
        node["releaseAuthority"]["signatureSha256"],
        "sha256:801534e2d4c769c087e2e3eec89e879032872357e64e82336f86f03e72ece630",
        "Node release signature pin",
    )
    if any("npm" in path or "corepack" in path for path in node["retainedRuntimePaths"]):
        raise ValueError("Node runtime must not retain package installers")

    _keys(
        canvas,
        {
            "dynamicLibraries",
            "forbiddenAlternatives",
            "implementation",
            "javascriptArchive",
            "missing",
            "nativeLineage",
            "platformArchive",
            "requiredInterface",
            "schema",
            "state",
        },
        "Canvas lock",
    )
    _keys(
        canvas["implementation"],
        {
            "licenseExpression",
            "licensePath",
            "package",
            "sourceArchiveBytes",
            "sourceArchiveSha256",
            "sourceArchiveUrl",
            "sourceCommit",
            "sourceRepository",
            "version",
        },
        "Canvas implementation",
    )
    _keys(
        canvas["javascriptArchive"],
        {"bytes", "npmAttestationUrl", "npmIntegrity", "sha256", "url"},
        "Canvas JavaScript archive",
    )
    _keys(
        canvas["platformArchive"],
        {
            "bytes",
            "nativeBytes",
            "nativePath",
            "nativeSha256",
            "npmAttestationUrl",
            "npmIntegrity",
            "package",
            "sha256",
            "url",
            "version",
        },
        "Canvas platform archive",
    )
    _keys(
        canvas["requiredInterface"],
        {"DOMMatrix", "ImageData", "Path2D", "createCanvas", "pngEncoding"},
        "Canvas required interface",
    )
    _keys(
        canvas["nativeLineage"],
        {
            "cargoDependencyLock",
            "completeThirdPartyLicenseRoster",
            "completeThirdPartySourceRoster",
            "skiaBuildConfiguration",
            "skiaCommit",
            "skiaSourceArchiveSha256",
        },
        "Canvas native lineage",
    )
    _expect(
        canvas["schema"],
        "ambit.runtime-pack-pdfjs-canvas-input-lock/v1",
        "Canvas schema",
    )
    _expect(canvas["state"], "unavailable", "Canvas state")
    _expect(canvas["implementation"]["version"], "1.0.7", "Canvas version")
    _expect(
        set(canvas["requiredInterface"].values()),
        {True},
        "Canvas required interface availability",
    )
    _sha256(
        canvas["implementation"]["sourceArchiveSha256"],
        "Canvas source archive",
    )
    _sha256(canvas["javascriptArchive"]["sha256"], "Canvas JavaScript archive")
    _sha256(canvas["platformArchive"]["sha256"], "Canvas platform archive")
    _sha256(canvas["platformArchive"]["nativeSha256"], "Canvas native binary")
    _sha256(
        canvas["nativeLineage"]["skiaSourceArchiveSha256"],
        "Canvas Skia source",
    )
    for key in (
        "cargoDependencyLock",
        "completeThirdPartyLicenseRoster",
        "completeThirdPartySourceRoster",
        "skiaBuildConfiguration",
    ):
        _expect(canvas["nativeLineage"][key], "unavailable", f"Canvas {key}")
    _expect(
        canvas["implementation"]["sourceArchiveSha256"],
        "sha256:a742c5453323327c4d6de7bfdcc69d0678144c3bf0db8f7dc246668dc5273c22",
        "Canvas source pin",
    )
    _expect(
        canvas["javascriptArchive"]["sha256"],
        "sha256:8f969d4166974b4508007838d1bb53f27d030b2554ffbbbbf50f8dba0a7fbabe",
        "Canvas JavaScript pin",
    )
    _expect(
        canvas["platformArchive"]["sha256"],
        "sha256:8bbe6cbfcf5add8a43232b90d86636d90ed8f28a9acb0a91c0e9a49dc2124699",
        "Canvas platform archive pin",
    )
    _expect(
        canvas["platformArchive"]["nativeSha256"],
        "sha256:b180b8e12464e337f5bc0c4195a7bed73c65f588542ca7d0de20c596419eff03",
        "Canvas native binary pin",
    )
    _expect(
        canvas["nativeLineage"]["skiaSourceArchiveSha256"],
        "sha256:83edae36346f1cd9122a1674b82277693bb101d17a106822835c0863f002b5bd",
        "Canvas Skia source pin",
    )

    _keys(
        offline,
        {
            "baseOci",
            "buildFrontend",
            "buildTargets",
            "frozenEvidence",
            "missing",
            "namedBuildContext",
            "networkDuringBuild",
            "platform",
            "proprietaryHelper",
            "publicArtifactByteManifest",
            "publicArtifactSha256Manifest",
            "publicArtifacts",
            "requiredUnfrozenEvidence",
            "schema",
            "state",
        },
        "offline build input lock",
    )
    _keys(
        offline["proprietaryHelper"],
        {"includedInPublicContext", "secretId", "state", "transport"},
        "offline proprietary helper",
    )
    _keys(
        offline["buildTargets"],
        {"coreDocumentV5", "rendererSubstrate"},
        "offline build targets",
    )
    _keys(
        offline["buildFrontend"],
        {"digest", "reference"},
        "offline Dockerfile frontend",
    )
    _keys(
        offline["baseOci"],
        {"configDigest", "indexDigest", "layerDigest", "platformManifestDigest"},
        "offline base OCI",
    )
    _expect(
        offline["schema"],
        "ambit.runtime-pack-offline-build-input-lock/v1",
        "offline build schema",
    )
    _expect(offline["state"], "unavailable", "offline build state")
    _expect(offline["platform"], "linux/amd64", "offline build platform")
    _expect(offline["networkDuringBuild"], "none", "offline build network")
    _expect(
        offline["buildFrontend"]["digest"],
        "sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
        "offline Dockerfile frontend digest",
    )
    _expect(
        offline["baseOci"],
        {
            "indexDigest": base["index"]["digest"],
            "platformManifestDigest": base["platform"]["manifestDigest"],
            "configDigest": base["platform"]["configDigest"],
            "layerDigest": base["platform"]["layers"][0]["digest"],
        },
        "offline base OCI pins",
    )
    _expect(
        offline["proprietaryHelper"]["includedInPublicContext"],
        False,
        "helper public-context exclusion",
    )
    _expect(
        offline["proprietaryHelper"]["state"],
        "unavailable",
        "offline helper state",
    )
    expected_public_artifacts = [
        {
            "path": "public/canvas/canvas-1.0.7.tgz",
            "bytes": canvas["javascriptArchive"]["bytes"],
            "sha256": canvas["javascriptArchive"]["sha256"],
        },
        {
            "path": "public/canvas/canvas-linux-x64-gnu-1.0.7.tgz",
            "bytes": canvas["platformArchive"]["bytes"],
            "sha256": canvas["platformArchive"]["sha256"],
        },
        {
            "path": (
                "public/canvas/canvas-source-"
                "062130c03715f275fd46a59a4bb224e907c91686.tar.gz"
            ),
            "bytes": canvas["implementation"]["sourceArchiveBytes"],
            "sha256": canvas["implementation"]["sourceArchiveSha256"],
        },
        {
            "path": (
                "public/canvas/skia-source-"
                "7219df0fb0ff64f26adad448f94e8c001b964e6a.tar.gz"
            ),
            "bytes": 68583095,
            "sha256": canvas["nativeLineage"]["skiaSourceArchiveSha256"],
        },
        {
            "path": "public/node/SHASUMS256.txt",
            "bytes": node["releaseAuthority"]["shasumsBytes"],
            "sha256": node["releaseAuthority"]["shasumsSha256"],
        },
        {
            "path": "public/node/SHASUMS256.txt.sig",
            "bytes": node["releaseAuthority"]["signatureBytes"],
            "sha256": node["releaseAuthority"]["signatureSha256"],
        },
        {
            "path": "public/node/node-v24.19.0-linux-x64.tar.xz",
            "bytes": node["binary"]["archiveBytes"],
            "sha256": node["binary"]["archiveSha256"],
        },
        {
            "path": "public/node/node-v24.19.0.tar.xz",
            "bytes": node["source"]["archiveBytes"],
            "sha256": node["source"]["archiveSha256"],
        },
        {
            "path": "public/pdfjs/pdfjs-dist-6.2.108.tgz",
            "bytes": pdfjs["archive"]["bytes"],
            "sha256": pdfjs["archive"]["sha256"],
        },
    ]
    _expect(
        offline["publicArtifacts"],
        expected_public_artifacts,
        "offline public artifact roster",
    )
    _expect(offline["frozenEvidence"], [], "offline frozen evidence roster")
    if not offline["requiredUnfrozenEvidence"]:
        raise ValueError("unavailable offline build must name its evidence gaps")
    _expect(
        offline["publicArtifactSha256Manifest"],
        "offline-public-artifacts.sha256",
        "offline public SHA manifest",
    )
    _expect(
        offline["publicArtifactByteManifest"],
        "offline-public-artifacts.bytes",
        "offline public byte manifest",
    )
    _verify_offline_public_manifests(root, offline["publicArtifacts"])

    _keys(
        debian,
        {
            "archives",
            "platform",
            "requestedPackages",
            "resolution",
            "schema",
            "signaturePolicy",
        },
        "Debian lock",
    )
    _expect(debian["schema"], "ambit.runtime-pack-debian-input-lock/v1", "Debian schema")
    _expect(debian["platform"], "linux/amd64", "Debian platform")
    _expect(
        debian["requestedPackages"],
        [
            "fonts-noto-cjk=1:20240730+repack1-1",
            "fonts-noto-core=20201225-2",
            "fonts-noto-mono=20201225-2",
            "libreoffice-writer-nogui=4:25.2.3-2+deb13u6",
        ],
        "Debian requested package roster",
    )
    _expect(debian["signaturePolicy"]["verifyInRelease"], True, "Debian signatures")
    _keys(
        debian["signaturePolicy"],
        {
            "checkValidUntil",
            "checkValidUntilException",
            "trustedKeyring",
            "verifyInRelease",
        },
        "Debian signature policy",
    )
    _keys(
        debian["resolution"],
        {"installRecommends", "missing", "requiredClosureLock", "state"},
        "Debian resolution",
    )
    _expect(debian["resolution"]["state"], "unavailable", "Debian closure state")
    if len(debian["archives"]) != 2:
        raise ValueError("Debian archive roster must contain exactly two archives")
    for archive in debian["archives"]:
        _keys(
            archive,
            {"component", "inRelease", "name", "snapshot", "suite"},
            "Debian archive",
        )
        _keys(archive["inRelease"], {"sha256", "url"}, "Debian InRelease")
        _sha256(archive["inRelease"]["sha256"], f"{archive['name']} InRelease")
        if not archive["snapshot"].startswith("https://snapshot.debian.org/archive/"):
            raise ValueError("Debian snapshot must use the official immutable archive")
    _expect(
        [archive["inRelease"]["sha256"] for archive in debian["archives"]],
        [
            "sha256:98b25b5cd185c59d34aa6e4c3e9b5b8f01bbe9d104fe2dcfbcd30dc0a14a59ed",
            "sha256:c5b38b54765337d3f141385c5cd7b5ef2dd64557c44b519bd079c5ac8f40b369",
        ],
        "Debian InRelease pin roster",
    )

    _keys(
        pdfjs,
        {
            "archive",
            "excludedRoots",
            "execution",
            "extractedRoster",
            "package",
            "requiredLicenseFiles",
            "retainedStaticRoots",
            "schema",
            "source",
            "version",
        },
        "PDF.js lock",
    )
    _keys(pdfjs["source"], {"commit", "repository", "tag"}, "PDF.js source")
    _keys(
        pdfjs["archive"],
        {
            "bytes",
            "npmAttestationUrl",
            "npmIntegrity",
            "sha256",
            "sha512",
            "url",
        },
        "PDF.js archive",
    )
    _keys(
        pdfjs["execution"],
        {
            "canvasInputLock",
            "forbiddenSubstitutions",
            "nodeInputLock",
            "reason",
            "state",
        },
        "PDF.js execution",
    )
    _keys(
        pdfjs["extractedRoster"],
        {"fileCount", "lockSha256", "requiredLock", "state"},
        "PDF.js extracted roster",
    )
    _expect(pdfjs["schema"], "ambit.runtime-pack-pdfjs-input-lock/v1", "PDF.js schema")
    _expect(pdfjs["package"], "pdfjs-dist", "PDF.js package")
    _expect(pdfjs["version"], "6.2.108", "PDF.js version")
    _sha256(pdfjs["archive"]["sha256"], "PDF.js archive")
    _sha512(pdfjs["archive"]["sha512"], "PDF.js archive SHA-512")
    _expect(pdfjs["execution"]["state"], "unavailable", "PDF.js execution state")
    _expect(pdfjs["extractedRoster"]["state"], "pinned", "PDF.js roster state")
    _sha256(pdfjs["extractedRoster"]["lockSha256"], "PDF.js roster lock")
    _verify_pdfjs_roster(root, pdfjs["extractedRoster"])
    _expect(
        pdfjs["archive"]["sha256"],
        "sha256:b3e68d5cda70551a90b3f771419d379e20fc788ce056fa32de73608e01df47f4",
        "PDF.js archive pin",
    )
    _expect(
        pdfjs["retainedStaticRoots"],
        [
            "legacy/build/pdf.mjs",
            "legacy/build/pdf.worker.mjs",
            "cmaps",
            "iccs",
            "wasm",
        ],
        "PDF.js retained roster roots",
    )
    if "standard_fonts" not in pdfjs["excludedRoots"]:
        raise ValueError("unreviewed PDF.js standard fonts must remain excluded")
    if any("node_modules" in item for item in pdfjs["retainedStaticRoots"]):
        raise ValueError("PDF.js static roster must not smuggle a Node dependency tree")

    _keys(
        helper,
        {
            "archiveAdmission",
            "interfaceRef",
            "license",
            "missing",
            "requiredExternalAuthority",
            "roleRef",
            "schema",
            "state",
        },
        "capture helper lock",
    )
    _keys(
        helper["license"],
        {"distribution", "packageLicenseField", "spdxExpression"},
        "capture helper license",
    )
    _keys(
        helper["requiredExternalAuthority"],
        {
            "archivePath",
            "detachedSignature",
            "downgrade",
            "expectedPublisherKeySha256",
            "expectedRawSha256",
            "expectedSignatureSha256",
            "publisherPublicKey",
        },
        "capture helper external authority",
    )
    _keys(
        helper["archiveAdmission"],
        {
            "absoluteParentDuplicateExtraAndMissingPaths",
            "canonicalMemberRosterRequired",
            "exactByteCountRequired",
            "exactModeOwnerTimestampSizeAndContentDigest",
            "hashRawBytesBeforeParsing",
            "linksDevicesFifosSocketsSparseAndUnknownPax",
            "regularFilesAndDirectoriesOnly",
            "selfDescribedDigestsGrantAuthority",
        },
        "capture helper archive admission",
    )
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

    _keys(
        toolchain,
        {
            "activation",
            "backendLineageInputLock",
            "baseOciLock",
            "canvasInputLock",
            "captureHelperInputLock",
            "debianInputLock",
            "fonts",
            "knownBlockers",
            "installedEngineLineage",
            "libreOffice",
            "nodeInputLock",
            "offlineBuildInputLock",
            "pack",
            "pdfjs",
            "pdfjsInputLock",
            "platform",
            "runtime",
            "schema",
            "state",
        },
        "toolchain",
    )
    _keys(toolchain["platform"], {"architecture", "os"}, "toolchain platform")
    _keys(
        toolchain["libreOffice"],
        {"mode", "notClaimed", "package", "version"},
        "toolchain LibreOffice",
    )
    _keys(
        toolchain["fonts"],
        {
            "packages",
            "requiredFontconfigRoster",
            "requiredLicenseInventory",
            "requiredManifest",
            "state",
        },
        "toolchain fonts",
    )
    _keys(
        toolchain["pdfjs"],
        {
            "delivery",
            "nativeCanvas",
            "runtimeNode",
            "runtimeNpm",
            "staticRoster",
            "version",
        },
        "toolchain PDF.js",
    )
    _keys(
        toolchain["runtime"],
        {
            "network",
            "packageInstallers",
            "rootFilesystem",
            "uid",
            "user",
            "workspacePublication",
        },
        "toolchain runtime",
    )
    _keys(
        toolchain["installedEngineLineage"],
        {"callerSuppliedEnginePins", "derivedFrom", "runtimePath", "state"},
        "installed engine lineage",
    )
    _expect(toolchain["schema"], "ambit.runtime-pack-toolchain/v3", "toolchain schema")
    _expect(toolchain["pack"], "ambit.runtime-pack/core-document@5", "pack ref")
    _expect(toolchain["state"], "unavailable", "toolchain state")
    _expect(toolchain["platform"], {"os": "linux", "architecture": "amd64"}, "platform")
    _expect(toolchain["pdfjs"]["runtimeNode"], "24.19.0", "runtime Node")
    _expect(toolchain["pdfjs"]["runtimeNpm"], "absent", "runtime npm")
    _expect(
        toolchain["pdfjs"]["nativeCanvas"],
        "@napi-rs/canvas-linux-x64-gnu@1.0.7-unavailable",
        "native Canvas",
    )
    _expect(
        toolchain["pdfjs"]["staticRoster"],
        "pinned-185-files",
        "PDF.js static roster",
    )
    _expect(
        toolchain["fonts"]["packages"],
        [
            package
            for package in debian["requestedPackages"]
            if package.startswith("fonts-noto-")
        ],
        "toolchain and Debian font rosters",
    )
    _expect(toolchain["activation"], "forbidden", "activation")
    _expect(
        toolchain["installedEngineLineage"]["state"],
        "unavailable",
        "installed engine lineage state",
    )
    _expect(
        toolchain["installedEngineLineage"]["callerSuppliedEnginePins"],
        "forbidden",
        "caller supplied engine pins",
    )
    if len(toolchain["knownBlockers"]) != len(set(toolchain["knownBlockers"])):
        raise ValueError("toolchain blockers must be unique")

    _keys(
        runtime,
        {
            "ambientDependencyResolution",
            "hostSocketsAndDevices",
            "longLivedOfficeOrUnoDaemon",
            "network",
            "rootEscalation",
            "rootFilesystem",
            "runtimePackageInstallers",
            "runtimeUid",
            "runtimeUser",
            "schema",
            "secretsInImageOrEnvironment",
            "workspacePublication",
            "writableRoots",
        },
        "runtime policy",
    )
    _keys(
        render,
        {
            "canonicalArtifactBoundary",
            "input",
            "libreOffice",
            "pages",
            "pdfjs",
            "policyRef",
            "renderOutputGrantsCanonicalAuthority",
            "schema",
        },
        "render policy",
    )
    _keys(
        render["input"],
        {
            "externalLinks",
            "localImmutableBytesOnly",
            "macros",
            "maximumBytes",
            "passwordProtected",
            "remoteUrls",
        },
        "render input policy",
    )
    _keys(
        render["libreOffice"],
        {
            "headless",
            "maximumWallMilliseconds",
            "nodefault",
            "nologo",
            "norestore",
            "privateUserProfile",
            "processModel",
            "profileReuse",
        },
        "render LibreOffice policy",
    )
    _keys(
        render["pages"],
        {
            "exactPngSha256Required",
            "background",
            "maximumCount",
            "maximumHeightPixels",
            "maximumPixelsPerPage",
            "maximumTotalOutputBytes",
            "maximumTotalPixels",
            "maximumWidthPixels",
            "orderedZeroBasedRosterRequired",
            "pngEncoding",
            "rasterScale",
        },
        "render page policy",
    )
    _keys(
        render["pdfjs"],
        {
            "bytesInputOnly",
            "canvasFactory",
            "executionState",
            "localStaticResourcesOnly",
            "popplerFallback",
            "requiredGlobals",
            "standardFonts",
            "workerVersionMustEqualApiVersion",
        },
        "render PDF.js policy",
    )
    _keys(
        license_policy,
        {
            "nativeCanvas",
            "noAssertion",
            "pdfjsStandardFonts",
            "promotionWithoutCompleteInventory",
            "proprietary",
            "requiredEvidence",
            "schema",
            "state",
            "unknown",
        },
        "license policy",
    )
    _keys(
        license_policy["pdfjsStandardFonts"],
        {"disposition", "reason"},
        "PDF.js standard-font license policy",
    )
    _keys(
        license_policy["nativeCanvas"],
        {"candidate", "disposition", "requiredBeforeAdmission"},
        "native Canvas license policy",
    )
    _expect(runtime["runtimeUid"], 1000, "runtime UID")
    _expect(runtime["rootEscalation"], "denied", "root escalation")
    _expect(runtime["rootFilesystem"], "read-only", "root filesystem")
    _expect(runtime["network"], "provider-enforced-none", "runtime network")
    _expect(runtime["runtimePackageInstallers"], "absent", "runtime installers")
    _expect(render["pdfjs"]["popplerFallback"], "forbidden", "Poppler fallback")
    _expect(render["pdfjs"]["executionState"], "unavailable", "render execution")
    _expect(render["pages"]["maximumTotalPixels"], 536870912, "total pixels")
    _expect(
        render["pages"]["maximumTotalOutputBytes"],
        536870912,
        "total output bytes",
    )
    _expect(render["pages"]["rasterScale"], 2, "page raster scale")
    _expect(render["pages"]["background"], "#ffffff", "page background")
    _expect(
        render["pdfjs"]["requiredGlobals"],
        ["DOMMatrix", "ImageData", "Path2D"],
        "PDF.js Canvas globals",
    )
    _expect(
        render["pdfjs"]["canvasFactory"],
        "ambit.pdfjs-canvas-factory/napi-rs@1",
        "PDF.js Canvas factory",
    )
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

    unavailable = {
        "backendLineage": backend_lineage["state"],
        "installedEngineLineage": toolchain["installedEngineLineage"]["state"],
        "offlineBuild": offline["state"],
        "toolchain": toolchain["state"],
        "node": node["state"],
        "canvas": canvas["state"],
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


def verify(root: Path, *, require_ready: bool = False) -> dict[str, Any]:
    try:
        return _verify(root, require_ready=require_ready)
    except ValueError:
        raise
    except (AttributeError, IndexError, KeyError, TypeError) as error:
        raise ValueError("source contract structure is invalid") from error


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
