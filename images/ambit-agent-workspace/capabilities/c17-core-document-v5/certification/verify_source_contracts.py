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
    "README.md",
    "certification/audit_offline_inputs.py",
    "certification/runtime_pty_conformance.py",
    "certification/verify_render_output.mjs",
    "certification/verify_signed_debian_snapshot.py",
    "certification/verify_source_contracts.py",
    "certification/verify_structural_contracts.py",
    "certification/verify_structural_runtime_archive.py",
    "locks/backend-lineage-input.lock.json",
    "locks/base-oci.lock.json",
    "locks/canvas-input.lock.json",
    "locks/canvas-native-runtime-input.lock.json",
    "locks/capture-helper-input.lock.json",
    "locks/debian-copyright-files.sha256",
    "locks/debian-index-artifacts.bytes",
    "locks/debian-index-artifacts.sha256",
    "locks/debian-input.lock.json",
    "locks/debian-runtime-debs.bytes",
    "locks/debian-runtime-debs.sha256",
    "locks/debian-runtime-dpkg.lock",
    "locks/debian-source-artifacts.bytes",
    "locks/debian-source-artifacts.sha256",
    "locks/document-render-interface.lock.json",
    "locks/font-files.sha256",
    "locks/font-license-inventory.json",
    "locks/font-package-ownership.tsv",
    "locks/fontconfig-roster.tsv",
    "locks/installed-render-engine-lineage.json",
    "locks/node-input.lock.json",
    "locks/node-release-keyring-verification.json",
    "locks/offline-build-input.lock.json",
    "locks/offline-build-tools.bytes",
    "locks/offline-build-tools.sha256",
    "locks/offline-frozen-evidence.bytes",
    "locks/offline-frozen-evidence.sha256",
    "locks/offline-public-artifacts.bytes",
    "locks/offline-public-artifacts.sha256",
    "locks/pdfjs-input.lock.json",
    "locks/pdfjs-static-files.sha256",
    "locks/package-copyright.tsv",
    "locks/runtime-cancellation-authority.lock.json",
    "locks/structural-compatibility-input.lock.json",
    "locks/structural-runtime-conformance.json",
    "locks/structural-runtime-files.sha256",
    "locks/structural-runtime-links.txt",
    "locks/structural-runtime-loaded-elf.sha256",
    "locks/structural-runtime-tree.jsonl",
    "policy/license-policy.json",
    "policy/render-policy.json",
    "policy/runtime-policy.json",
    "renderer/ambit-render-document.mjs",
    "renderer/ambit-render-pages.mjs",
    "renderer/docx-package-admission.mjs",
    "renderer/framed-jsonl-protocol.mjs",
    "renderer/pdfjs-page-renderer.mjs",
    "renderer/process-group-execution.mjs",
    "renderer/process-group-subreaper.py",
    "renderer/render-output-verification.mjs",
    "renderer/render-terminal-arbiter.mjs",
    "renderer/render-contracts.mjs",
    "renderer/restricted-xml.mjs",
    "structural/ambit-structural-python",
    "structural/verify_private_elf.py",
    "toolchain-manifest.json",
)

PROTOCOL_SOURCE_PATHS = (
    "Dockerfile",
    "certification/audit_offline_inputs.py",
    "certification/runtime_pty_conformance.py",
    "certification/verify_render_output.mjs",
    "certification/verify_signed_debian_snapshot.py",
    "certification/verify_source_contracts.py",
    "certification/verify_structural_contracts.py",
    "certification/verify_structural_runtime_archive.py",
    "renderer/ambit-render-document.mjs",
    "renderer/ambit-render-pages.mjs",
    "renderer/docx-package-admission.mjs",
    "renderer/framed-jsonl-protocol.mjs",
    "renderer/pdfjs-page-renderer.mjs",
    "renderer/process-group-execution.mjs",
    "renderer/process-group-subreaper.py",
    "renderer/render-contracts.mjs",
    "renderer/render-output-verification.mjs",
    "renderer/render-terminal-arbiter.mjs",
    "renderer/restricted-xml.mjs",
    "structural/ambit-structural-python",
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


def _raw_sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _verify_candidate_evidence(
    root: Path,
    *,
    node: dict[str, Any],
    canvas: dict[str, Any],
    pdfjs: dict[str, Any],
) -> None:
    node_release = _read(root / "locks/node-release-keyring-verification.json")
    _keys(
        node_release,
        {
            "artifacts",
            "release",
            "releaseKeysRepository",
            "schema",
            "signedManifest",
            "state",
        },
        "Node release verification",
    )
    _expect(
        node_release["schema"],
        "ambit.runtime-pack-node-release-verification/v1",
        "Node release verification schema",
    )
    _expect(node_release["state"], "candidate-ready", "Node release evidence state")
    _expect(node_release["release"], f"v{node['version']}", "Node release evidence")
    _expect(
        node_release["releaseKeysRepository"]["fingerprint"],
        node["releaseAuthority"]["signerFingerprint"],
        "Node release signer",
    )
    _expect(
        node_release["signedManifest"]["sha256"],
        node["releaseAuthority"]["shasumsSha256"],
        "Node signed manifest",
    )
    _expect(
        node_release["signedManifest"]["signatureSha256"],
        node["releaseAuthority"]["signatureSha256"],
        "Node release signature",
    )
    _expect(
        [(entry["bytes"], entry["sha256"]) for entry in node_release["artifacts"]],
        [
            (node["binary"]["archiveBytes"], node["binary"]["archiveSha256"]),
            (node["source"]["archiveBytes"], node["source"]["archiveSha256"]),
        ],
        "Node signed artifact roster",
    )

    native = _read(root / "locks/canvas-native-runtime-input.lock.json")
    _keys(
        native,
        {
            "package",
            "promotionBlockers",
            "runtimeBinary",
            "runtimeDynamicLibraries",
            "schema",
            "sourceInputs",
            "state",
        },
        "Canvas native runtime input",
    )
    _expect(
        native["schema"],
        "ambit.runtime-pack-canvas-native-runtime-input/v1",
        "Canvas native runtime schema",
    )
    _expect(native["state"], "candidate-ready", "Canvas native runtime state")
    _expect(
        native["runtimeBinary"]["sha256"],
        canvas["platformArchive"]["nativeSha256"],
        "Canvas native runtime binary",
    )
    _expect(
        native["runtimeDynamicLibraries"],
        canvas["dynamicLibraries"],
        "Canvas dynamic library roster",
    )
    _expect(
        [(entry["bytes"], entry["sha256"]) for entry in native["sourceInputs"]],
        [
            (
                canvas["implementation"]["sourceArchiveBytes"],
                canvas["implementation"]["sourceArchiveSha256"],
            ),
            (68583095, canvas["nativeLineage"]["skiaSourceArchiveSha256"]),
        ],
        "Canvas native source roster",
    )

    font_inventory = _read(root / "locks/font-license-inventory.json")
    _keys(
        font_inventory,
        {"fontManifestSha256", "packages", "schema", "state"},
        "font license inventory",
    )
    _expect(
        font_inventory["schema"],
        "ambit.runtime-pack-font-license-inventory/v1",
        "font inventory schema",
    )
    _expect(font_inventory["state"], "candidate-ready", "font inventory state")
    _expect(
        font_inventory["fontManifestSha256"],
        _raw_sha256(root / "locks/font-files.sha256"),
        "font manifest digest",
    )
    if sum(entry["fontFiles"] for entry in font_inventory["packages"]) != 276:
        raise ValueError("font inventory count differs")
    copyright_rows = {
        row.split("\t")[0]: row.split("\t")[3]
        for row in (root / "locks/package-copyright.tsv")
        .read_text(encoding="utf-8")
        .splitlines()
    }
    for entry in font_inventory["packages"]:
        _keys(
            entry,
            {
                "copyrightPath",
                "copyrightSha256",
                "fontFiles",
                "package",
                "runtimeLicense",
            },
            "font package inventory",
        )
        _expect(
            entry["copyrightSha256"],
            f"sha256:{copyright_rows[entry['package']]}",
            f"{entry['package']} copyright",
        )

    installed = _read(root / "locks/installed-render-engine-lineage.json")
    canonical = json.dumps(installed, sort_keys=True, separators=(",", ":")) + "\n"
    _expect(
        (root / "locks/installed-render-engine-lineage.json").read_text(
            encoding="utf-8"
        ),
        canonical,
        "installed engine canonical bytes",
    )
    _keys(
        installed,
        {
            "canvasNative",
            "canvasSource",
            "fontManifest",
            "libreOfficeClosure",
            "nodeBinary",
            "pdfjsRoster",
            "schema",
        },
        "installed render engine lineage",
    )
    _expect(
        installed["schema"],
        "ambit.runtime-pack-installed-render-engine-lineage/v1",
        "installed engine schema",
    )
    expected_digests = {
        "canvasNative": canvas["platformArchive"]["nativeSha256"],
        "canvasSource": canvas["implementation"]["sourceArchiveSha256"],
        "fontManifest": _raw_sha256(root / "locks/font-files.sha256"),
        "libreOfficeClosure": _raw_sha256(root / "locks/debian-runtime-dpkg.lock"),
        "nodeBinary": node["binary"]["nodeSha256"],
        "pdfjsRoster": pdfjs["extractedRoster"]["lockSha256"],
    }
    for name, expected in expected_digests.items():
        _keys(installed[name], {"digest", "ref"}, f"installed engine {name}")
        _expect(installed[name]["digest"], expected, f"installed engine {name}")

    render_interface = _read(root / "locks/document-render-interface.lock.json")
    _keys(
        render_interface,
        {"contract", "digest", "schema", "state"},
        "document render interface lock",
    )
    _expect(
        render_interface["schema"],
        "ambit.runtime-interface-lock/v1",
        "document render interface schema",
    )
    _expect(
        render_interface["state"],
        "candidate-ready",
        "document render interface state",
    )
    contract_bytes = json.dumps(
        render_interface["contract"], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    _expect(
        render_interface["digest"],
        f"sha256:{hashlib.sha256(contract_bytes).hexdigest()}",
        "document render interface digest",
    )
    readme = (root / "README.md").read_text(encoding="utf-8")
    documented_interface = re.search(
        r"The stable component contract is:\n\n"
        r"- role: `([^`]+)`;\n"
        r"- interface: `([^`]+)`;\n"
        r"- digest:\n  `([^`]+)`;\n"
        r"- exact preimage: `([^`]+)`\.",
        readme,
    )
    if documented_interface is None:
        raise ValueError("documented render interface identity is absent")
    _expect(
        list(documented_interface.groups()),
        [
            render_interface["contract"]["roleRef"],
            render_interface["contract"]["interfaceRef"],
            render_interface["digest"],
            "locks/document-render-interface.lock.json",
        ],
        "documented render interface identity",
    )
    _expect(
        render_interface["contract"]["roleRef"],
        "ambit.runtime-component/document-renderer@1",
        "document renderer role",
    )
    _expect(
        render_interface["contract"]["interfaceRef"],
        "ambit.runtime-interface/docx-paginated-render@1",
        "document renderer interface",
    )
    contract = render_interface["contract"]
    _keys(
        contract,
        {
            "arguments",
            "authority",
            "cancellation",
            "execution",
            "executable",
            "frames",
            "identities",
            "input",
            "interfaceRef",
            "output",
            "policy",
            "roleRef",
            "runtime",
            "schema",
            "transport",
        },
        "document render interface contract",
    )
    _expect(
        contract["arguments"],
        ["--framed-jsonl", "--nonce", "LOWERCASE_128_BIT_HEX"],
        "document render arguments",
    )
    _expect(contract["runtime"]["pathAuthority"], "none", "render path authority")
    _expect(contract["transport"]["medium"], "raw-noecho-pty", "render transport")
    _expect(contract["transport"]["chunkBytes"], 49152, "render chunk bytes")
    _expect(contract["transport"]["maximumLineBytes"], 70000, "render line bytes")
    _expect(
        contract["transport"]["providerLaunch"],
        "stty raw -echo -onlcr && exec exact-helper --framed-jsonl --nonce exact-nonce",
        "fail-closed render provider launch",
    )
    _expect(
        contract["identities"]["protocolSources"],
        {
            relative: _raw_sha256(root / relative)
            for relative in PROTOCOL_SOURCE_PATHS
        },
        "document render protocol source roster",
    )
    render_document_source = (
        root / "renderer/ambit-render-document.mjs"
    ).read_text(encoding="utf-8")
    if "process.stderr.write" in render_document_source:
        raise ValueError("top render helper plaintext stderr is forbidden")
    for required in (
        "new RenderTerminalArbiter()",
        "streamSealedResponseBody",
        "lineReader.close(new RenderControlAdmissionClosed())",
        "process-group-subreaper.py",
        "--internal-render-child",
        "maximumTerminalWriteMilliseconds",
        "maximumCleanupMilliseconds",
        "all-render-process-groups-settled-and-private-roots-removed",
        "removePrivateMountContents",
        "mount.handle.sync()",
        "sealAndReadConvertedPdf",
        "handle.chmod(0o444)",
    ):
        if required not in render_document_source:
            raise ValueError(f"whole-pipeline render control is absent: {required}")
    if "renderPagesToDirectory({" in render_document_source:
        raise ValueError("PDF.js/native rendering is not process-group isolated")
    if "chmod(join(heldOutput, 'document.pdf')" in render_document_source:
        raise ValueError("converted PDF is mutated before no-follow inode admission")
    pdfjs_renderer_source = (
        root / "renderer/pdfjs-page-renderer.mjs"
    ).read_text(encoding="utf-8")
    if (
        "pdfBytes.byteLength > admittedPolicy.libreOffice.maximumPdfBytes"
        not in pdfjs_renderer_source
        or "pdfBytes.byteLength > admittedPolicy.input.maximumBytes"
        in pdfjs_renderer_source
    ):
        raise ValueError("PDF.js renderer does not enforce the intermediate PDF bound")
    subreaper_source = (
        root / "renderer/process-group-subreaper.py"
    ).read_text(encoding="utf-8")
    if "if forced:\n            for pid in members:" not in subreaper_source:
        raise ValueError("subreaper does not repeatedly kill late adopted descendants")
    protocol_source = (root / "renderer/framed-jsonl-protocol.mjs").read_text(
        encoding="utf-8"
    )
    if (
        "canonicalBytes.equals(lineBytes)" not in protocol_source
        or "Buffer.from(canonicalJson(value), 'utf8')" not in protocol_source
    ):
        raise ValueError("raw canonical UTF-8 frame admission is absent")
    dockerfile_source = (root / "Dockerfile").read_text(encoding="utf-8")
    for required in (
        "renderer/process-group-subreaper.py",
        "renderer/render-terminal-arbiter.mjs",
        "renderer/restricted-xml.mjs",
    ):
        if required not in dockerfile_source:
            raise ValueError(f"runtime image omits transitive behavior owner: {required}")
    pty_source = (root / "certification/runtime_pty_conformance.py").read_text(
        encoding="utf-8"
    )
    for required in (
        "size=800m,uid=1000,gid=1000,mode=0700",
        "all-render-process-groups-settled-and-private-roots-removed",
        '("success", "cancel", "error", "backpressure")',
    ):
        if required not in pty_source:
            raise ValueError(f"real PTY conformance coverage is absent: {required}")
    _expect(contract["input"]["maximumBytes"], 67108864, "interface DOCX bytes")
    _expect(
        contract["input"]["metadataXmlBounds"],
        "bytes=4194304,nodes=65536,depth=64,attributes-per-element=64,attribute-bytes=1048576,entities=65536,decoded-text-bytes=4194304",
        "interface restricted XML bounds",
    )
    _expect(
        contract["output"]["maximumBytesPerPage"],
        67108864,
        "interface page bytes",
    )
    _expect(
        contract["output"]["maximumTotalOutputBytes"],
        536870912,
        "interface total output bytes",
    )
    _expect(
        contract["output"]["evidenceInvariant"],
        "source<=input-max;pdf<=pdf-max;dense-exact-page-identity;width*height=pixels;png-dimensions-and-digest;per-page-and-aggregate-bounds",
        "interface render evidence invariant",
    )
    _expect(
        contract["execution"],
        _read(root / "policy/render-policy.json")["execution"],
        "interface whole-pipeline execution bounds",
    )
    _expect(
        contract["runtime"],
        {
            "network": "none",
            "pathAuthority": "none",
            "processModel": "one-helper-with-separate-bounded-libreoffice-and-pdfjs-native-process-groups",
            "rootFilesystem": "read-only",
            "taskCache": {
                "path": "/tmp",
                "filesystem": "task-private-tmpfs",
                "requiredBytes": 67108864,
                "uid": 1000,
                "gid": 1000,
                "mode": "0700",
            },
            "workspaceScratch": {
                "path": "/workspace",
                "filesystem": "task-private-tmpfs",
                "requiredBytes": 838860800,
                "derivation": "max(input-docx+intermediate-pdf,intermediate-pdf+page-output)+33554432-bounded-overhead",
                "uid": 1000,
                "gid": 1000,
                "mode": "0700",
            },
        },
        "interface runtime and scratch contract",
    )
    _expect(
        contract["transport"]["plaintextHelperStderr"],
        "forbidden",
        "render PTY plaintext stderr",
    )
    _expect(
        contract["policy"],
        {
            "ref": "ambit.render-policy/core-document-paginated@1",
            "digest": _raw_sha256(root / "policy/render-policy.json"),
        },
        "interface render policy",
    )

    cancellation = _read(root / "locks/runtime-cancellation-authority.lock.json")
    _keys(
        cancellation,
        {"hardTransportFailure", "helperProtocol", "schema", "state"},
        "runtime cancellation authority",
    )
    _expect(
        cancellation["schema"],
        "ambit.runtime-pack-cancellation-authority-lock/v1",
        "runtime cancellation schema",
    )
    _expect(
        cancellation["state"],
        "candidate-ready-local-xfs",
        "runtime cancellation state",
    )
    _expect(cancellation["helperProtocol"]["exitCode"], 130, "cancel exit code")
    _expect(
        cancellation["helperProtocol"]["typedOutcomeRequires"],
        [
            "exact-nonce-match",
            "all-render-process-groups-empty",
            "private-workspace-root-removed",
            "private-cache-root-removed",
        ],
        "complete render cancellation quiescence",
    )
    _expect(
        contract["cancellation"]["quiescence"],
        "all-render-process-groups-settled-and-private-roots-removed",
        "interface cancellation quiescence",
    )
    _expect(
        contract["cancellation"]["privateRootCustody"],
        "held-empty-workspace-and-cache-mount-authorities-cleaned-to-closed-empty-rosters-before-terminal",
        "interface private-root custody",
    )
    _expect(
        contract["cancellation"]["successCommit"],
        "control-admission-atomically-closed-before-awaited-response_end-write",
        "interface success terminal arbitration",
    )
    hard_failure = cancellation["hardTransportFailure"]
    _expect(
        hard_failure["typedCancelledWithoutProviderReceipt"],
        "forbidden",
        "hard transport cancellation outcome",
    )
    _expect(
        hard_failure["requiredAuthority"],
        "ambit.runtime-provider-quiescence-receipt/v1",
        "provider quiescence authority",
    )
    local_xfs = hard_failure["localXfsAdapter"]
    local_xfs_contract = local_xfs["interfaceContract"]
    local_xfs_bytes = json.dumps(
        local_xfs_contract, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    _expect(
        local_xfs["interfaceRef"],
        "ambit.runtime-provider-quiescence/local-xfs-isolated-docker@1",
        "local XFS cancellation interface",
    )
    _expect(
        local_xfs["interfaceDigest"],
        f"sha256:{hashlib.sha256(local_xfs_bytes).hexdigest()}",
        "local XFS cancellation interface digest",
    )
    _expect(
        local_xfs_contract["sourceCommit"],
        "b0efa08fb744c94cec5e074a6fc34ae340a4e177",
        "local XFS cancellation source",
    )
    _expect(
        local_xfs_contract["supervisor"]["sha256"],
        "sha256:8a5f11cafb228b5f79a3d0a468bc35d5e5a9b32d4f800e6baec135801613be1f",
        "local XFS supervisor source",
    )
    _expect(
        local_xfs_contract["launcher"]["sha256"],
        "sha256:a8eba1b974859aecb6423daa1babbce27fb6ca10314fdd0da59c862b014a0a09",
        "local XFS stop launcher source",
    )
    _expect(
        local_xfs_contract["receipt"]["schema"],
        "ambit.local-daytona-isolated-docker-stop/v2",
        "local XFS stop receipt",
    )
    _expect(
        contract["cancellation"]["authorityLock"],
        {
            "ref": "locks/runtime-cancellation-authority.lock.json",
            "digest": _raw_sha256(
                root / "locks/runtime-cancellation-authority.lock.json"
            ),
        },
        "interface cancellation authority",
    )


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

    _verify_candidate_evidence(root, node=node, canvas=canvas, pdfjs=pdfjs)

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
            "promotionBlockers",
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
    _expect(node["state"], "candidate-ready", "Node state")
    _expect(node["version"], "24.19.0", "Node version")
    for key in ("archiveSha256",):
        _sha256(node["source"][key], f"Node source {key}")
    for key in ("archiveSha256", "licenseSha256", "nodeSha256"):
        _sha256(node["binary"][key], f"Node binary {key}")
    for key in ("shasumsSha256", "signatureSha256"):
        _sha256(node["releaseAuthority"][key], f"Node release {key}")
    _expect(
        node["releaseAuthority"]["verificationState"],
        "verified",
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
            "promotionBlockers",
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
    _expect(canvas["state"], "candidate-ready", "Canvas state")
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
            "atomicMaterializer",
            "baseOci",
            "buildFrontend",
            "buildTargets",
            "frozenEvidence",
            "frozenEvidenceByteManifest",
            "frozenEvidenceSha256Manifest",
            "missing",
            "materializerNamedBuildContext",
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
        offline["atomicMaterializer"],
        {
            "binaryBytes",
            "binarySecretId",
            "binarySha256",
            "includedInNamedContext",
            "publisherAuthentication",
            "sourceArchiveBytes",
            "sourceArchiveSecretId",
            "sourceArchiveSha256",
            "state",
        },
        "offline atomic materializer",
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
    _expect(offline["state"], "candidate-ready", "offline build state")
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
        "provider-external",
        "offline helper state",
    )
    _expect(
        offline["atomicMaterializer"]["state"],
        "candidate-ready",
        "offline atomic materializer state",
    )
    _expect(
        offline["atomicMaterializer"]["includedInNamedContext"],
        True,
        "atomic materializer named-context inclusion",
    )
    _expect(
        offline["atomicMaterializer"]["publisherAuthentication"],
        "local-content-binding-only",
        "atomic materializer publisher authentication",
    )
    _sha256(
        offline["atomicMaterializer"]["sourceArchiveSha256"],
        "atomic materializer source archive",
    )
    _sha256(
        offline["atomicMaterializer"]["binarySha256"],
        "atomic materializer binary",
    )
    _expect(
        offline["materializerNamedBuildContext"],
        "materializer_inputs",
        "materializer named build context",
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
    _expect(
        offline["requiredUnfrozenEvidence"],
        [],
        "candidate build missing input roster",
    )
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
    _expect(
        offline["frozenEvidenceSha256Manifest"],
        "offline-frozen-evidence.sha256",
        "offline frozen SHA manifest",
    )
    _expect(
        offline["frozenEvidenceByteManifest"],
        "offline-frozen-evidence.bytes",
        "offline frozen byte manifest",
    )
    _verify_offline_public_manifests(root, offline["publicArtifacts"])

    try:
        from .verify_structural_contracts import verify as verify_structural_contracts
    except ImportError:
        from verify_structural_contracts import verify as verify_structural_contracts

    structural_result = verify_structural_contracts(root, offline)

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
    _expect(debian["resolution"]["state"], "candidate-ready", "Debian closure state")
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
    _expect(pdfjs["execution"]["state"], "candidate-ready", "PDF.js execution state")
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
            "documentRenderInterfaceLock",
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
            "runtimeCancellationAuthorityLock",
            "schema",
            "state",
            "structuralCompatibility",
            "structuralCompatibilityInputLock",
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
        toolchain["structuralCompatibility"],
        {"atomicMaterializerConformance", "composition", "documentConformance", "runtimeArchive", "state"},
        "toolchain structural compatibility",
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
    _expect(toolchain["state"], "candidate-ready", "toolchain state")
    _expect(toolchain["platform"], {"os": "linux", "architecture": "amd64"}, "platform")
    _expect(toolchain["pdfjs"]["runtimeNode"], "24.19.0", "runtime Node")
    _expect(toolchain["pdfjs"]["runtimeNpm"], "absent", "runtime npm")
    _expect(
        toolchain["pdfjs"]["nativeCanvas"],
        "@napi-rs/canvas-linux-x64-gnu@1.0.7",
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
    _expect(toolchain["activation"], "candidate-only", "activation")
    _expect(
        toolchain["installedEngineLineage"]["state"],
        "candidate-ready",
        "installed engine lineage state",
    )
    _expect(
        toolchain["installedEngineLineage"]["callerSuppliedEnginePins"],
        "forbidden",
        "caller supplied engine pins",
    )
    _expect(
        toolchain["structuralCompatibility"]["state"],
        structural_result["state"],
        "toolchain structural compatibility state",
    )
    _expect(
        toolchain["structuralCompatibility"]["composition"],
        "external-curated-files-not-core-document-v4-layer",
        "toolchain structural composition",
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
            "execution",
            "input",
            "libreOffice",
            "pages",
            "pdfjs",
            "policyRef",
            "renderOutputGrantsCanonicalAuthority",
            "schema",
            "scratch",
        },
        "render policy",
    )
    _keys(
        render["input"],
        {
            "externalLinks",
            "formats",
            "localImmutableBytesOnly",
            "macros",
            "maximumBytes",
            "maximumEntryBytes",
            "maximumPackageEntries",
            "maximumRelationshipBytes",
            "maximumUncompressedBytes",
            "maximumXmlAttributeBytes",
            "maximumXmlAttributesPerElement",
            "maximumXmlBytes",
            "maximumXmlDecodedTextBytes",
            "maximumXmlDepth",
            "maximumXmlEntityReferences",
            "maximumXmlNodes",
            "passwordProtected",
            "remoteUrls",
        },
        "render input policy",
    )
    _keys(
        render["execution"],
        {
            "maximumChildStderrBytes",
            "maximumChildStdoutBytes",
            "maximumCleanupMilliseconds",
            "maximumPipelineWallMilliseconds",
            "maximumTerminalWriteMilliseconds",
        },
        "render execution policy",
    )
    _keys(
        render["libreOffice"],
        {
            "headless",
            "maximumPdfBytes",
            "maximumWallMilliseconds",
            "nodefault",
            "nolockcheck",
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
            "maximumBytesPerPage",
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
        render["scratch"],
        {
            "cacheRequiredBytes",
            "derivation",
            "workspaceOverheadBytes",
            "workspaceRequiredBytes",
        },
        "render scratch policy",
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
    _expect(render["pdfjs"]["executionState"], "available", "render execution")
    _expect(render["input"]["maximumBytes"], 67108864, "DOCX transport bytes")
    _expect(render["input"]["maximumEntryBytes"], 67108864, "DOCX entry bytes")
    _expect(render["input"]["maximumPackageEntries"], 2048, "DOCX entry count")
    _expect(
        render["input"]["maximumRelationshipBytes"],
        4194304,
        "DOCX relationship bytes",
    )
    _expect(
        render["input"]["maximumUncompressedBytes"],
        268435456,
        "DOCX uncompressed bytes",
    )
    _expect(render["input"]["maximumXmlBytes"], 4194304, "DOCX XML bytes")
    _expect(render["input"]["maximumXmlNodes"], 65536, "DOCX XML nodes")
    _expect(render["input"]["maximumXmlDepth"], 64, "DOCX XML depth")
    _expect(
        render["input"]["maximumXmlAttributesPerElement"],
        64,
        "DOCX XML attributes",
    )
    _expect(
        render["input"]["maximumXmlAttributeBytes"],
        1048576,
        "DOCX XML attribute bytes",
    )
    _expect(
        render["input"]["maximumXmlEntityReferences"],
        65536,
        "DOCX XML entity references",
    )
    _expect(
        render["input"]["maximumXmlDecodedTextBytes"],
        4194304,
        "DOCX XML decoded bytes",
    )
    _expect(
        render["libreOffice"]["maximumPdfBytes"],
        268435456,
        "intermediate PDF bytes",
    )
    _expect(render["pages"]["maximumTotalPixels"], 536870912, "total pixels")
    _expect(
        render["pages"]["maximumBytesPerPage"],
        67108864,
        "per-page output bytes",
    )
    _expect(
        render["pages"]["maximumTotalOutputBytes"],
        536870912,
        "total output bytes",
    )
    _expect(render["pages"]["rasterScale"], 2, "page raster scale")
    _expect(render["pages"]["background"], "#ffffff", "page background")
    _expect(
        render["execution"],
        {
            "maximumChildStderrBytes": 65536,
            "maximumChildStdoutBytes": 16384,
            "maximumCleanupMilliseconds": 10000,
            "maximumPipelineWallMilliseconds": 180000,
            "maximumTerminalWriteMilliseconds": 5000,
        },
        "whole-pipeline execution bounds",
    )
    expected_workspace_bytes = max(
        render["input"]["maximumBytes"]
        + render["libreOffice"]["maximumPdfBytes"],
        render["libreOffice"]["maximumPdfBytes"]
        + render["pages"]["maximumTotalOutputBytes"],
    ) + render["scratch"]["workspaceOverheadBytes"]
    _expect(
        render["scratch"],
        {
            "cacheRequiredBytes": 67108864,
            "derivation": "max(input-docx+intermediate-pdf,intermediate-pdf+page-output)+bounded-overhead",
            "workspaceOverheadBytes": 33554432,
            "workspaceRequiredBytes": expected_workspace_bytes,
        },
        "derived render scratch bounds",
    )
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
    _expect(license_policy["state"], "candidate-ready", "license policy state")
    _expect(
        license_policy["nativeCanvas"]["disposition"],
        "candidate-only",
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
        "structuralCompatibility": structural_result["state"],
        "atomicMaterializer": structural_result["atomicMaterializerState"],
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
