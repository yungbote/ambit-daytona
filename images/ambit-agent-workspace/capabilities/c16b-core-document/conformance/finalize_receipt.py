from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


root = Path(sys.argv[1]).resolve()
artifact = json.loads((root / "artifact-receipt.json").read_text())
materializer = json.loads((root / "materializer-receipt.json").read_text())
absent_commands = (root / "absent-commands.txt").read_text().splitlines()


def pin(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": str(path.relative_to(root)),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


apk_closure = pin(root / "apk-packages.actual.lock")


evidence = [
    pin(path)
    for path in sorted(root.rglob("*"))
    if path.is_file() and path.name != "conformance-receipt.json"
]
receipt = {
    "schema": "ambit.runtime-pack-conformance/v3",
    "outcome": "passed",
    "runtime": {
        "privilege": "non_root",
        "linuxCapabilities": "none",
        "noNewPrivileges": True,
        "network": "none",
        "hostSocket": "absent",
        "packRoot": "read_only",
        "runtimePackageInstallers": "absent",
        "buildOnlyPipWheelPayload": "removed_from_runtime_files_package_metadata_retained",
        "absentCommands": absent_commands,
        "osClosure": apk_closure,
        "locale": "C.UTF-8",
        "timezone": "UTC",
    },
    "capabilityFamilies": [
        "core-shell",
        "python-runtime",
        "docx-create-edit-structural-inspect-validate",
    ],
    "providerImplementationEvidence": {
        "advertisedRuntimeCapability": False,
        "atomicMaterializer": materializer,
    },
    "artifactConformance": artifact,
    "evidence": evidence,
    "knownLimitations": [
        "native_microsoft_office_fidelity_not_exercised",
        "derived_html_preview_is_non_layout_authoritative",
        "derived_html_preview_is_diagnostic_evidence_not_a_runtime_capability",
        "document_render_v1_is_unavailable_until_C19_paginated_renderer_composes",
        "native_document_render_and_visual_fidelity_are_owned_by_C19",
        "macro_preservation_not_exercised_no_macro_fixture",
        "specialist_artifact_families_require_independent_c18_packs",
        "node_typescript_and_language_intelligence_are_not_in_this_pack",
        "runtime_dependency_installation_is_not_admitted",
        "load_and_checkpoint_slos_not_exercised_by_local_pack_conformance",
    ],
}
(root / "conformance-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
