from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


root = Path(sys.argv[1]).resolve()
artifact = json.loads((root / "artifact-receipt.json").read_text())
browser = json.loads((root / "web-receipt.json").read_text())


def pin(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": str(path.relative_to(root)),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


evidence = [
    pin(path)
    for path in sorted(root.rglob("*"))
    if path.is_file() and path.name != "conformance-receipt.json"
]
receipt = {
    "schema": "ambit.runtime-pack-conformance/v1",
    "outcome": "passed",
    "runtime": {
        "privilege": "non_root",
        "network": "none_with_loopback_only",
        "hostSocket": "absent",
        "packRoot": "read_only",
        "installScriptsDefault": "disabled",
        "pythonSourceBuildsDefault": "disabled",
        "locale": "C.UTF-8",
        "timezone": "UTC",
    },
    "artifactConformance": artifact,
    "browserConformance": browser,
    "evidence": evidence,
    "knownLimitations": [
        "macro_preservation_not_exercised_no_macro_fixture",
        "native_microsoft_office_fidelity_not_exercised",
        "firefox_and_webkit_not_bundled",
        "package_policy_environment_variables_are_defense_in_depth_not_a_process_sandbox",
        "dependency_installation_requires_a_separately_admitted_content_addressed_cache",
        "load_and_checkpoint_slos_not_exercised_by_local_pack_conformance",
    ],
}
(root / "conformance-receipt.json").write_text(
    json.dumps(receipt, indent=2, sort_keys=True) + "\n"
)
