from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


PACK = Path(__file__).resolve().parent.parent


class HelperPackagingContractTest(unittest.TestCase):
    def test_v4_helper_lock_and_toolchain_bind_both_protocols(self) -> None:
        helper = json.loads((PACK / "helper-input.lock.json").read_text())
        toolchain = json.loads((PACK / "toolchain-manifest.json").read_text())
        self.assertEqual(helper["schema"], "ambit.runtime-pack-helper-input-lock/v2")
        self.assertEqual(toolchain["schema"], "ambit.runtime-pack-toolchain/v2")
        self.assertEqual(toolchain["pack"], "ambit.runtime-pack/core-document@4")
        materializer = toolchain["atomicMaterializer"]
        self.assertEqual(materializer["version"], 2)
        self.assertEqual(materializer["sourceRevision"], helper["revision"])
        self.assertEqual(materializer["sourceTree"], helper["tree"])
        self.assertEqual(
            materializer["sourceArchiveSha256"], helper["archive"]["sha256"]
        )
        self.assertEqual(materializer["binarySha256"], helper["binary"]["sha256"])
        self.assertEqual(
            materializer["protocolDigest"], f"sha256:{helper['protocolSha256']}"
        )
        self.assertEqual(
            materializer["treeProtocolDigest"],
            f"sha256:{helper['treeProtocolSha256']}",
        )
        policy = json.loads((PACK / "policy/runtime-policy.json").read_text())
        self.assertEqual(policy["schema"], "ambit.runtime-pack-policy/v2")
        self.assertEqual(
            policy["atomicMaterializer"]["helperSha256"], helper["binary"]["sha256"]
        )
        self.assertEqual(
            policy["atomicMaterializer"]["treeProtocolSha256"],
            helper["treeProtocolSha256"],
        )

    def test_closed_helper_manifest_and_general_go_copy_remove_duplicate_roster(self) -> None:
        manifest = PACK / "helper-input.sha256"
        self.assertEqual(
            hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "10bc2e0565fb4bc5adc7ce889a15b31257ae852017b1f989bca58cfdb23b1c01",
        )
        names = [line.split("/helper-input/", 1)[1] for line in manifest.read_text().splitlines()]
        self.assertEqual(names, sorted(set(names)))
        self.assertEqual(
            names,
            [
                "LICENSE.md",
                "README.md",
                "binary.sha256",
                "go.mod",
                "go.sum",
                "license.lock.json",
                "main.go",
                "main_test.go",
                "materializer.lock.json",
                "source.sha256",
                "tree.go",
                "tree_live_conformance.py",
                "tree_test.go",
            ],
        )
        dockerfile = (PACK / "Dockerfile").read_text()
        self.assertIn("cp /helper-input/*.go /helper-input/source.sha256 ./", dockerfile)
        self.assertNotIn("cp /helper-input/main.go /helper-input/main_test.go", dockerfile)
        self.assertIn("io.ambit.atomic-tree-materializer-protocol", dockerfile)
        self.assertIn('io.ambit.runtime-pack="${BUILD_RUNTIME_PACK_REF}"', dockerfile)
        certification = (PACK / "certification/certify-local.sh").read_text()
        self.assertIn('schema:"ambit.runtime-pack-evidence-binding/v4"', certification)
        self.assertIn('packRef:$runtime_pack_ref', certification)

    def test_v3_terminal_evidence_remains_historical(self) -> None:
        historical = json.loads(
            (PACK / "certification/evidence/a900dee66-terminal.json").read_text()
        )
        self.assertEqual(historical["packRef"], "ambit.runtime-pack/core-document@3")
        self.assertEqual(
            historical["helper"]["binarySha256"],
            "sha256:09e0d936c23d7625af9f67c09b703ed41135b185c3822a98f1f62cd401ded3ed",
        )
        self.assertFalse(historical["releaseDisposition"]["promotionPerformed"])


if __name__ == "__main__":
    unittest.main()
