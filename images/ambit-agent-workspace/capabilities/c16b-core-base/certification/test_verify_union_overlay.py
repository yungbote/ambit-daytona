from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from verify_union_overlay import UnionOverlayError, verify


ROOT = Path(__file__).resolve().parents[1]
SHA = "sha256:" + "1" * 64
CONTRACT_PENDING = (
    json.loads((ROOT / "composition/union-overlay-contract.lock.json").read_text())["coreParent"]["status"]
    != "qualified"
)


@unittest.skipIf(CONTRACT_PENDING, "qualified core parent identity is pending")
class UnionOverlayTests(unittest.TestCase):
    def test_accepts_one_canonical_union_over_literal_core_parent(self) -> None:
        receipt = self._verify(self._receipt())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertFalse(receipt["lastWriterWins"])

    def test_rejects_sequential_or_last_writer_wins_composition(self) -> None:
        value = self._receipt()
        value["unionResolution"]["lastWriterWins"] = True
        with self.assertRaisesRegex(UnionOverlayError, "last-writer-wins"):
            self._verify(value)

    def test_rejects_reordered_selected_bundles(self) -> None:
        value = self._receipt(two_bundles=True)
        value["selectedBundles"].reverse()
        with self.assertRaisesRegex(UnionOverlayError, "not canonical"):
            self._verify(value)

    def test_rejects_missing_core_prefix_or_unbound_overlay_suffix(self) -> None:
        value = self._receipt()
        value["finalImage"]["orderedLayers"] = value["finalImage"]["orderedLayers"][1:]
        with self.assertRaisesRegex(UnionOverlayError, "exact core layer prefix"):
            self._verify(value)
        value = self._receipt()
        value["finalImage"]["orderedLayers"][-1] = {"digest": "sha256:" + "9" * 64, "size": 10}
        with self.assertRaisesRegex(UnionOverlayError, "suffix"):
            self._verify(value)

    def test_rejects_runtime_installer_or_core_path_regression(self) -> None:
        value = self._receipt()
        value["finalImage"]["installerCommandsAbsent"] = value["finalImage"]["installerCommandsAbsent"][:-1]
        with self.assertRaisesRegex(UnionOverlayError, "installer absence"):
            self._verify(value)
        value = self._receipt()
        value["unionResolution"]["protectedCorePaths"] = "failed"
        with self.assertRaisesRegex(UnionOverlayError, "protected-core"):
            self._verify(value)

    def test_rejects_non_string_or_duplicate_capability_rosters(self) -> None:
        value = self._receipt()
        value["selectedBundles"][0]["capabilityRefs"] = [{}]
        with self.assertRaisesRegex(UnionOverlayError, "capability roster is invalid"):
            self._verify(value)
        value = self._receipt()
        capability = value["selectedBundles"][0]["capabilityRefs"][0]
        value["selectedBundles"][0]["capabilityRefs"].append(capability)
        with self.assertRaisesRegex(UnionOverlayError, "not canonical"):
            self._verify(value)

    def _verify(self, value: dict[str, object]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return verify(ROOT, path)

    @staticmethod
    def _receipt(*, two_bundles: bool = False) -> dict[str, object]:
        contract = json.loads((ROOT / "composition/union-overlay-contract.lock.json").read_text())
        refs = ["ambit.runtime-pack/document@1"]
        if two_bundles:
            refs = ["ambit.runtime-pack/browser@1", "ambit.runtime-pack/document@1"]
        bundles = [
            {
                "packRevisionRef": ref,
                "artifact": {"ref": f"runtime-pack-artifact:{index}", "digest": SHA},
                "installer": {"ref": f"runtime-pack-installer:{index}", "digest": SHA},
                "capabilityRefs": ["ambit.runtime/document.edit@1"],
            }
            for index, ref in enumerate(refs)
        ]
        overlay = [{"digest": "sha256:" + "2" * 64, "size": 10}]
        conformance = [
            {
                "packRevisionRef": ref,
                "receipt": {"ref": f"pack-conformance-receipt:{index}", "digest": SHA},
            }
            for index, ref in enumerate(refs)
        ]
        return {
            "schema": "ambit.runtime-core-union-overlay-receipt/v1",
            "coreParent": {
                "platformManifestDigest": contract["coreParent"]["platformManifestDigest"],
                "configDigest": contract["coreParent"]["configDigest"],
                "sourceIdentitySha256": contract["coreParent"]["sourceIdentitySha256"],
                "orderedLayers": contract["coreParent"]["orderedLayers"],
            },
            "selectedBundles": bundles,
            "builder": {
                "baseInput": contract["union"]["builderBaseInput"],
                "network": "none",
                "offline": True,
                "packageManagersAvailableOnlyHere": True,
            },
            "unionResolution": {
                "bundleOrder": refs,
                "closedOverlayOutcome": "passed",
                "closedOverlayEntryManifest": {"ref": "ambit.overlay/entries@1", "digest": SHA},
                "dependencyResolutionOutcome": "passed",
                "dependencyGraph": {"ref": "ambit.overlay/dependencies@1", "digest": SHA},
                "globalPostState": {"ref": "ambit.rootfs/post@1", "digest": SHA},
                "globalPreState": {"ref": "ambit.rootfs/pre@1", "digest": SHA},
                "installPasses": 1,
                "lastWriterWins": False,
                "ownershipManifest": {"ref": "ambit.overlay/ownership@1", "digest": SHA},
                "ownershipOutcome": "passed",
                "pathConflictOutcome": "passed",
                "pathConflictReport": {"ref": "ambit.overlay/conflicts@1", "digest": SHA},
                "protectedCorePathReceipt": {"ref": "ambit.overlay/protected-core@1", "digest": SHA},
                "protectedCorePaths": "passed",
                "prunePasses": 1,
                "resultingLayers": overlay,
            },
            "finalImage": {
                "platformManifestDigest": "sha256:" + "3" * 64,
                "configDigest": "sha256:" + "4" * 64,
                "orderedLayers": [*contract["coreParent"]["orderedLayers"], *overlay],
                "coreConformanceReceipt": {"ref": "ambit.core-conformance/result@1", "digest": SHA},
                "installerCommandsAbsent": contract["finalRuntime"]["forbiddenInstallerCommands"],
                "packConformanceReceipts": conformance,
                "runtimeProbe": {
                    "hostSocketsAbsent": True,
                    "linuxCapabilities": [],
                    "network": "none",
                    "noNewPrivileges": True,
                    "readOnlyRoot": True,
                    "runtimeUser": "1000:1000",
                    "secretEnvironmentNames": [],
                },
            },
            "outcome": "passed",
        }


if __name__ == "__main__":
    unittest.main()
