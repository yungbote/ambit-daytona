from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from verify_source import SourceContractError, verify


ROOT = Path(__file__).resolve().parents[1]


class CoreBaselineSourceTests(unittest.TestCase):
    def test_current_source_is_exact_and_unpromoted(self) -> None:
        receipt = verify(ROOT)
        self.assertEqual(receipt["outcome"], "passed")
        self.assertFalse(receipt["historicalCoreDocumentReusable"])
        self.assertFalse(receipt["promotionPerformed"])
        self.assertFalse(receipt["backendCompositionContractFrozen"])

    def test_rejects_document_capability_smuggled_into_core(self) -> None:
        with self._copy() as root:
            value = self._baseline(root)
            value["capabilityProjection"]["provides"].append(
                "ambit.runtime/document.edit@1"
            )
            value["capabilityProjection"]["provides"].sort()
            self._write(root, value)
            with self.assertRaisesRegex(SourceContractError, "widened"):
                verify(root)

    def test_rejects_tar_copy_as_artifact_reuse(self) -> None:
        with self._copy() as root:
            value = self._baseline(root)
            value["composition"]["tarOrFilesystemCopyCountsAsArtifactReuse"] = True
            self._write(root, value)
            with self.assertRaisesRegex(SourceContractError, "copied-file equivalence"):
                verify(root)

    def test_rejects_claimed_source_promotion(self) -> None:
        with self._copy() as root:
            value = self._baseline(root)
            value["promotion"]["disposition"] = "promoted"
            self._write(root, value)
            with self.assertRaisesRegex(SourceContractError, "falsely claims"):
                verify(root)

    def test_rejects_relabeling_core_document_v4_as_reusable(self) -> None:
        with self._copy() as root:
            value = self._baseline(root)
            value["historicalInput"]["reusableAsCoreBaseline"] = True
            self._write(root, value)
            with self.assertRaisesRegex(SourceContractError, "relabeled"):
                verify(root)

    def _copy(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        for path in ROOT.rglob("*"):
            if path.is_file():
                target = root / path.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())

        class ManagedPath:
            def __enter__(self) -> Path:
                return root

            def __exit__(self, *_: object) -> None:
                temporary.cleanup()

        return ManagedPath()

    @staticmethod
    def _baseline(root: Path) -> dict[str, object]:
        return copy.deepcopy(
            json.loads((root / "core-baseline.lock.json").read_text(encoding="utf-8"))
        )

    @staticmethod
    def _write(root: Path, value: dict[str, object]) -> None:
        (root / "core-baseline.lock.json").write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    unittest.main()
