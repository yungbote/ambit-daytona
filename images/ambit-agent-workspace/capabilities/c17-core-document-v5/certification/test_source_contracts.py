from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from certification.verify_source_contracts import verify


ROOT = Path(__file__).resolve().parents[1]


class SourceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "pack"
        shutil.copytree(ROOT, self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mutate(self, relative: str, update) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        update(value)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def assert_rejected(self, relative: str, update) -> None:
        self.mutate(relative, update)
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_exact_unavailable_contract_passes_source_verification(self) -> None:
        result = verify(self.root)
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(set(result["availability"].values()), {"unavailable"})

    def test_ready_gate_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "core-document@5 is unavailable"):
            verify(self.root, require_ready=True)

    def test_base_platform_substitution_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/base-oci.lock.json",
            lambda value: value["platform"].__setitem__("architecture", "arm64"),
        )

    def test_mutable_base_reference_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/base-oci.lock.json",
            lambda value: value["index"].__setitem__(
                "reference", "docker.io/library/debian:trixie-slim"
            ),
        )

    def test_debian_package_expansion_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/debian-input.lock.json",
            lambda value: value["requestedPackages"].append("libreoffice-nogui=4:25.2.3-2+deb13u6"),
        )

    def test_unsigned_debian_metadata_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/debian-input.lock.json",
            lambda value: value["signaturePolicy"].__setitem__("verifyInRelease", False),
        )

    def test_pdfjs_standard_font_expansion_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/pdfjs-input.lock.json",
            lambda value: value["excludedRoots"].remove("standard_fonts"),
        )

    def test_pdfjs_execution_claim_without_canvas_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/pdfjs-input.lock.json",
            lambda value: value["execution"].__setitem__("state", "available"),
        )

    def test_helper_cannot_self_mint_expected_archive_digest(self) -> None:
        self.assert_rejected(
            "locks/capture-helper-input.lock.json",
            lambda value: value.__setitem__("expectedRawSha256", "0" * 64),
        )

    def test_helper_signature_downgrade_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/capture-helper-input.lock.json",
            lambda value: value["requiredExternalAuthority"].__setitem__(
                "downgrade", "digest-only"
            ),
        )

    def test_runtime_network_or_root_expansion_is_rejected(self) -> None:
        for field, replacement in (("network", "default"), ("rootEscalation", "allowed")):
            with self.subTest(field=field):
                self.assert_rejected(
                    "policy/runtime-policy.json",
                    lambda value, field=field, replacement=replacement: value.__setitem__(
                        field, replacement
                    ),
                )
                shutil.rmtree(self.root)
                shutil.copytree(ROOT, self.root)

    def test_poppler_fallback_and_canonical_render_authority_are_rejected(self) -> None:
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value["pdfjs"].__setitem__("popplerFallback", "allowed"),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value.__setitem__("renderOutputGrantsCanonicalAuthority", True),
        )

    def test_duplicate_json_keys_are_rejected_before_interpretation(self) -> None:
        path = self.root / "policy/license-policy.json"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("{\n", '{\n  "state": "ready",\n', 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
