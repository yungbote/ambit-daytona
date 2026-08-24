from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from certification.audit_offline_inputs import audit, verify_exact_file


ROOT = Path(__file__).resolve().parents[1]


class OfflineInputAuditTests(unittest.TestCase):
    def test_candidate_requires_every_exact_external_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = audit(ROOT, Path(directory))
        self.assertEqual(result["outcome"], "unavailable")
        self.assertEqual(result["sourceState"], "candidate-ready")
        self.assertEqual(result["networkOperations"], "none")
        self.assertEqual(len(result["missing"]), 14)
        lock = json.loads(
            (ROOT / "locks/offline-build-input.lock.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertNotIn("requiredFrozenFiles", lock)
        self.assertEqual(len(lock["frozenEvidence"]), 5)
        self.assertEqual(
            lock["frozenEvidence"][0]["sha256"],
            "sha256:89f4f0fdcb0376e5079922a3bfb6dcc3a0262ab5a0e2449813f2b658ea94641c",
        )
        self.assertEqual(lock["requiredUnfrozenEvidence"], [])
        for artifact in lock["publicArtifacts"]:
            self.assertGreater(artifact["bytes"], 0)
            self.assertRegex(artifact["sha256"], r"^sha256:[0-9a-f]{64}$")
        for evidence in lock["frozenEvidence"]:
            self.assertGreater(evidence["bytes"], 0)
            self.assertRegex(evidence["sha256"], r"^sha256:[0-9a-f]{64}$")

    def test_exact_file_requires_raw_digest_size_mode_and_no_follow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = root / "value.bin"
            value.write_bytes(b"exact public input")
            value.chmod(0o444)
            digest = f"sha256:{hashlib.sha256(value.read_bytes()).hexdigest()}"
            verify_exact_file(
                value,
                expected_bytes=value.stat().st_size,
                expected_sha256=digest,
            )
            with self.assertRaisesRegex(ValueError, "digest differs"):
                verify_exact_file(
                    value,
                    expected_bytes=value.stat().st_size,
                    expected_sha256=f"sha256:{'0' * 64}",
                )
            value.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "not exact and immutable"):
                verify_exact_file(
                    value,
                    expected_bytes=value.stat().st_size,
                    expected_sha256=digest,
                )
            value.chmod(0o444)
            alias = root / "alias.bin"
            alias.symlink_to(value)
            with self.assertRaises(OSError):
                verify_exact_file(
                    alias,
                    expected_bytes=value.stat().st_size,
                    expected_sha256=digest,
                )

    def test_auditor_source_has_no_download_or_process_surface(self) -> None:
        source = (ROOT / "certification/audit_offline_inputs.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "requests",
            "subprocess",
            "urllib",
            "urlopen",
            "curl",
            "wget",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
