from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from certification.verify_signed_debian_snapshot import (
    control_records,
    parse_manifest,
    signed_cleartext,
    source_pair,
)


class SignedDebianSnapshotVerificationTests(unittest.TestCase):
    def test_control_records_preserve_multiline_fields_and_reject_duplicates(self) -> None:
        self.assertEqual(
            control_records("Package: example\nChecksums-Sha256:\n abc 1 x\n\n"),
            [
                {
                    "Package": "example",
                    "Checksums-Sha256": "\nabc 1 x",
                }
            ],
        )
        with self.assertRaisesRegex(ValueError, "duplicate"):
            control_records("Package: one\nPackage: two\n")
        with self.assertRaisesRegex(ValueError, "orphan"):
            control_records(" continuation\n")

    def test_clear_signed_payload_is_exactly_dash_unescaped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "InRelease"
            path.write_text(
                "-----BEGIN PGP SIGNED MESSAGE-----\n"
                "Hash: SHA256\n\n"
                "Field: value\n"
                "- -escaped\n"
                "-----BEGIN PGP SIGNATURE-----\n"
                "opaque\n"
                "-----END PGP SIGNATURE-----\n",
                encoding="utf-8",
            )
            self.assertEqual(signed_cleartext(path), "Field: value\n-escaped\n")

    def test_manifest_and_binary_source_identity_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.sha256"
            path.write_text(f"{'a' * 64}  one\n{'b' * 64}  one\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                parse_manifest(path, digest_manifest=True)
        self.assertEqual(
            source_pair(
                {
                    "Package": "binary",
                    "Version": "1+b1",
                    "Source": "source (1)",
                }
            ),
            ("source", "1"),
        )
        with self.assertRaisesRegex(ValueError, "invalid binary Source"):
            source_pair({"Package": "binary", "Version": "1", "Source": "bad ("})


if __name__ == "__main__":
    unittest.main()
