from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent
HELPER_VERIFIER = ROOT / "verify_helper_input_manifest.py"
INSTALLER_GATE = ROOT / "verify_runtime_installer_absence.sh"


class HelperInputManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.helper = self.root / "helper"
        self.helper.mkdir()
        self.manifest = self.root / "helper-input.sha256"
        self.output = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_fixture(self) -> None:
        files = {"main.go": b"package main\n", "source.sha256": b"source manifest\n"}
        for name, payload in files.items():
            (self.helper / name).write_bytes(payload)
        self.manifest.write_text(
            "".join(
                f"{hashlib.sha256(payload).hexdigest()}  /helper-input/{name}\n"
                for name, payload in sorted(files.items())
            )
        )

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(HELPER_VERIFIER),
                "--manifest",
                str(self.manifest),
                "--helper-root",
                str(self.helper),
                "--output",
                str(self.output),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_exact_regular_file_roster_passes(self) -> None:
        self.write_fixture()
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["fileCount"], 2)

    def test_absolute_path_outside_helper_prefix_is_rejected(self) -> None:
        self.write_fixture()
        self.manifest.write_text("0" * 64 + "  /etc/passwd\n")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe or noncanonical path", result.stderr)

    def test_symlink_and_extra_file_are_rejected(self) -> None:
        self.write_fixture()
        (self.helper / "extra").write_text("extra")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("file roster differs", result.stderr)
        (self.helper / "extra").unlink()
        (self.helper / "main.go").unlink()
        os.symlink("source.sha256", self.helper / "main.go")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no-follow regular file", result.stderr)


class RuntimeInstallerGateTest(unittest.TestCase):
    def test_all_absent_reaches_expected_terminal_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["/bin/bash", str(INSTALLER_GATE)],
                check=False,
                env={"PATH": directory},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 93, result.stderr)

    def test_present_installer_fails_distinctly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "pip"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", str(INSTALLER_GATE)],
                check=False,
                env={"PATH": directory},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 94)
        self.assertIn("runtime installer unexpectedly available: pip", result.stderr)


if __name__ == "__main__":
    unittest.main()
