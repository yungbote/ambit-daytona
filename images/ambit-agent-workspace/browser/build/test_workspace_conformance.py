"""Execute the source-owned Bash roster gate, including producer failures."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class LiveDpkgConformanceTests(unittest.TestCase):
    def run_gate(self, output, status=0, receipt="first=1\nsecond=2\n"):
        source = Path(__file__).parents[2] / "conformance/verify.sh"
        script = source.read_text()
        start = script.index("# A matching source/receipt pair")
        end = script.index("# --- runtime user", start)
        gate = script[start:end]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "installed-dpkg.lock").write_text(receipt)
            query = root / "dpkg-query"
            query.write_text("#!/bin/bash\nprintf '%s' \"$QUERY_OUTPUT\"\nexit \"$QUERY_STATUS\"\n")
            query.chmod(0o755)
            return subprocess.run(
                ["bash", "-c", "set -euo pipefail\nfailures=0\n"
                 "ok() { printf 'ok: %s\\n' \"$*\"; }\n"
                 "fail() { printf 'FAIL: %s\\n' \"$*\"; failures=$((failures + 1)); }\n"
                 + gate + "\n[ \"$failures\" -eq 0 ]\n"],
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                     "LINEAGE": str(root), "QUERY_OUTPUT": output, "QUERY_STATUS": str(status)},
                capture_output=True, text=True, check=False,
            )

    def test_successful_query_is_sorted_and_compared(self):
        result = self.run_gate("second=2\nfirst=1\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok: live dpkg roster equals", result.stdout)

    def test_matching_output_cannot_conceal_an_unsuccessful_query(self):
        result = self.run_gate("first=1\nsecond=2\n", status=42)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: could not read the live dpkg roster", result.stdout)
        self.assertNotIn("ok: live dpkg roster equals", result.stdout)

    def test_successful_query_with_different_packages_fails(self):
        result = self.run_gate("first=1\nsecond=3\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: live dpkg roster drifted", result.stdout)

    def test_query_failure_without_output_fails(self):
        result = self.run_gate("", status=42)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: could not read the live dpkg roster", result.stdout)


if __name__ == "__main__":
    unittest.main()
