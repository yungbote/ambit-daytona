from __future__ import annotations

import shlex
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent


class StructuralWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "ambit-structural-python").read_text(encoding="utf-8")

    def test_uses_only_private_loader_and_library_path(self) -> None:
        self.assertIn(
            '"${runtime_root}/lib/ld-linux-x86-64.so.2"',
            self.source,
        )
        self.assertIn("--inhibit-cache", self.source)
        self.assertIn('--library-path "${runtime_root}/lib"', self.source)
        self.assertNotIn("LD_LIBRARY_PATH=", self.source)
        self.assertNotIn("/lib64/ld-linux", self.source)

    def test_clears_ambient_environment_and_forwards_argv_without_eval(self) -> None:
        self.assertIn("exec env -i", self.source)
        self.assertIn('"$@"', self.source)
        for forbidden in ("eval", "sh -c", "curl", "wget", "pip", "python -m"):
            self.assertNotIn(forbidden, self.source)
        self.assertEqual(shlex.split('"$@"'), ["$@"])


if __name__ == "__main__":
    unittest.main()
