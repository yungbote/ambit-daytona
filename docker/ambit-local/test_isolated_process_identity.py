from __future__ import annotations

import importlib.util
import os
import subprocess
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("isolated_process_identity.py")
SPEC = importlib.util.spec_from_file_location("ambit_isolated_process_identity", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("could not load isolated process identity module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IsolatedProcessIdentityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.executable = Path("/usr/bin/sleep").resolve(strict=True)
        self.process = subprocess.Popen([str(self.executable), "30"])
        self.addCleanup(self.stop_process)
        for _ in range(100):
            cmdline = Path(f"/proc/{self.process.pid}/cmdline")
            if cmdline.exists() and cmdline.read_bytes().startswith(str(self.executable).encode()):
                break
            time.sleep(0.001)

    def stop_process(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)

    def test_exact_process_identity_passes(self) -> None:
        receipt = MODULE.verify_process(
            self.process.pid,
            self.executable,
            ("30",),
            expected_uid=os.geteuid(),
        )
        self.assertEqual(receipt["pid"], self.process.pid)
        self.assertEqual(receipt["executable"], str(self.executable))
        self.assertGreater(receipt["startTimeTicks"], 0)

    def test_argument_and_executable_substitution_are_rejected(self) -> None:
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.verify_process(
                self.process.pid,
                self.executable,
                ("31",),
                expected_uid=os.geteuid(),
            )
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.verify_process(
                self.process.pid,
                Path("/usr/bin/true"),
                ("30",),
                expected_uid=os.geteuid(),
            )

    def test_exited_pid_is_rejected(self) -> None:
        self.stop_process()
        with self.assertRaises((FileNotFoundError, ProcessLookupError)):
            MODULE.verify_process(
                self.process.pid,
                self.executable,
                ("30",),
                expected_uid=os.geteuid(),
            )


if __name__ == "__main__":
    unittest.main()
