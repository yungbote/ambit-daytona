from __future__ import annotations

import importlib.util
import hashlib
import json
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
        self.assertEqual(receipt["parentPid"], os.getpid())
        self.assertEqual(receipt["executable"], str(self.executable))
        self.assertGreater(receipt["startTimeTicks"], 0)
        own_namespace = os.stat("/proc/self/ns/mnt")
        self.assertEqual(
            receipt["mountNamespace"],
            {"device": own_namespace.st_dev, "inode": own_namespace.st_ino},
        )

    def test_digest_parent_and_namespace_authorities_pass_together(self) -> None:
        raw_arguments = Path(f"/proc/{self.process.pid}/cmdline").read_bytes()
        namespace = os.stat("/proc/self/ns/mnt")
        receipt = MODULE.verify_process(
            self.process.pid,
            self.executable,
            None,
            expected_uid=os.geteuid(),
            expected_arguments_sha256=hashlib.sha256(raw_arguments).hexdigest(),
            expected_parent_pid=os.getpid(),
            expected_mount_namespace={
                "device": namespace.st_dev,
                "inode": namespace.st_ino,
            },
        )
        self.assertEqual(receipt["argumentsSha256"], hashlib.sha256(raw_arguments).hexdigest())

    def test_digest_parent_and_namespace_substitutions_are_rejected(self) -> None:
        raw_arguments = Path(f"/proc/{self.process.pid}/cmdline").read_bytes()
        digest = hashlib.sha256(raw_arguments).hexdigest()
        namespace = os.stat("/proc/self/ns/mnt")
        mutations = (
            {"expected_arguments_sha256": "0" * 64},
            {"expected_parent_pid": os.getpid() + 1},
            {
                "expected_mount_namespace": {
                    "device": namespace.st_dev,
                    "inode": namespace.st_ino + 1,
                }
            },
        )
        base = {
            "expected_arguments_sha256": digest,
            "expected_parent_pid": os.getpid(),
            "expected_mount_namespace": {
                "device": namespace.st_dev,
                "inode": namespace.st_ino,
            },
        }
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(MODULE.ProcessIdentityError):
                    MODULE.verify_process(
                        self.process.pid,
                        self.executable,
                        None,
                        expected_uid=os.geteuid(),
                        **{**base, **mutation},
                    )

    def test_cli_digest_mode_emits_the_same_closed_identity(self) -> None:
        raw_arguments = Path(f"/proc/{self.process.pid}/cmdline").read_bytes()
        namespace = os.stat("/proc/self/ns/mnt")
        output = subprocess.check_output(
            [
                str(Path("/usr/bin/python3")),
                str(SCRIPT),
                "verify-digest",
                str(self.process.pid),
                str(self.executable),
                str(os.geteuid()),
                hashlib.sha256(raw_arguments).hexdigest(),
                "--parent-pid",
                str(os.getpid()),
                "--mount-namespace",
                json.dumps(
                    {"device": namespace.st_dev, "inode": namespace.st_ino},
                    separators=(",", ":"),
                ),
            ],
            text=True,
        )
        receipt = json.loads(output)
        self.assertEqual(receipt["parentPid"], os.getpid())
        self.assertEqual(receipt["mountNamespace"]["inode"], namespace.st_ino)

    def test_argument_and_executable_substitution_are_rejected(self) -> None:
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.verify_process(
                self.process.pid,
                self.executable,
                ("31",),
                expected_uid=os.geteuid(),
            )

    def test_missing_or_competing_argument_authorities_are_rejected(self) -> None:
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.verify_process(
                self.process.pid,
                self.executable,
                None,
                expected_uid=os.geteuid(),
            )
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.verify_process(
                self.process.pid,
                self.executable,
                ("30",),
                expected_uid=os.geteuid(),
                expected_arguments_sha256="0" * 64,
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
