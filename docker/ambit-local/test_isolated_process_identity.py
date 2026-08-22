from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("isolated_process_identity.py")
PYTHON = Path("/usr/bin/python3").resolve(strict=True)
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
        self.wait_for_arguments(self.process, b"30\0")

    @staticmethod
    def wait_for_arguments(process: subprocess.Popen[object], fragment: bytes) -> bytes:
        raw_arguments = b""
        for _ in range(200):
            raw_arguments = Path(f"/proc/{process.pid}/cmdline").read_bytes()
            if fragment in raw_arguments:
                return raw_arguments
            time.sleep(0.001)
        raise AssertionError("child arguments did not become observable")

    def stop_process(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)

    def recorded_identity(self) -> dict[str, object]:
        return MODULE.verify_process(
            self.process.pid,
            self.executable,
            ("30",),
            expected_uid=os.geteuid(),
            expected_parent_pid=os.getpid(),
        )

    def test_exact_process_identity_passes(self) -> None:
        receipt = self.recorded_identity()
        self.assertEqual(receipt["pid"], self.process.pid)
        self.assertEqual(receipt["parentPid"], os.getpid())
        self.assertEqual(receipt["executable"], str(self.executable))
        self.assertGreater(receipt["procInode"], 0)
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

    def test_full_recorded_identity_validator_rejects_malformed_and_extra_fields(self) -> None:
        valid = self.recorded_identity()
        mutations: list[tuple[str, object]] = []

        missing = copy.deepcopy(valid)
        del missing["procInode"]
        mutations.append(("missing field", missing))

        extra = copy.deepcopy(valid)
        extra["ready"] = True
        mutations.append(("extra field", extra))

        field_values = {
            "pid": False,
            "parentPid": 0,
            "procInode": 0,
            "startTimeTicks": -1,
            "executable": "usr/bin/sleep",
            "argumentsSha256": "A" * 64,
        }
        for field, value in field_values.items():
            mutated = copy.deepcopy(valid)
            mutated[field] = value
            mutations.append((field, mutated))

        bad_namespace = copy.deepcopy(valid)
        bad_namespace["mountNamespace"] = {"device": 1, "inode": 2, "extra": 3}
        mutations.append(("mount namespace shape", bad_namespace))

        boolean_namespace = copy.deepcopy(valid)
        boolean_namespace["mountNamespace"] = {"device": False, "inode": 2}
        mutations.append(("mount namespace boolean", boolean_namespace))

        for name, value in mutations:
            with self.subTest(name=name):
                with self.assertRaises(MODULE.ProcessIdentityError):
                    MODULE.validate_recorded_identity(value)

    def test_recorded_identity_json_is_bounded_and_rejects_duplicate_fields(self) -> None:
        valid = self.recorded_identity()
        raw = json.dumps(valid, sort_keys=True, separators=(",", ":"))
        duplicate = raw[:-1] + f',"pid":{self.process.pid}' + "}"
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.parse_recorded_identity_json(duplicate)
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.parse_recorded_identity_json(
                " " * (MODULE.MAX_RECORDED_IDENTITY_JSON_BYTES + 1)
            )
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.parse_recorded_identity_json('{"pid":NaN}')
        with self.assertRaises(MODULE.ProcessIdentityError):
            MODULE.parse_recorded_identity_json("[" * 1100 + "]" * 1100)

    def test_verify_recorded_proves_the_whole_identity(self) -> None:
        recorded = self.recorded_identity()
        self.assertEqual(
            MODULE.verify_recorded_process(recorded, expected_uid=os.geteuid()),
            recorded,
        )

    def test_every_recorded_identity_mismatch_sends_no_signal(self) -> None:
        recorded = self.recorded_identity()
        mutations: list[tuple[str, object]] = [
            ("pid", os.getpid()),
            ("parentPid", recorded["parentPid"] + 1),
            ("procInode", recorded["procInode"] + 1),
            ("startTimeTicks", recorded["startTimeTicks"] + 1),
            ("executable", str(Path("/usr/bin/true").resolve(strict=True))),
            ("argumentsSha256", "0" * 64),
        ]
        namespace = recorded["mountNamespace"]
        assert isinstance(namespace, dict)
        mismatched_namespace = copy.deepcopy(recorded)
        mismatched_namespace["mountNamespace"] = {
            "device": namespace["device"],
            "inode": namespace["inode"] + 1,
        }

        for field, value in mutations:
            mismatched = copy.deepcopy(recorded)
            mismatched[field] = value
            with self.subTest(field=field):
                with mock.patch.object(MODULE.signal, "pidfd_send_signal") as sender:
                    with self.assertRaises(MODULE.ProcessIdentityError):
                        MODULE.signal_recorded_process(
                            mismatched,
                            expected_uid=os.geteuid(),
                            exit_timeout_seconds=0.1,
                        )
                    sender.assert_not_called()
                self.assertIsNone(self.process.poll())

        with self.subTest(field="mountNamespace"):
            with mock.patch.object(MODULE.signal, "pidfd_send_signal") as sender:
                with self.assertRaises(MODULE.ProcessIdentityError):
                    MODULE.signal_recorded_process(
                        mismatched_namespace,
                        expected_uid=os.geteuid(),
                        exit_timeout_seconds=0.1,
                    )
                sender.assert_not_called()
            self.assertIsNone(self.process.poll())

    def test_pid_reuse_after_pidfd_open_is_modeled_as_no_signal(self) -> None:
        recorded = self.recorded_identity()
        replacement = copy.deepcopy(recorded)
        replacement["procInode"] = recorded["procInode"] + 1
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, write_fd)
        with (
            mock.patch.object(MODULE.os, "pidfd_open", return_value=read_fd) as pidfd_open,
            mock.patch.object(MODULE, "verify_process", return_value=replacement),
            mock.patch.object(MODULE.signal, "pidfd_send_signal") as sender,
        ):
            with self.assertRaisesRegex(MODULE.ProcessIdentityError, "procInode differs"):
                MODULE.signal_recorded_process(
                    recorded,
                    expected_uid=os.geteuid(),
                    exit_timeout_seconds=0.1,
                )
        pidfd_open.assert_called_once_with(self.process.pid, 0)
        sender.assert_not_called()
        self.assertIsNone(self.process.poll())

    def test_parent_mismatch_requires_explicit_recovery_relaxation(self) -> None:
        recorded = self.recorded_identity()
        recorded["parentPid"] = recorded["parentPid"] + 1
        with mock.patch.object(MODULE.signal, "pidfd_send_signal") as sender:
            with self.assertRaisesRegex(MODULE.ProcessIdentityError, "parent differs"):
                MODULE.signal_recorded_process(
                    recorded,
                    expected_uid=os.geteuid(),
                    exit_timeout_seconds=0.1,
                )
            sender.assert_not_called()
        self.assertIsNone(self.process.poll())

        non_parent_mismatch = copy.deepcopy(recorded)
        non_parent_mismatch["startTimeTicks"] = recorded["startTimeTicks"] + 1
        with mock.patch.object(MODULE.signal, "pidfd_send_signal") as sender:
            with self.assertRaisesRegex(MODULE.ProcessIdentityError, "startTimeTicks differs"):
                MODULE.signal_recorded_process(
                    non_parent_mismatch,
                    expected_uid=os.geteuid(),
                    relax_parent_for_recovery=True,
                    exit_timeout_seconds=0.1,
                )
            sender.assert_not_called()
        self.assertIsNone(self.process.poll())

        observed = MODULE.signal_recorded_process(
            recorded,
            expected_uid=os.geteuid(),
            relax_parent_for_recovery=True,
            exit_timeout_seconds=2,
        )
        self.assertEqual(observed["parentPid"], os.getpid())
        self.assertEqual(self.process.wait(timeout=5), -signal.SIGTERM)

    def test_exact_real_subprocess_is_signaled_and_waited_through_pidfd(self) -> None:
        recorded = self.recorded_identity()
        observed = MODULE.signal_recorded_process(
            recorded,
            expected_uid=os.geteuid(),
            exit_timeout_seconds=2,
        )
        self.assertEqual(observed, recorded)
        self.assertEqual(self.process.wait(timeout=5), -signal.SIGTERM)

    def test_pidfd_exit_wait_is_bounded(self) -> None:
        source = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('ready',flush=True);time.sleep(30)"
        child = subprocess.Popen(
            [str(PYTHON), "-c", source],
            stdout=subprocess.PIPE,
            text=True,
        )

        def cleanup() -> None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
            if child.stdout is not None:
                child.stdout.close()

        self.addCleanup(cleanup)
        assert child.stdout is not None
        self.assertEqual(child.stdout.readline().strip(), "ready")
        recorded = MODULE.verify_process(
            child.pid,
            PYTHON,
            ("-c", source),
            expected_uid=os.geteuid(),
            expected_parent_pid=os.getpid(),
        )
        started = time.monotonic()
        with self.assertRaisesRegex(MODULE.ProcessIdentityError, "bounded deadline"):
            MODULE.signal_recorded_process(
                recorded,
                expected_uid=os.geteuid(),
                exit_timeout_seconds=0.05,
            )
        self.assertLess(time.monotonic() - started, 1)
        self.assertIsNone(child.poll())

    def test_invalid_exit_wait_is_rejected_before_any_signal(self) -> None:
        recorded = self.recorded_identity()
        for timeout in (0, -1, True, float("inf"), MODULE.MAX_EXIT_WAIT_SECONDS + 1):
            with self.subTest(timeout=timeout):
                with mock.patch.object(MODULE.signal, "pidfd_send_signal") as sender:
                    with self.assertRaises(MODULE.ProcessIdentityError):
                        MODULE.signal_recorded_process(
                            recorded,
                            expected_uid=os.geteuid(),
                            exit_timeout_seconds=timeout,
                        )
                    sender.assert_not_called()
                self.assertIsNone(self.process.poll())

    def test_cli_verifies_and_signals_only_a_full_recorded_identity(self) -> None:
        recorded = self.recorded_identity()
        raw = json.dumps(recorded, sort_keys=True, separators=(",", ":"))
        verified = subprocess.check_output(
            [str(PYTHON), str(SCRIPT), "verify-recorded", str(os.geteuid()), raw],
            text=True,
        )
        self.assertEqual(json.loads(verified), recorded)

        signaled = subprocess.check_output(
            [
                str(PYTHON),
                str(SCRIPT),
                "signal-recorded",
                str(os.geteuid()),
                raw,
                "--timeout-ms",
                "2000",
            ],
            text=True,
        )
        self.assertEqual(json.loads(signaled), recorded)
        self.assertEqual(self.process.wait(timeout=5), -signal.SIGTERM)

    def test_old_partial_and_parent_blind_cli_invocations_are_rejected(self) -> None:
        raw_arguments = Path(f"/proc/{self.process.pid}/cmdline").read_bytes()
        old_invocations = (
            [str(self.process.pid), str(self.executable), "/tmp/dockerd.json"],
            [
                "verify-digest",
                str(self.process.pid),
                str(self.executable),
                str(os.geteuid()),
                hashlib.sha256(raw_arguments).hexdigest(),
            ],
        )
        for invocation in old_invocations:
            with self.subTest(invocation=invocation[0]):
                result = subprocess.run(
                    [str(PYTHON), str(SCRIPT), *invocation],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

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

    def test_exited_pid_is_rejected(self) -> None:
        self.stop_process()
        with self.assertRaises((FileNotFoundError, ProcessLookupError)):
            MODULE.verify_recorded_process(
                {
                    "pid": self.process.pid,
                    "parentPid": os.getpid(),
                    "procInode": 1,
                    "startTimeTicks": 1,
                    "executable": str(self.executable),
                    "argumentsSha256": "0" * 64,
                    "mountNamespace": {"device": 0, "inode": 1},
                },
                expected_uid=os.geteuid(),
            )


if __name__ == "__main__":
    unittest.main()
