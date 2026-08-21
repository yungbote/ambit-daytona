from __future__ import annotations

import fcntl
import importlib.util
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("runner-storage-lifecycle.py")
SPEC = importlib.util.spec_from_file_location("ambit_runner_storage_lifecycle", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("could not load runner-storage-lifecycle.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def temporary_parent() -> str | None:
    candidate = Path(f"/run/user/{os.getuid()}")
    return str(candidate) if candidate.is_dir() and os.access(candidate, os.W_OK) else None


def image_facts(size: int):
    return MODULE.NodeFacts(
        kind="regular",
        owner_uid=0,
        owner_gid=0,
        mode=0o600,
        device=47,
        inode=73,
        size=size,
    )


class RunnerStorageLifecycleTest(unittest.TestCase):
    def test_authority_coordinate_is_root_owned_and_state_root_independent(self) -> None:
        self.assertEqual(
            MODULE.AUTHORITY_ROOT,
            Path("/home/.ambit-c16b-runner-storage"),
        )
        self.assertEqual(
            MODULE.AUTHORITY_ROOT / MODULE.TARGET_NAME,
            Path("/home/.ambit-c16b-runner-storage/runner-docker"),
        )
        helper = SCRIPT.read_text()
        self.assertNotIn('state_root / "capacity"', helper)
        self.assertNotIn('state_root / "runner-docker"', helper)

    def test_image_cutpoints_are_total_and_only_exact_size_can_recover(self) -> None:
        for size in (0, 1, MODULE.IMAGE_BYTES - 1):
            with self.subTest(size=size):
                state = MODULE.classify_image(image_facts(size), authority_device=47)
                self.assertEqual(state, "root_0600_incomplete_prepublication")
                self.assertEqual(MODULE.prepare_disposition(state, False), "teardown_required")
                self.assertEqual(MODULE.remove_disposition(state, False), "remove_image_authority")
        exact = MODULE.classify_image(
            image_facts(MODULE.IMAGE_BYTES), authority_device=47
        )
        self.assertEqual(exact, "root_0600_exact")
        self.assertEqual(MODULE.prepare_disposition(exact, True), "recover")
        for size in (-1, MODULE.IMAGE_BYTES + 1):
            with self.subTest(invalid_size=size):
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.classify_image(image_facts(size), authority_device=47)

    def test_old_or_incomplete_receipt_is_never_reinterpreted(self) -> None:
        with self.assertRaises(MODULE.RunnerStorageLifecycleError):
            MODULE.remove_disposition(
                "root_0600_incomplete_prepublication",
                True,
            )
        context = mock.Mock()
        context.root_fd = 3
        context.image_fd = 4
        with self.assertRaisesRegex(
            MODULE.RunnerStorageLifecycleError,
            "version is unsupported",
        ):
            MODULE.validate_receipt(
                {"schema": "ambit.local-daytona-runner-storage/v1"},
                context,
                Path("/home/example/state"),
            )

    def test_secure_umask_precedes_create_cutpoints(self) -> None:
        old = os.umask(0o777)
        try:
            MODULE.configure_secure_umask()
            with tempfile.TemporaryDirectory(
                prefix="runner-umask-", dir=temporary_parent()
            ) as directory:
                root = Path(directory)
                child = root / "authority"
                child.mkdir(mode=0o700)
                image = child / "image"
                descriptor = os.open(
                    image,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                os.close(descriptor)
                self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
        finally:
            os.umask(old)
        helper = SCRIPT.read_text()
        self.assertLess(
            helper.index("configure_secure_umask()", helper.index("def main")),
            helper.index("parser().parse_args()", helper.index("def main")),
        )

    def test_mutating_child_inherits_exact_lifecycle_lock_fd(self) -> None:
        context = mock.Mock()
        context.exclusive = True
        context.lock_fd = 11
        self.assertEqual(MODULE.mutation_pass_fds(context, (7, 11)), (7, 11))
        context.exclusive = False
        with self.assertRaises(MODULE.RunnerStorageLifecycleError):
            MODULE.mutation_pass_fds(context, ())
        helper = SCRIPT.read_text()
        self.assertIn("MUTATION_GUARDIAN", helper)
        self.assertIn("os.fstat(lock_fd)", MODULE.MUTATION_GUARDIAN)
        self.assertIn("child.communicate()", MODULE.MUTATION_GUARDIAN)

    def test_killed_guardian_keeps_lock_until_mutating_child_exits(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-lock-", dir=temporary_parent()
        ) as directory:
            lock_path = Path(directory) / "lock"
            lock_path.touch(mode=0o600)
            program = """
import fcntl, os, subprocess, sys, time
fd = os.open(sys.argv[1], os.O_RDWR)
fcntl.flock(fd, fcntl.LOCK_EX)
child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
    pass_fds=(fd,),
)
print(child.pid, flush=True)
time.sleep(30)
"""
            guardian = subprocess.Popen(
                [sys.executable, "-c", program, str(lock_path)],
                stdout=subprocess.PIPE,
                text=True,
            )
            assert guardian.stdout is not None
            child_pid = int(guardian.stdout.readline().strip())
            guardian.stdout.close()
            os.kill(guardian.pid, signal.SIGKILL)
            guardian.wait(timeout=5)
            contender = os.open(lock_path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.kill(child_pid, signal.SIGKILL)
                for _ in range(100):
                    try:
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(0.01)
                else:
                    self.fail("lock remained after mutating child exited")
            finally:
                os.close(contender)

    def test_private_propagation_is_a_precondition(self) -> None:
        private = MODULE.MountRecord("8:1", "/home", ())
        MODULE.require_private_mount_record(private)
        for optional in (("shared:1",), ("master:1",), ("propagate_from:2",)):
            with self.subTest(optional=optional):
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.require_private_mount_record(
                        MODULE.MountRecord("8:1", "/home", optional)
                    )

    def test_namespace_and_occurrence_churn_fail_closed(self) -> None:
        first = MODULE.NamespaceObservation("1:1", 1, ())
        second = MODULE.NamespaceObservation("2:2", 2, ())
        with mock.patch.object(
            MODULE,
            "read_namespace_roster_once",
            side_effect=((first,), (first, second)),
        ):
            with self.assertRaisesRegex(
                MODULE.RunnerStorageLifecycleError,
                "namespace roster changed",
            ):
                MODULE.stable_namespace_pair()
        mounted = MODULE.NamespaceObservation(
            "1:1",
            1,
            (MODULE.MountRecord("7:7", str(MODULE.AUTHORITY_ROOT / "runner-docker"), ()),),
        )
        with mock.patch.object(
            MODULE,
            "read_namespace_roster_once",
            side_effect=((mounted,), (first,)),
        ):
            with self.assertRaisesRegex(
                MODULE.RunnerStorageLifecycleError,
                "occurrence roster changed",
            ):
                MODULE.target_occurrences()

    def test_foreign_target_blocks_image_absent_remove(self) -> None:
        foreign = MODULE.NamespaceOccurrence(
            namespace_id="2:2",
            representative_pid=22,
            device_number="8:1",
            target=str(MODULE.AUTHORITY_ROOT / MODULE.TARGET_NAME),
        )
        context = mock.MagicMock()
        context.__enter__.return_value = context
        context.__exit__.return_value = None
        context.root_fd = 10
        with mock.patch.object(MODULE, "open_authority", return_value=context), mock.patch.object(
            MODULE, "target_occurrences", return_value=(foreign,)
        ):
            with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                MODULE.remove_authority(
                    argparse_namespace(
                        state_root=Path("/home/example/state"),
                        caller_uid=1000,
                        caller_gid=1000,
                    )
                )

    def test_receipt_atomic_write_fsyncs_file_before_rename_and_parent(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-receipt-", dir=temporary_parent()
        ) as directory:
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            events: list[str] = []
            real_fsync = os.fsync
            real_replace = os.replace

            def observed_fsync(descriptor: int) -> None:
                events.append("parent-fsync" if descriptor == directory_fd else "file-fsync")
                real_fsync(descriptor)

            def observed_replace(*args: object, **kwargs: object) -> None:
                events.append("rename")
                real_replace(*args, **kwargs)

            try:
                with mock.patch.object(MODULE.os, "fsync", side_effect=observed_fsync), mock.patch.object(
                    MODULE.os, "replace", side_effect=observed_replace
                ):
                    MODULE.write_bytes_atomic(
                        directory_fd,
                        "receipt.json",
                        b"{}\n",
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(events, ["file-fsync", "rename", "parent-fsync"])
            finally:
                os.close(directory_fd)


def argparse_namespace(**values: object):
    class Namespace:
        pass

    result = Namespace()
    for key, value in values.items():
        setattr(result, key, value)
    return result


if __name__ == "__main__":
    unittest.main()
