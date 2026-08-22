from __future__ import annotations

import fcntl
import importlib.util
import copy
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("runner-storage-lifecycle.py")
REMOVE_SCRIPT = Path(__file__).with_name("remove-runner-storage.sh")
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
        link_count=1,
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

    def test_claim_preimage_is_canonical_domain_separated_and_identity_total(self) -> None:
        state = MODULE.DirectoryIdentity(
            Path("/home/example/ambit/state"), 47, 61, 1000, 100, 0o700
        )
        evidence = MODULE.DirectoryIdentity(
            state.path / "evidence", 47, 62, 1000, 100, 0o700
        )
        baseline = MODULE.claim_name_for_identity(state, evidence, 1000, 100)
        self.assertRegex(
            baseline,
            rf"^{MODULE.CLAIM_PREFIX}[0-9a-f]{{64}}$",
        )
        document = MODULE.claim_binding_document(state, evidence, 1000, 100)
        self.assertEqual(document["domain"], MODULE.CLAIM_DOMAIN)
        state_changes = {
            "path": Path("/home/example/ambit/other"),
            "device": 48,
            "inode": 63,
            "owner_uid": 1001,
            "owner_gid": 101,
            "mode": 0o750,
        }
        evidence_changes = {
            "path": state.path / "other-evidence",
            "device": 48,
            "inode": 64,
            "owner_uid": 1001,
            "owner_gid": 101,
            "mode": 0o750,
        }
        candidates = [
            MODULE.claim_name_for_identity(replace(state, **{field: value}), evidence, 1000, 100)
            for field, value in state_changes.items()
        ]
        candidates.extend(
            MODULE.claim_name_for_identity(state, replace(evidence, **{field: value}), 1000, 100)
            for field, value in evidence_changes.items()
        )
        candidates.extend(
            (
                MODULE.claim_name_for_identity(state, evidence, 1001, 100),
                MODULE.claim_name_for_identity(state, evidence, 1000, 101),
            )
        )
        self.assertEqual(len(candidates), len(set(candidates)))
        self.assertNotIn(baseline, candidates)

    def test_lifecycle_prefix_classifier_covers_crash_and_legacy_cutpoints(self) -> None:
        expected = f"{MODULE.CLAIM_PREFIX}{'a' * 64}"
        authority = MODULE.NodeFacts("directory", 0, 0, 0o700, 47, 71, 0)
        claim = MODULE.NodeFacts("regular", 0, 0, 0o600, 47, 72, 0, 1)
        cases = (
            (MODULE.absent_node(), MODULE.absent_node(), (), False, True, "absent_unclaimed"),
            (MODULE.absent_node(), claim, (expected,), False, True, "claim_only"),
            (authority, claim, (expected,), False, False, "claimed_authority"),
            (authority, MODULE.absent_node(), (), True, True, "legacy_empty_authority"),
        )
        for authority_facts, claim_facts, roster, allow_legacy, empty, outcome in cases:
            with self.subTest(outcome=outcome):
                self.assertEqual(
                    MODULE.classify_lifecycle_prefix(
                        authority_facts,
                        claim_facts,
                        roster,
                        expected,
                        home_device=47,
                        allow_legacy_empty=allow_legacy,
                        authority_empty=empty,
                    ),
                    outcome,
                )
        rejected = [
            (authority, MODULE.absent_node(), (), False, True),
            (authority, MODULE.absent_node(), (), True, False),
            (authority, claim, (f"{MODULE.CLAIM_PREFIX}{'b' * 64}",), False, False),
            (authority, claim, (expected, f"{MODULE.CLAIM_PREFIX}{'b' * 64}"), False, False),
        ]
        rejected.extend(
            (replace(authority, **{field: value}), claim, (expected,), False, False)
            for field, value in {
                "kind": "regular",
                "owner_uid": 1000,
                "owner_gid": 100,
                "mode": 0o755,
                "device": 48,
                "inode": 0,
            }.items()
        )
        rejected.extend(
            (authority, replace(claim, **{field: value}), (expected,), False, False)
            for field, value in {
                "kind": "symlink",
                "owner_uid": 1000,
                "owner_gid": 100,
                "mode": 0o644,
                "device": 48,
                "inode": 0,
                "size": 1,
                "link_count": 2,
            }.items()
        )
        for index, (authority_facts, claim_facts, roster, allow_legacy, empty) in enumerate(rejected):
            with self.subTest(rejected=index), self.assertRaises(
                MODULE.RunnerStorageLifecycleError
            ):
                MODULE.classify_lifecycle_prefix(
                    authority_facts,
                    claim_facts,
                    roster,
                    expected,
                    home_device=47,
                    allow_legacy_empty=allow_legacy,
                    authority_empty=empty,
                )

    def test_claim_is_durable_before_authority_and_removed_last(self) -> None:
        helper = SCRIPT.read_text()
        opening = helper[helper.index("def open_authority("):helper.index("def require_trusted_parent_chain")]
        self.assertLess(
            opening.index("open_caller_directories("),
            opening.index("trusted_tool(tool_name)"),
        )
        self.assertLess(
            opening.index("trusted_tool(tool_name)"),
            opening.index("os.open(HOME_ROOT"),
        )
        self.assertLess(opening.index("create_claim(home_fd"), opening.index("os.mkdir(AUTHORITY_NAME"))
        claim_creation = helper[helper.index("def create_claim"):helper.index("@dataclass\nclass AuthorityContext")]
        self.assertLess(claim_creation.index("os.fsync(descriptor)"), claim_creation.index("os.fsync(home_fd)"))
        removal = helper[helper.index("def remove_authority"):helper.index("def parser")]
        self.assertLess(removal.rindex("os.rmdir(AUTHORITY_NAME"), removal.rindex("os.unlink(context.claim_name"))
        self.assertNotIn("lifecycle.lock", helper)

    def test_absolute_directory_walk_rejects_parent_and_leaf_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-directory-walk-", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            real_parent = root / "real"
            real_parent.mkdir()
            leaf = real_parent / "leaf"
            leaf.mkdir()
            descriptor = MODULE.open_absolute_directory_no_symlinks(leaf)
            try:
                self.assertEqual(
                    (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
                    (leaf.stat().st_dev, leaf.stat().st_ino),
                )
            finally:
                os.close(descriptor)
            parent_link = root / "parent-link"
            parent_link.symlink_to(real_parent, target_is_directory=True)
            leaf_link = real_parent / "leaf-link"
            leaf_link.symlink_to(leaf, target_is_directory=True)
            for candidate in (parent_link / "leaf", leaf_link):
                with self.subTest(candidate=candidate), self.assertRaises(OSError):
                    MODULE.open_absolute_directory_no_symlinks(candidate)

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
        with self.assertRaisesRegex(
            MODULE.RunnerStorageLifecycleError,
            "link count differs",
        ):
            MODULE.classify_image(
                replace(image_facts(MODULE.IMAGE_BYTES), link_count=2),
                authority_device=47,
            )

    def test_old_or_incomplete_receipt_is_never_reinterpreted(self) -> None:
        with self.assertRaises(MODULE.RunnerStorageLifecycleError):
            MODULE.remove_disposition(
                "root_0600_incomplete_prepublication",
                True,
            )
        context = mock.Mock()
        context.root_fd = 3
        context.image_fd = 4
        for version in ("v1", "v2"):
            with self.subTest(version=version), self.assertRaisesRegex(
                MODULE.RunnerStorageLifecycleError,
                "version is unsupported",
            ):
                MODULE.validate_receipt(
                    {"schema": f"ambit.local-daytona-runner-storage/{version}"},
                    context,
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
        context.home_fd = 11
        self.assertEqual(MODULE.mutation_pass_fds(context, (7, 11)), (7, 11))
        context.exclusive = False
        with self.assertRaises(MODULE.RunnerStorageLifecycleError):
            MODULE.mutation_pass_fds(context, ())
        helper = SCRIPT.read_text()
        self.assertIn("MUTATION_GUARDIAN", helper)
        self.assertIn("os.fstat(lock_fd)", MODULE.MUTATION_GUARDIAN)
        self.assertIn("tool_fds = tuple(sorted(set(inherited) | {lock_fd}))", MODULE.MUTATION_GUARDIAN)
        self.assertIn("deadline = time.monotonic() + timeout", MODULE.MUTATION_GUARDIAN)
        self.assertIn("os.killpg(child.pid, signal.SIGKILL)", MODULE.MUTATION_GUARDIAN)

    def test_killed_guardian_keeps_lock_until_mutating_child_exits(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-lock-", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            pid_path = root / "tool.pid"
            lock_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            tool = (
                "import os,pathlib,sys,time; "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
                "time.sleep(30)"
            )
            guardian = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    MODULE.MUTATION_GUARDIAN,
                    str(lock_fd),
                    str(lock_fd),
                    "30",
                    "1",
                    sys.executable,
                    "-c",
                    tool,
                    str(pid_path),
                ],
                pass_fds=(lock_fd,),
            )
            for _ in range(200):
                if pid_path.exists():
                    break
                time.sleep(0.01)
            else:
                guardian.kill()
                guardian.wait(timeout=5)
                os.close(lock_fd)
                self.fail("production guardian did not start its mutating tool")
            child_pid = int(pid_path.read_text())
            os.kill(guardian.pid, signal.SIGKILL)
            guardian.wait(timeout=5)
            os.close(lock_fd)
            contender = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
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

    def test_lifecycle_lock_contention_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-lock-timeout-", dir=temporary_parent()
        ) as directory:
            holder = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            contender = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(holder, fcntl.LOCK_EX)
                started = time.monotonic()
                with mock.patch.object(MODULE, "LIFECYCLE_LOCK_TIMEOUT_SECONDS", 0.03):
                    with self.assertRaisesRegex(
                        MODULE.RunnerStorageLifecycleError,
                        "lock timed out",
                    ):
                        MODULE.acquire_lifecycle_lock(contender, exclusive=True)
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                os.close(contender)
                os.close(holder)

    def test_mutation_guardian_times_out_terminates_and_reaps_tool_group(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-guardian-timeout-", dir=temporary_parent()
        ) as directory:
            lock_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            started = time.monotonic()
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        MODULE.MUTATION_GUARDIAN,
                        str(lock_fd),
                        str(lock_fd),
                        "0.05",
                        "0.05",
                        sys.executable,
                        "-c",
                        "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
                    ],
                    pass_fds=(lock_fd,),
                    capture_output=True,
                    timeout=2,
                )
            finally:
                os.close(lock_fd)
            self.assertEqual(completed.returncode, 124)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_trusted_python_literal_symlink_resolves_to_root_controlled_executable(self) -> None:
        self.assertEqual(
            MODULE.trusted_tool("python"),
            str(Path("/usr/bin/python3").resolve(strict=True)),
        )
        literal = os.stat("/usr/bin/python3", follow_symlinks=False)
        self.assertTrue(stat.S_ISLNK(literal.st_mode) or stat.S_ISREG(literal.st_mode))
        resolved = Path("/usr/bin/python3").resolve(strict=True)
        self.assertTrue(stat.S_ISREG(os.stat(resolved, follow_symlinks=False).st_mode))

    def test_requester_environment_must_exactly_match_cli_identity(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SUDO_UID": "1000", "SUDO_GID": "100"},
            clear=True,
        ):
            MODULE.require_requester_environment(1000, 100)
            for uid, gid in ((1001, 100), (1000, 101)):
                with self.subTest(uid=uid, gid=gid), self.assertRaises(
                    MODULE.RunnerStorageLifecycleError
                ):
                    MODULE.require_requester_environment(uid, gid)

    def test_remove_wrapper_uses_absolute_tools_and_sanitized_requester_environment(self) -> None:
        source = REMOVE_SCRIPT.read_text()
        for executable in (
            "/usr/bin/dirname",
            "/usr/bin/id",
            "/usr/bin/pwd",
            "/usr/bin/python3",
            "/usr/bin/realpath",
            "/usr/bin/stat",
            "/usr/bin/sudo",
        ):
            with self.subTest(executable=executable):
                self.assertIn(executable, source)
        self.assertIn('authenticated_requester("SUDO_UID", expected_uid)', source)
        self.assertIn('authenticated_requester("SUDO_GID", expected_gid)', source)
        self.assertIn("os.environ.clear()", source)
        self.assertIn('"HOME": "/root"', source)
        self.assertIn('"PATH": "/usr/bin:/bin"', source)

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
            MODULE, "require_context_binding"
        ), mock.patch.object(
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

    def test_deactivate_is_idempotent_after_committed_detach_output_loss(self) -> None:
        args = argparse_namespace(
            state_root=Path("/home/example/state"),
            caller_uid=1000,
            caller_gid=1000,
            namespace_device=4,
            namespace_inode=4026533000,
        )
        context = mock.MagicMock()
        context.__enter__.return_value = context
        context.__exit__.return_value = None
        context.root_fd = 10
        context.image_fd = 11
        stored = {
            "schema": MODULE.RECEIPT_SCHEMA,
            "lifecycleState": "detached",
            "filesystem": {"uuid": "12345678-1234-1234-1234-123456789abc"},
        }
        with mock.patch.object(
            MODULE, "require_private_namespace", return_value="4:4026533000"
        ), mock.patch.object(
            MODULE, "require_context_binding"
        ), mock.patch.object(
            MODULE, "open_authority", return_value=context
        ), mock.patch.object(
            MODULE, "read_json_at", return_value=stored
        ), mock.patch.object(
            MODULE, "validate_receipt", return_value=stored["filesystem"]["uuid"]
        ), mock.patch.object(
            MODULE, "associated_loops", return_value=()
        ), mock.patch.object(
            MODULE, "target_occurrences", return_value=()
        ), mock.patch.object(
            MODULE,
            "publish_receipt",
            return_value=("1" * 64, {}),
        ) as publish, mock.patch.object(MODULE, "unmount_and_detach") as teardown:
            result = MODULE.deactivate_private(args)
        self.assertEqual(result["outcome"], "deactivated")
        publish.assert_called_once()
        teardown.assert_not_called()

        foreign = MODULE.NamespaceOccurrence("8:8", 8, "7:7", str(MODULE.AUTHORITY_ROOT / MODULE.TARGET_NAME))
        with mock.patch.object(
            MODULE, "require_private_namespace", return_value="4:4026533000"
        ), mock.patch.object(
            MODULE, "require_context_binding"
        ), mock.patch.object(
            MODULE, "open_authority", return_value=context
        ), mock.patch.object(
            MODULE, "read_json_at", return_value=stored
        ), mock.patch.object(
            MODULE, "validate_receipt", return_value=stored["filesystem"]["uuid"]
        ), mock.patch.object(
            MODULE, "associated_loops", return_value=()
        ), mock.patch.object(
            MODULE, "target_occurrences", return_value=(foreign,)
        ):
            with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                MODULE.deactivate_private(args)

    def test_deactivate_releases_unpublished_startup_prefix_without_receipt(self) -> None:
        args = argparse_namespace(
            state_root=Path("/home/example/state"),
            caller_uid=1000,
            caller_gid=1000,
            namespace_device=4,
            namespace_inode=4026533000,
        )
        context = mock.MagicMock()
        context.__enter__.return_value = context
        context.__exit__.return_value = None
        context.root_fd = 10
        context.image_fd = 11
        with mock.patch.object(
            MODULE, "require_private_namespace", return_value="4:4026533000"
        ), mock.patch.object(
            MODULE, "require_context_binding"
        ), mock.patch.object(
            MODULE, "open_authority", return_value=context
        ), mock.patch.object(
            MODULE, "read_json_at", return_value=None
        ), mock.patch.object(
            MODULE, "associated_loops", return_value=("/dev/loop7",)
        ), mock.patch.object(MODULE, "unmount_and_detach") as teardown:
            result = MODULE.deactivate_private(args)
        self.assertEqual(result["outcome"], "deactivated")
        self.assertIsNone(result["authorityReceiptSha256"])
        self.assertIsNone(result["receipt"])
        teardown.assert_called_once_with(context, "/dev/loop7", "4:4026533000")

    def test_deactivate_treats_precreation_authority_absence_as_exact_noop(self) -> None:
        args = argparse_namespace(
            state_root=Path("/home/example/state"),
            caller_uid=1000,
            caller_gid=1000,
            namespace_device=4,
            namespace_inode=4026533000,
        )
        context = mock.MagicMock()
        context.__enter__.return_value = context
        context.__exit__.return_value = None
        context.root_fd = None
        with mock.patch.object(
            MODULE, "require_private_namespace", return_value="4:4026533000"
        ), mock.patch.object(
            MODULE, "require_context_binding"
        ), mock.patch.object(
            MODULE,
            "open_authority",
            return_value=context,
        ), mock.patch.object(MODULE, "path_occurrences", return_value=()):
            result = MODULE.deactivate_private(args)
        self.assertEqual(result["outcome"], "deactivated")
        self.assertIsNone(result["receipt"])
        self.assertIsNone(result["authorityReceiptSha256"])

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
                        MODULE.RECEIPT_NAME,
                        b"{}\n",
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(events, ["file-fsync", "rename", "parent-fsync"])
            finally:
                os.close(directory_fd)

    def test_receipt_writer_only_admits_fixed_pending_names(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-fixed-pending-", dir=temporary_parent()
        ) as directory:
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    MODULE.RunnerStorageLifecycleError,
                    "destination is not admitted",
                ):
                    MODULE.write_bytes_atomic(
                        directory_fd,
                        "foreign.json",
                        b"{}\n",
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertEqual(os.listdir(directory_fd), [])
            finally:
                os.close(directory_fd)

    def test_v3_receipt_binds_caller_state_evidence_and_inner_data_root(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-receipt-binding-", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            image = root / "image"
            image.write_bytes(b"x")
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            image_fd = os.open(image, os.O_RDONLY)
            try:
                root_stat = os.fstat(root_fd)
                image_stat = os.fstat(image_fd)
                state = MODULE.DirectoryIdentity(
                    Path("/home/example/ambit/state"), 47, 61, 1000, 100, 0o700
                )
                evidence = MODULE.DirectoryIdentity(
                    state.path / "evidence", 47, 62, 1000, 100, 0o700
                )
                context = mock.Mock(
                    state_identity=state,
                    evidence_identity=evidence,
                    caller_uid=1000,
                    caller_gid=100,
                    root_fd=root_fd,
                    image_fd=image_fd,
                    claim_present=True,
                    claim_name=f"{MODULE.CLAIM_PREFIX}{'a' * 64}",
                )
                target_device = os.makedev(7, 7)
                receipt = {
                    "schema": MODULE.RECEIPT_SCHEMA,
                    "lifecycleState": "detached",
                    "stateRoot": str(state.path),
                    "authorityClaimSha256": "a" * 64,
                    "caller": {"uid": 1000, "gid": 100},
                    "stateRootIdentity": state.document(),
                    "evidenceDirectoryIdentity": evidence.document(),
                    "authorityRoot": {
                        "path": str(MODULE.AUTHORITY_ROOT),
                        "device": root_stat.st_dev,
                        "inode": root_stat.st_ino,
                        "ownerUid": 0,
                        "ownerGid": 0,
                        "mode": "0700",
                    },
                    "mountTarget": {
                        "path": str(MODULE.AUTHORITY_ROOT / MODULE.TARGET_NAME),
                        "device": target_device,
                        "inode": 79,
                        "ownerUid": 0,
                        "ownerGid": 0,
                        "mode": "0700",
                    },
                    "innerRunnerDataRoot": {
                        "path": str(
                            MODULE.AUTHORITY_ROOT
                            / MODULE.TARGET_NAME
                            / MODULE.RUNNER_DATA_NAME
                        ),
                        "device": target_device,
                        "inode": 80,
                        "ownerUid": 0,
                        "ownerGid": 0,
                        "mode": "0700",
                    },
                    "image": {
                        "path": str(MODULE.AUTHORITY_ROOT / MODULE.IMAGE_NAME),
                        "logicalBytes": MODULE.IMAGE_BYTES,
                        "allocatedBytes": 1,
                        "device": image_stat.st_dev,
                        "inode": image_stat.st_ino,
                        "ownerUid": 0,
                        "ownerGid": 0,
                        "mode": "0600",
                    },
                    "loop": None,
                    "filesystem": {
                        "uuid": "12345678-1234-1234-1234-123456789abc"
                    },
                    "mountNamespace": {"device": 4, "inode": 5},
                    "backingFilesystem": {},
                    "sandboxDiskPolicy": {},
                }
                real_fstat = os.fstat
                fake_image_stat = mock.Mock(
                    st_dev=image_stat.st_dev,
                    st_ino=image_stat.st_ino,
                    st_uid=0,
                    st_gid=0,
                    st_mode=stat.S_IFREG | 0o600,
                    st_nlink=1,
                    st_size=MODULE.IMAGE_BYTES,
                )

                def observed_fstat(descriptor: int):
                    return fake_image_stat if descriptor == image_fd else real_fstat(descriptor)

                with mock.patch.object(MODULE, "require_context_binding"), mock.patch.object(
                    MODULE.os, "fstat", side_effect=observed_fstat
                ):
                    self.assertEqual(
                        MODULE.validate_receipt(receipt, context),
                        receipt["filesystem"]["uuid"],
                    )
                    mutations = (
                        ("caller", "uid", 1001),
                        ("stateRootIdentity", "inode", 63),
                        ("evidenceDirectoryIdentity", "inode", 64),
                        ("innerRunnerDataRoot", "device", os.makedev(7, 8)),
                        ("innerRunnerDataRoot", "inode", 0),
                        ("innerRunnerDataRoot", "mode", "0755"),
                    )
                    for section, field, value in mutations:
                        candidate = copy.deepcopy(receipt)
                        candidate[section][field] = value
                        with self.subTest(section=section, field=field), self.assertRaises(
                            MODULE.RunnerStorageLifecycleError
                        ):
                            MODULE.validate_receipt(candidate, context)
            finally:
                os.close(image_fd)
                os.close(root_fd)

    def test_admitted_pending_receipt_is_reduced_without_foreign_roster(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-pending-", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            pending = root / MODULE.RECEIPT_PENDING_NAME
            pending.write_text("partial")
            pending.chmod(0o600)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                MODULE.remove_admitted_pending(
                    descriptor,
                    MODULE.RECEIPT_PENDING_NAME,
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
            finally:
                os.close(descriptor)
            self.assertFalse(pending.exists())
        helper = SCRIPT.read_text()
        self.assertIn("RECEIPT_PENDING_NAME", helper)
        self.assertIn("PROJECTION_PENDING_NAME", helper)

    def test_descriptor_relative_outer_tree_removal_never_follows_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-tree-", dir=temporary_parent()
        ) as directory:
            parent = Path(directory)
            sentinel = parent / "sentinel"
            sentinel.write_text("preserve", encoding="utf-8")
            tree = parent / "outer-docker"
            nested = tree / "nested"
            nested.mkdir(parents=True)
            (nested / "payload").write_text("remove", encoding="utf-8")
            (tree / "outside").symlink_to(sentinel)
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                MODULE.remove_tree_descriptor_relative(descriptor, tree.name)
            finally:
                os.close(descriptor)
            self.assertFalse(tree.exists())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_remove_validates_bound_receipt_before_loop_or_path_mutation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        remove = source.index("def remove_authority")
        receipt = source.index("validate_receipt(stored, context)", remove)
        loop = source.index("associated_loops(context)", remove)
        projection = source.index("remove_user_projection(context)", loop)
        self.assertLess(receipt, loop)
        self.assertLess(receipt, projection)
        self.assertIn("require_root_credentials()", source[source.index("def main"):])

    def test_pending_identity_rejects_hardlinks_and_oversize_before_unlink(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-pending-identity-", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            pending = root / MODULE.RECEIPT_PENDING_NAME
            pending.write_bytes(b"partial")
            pending.chmod(0o600)
            sibling = root / "hardlink"
            os.link(pending, sibling)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(
                    MODULE.RunnerStorageLifecycleError,
                    "pending receipt identity differs",
                ):
                    MODULE.remove_admitted_pending(
                        descriptor,
                        MODULE.RECEIPT_PENDING_NAME,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertTrue(pending.exists())
                sibling.unlink()
                with pending.open("wb") as output:
                    output.truncate(MODULE.MAX_DOCUMENT_BYTES + 1)
                with self.assertRaisesRegex(
                    MODULE.RunnerStorageLifecycleError,
                    "pending receipt identity differs",
                ):
                    MODULE.remove_admitted_pending(
                        descriptor,
                        MODULE.RECEIPT_PENDING_NAME,
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                    )
                self.assertTrue(pending.exists())
            finally:
                os.close(descriptor)

    def test_complete_pending_receipt_is_promoted_and_wrong_binding_blocks(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-pending-promote-", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            pending = root / MODULE.RECEIPT_PENDING_NAME
            pending.write_text("{}\n")
            pending.chmod(0o600)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            context = mock.Mock(root_fd=root_fd)
            receipt = {"schema": MODULE.RECEIPT_SCHEMA}
            try:
                with mock.patch.object(MODULE, "require_context_binding"), mock.patch.object(
                    MODULE, "read_json_at", return_value=receipt
                ), mock.patch.object(MODULE, "validate_receipt") as validate:
                    MODULE.reconcile_receipt_pending(context)
                validate.assert_called_once_with(receipt, context)
                self.assertFalse(pending.exists())
                self.assertTrue((root / MODULE.RECEIPT_NAME).is_file())

                (root / MODULE.RECEIPT_NAME).unlink()
                pending.write_text("{}\n")
                pending.chmod(0o600)
                with mock.patch.object(MODULE, "require_context_binding"), mock.patch.object(
                    MODULE, "read_json_at", return_value=receipt
                ), mock.patch.object(
                    MODULE,
                    "validate_receipt",
                    side_effect=MODULE.RunnerStorageLifecycleError("wrong binding"),
                ):
                    with self.assertRaisesRegex(
                        MODULE.RunnerStorageLifecycleError,
                        "wrong binding",
                    ):
                        MODULE.reconcile_receipt_pending(context)
                self.assertTrue(pending.exists())
                self.assertFalse((root / MODULE.RECEIPT_NAME).exists())
            finally:
                os.close(root_fd)


def argparse_namespace(**values: object):
    class Namespace:
        pass

    result = Namespace()
    for key, value in values.items():
        setattr(result, key, value)
    return result


if __name__ == "__main__":
    unittest.main()
