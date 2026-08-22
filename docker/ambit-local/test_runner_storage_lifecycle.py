from __future__ import annotations

import fcntl
import hashlib
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
        claim_bytes = MODULE.claim_bytes_for_identity(state, evidence, 1000, 100)
        self.assertEqual(claim_bytes, MODULE.canonical_json_bytes(document))
        self.assertTrue(baseline.endswith(MODULE.sha256_bytes(claim_bytes)))
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
        expected_size = 128
        authority = MODULE.NodeFacts("directory", 0, 0, 0o700, 47, 71, 0)
        claim = MODULE.NodeFacts("regular", 0, 0, 0o600, 47, 72, expected_size, 1)
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
                        expected_claim_size=expected_size,
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
            (MODULE.absent_node(), replace(claim, size=0), (expected,), False, True),
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
                    expected_claim_size=expected_size,
                    allow_legacy_empty=allow_legacy,
                    authority_empty=empty,
                )

        pending = replace(claim, size=17)
        self.assertEqual(
            MODULE.classify_lifecycle_prefix(
                MODULE.absent_node(),
                MODULE.absent_node(),
                (),
                expected,
                home_device=47,
                expected_claim_size=expected_size,
                allow_legacy_empty=False,
                authority_empty=True,
                pending=pending,
            ),
            "pending_claim",
        )
        self.assertEqual(
            MODULE.classify_lifecycle_prefix(
                authority,
                MODULE.absent_node(),
                (),
                expected,
                home_device=47,
                expected_claim_size=expected_size,
                allow_legacy_empty=False,
                authority_empty=False,
                pending=pending,
                admit_legacy_authority=True,
            ),
            "pending_legacy_authority",
        )
        with self.assertRaisesRegex(
            MODULE.RunnerStorageLifecycleError,
            "storage authority",
        ):
            MODULE.classify_lifecycle_prefix(
                authority,
                MODULE.absent_node(),
                (),
                expected,
                home_device=47,
                expected_claim_size=expected_size,
                allow_legacy_empty=False,
                authority_empty=False,
                pending=pending,
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
        claim_creation = helper[
            helper.index("def create_claim") : helper.index("def directory_identity_from_document")
        ]
        self.assertIn("CLAIM_PENDING_NAME", claim_creation)
        self.assertLess(claim_creation.index("os.write("), claim_creation.index("os.fsync(descriptor)"))
        self.assertLess(claim_creation.index("os.fsync(descriptor)"), claim_creation.index("os.replace("))
        self.assertLess(claim_creation.index("os.replace("), claim_creation.index("os.fsync(home_fd)"))
        seal = helper[helper.index("def seal_claim") : helper.index("def directory_identity_from_document")]
        self.assertLess(seal.index("os.fsync(descriptor)"), seal.index("os.fsync(home_fd)"))
        self.assertNotIn("ftruncate", claim_creation)
        removal = helper[
            helper.index("def _remove_authority_locked") : helper.index("def parser")
        ]
        self.assertLess(
            removal.rindex("os.rmdir(AUTHORITY_NAME"),
            removal.rindex("context.claim_name"),
        )
        self.assertIn("unlink_bound_leaf(", removal)
        self.assertEqual(helper.count('"lifecycle.lock"'), 1)

    def test_format_bytes_are_fsynced_before_publication_can_continue(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        create = source[source.index("def create_image") : source.index("def mount_image")]
        mkfs = create.index('"mkfs.xfs"')
        image_fsync = create.index("os.fsync(context.image_fd)", mkfs)
        root_fsync = create.index("os.fsync(context.root_fd)", image_fsync)
        self.assertLess(mkfs, image_fsync)
        self.assertLess(image_fsync, root_fsync)

    def test_pending_claim_reducer_requires_exact_admitted_runtime_roster(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-claim-pending-", dir=temporary_parent()
        ) as directory:
            home_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            pending = Path(directory) / MODULE.CLAIM_PENDING_NAME
            pending.write_bytes(b"partial")
            pending.chmod(0o600)
            real_fstat = os.fstat

            def root_owned_regular(descriptor: int):
                value = real_fstat(descriptor)
                if descriptor == home_fd or not stat.S_ISREG(value.st_mode):
                    return value
                return mock.Mock(
                    st_mode=stat.S_IFREG | 0o600,
                    st_uid=0,
                    st_gid=0,
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_nlink=value.st_nlink,
                    st_size=value.st_size,
                )

            try:
                state_root = Path("/home/example/state")
                with mock.patch.object(
                    MODULE,
                    "lifecycle_prefix_state",
                    side_effect=("pending_claim", "absent_unclaimed"),
                ), mock.patch.object(
                    MODULE.os, "fstat", side_effect=root_owned_regular
                ), mock.patch.object(
                    MODULE, "task_runtime_authority_roster", return_value=()
                ), mock.patch.object(
                    MODULE, "require_runtime_paths_absent"
                ), mock.patch.object(MODULE, "path_occurrences", return_value=()):
                    self.assertEqual(
                        MODULE.reduce_lifecycle_prefix(
                            home_fd,
                            state_root,
                            allow_current_runtime=False,
                            allow_legacy_empty=False,
                        ),
                        "absent_unclaimed",
                    )
                self.assertFalse(pending.exists())

                pending.write_bytes(b"partial")
                pending.chmod(0o600)
                with mock.patch.object(
                    MODULE, "lifecycle_prefix_state", return_value="pending_claim"
                ), mock.patch.object(MODULE.os, "fstat", side_effect=root_owned_regular), mock.patch.object(
                    MODULE, "task_runtime_authority_roster", return_value=("/run/runtime",)
                ), self.assertRaisesRegex(
                    MODULE.RunnerStorageLifecycleError,
                    "foreign, legacy, or absent",
                ):
                    MODULE.reduce_lifecycle_prefix(
                        home_fd,
                        state_root,
                        allow_current_runtime=True,
                        allow_legacy_empty=False,
                    )
                self.assertTrue(pending.exists())

                current_runtime = str(MODULE.runtime_authority_paths(state_root)[0])
                with mock.patch.object(
                    MODULE,
                    "lifecycle_prefix_state",
                    side_effect=("pending_claim", "absent_unclaimed"),
                ), mock.patch.object(MODULE.os, "fstat", side_effect=root_owned_regular), mock.patch.object(
                    MODULE, "task_runtime_authority_roster", return_value=(current_runtime,)
                ), mock.patch.object(
                    MODULE,
                    "path_occurrences",
                    return_value=(mock.Mock(),),
                ), self.assertRaisesRegex(
                    MODULE.RunnerStorageLifecycleError,
                    "observable storage mount",
                ):
                    MODULE.reduce_lifecycle_prefix(
                        home_fd,
                        state_root,
                        allow_current_runtime=True,
                        allow_legacy_empty=False,
                    )
                self.assertTrue(pending.exists())

                with mock.patch.object(
                    MODULE,
                    "lifecycle_prefix_state",
                    side_effect=("pending_claim", "absent_unclaimed"),
                ), mock.patch.object(
                    MODULE.os, "fstat", side_effect=root_owned_regular
                ), mock.patch.object(
                    MODULE,
                    "task_runtime_authority_roster",
                    return_value=(current_runtime,),
                ), mock.patch.object(
                    MODULE, "path_occurrences", return_value=()
                ):
                    self.assertEqual(
                        MODULE.reduce_lifecycle_prefix(
                            home_fd,
                            state_root,
                            allow_current_runtime=True,
                            allow_legacy_empty=False,
                        ),
                        "absent_unclaimed",
                    )
                self.assertFalse(pending.exists())
            finally:
                os.close(home_fd)

    def test_inherited_runtime_lease_proves_exact_path_identity_and_flock(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-runtime-lease-", dir=temporary_parent()
        ) as directory:
            parent = Path(directory)
            lease_path = parent / MODULE.GLOBAL_RUNTIME_LEASE_NAME
            lease_path.write_bytes(b"")
            lease_path.chmod(0o600)
            descriptor = os.open(lease_path, os.O_RDWR | os.O_NOFOLLOW)
            foreign = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            real_fstat = os.fstat

            def root_lease_fstat(candidate: int):
                value = real_fstat(candidate)
                if candidate != descriptor:
                    return value
                return mock.Mock(
                    st_mode=stat.S_IFREG | 0o600,
                    st_uid=0,
                    st_gid=0,
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_nlink=1,
                    st_size=0,
                )

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                with mock.patch.object(MODULE, "RUNTIME_PARENT", parent), mock.patch.object(
                    MODULE, "require_root_directory"
                ), mock.patch.object(MODULE.os, "fstat", side_effect=root_lease_fstat):
                    MODULE.require_inherited_runtime_lease(
                        descriptor,
                        Path("/home/example/state"),
                    )
                    with self.assertRaisesRegex(
                        MODULE.RunnerStorageLifecycleError,
                        "identity differs",
                    ):
                        MODULE.require_inherited_runtime_lease(
                            foreign,
                            Path("/home/example/state"),
                        )
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    with self.assertRaisesRegex(
                        MODULE.RunnerStorageLifecycleError,
                        "not exclusively held",
                    ):
                        MODULE.require_inherited_runtime_lease(
                            descriptor,
                            Path("/home/example/state"),
                        )
            finally:
                os.close(foreign)
                os.close(descriptor)

    def test_total_absence_is_a_terminal_remove_without_a_tombstone(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-total-absence-", dir=temporary_parent()
        ) as directory:
            home = Path(directory)
            args = argparse_namespace(
                state_root=home / "deleted-state",
                caller_uid=1000,
                caller_gid=1000,
            )
            with mock.patch.object(MODULE, "HOME_ROOT", home), mock.patch.object(
                MODULE, "require_inherited_runtime_lease"
            ), mock.patch.object(MODULE, "require_root_directory"), mock.patch.object(
                MODULE, "acquire_lifecycle_lock"
            ), mock.patch.object(
                MODULE, "lifecycle_prefix_state", return_value="absent_unclaimed"
            ), mock.patch.object(
                MODULE, "task_runtime_authority_roster", return_value=()
            ), mock.patch.object(
                MODULE, "require_runtime_paths_absent"
            ), mock.patch.object(MODULE, "path_occurrences", return_value=()):
                self.assertTrue(
                    MODULE.reduce_removal_lifecycle_prefix(args, runtime_lease_fd=19)
                )
            self.assertEqual(tuple(home.iterdir()), ())

    def test_remove_reduces_total_prefix_without_separate_path_discovery(self) -> None:
        lease = mock.MagicMock()
        lease.__enter__.return_value = lease
        lease.descriptor = 19
        with mock.patch.object(
            MODULE, "acquire_runtime_deletion_lease", return_value=lease
        ), mock.patch.object(
            MODULE, "reduce_removal_lifecycle_prefix", return_value=True
        ) as reduce_prefix, mock.patch.object(MODULE, "_remove_authority_locked") as remove:
            result = MODULE.remove_authority(
                argparse_namespace(
                    state_root=Path("/home/example/deleted-state"),
                    caller_uid=1000,
                    caller_gid=1000,
                )
            )
        self.assertEqual(result["outcome"], "removed")
        reduce_prefix.assert_called_once_with(mock.ANY, 19)
        remove.assert_not_called()
        self.assertNotIn(
            "discover_remove_binding_path",
            SCRIPT.read_text(encoding="utf-8"),
        )

    def test_legacy_v2_has_an_explicit_remove_only_migration(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        migration = source[
            source.index("def migrate_legacy_v2_for_removal") : source.index("def remove_legacy_v2_authority")
        ]
        self.assertLess(migration.index("create_claim("), migration.rindex("unlink_bound_leaf("))
        self.assertIn("seal_claim(home_fd, claim_name, claim_bytes)", migration)
        self.assertIn("LEGACY_RECEIPT_TEMP_NAME", migration)
        self.assertIn("LEGACY_PROJECTION_TEMP_NAME", migration)
        self.assertLess(
            migration.index("seal_claim(home_fd, claim_name, claim_bytes)"),
            migration.index("LEGACY_PROJECTION_TEMP_NAME"),
        )
        self.assertIn("legacy pending recovery requires exact lock and receipt authority", migration)
        self.assertIn("remove-legacy-v2-authority", source)
        wrapper = SCRIPT.with_name("remove-runner-storage.sh").read_text(encoding="utf-8")
        self.assertIn("--legacy-v2", wrapper)
        self.assertIn("remove-legacy-v2-authority", wrapper)
        self.assertNotIn(
            "legacy v2 removal requires the original existing STATE_ROOT identity",
            wrapper,
        )
        state = MODULE.DirectoryIdentity(
            Path("/home/example/state"), 47, 61, 1000, 100, 0o700
        )
        root_stat = mock.Mock(st_dev=47, st_ino=71)
        image_stat = mock.Mock(st_dev=47, st_ino=72)
        receipt = {
            "schema": MODULE.LEGACY_RECEIPT_SCHEMA,
            "stateRoot": str(state.path),
            "stateRootIdentity": {
                "device": 47,
                "inode": 61,
                "ownerUid": 1000,
                "ownerGid": 100,
                "mode": "0700",
            },
            "authorityRoot": {
                "path": str(MODULE.AUTHORITY_ROOT),
                "device": 47,
                "inode": 71,
            },
            "image": {
                "path": str(MODULE.AUTHORITY_ROOT / MODULE.IMAGE_NAME),
                "device": 47,
                "inode": 72,
                "logicalBytes": MODULE.IMAGE_BYTES,
            },
            "filesystem": {"uuid": "12345678-1234-1234-1234-123456789abc"},
        }
        MODULE.validate_legacy_v2_removal_receipt(
            receipt,
            state_identity=state,
            root_stat=root_stat,
            image_stat=image_stat,
        )
        for mutate in (
            lambda value: value.update(stateRoot="/home/other/state"),
            lambda value: value["image"].update(inode=73),
            lambda value: value.update(schema=MODULE.RECEIPT_SCHEMA),
        ):
            candidate = copy.deepcopy(receipt)
            mutate(candidate)
            with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                MODULE.validate_legacy_v2_removal_receipt(
                    candidate,
                    state_identity=state,
                    root_stat=root_stat,
                    image_stat=image_stat,
                )

    def test_legacy_v2_reentry_routes_every_migration_and_delete_cutpoint(self) -> None:
        v2 = MODULE.LEGACY_RECEIPT_SCHEMA
        v3 = MODULE.RECEIPT_SCHEMA
        cutpoints = (
            (
                "pending claim after exact v2 validation",
                "pending_legacy_authority",
                False,
                (MODULE.LEGACY_LOCK_NAME, MODULE.RECEIPT_NAME, MODULE.IMAGE_NAME),
                v2,
                "migrate",
            ),
            (
                "final claim before legacy temporary cleanup",
                "claimed_authority",
                False,
                (
                    MODULE.LEGACY_LOCK_NAME,
                    ".storage-receipt.json.123.0123456789abcdef",
                    MODULE.RECEIPT_NAME,
                    MODULE.IMAGE_NAME,
                ),
                v2,
                "migrate",
            ),
            (
                "final claim after legacy lock deletion",
                "claimed_authority",
                False,
                (MODULE.RECEIPT_NAME, MODULE.IMAGE_NAME),
                v2,
                "migrate",
            ),
            (
                "ordinary receipt-delete cutpoint",
                "claimed_authority",
                False,
                (MODULE.IMAGE_NAME, MODULE.TARGET_NAME),
                None,
                "ordinary",
            ),
            (
                "ordinary image-delete cutpoint",
                "claimed_authority",
                False,
                (MODULE.TARGET_NAME,),
                None,
                "ordinary",
            ),
            (
                "ordinary authority-delete cutpoint",
                "claim_only",
                True,
                (),
                None,
                "ordinary",
            ),
            (
                "ordinary claim-delete response loss with state present",
                "absent_unclaimed",
                False,
                (),
                None,
                "ordinary",
            ),
            (
                "total absence response loss",
                "absent_unclaimed",
                True,
                (),
                None,
                "removed",
            ),
            (
                "current v3 lifecycle",
                "claimed_authority",
                False,
                (MODULE.RECEIPT_NAME, MODULE.IMAGE_NAME),
                v3,
                "ordinary",
            ),
        )
        for label, state, absent, roster, schema, expected in cutpoints:
            with self.subTest(label=label):
                self.assertEqual(
                    MODULE.classify_legacy_v2_removal_route(
                        state,
                        state_root_absent=absent,
                        authority_roster=roster,
                        receipt_schema=schema,
                    ),
                    expected,
                )
        with self.assertRaisesRegex(
            MODULE.RunnerStorageLifecycleError,
            "prepublication pending claim is unsupported",
        ):
            MODULE.classify_legacy_v2_removal_route(
                "pending_claim",
                state_root_absent=False,
            )

    def test_legacy_remove_response_loss_retry_is_terminal_and_does_not_remigrate(self) -> None:
        args = argparse_namespace(
            state_root=Path("/home/example/deleted-state"),
            caller_uid=1000,
            caller_gid=1000,
        )
        lease = mock.MagicMock()
        lease.__enter__.return_value = lease
        lease.descriptor = 23
        removed = MODULE.operation_result("removed", None, None, None)
        common = (
            mock.patch.object(MODULE, "acquire_runtime_deletion_lease", return_value=lease),
            mock.patch.object(MODULE, "require_inherited_runtime_lease"),
            mock.patch.object(MODULE, "require_runtime_paths_absent"),
            mock.patch.object(MODULE, "task_runtime_authority_roster", return_value=()),
            mock.patch.object(MODULE, "path_occurrences", return_value=()),
        )
        with common[0], common[1], common[2], common[3], common[4], mock.patch.object(
            MODULE,
            "legacy_v2_removal_route",
            side_effect=("ordinary", "removed"),
        ), mock.patch.object(
            MODULE, "_remove_authority_locked", return_value=removed
        ) as ordinary, mock.patch.object(MODULE, "migrate_legacy_v2_for_removal") as migrate:
            self.assertEqual(MODULE.remove_legacy_v2_authority(args), removed)
            self.assertEqual(MODULE.remove_legacy_v2_authority(args), removed)
        ordinary.assert_called_once_with(args)
        migrate.assert_not_called()

    def test_legacy_v2_random_atomic_temporaries_are_typed_reducible_prefixes(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-legacy-receipt-temp-", dir=temporary_parent()
        ) as directory:
            root_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            real_fstat = os.fstat

            try:
                for pattern, admitted_name, foreign_name, label, owner_uid, owner_gid in (
                    (
                        MODULE.LEGACY_RECEIPT_TEMP_NAME,
                        ".storage-receipt.json.123.0123456789abcdef",
                        ".storage-receipt.json.bad",
                        "authority receipt",
                        0,
                        0,
                    ),
                    (
                        MODULE.LEGACY_PROJECTION_TEMP_NAME,
                        ".runner-docker-storage.json.456.fedcba9876543210",
                        ".runner-docker-storage.json.bad",
                        "user projection",
                        1000,
                        100,
                    ),
                ):
                    with self.subTest(label=label):
                        temporary = Path(directory) / admitted_name
                        temporary.write_bytes(b"partial")
                        temporary.chmod(0o600)
                        foreign = Path(directory) / foreign_name
                        foreign.write_bytes(b"preserve")

                        def owned_regular(descriptor: int):
                            value = real_fstat(descriptor)
                            if descriptor == root_fd or not stat.S_ISREG(value.st_mode):
                                return value
                            return mock.Mock(
                                st_mode=stat.S_IFREG | 0o600,
                                st_uid=owner_uid,
                                st_gid=owner_gid,
                                st_dev=value.st_dev,
                                st_ino=value.st_ino,
                                st_nlink=value.st_nlink,
                                st_size=value.st_size,
                            )

                        with mock.patch.object(
                            MODULE.os, "fstat", side_effect=owned_regular
                        ):
                            MODULE.remove_legacy_atomic_temporaries(
                                root_fd,
                                pattern,
                                owner_uid=owner_uid,
                                owner_gid=owner_gid,
                                label=label,
                            )
                        self.assertFalse(temporary.exists())
                        self.assertTrue(foreign.exists())
            finally:
                os.close(root_fd)

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
        self.assertIn("libc.prctl(1, signal.SIGKILL", MODULE.MUTATION_GUARDIAN)

    def test_killed_guardian_kills_tool_and_releases_lock_bounded(self) -> None:
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
                for _ in range(200):
                    try:
                        fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(0.01)
                else:
                    self.fail("guardian death did not terminate the lock-owning tool")
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
        pinned = next(
            line.removeprefix("lifecycle_helper_sha256=")
            for line in source.splitlines()
            if line.startswith("lifecycle_helper_sha256=")
        )
        self.assertEqual(
            pinned,
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
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

    def test_supervisor_mutations_require_the_inherited_lease_fd_but_observe_does_not(self) -> None:
        common = ["/home/example/state", "1000", "100", "4", "4026533000"]
        for command in ("activate-private", "deactivate-private"):
            with self.subTest(command=command):
                parsed = MODULE.parser().parse_args([command, *common, "19"])
                self.assertEqual(parsed.runtime_lease_fd, 19)
        observed = MODULE.parser().parse_args(["observe-private", *common])
        self.assertFalse(hasattr(observed, "runtime_lease_fd"))
        source = SCRIPT.read_text(encoding="utf-8")
        prepare = source[
            source.index("def prepare_supervisor_storage_mutation") : source.index(
                "def activate_private"
            )
        ]
        self.assertLess(
            prepare.index("require_inherited_runtime_lease"),
            prepare.index("reduce_lifecycle_prefix"),
        )

    def test_private_propagation_is_a_precondition(self) -> None:
        private = MODULE.MountRecord("8:1", "/home", ())
        MODULE.require_private_mount_record(private)
        self.assertTrue(
            MODULE.mount_contains_path(MODULE.MountRecord("8:1", "/", ()), Path("/home"))
        )
        self.assertFalse(
            MODULE.mount_contains_path(
                MODULE.MountRecord("8:1", "/home-other", ()),
                Path("/home"),
            )
        )
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
        base = MODULE.MountRecord("8:1", "/", (), "/")
        unmounted = MODULE.NamespaceObservation("1:1", 1, (base,))
        mounted = MODULE.NamespaceObservation(
            "1:1",
            1,
            (
                base,
                MODULE.MountRecord(
                    "7:7",
                    str(MODULE.AUTHORITY_ROOT / "runner-docker"),
                    (),
                    "/",
                ),
            ),
        )
        with mock.patch.object(MODULE, "namespace_id", return_value="1:1"), mock.patch.object(
            MODULE,
            "read_namespace_roster_once",
            side_effect=((mounted,), (unmounted,)),
        ):
            with self.assertRaisesRegex(
                MODULE.RunnerStorageLifecycleError,
                "(backing anchors|occurrence roster) changed",
            ):
                MODULE.target_occurrences()

    def test_same_namespace_representatives_must_expose_the_same_mount_view(self) -> None:
        canonical = (MODULE.MountRecord("8:1", "/", (), "/", "ext4"),)
        chrooted = (MODULE.MountRecord("8:1", "/", (), "/tenant", "ext4"),)

        def mount_view(path: str = "/proc/self/mountinfo"):
            return chrooted if path == "/proc/101/mountinfo" else canonical

        with mock.patch.object(MODULE.os, "getpid", return_value=100), mock.patch.object(
            MODULE.os, "listdir", return_value=("100", "101")
        ), mock.patch.object(
            MODULE, "namespace_id", return_value="1:1"
        ), mock.patch.object(
            MODULE, "read_mount_records", side_effect=mount_view
        ), self.assertRaisesRegex(
            MODULE.RunnerStorageLifecycleError,
            "mount record view differs across namespace representatives",
        ):
            MODULE.read_namespace_roster_once()

        with mock.patch.object(MODULE.os, "getpid", return_value=100), mock.patch.object(
            MODULE.os, "listdir", return_value=("100", "101")
        ), mock.patch.object(
            MODULE, "namespace_id", return_value="1:1"
        ), mock.patch.object(
            MODULE, "read_mount_records", return_value=canonical
        ):
            self.assertEqual(
                MODULE.read_namespace_roster_once(),
                (MODULE.NamespaceObservation("1:1", 100, canonical),),
            )

    def test_mountinfo_parser_preserves_decoded_source_root(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as mountinfo:
            mountinfo.write(
                "20 1 8:2 /tenant\\040home /home rw shared:1 - ext4 /dev/root rw\n"
                "21 20 0:4 net:[4026533321] /run/docker/netns/default rw - nsfs nsfs rw\n"
            )
            mountinfo.flush()
            self.assertEqual(
                MODULE.read_mount_records(mountinfo.name),
                (
                    MODULE.MountRecord(
                        "8:2",
                        "/home",
                        ("shared:1",),
                        "/tenant home",
                        "ext4",
                    ),
                    MODULE.MountRecord(
                        "0:4",
                        "/run/docker/netns/default",
                        (),
                        "net:[4026533321]",
                        "nsfs",
                    ),
                ),
            )

    def test_opaque_mount_roots_are_exact_source_coordinates(self) -> None:
        target = Path("/run/ambit-c16b-docker-0123456789ab/docker-exec/netns/task-1")
        opaque = MODULE.MountRootCoordinate(opaque="net:[4026533321]")
        records = (
            MODULE.MountRecord(
                "0:4", str(target), (), opaque.wire(), "nsfs"
            ),
        )
        anchors = MODULE.mount_source_anchors(records, target)
        self.assertEqual(anchors, (("0:4", opaque),))
        self.assertTrue(
            MODULE.record_references_path(
                MODULE.MountRecord(
                    "0:4", "/outside/task-1", (), opaque.wire(), "nsfs"
                ),
                target,
                anchors,
            )
        )
        self.assertFalse(
            MODULE.record_references_path(
                MODULE.MountRecord(
                    "0:4",
                    "/outside/other-task",
                    (),
                    "net:[4026533322]",
                    "nsfs",
                ),
                target,
                anchors,
            )
        )
        with self.assertRaisesRegex(
            MODULE.RunnerStorageLifecycleError,
            "cannot address a descendant",
        ):
            opaque.translate(Path("nested"))
        with self.assertRaisesRegex(
            MODULE.RunnerStorageLifecycleError,
            "admitted nsfs identity",
        ):
            MODULE.MountRootCoordinate.parse("net:[4026533321]", "ext4")

    def test_storage_mount_scan_detects_bind_sources_outside_authority_tree(self) -> None:
        path = MODULE.AUTHORITY_ROOT / MODULE.OUTER_DOCKER_NAME
        own = MODULE.NamespaceObservation(
            "1:1",
            1,
            (MODULE.MountRecord("8:1", "/", (), "/"),),
        )
        foreign = MODULE.NamespaceObservation(
            "2:2",
            2,
            (
                MODULE.MountRecord("0:42", "/", (), "/"),
                MODULE.MountRecord("8:1", "/outside/docker-data", (), str(path)),
            ),
        )
        snapshots = ((own, foreign), (own, foreign))
        with mock.patch.object(MODULE, "namespace_id", return_value="1:1"), mock.patch.object(
            MODULE,
            "read_namespace_roster_once",
            side_effect=snapshots,
        ):
            self.assertEqual(
                tuple(item.target for item in MODULE.path_occurrences(path)),
                ("/outside/docker-data",),
            )

    def test_storage_mount_scan_translates_separate_home_source_coordinate(self) -> None:
        path = MODULE.AUTHORITY_ROOT / MODULE.OUTER_CONTAINERD_NAME
        own = MODULE.NamespaceObservation(
            "1:1",
            1,
            (
                MODULE.MountRecord("8:1", "/", (), "/"),
                MODULE.MountRecord("8:2", "/home", (), "/tenant-home"),
            ),
        )
        foreign = MODULE.NamespaceObservation(
            "2:2",
            2,
            (
                MODULE.MountRecord("0:42", "/", (), "/"),
                MODULE.MountRecord(
                    "8:2",
                    "/outside/containerd-data",
                    (),
                    "/tenant-home/.ambit-c16b-runner-storage/outer-containerd",
                ),
            ),
        )
        with mock.patch.object(MODULE, "namespace_id", return_value="1:1"), mock.patch.object(
            MODULE,
            "read_namespace_roster_once",
            side_effect=((own, foreign), (own, foreign)),
        ):
            self.assertEqual(
                tuple(item.target for item in MODULE.path_occurrences(path)),
                ("/outside/containerd-data",),
            )

    def test_storage_mount_scan_carries_descendant_filesystem_anchors(self) -> None:
        target = MODULE.AUTHORITY_ROOT / MODULE.TARGET_NAME
        own = MODULE.NamespaceObservation(
            "1:1",
            1,
            (
                MODULE.MountRecord("8:1", "/", (), "/"),
                MODULE.MountRecord("7:7", str(target), (), "/"),
            ),
        )
        foreign = MODULE.NamespaceObservation(
            "2:2",
            2,
            (
                MODULE.MountRecord("0:42", "/", (), "/"),
                MODULE.MountRecord("7:7", "/var/lib/docker", (), "/inner-runner"),
            ),
        )
        with mock.patch.object(MODULE, "namespace_id", return_value="1:1"), mock.patch.object(
            MODULE,
            "read_namespace_roster_once",
            side_effect=((own, foreign), (own, foreign)),
        ):
            self.assertEqual(
                {item.target for item in MODULE.path_occurrences(MODULE.AUTHORITY_ROOT)},
                {str(target), "/var/lib/docker"},
            )

    def test_storage_mount_scan_rejects_lexical_source_siblings(self) -> None:
        path = MODULE.AUTHORITY_ROOT / MODULE.OUTER_DOCKER_NAME
        own = MODULE.NamespaceObservation(
            "1:1",
            1,
            (MODULE.MountRecord("8:1", "/", (), "/"),),
        )
        sibling = MODULE.NamespaceObservation(
            "2:2",
            2,
            (
                MODULE.MountRecord(
                    "8:1",
                    "/outside",
                    (),
                    f"{path}-old",
                ),
            ),
        )
        with mock.patch.object(MODULE, "namespace_id", return_value="1:1"), mock.patch.object(
            MODULE,
            "read_namespace_roster_once",
            side_effect=((own, sibling), (own, sibling)),
        ):
            self.assertEqual(MODULE.path_occurrences(path), ())

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
        lease = mock.MagicMock()
        lease.__enter__.return_value = lease
        lease.descriptor = 19
        with mock.patch.object(
            MODULE, "acquire_runtime_deletion_lease", return_value=lease
        ), mock.patch.object(
            MODULE, "reduce_removal_lifecycle_prefix", return_value=False
        ), mock.patch.object(MODULE, "open_authority", return_value=context), mock.patch.object(
            MODULE, "require_context_binding"
        ), mock.patch.object(
            MODULE, "require_runtime_absent"
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
            "mountNamespace": {"device": 8, "inode": 8000},
            "filesystem": {"uuid": "12345678-1234-1234-1234-123456789abc"},
        }
        with mock.patch.object(
            MODULE, "prepare_supervisor_storage_mutation"
        ), mock.patch.object(
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
        ) as publish, mock.patch.object(
            MODULE, "publish_user_projection"
        ) as projection, mock.patch.object(MODULE, "unmount_and_detach") as teardown:
            result = MODULE.deactivate_private(args)
        self.assertEqual(result["outcome"], "deactivated")
        self.assertEqual(result["receipt"], stored)
        self.assertEqual(
            result["authorityReceiptSha256"],
            MODULE.sha256_bytes(MODULE.canonical_json_bytes(stored)),
        )
        publish.assert_not_called()
        projection.assert_called_once_with(
            context,
            stored,
            MODULE.sha256_bytes(MODULE.canonical_json_bytes(stored)),
        )
        teardown.assert_not_called()

        foreign = MODULE.NamespaceOccurrence("8:8", 8, "7:7", str(MODULE.AUTHORITY_ROOT / MODULE.TARGET_NAME))
        with mock.patch.object(
            MODULE, "prepare_supervisor_storage_mutation"
        ), mock.patch.object(
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
            MODULE, "prepare_supervisor_storage_mutation"
        ), mock.patch.object(
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
            MODULE, "prepare_supervisor_storage_mutation"
        ), mock.patch.object(
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

    def test_relocated_projection_cleanup_uses_only_the_pinned_evidence_inode(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-relocated-projection-", dir=temporary_parent()
        ) as directory:
            parent = Path(directory)
            evidence = parent / "evidence"
            evidence.mkdir(mode=0o700)
            projection = evidence / MODULE.USER_PROJECTION_NAME
            projection.write_text("{}\n", encoding="utf-8")
            projection.chmod(0o600)
            evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY)
            observed = os.fstat(evidence_fd)
            original = parent / "original-state/evidence"
            identity = MODULE.DirectoryIdentity(
                original,
                observed.st_dev,
                observed.st_ino,
                observed.st_uid,
                observed.st_gid,
                stat.S_IMODE(observed.st_mode),
            )
            relocated_again = parent / "relocated-again"
            evidence.rename(relocated_again)
            context = mock.Mock(
                orphaned_binding=True,
                state_fd=None,
                evidence_fd=None,
                projection_evidence_fd=evidence_fd,
                evidence_identity=identity,
                caller_uid=os.getuid(),
                caller_gid=os.getgid(),
            )
            try:
                MODULE.require_directory_identity_stat(os.fstat(evidence_fd), identity)
                with mock.patch.object(MODULE, "require_context_binding"):
                    MODULE.remove_user_projection(context)
                self.assertFalse((relocated_again / MODULE.USER_PROJECTION_NAME).exists())
            finally:
                os.close(evidence_fd)

    def test_deleted_orphan_projection_cleanup_is_an_exact_noop(self) -> None:
        context = mock.Mock(
            orphaned_binding=True,
            state_fd=None,
            evidence_fd=None,
            projection_evidence_fd=None,
        )
        with mock.patch.object(MODULE, "require_context_binding") as binding, mock.patch.object(
            MODULE, "lstat_at"
        ) as observed, mock.patch.object(MODULE.os, "unlink") as unlink:
            MODULE.remove_user_projection(context)
        binding.assert_called_once_with(context)
        observed.assert_not_called()
        unlink.assert_not_called()

    def test_relocated_binding_transfers_only_projection_cleanup_descriptor(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        opening = source[source.index("def open_authority(") : source.index("def require_trusted_parent_chain")]
        transfer = opening.index("projection_evidence_fd = evidence_fd")
        self.assertLess(opening.index("os.close(state_fd)"), transfer)
        self.assertLess(transfer, opening.index("evidence_fd = None", transfer))
        self.assertIn("projection_evidence_fd=projection_evidence_fd", opening)
        binding = source[source.index("def require_context_binding") : source.index("def runtime_authority_paths")]
        self.assertIn("require_directory_identity_stat(", binding)
        self.assertIn("os.fstat(context.projection_evidence_fd)", binding)

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

    def test_bound_leaf_unlink_rejects_entry_swap_immediately_before_delete(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-bound-leaf-", dir=temporary_parent()
        ) as directory:
            root = Path(directory)
            leaf = root / "leaf"
            displaced = root / "displaced"
            leaf.write_text("original", encoding="utf-8")
            leaf.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            original_identity = leaf.stat()
            real_binding = MODULE.require_descriptor_entry

            def swap_before_final_binding(
                candidate_directory_fd: int,
                name: str,
                descriptor: int,
            ) -> None:
                leaf.rename(displaced)
                leaf.write_text("replacement", encoding="utf-8")
                leaf.chmod(0o600)
                real_binding(candidate_directory_fd, name, descriptor)

            try:
                with mock.patch.object(
                    MODULE,
                    "require_descriptor_entry",
                    side_effect=swap_before_final_binding,
                ), self.assertRaisesRegex(
                    MODULE.RunnerStorageLifecycleError,
                    "entry changed",
                ):
                    MODULE.unlink_bound_leaf(
                        directory_fd,
                        leaf.name,
                        label="test leaf",
                        allowed_kinds=("regular",),
                        owner_uid=os.getuid(),
                        owner_gid=os.getgid(),
                        required_mode=0o600,
                        minimum_size=1,
                        maximum_size=1024,
                        required_link_count=1,
                        expected_identity=(
                            original_identity.st_dev,
                            original_identity.st_ino,
                        ),
                    )
                self.assertEqual(leaf.read_text(encoding="utf-8"), "replacement")
                self.assertEqual(displaced.read_text(encoding="utf-8"), "original")
            finally:
                os.close(directory_fd)

    def test_remove_validates_bound_receipt_before_loop_or_path_mutation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        remove = source.index("def _remove_authority_locked")
        runtime = source.index("require_runtime_absent(context)", remove)
        receipt = source.index("validate_receipt(stored, context)", remove)
        loop = source.index("associated_loops(context)", remove)
        projection = source.index("remove_user_projection(context)", loop)
        self.assertLess(runtime, receipt)
        self.assertLess(receipt, loop)
        self.assertLess(receipt, projection)
        self.assertIn("require_root_credentials()", source[source.index("def main"):])

    def test_storage_deletion_requires_all_ephemeral_runtime_authorities_absent(self) -> None:
        state_root = Path("/home/example/ambit-state")
        identifier = MODULE.sha256_bytes(str(state_root).encode())[:12]
        self.assertEqual(
            MODULE.runtime_authority_paths(state_root),
            (
                Path(f"/run/ambit-c16b-docker-{identifier}"),
                Path(f"/run/ambit-c16b-docker-removing-{identifier}"),
                Path(f"/run/ambit-c16b-docker-api-{identifier}"),
                Path(f"/sys/fs/cgroup/ambit-c16b-docker-{identifier}"),
            ),
        )
        self.assertEqual(
            MODULE.runtime_lease_path(state_root),
            MODULE.runtime_lease_path(Path("/home/other/state")),
        )
        context = mock.Mock()
        context.state_identity.path = state_root
        with mock.patch.object(MODULE.os, "stat", return_value=mock.Mock()):
            with self.assertRaisesRegex(
                MODULE.RunnerStorageLifecycleError,
                "runtime authority must be removed",
            ):
                MODULE.require_runtime_absent(context)
        self.assertIn(
            "not task_runtime_authority_roster()",
            SCRIPT.read_text(encoding="utf-8"),
        )
        source = SCRIPT.read_text(encoding="utf-8")
        remove = source[source.index("def remove_authority") : source.index("def validate_legacy_v2")]
        self.assertLess(
            remove.index("acquire_runtime_deletion_lease("),
            remove.index("reduce_removal_lifecycle_prefix("),
        )
        self.assertNotIn("discover_remove_binding_path", source)

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
                source = SCRIPT.read_text(encoding="utf-8")
                reconcile = source[
                    source.index("def reconcile_receipt_pending") : source.index("def write_bytes_atomic")
                ]
                self.assertLess(
                    reconcile.index("os.fsync(pending_fd)"),
                    reconcile.index("os.replace("),
                )

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
