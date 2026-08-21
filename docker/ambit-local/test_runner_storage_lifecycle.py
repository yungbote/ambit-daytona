from __future__ import annotations

import importlib.util
import itertools
import os
import sys
import tempfile
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

CALLER_UID = 1000
CALLER_GID = 100
DEVICE = 47
IMAGE_BYTES = 60 * 1024**3


def capacity(state: str):
    values = {
        "absent": MODULE.absent_node(),
        "caller_0700": MODULE.NodeFacts(
            kind="directory",
            owner_uid=CALLER_UID,
            owner_gid=CALLER_GID,
            mode=0o700,
            device=DEVICE,
            inode=11,
            size=0,
        ),
        "root_0700": MODULE.NodeFacts(
            kind="directory",
            owner_uid=0,
            owner_gid=0,
            mode=0o700,
            device=DEVICE,
            inode=11,
            size=0,
        ),
        "root_0711": MODULE.NodeFacts(
            kind="directory",
            owner_uid=0,
            owner_gid=0,
            mode=0o711,
            device=DEVICE,
            inode=11,
            size=0,
        ),
    }
    return values[state]


def image(state: str):
    values = {
        "absent": MODULE.absent_node(),
        "caller_0600_exact": MODULE.NodeFacts(
            kind="regular",
            owner_uid=CALLER_UID,
            owner_gid=CALLER_GID,
            mode=0o600,
            device=DEVICE,
            inode=13,
            size=IMAGE_BYTES,
        ),
        "root_0600_exact": MODULE.NodeFacts(
            kind="regular",
            owner_uid=0,
            owner_gid=0,
            mode=0o600,
            device=DEVICE,
            inode=13,
            size=IMAGE_BYTES,
        ),
        "caller_0600_incomplete_prepublication": MODULE.NodeFacts(
            kind="regular",
            owner_uid=CALLER_UID,
            owner_gid=CALLER_GID,
            mode=0o600,
            device=DEVICE,
            inode=13,
            size=0,
        ),
        "root_0600_incomplete_prepublication": MODULE.NodeFacts(
            kind="regular",
            owner_uid=0,
            owner_gid=0,
            mode=0o600,
            device=DEVICE,
            inode=13,
            size=0,
        ),
    }
    return values[state]


def facts(capacity_state: str, image_state: str, *, foreign_entries=()):
    return MODULE.CapacityPrefixFacts(
        state_root_device=DEVICE,
        capacity=capacity(capacity_state),
        image=image(image_state),
        foreign_entries=tuple(foreign_entries),
    )


def reduce(capacity_state: str, image_state: str, operation: str):
    return MODULE.reduce_prefix_state(
        facts(capacity_state, image_state),
        operation=operation,
        caller_uid=CALLER_UID,
        caller_gid=CALLER_GID,
        image_bytes=IMAGE_BYTES,
    )


class RunnerStorageLifecycleReducerTest(unittest.TestCase):
    valid_prefixes = {
        ("absent", "absent"),
        ("caller_0700", "absent"),
        ("caller_0700", "caller_0600_exact"),
        ("caller_0700", "root_0600_exact"),
        ("caller_0700", "caller_0600_incomplete_prepublication"),
        ("caller_0700", "root_0600_incomplete_prepublication"),
        ("root_0700", "absent"),
        ("root_0700", "caller_0600_exact"),
        ("root_0700", "root_0600_exact"),
        ("root_0700", "caller_0600_incomplete_prepublication"),
        ("root_0700", "root_0600_incomplete_prepublication"),
        ("root_0711", "absent"),
        ("root_0711", "root_0600_exact"),
        ("root_0711", "root_0600_incomplete_prepublication"),
    }

    def test_every_valid_prefix_has_total_prepare_and_remove_dispositions(self) -> None:
        for capacity_state, image_state in self.valid_prefixes:
            with self.subTest(capacity=capacity_state, image=image_state):
                prepare = reduce(capacity_state, image_state, "prepare")
                remove = reduce(capacity_state, image_state, "remove")
                if image_state == "absent":
                    self.assertEqual(prepare.disposition, "create_new")
                elif (capacity_state, image_state) == (
                    "root_0711",
                    "root_0600_exact",
                ):
                    self.assertEqual(
                        prepare.disposition, "existing_published_candidate"
                    )
                else:
                    self.assertEqual(prepare.disposition, "teardown_required")
                if capacity_state == "absent":
                    self.assertEqual(remove.disposition, "already_absent")
                elif image_state == "absent":
                    self.assertEqual(remove.disposition, "remove_empty_capacity")
                else:
                    self.assertEqual(remove.disposition, "remove_image_and_capacity")

    def test_every_presence_and_owner_prefix_is_admitted_or_rejected_explicitly(self) -> None:
        capacity_states = ("absent", "caller_0700", "root_0700", "root_0711")
        image_states = (
            "absent",
            "caller_0600_exact",
            "root_0600_exact",
            "caller_0600_incomplete_prepublication",
            "root_0600_incomplete_prepublication",
        )
        for prefix in itertools.product(capacity_states, image_states):
            with self.subTest(prefix=prefix):
                if prefix in self.valid_prefixes:
                    self.assertIsNotNone(reduce(*prefix, "prepare"))
                    self.assertIsNotNone(reduce(*prefix, "remove"))
                else:
                    with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                        reduce(*prefix, "prepare")
                    with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                        reduce(*prefix, "remove")

    def test_create_crash_prefixes_never_become_published_authority(self) -> None:
        crash_prefixes = self.valid_prefixes - {
            ("absent", "absent"),
            ("caller_0700", "absent"),
            ("root_0700", "absent"),
            ("root_0711", "absent"),
            ("root_0711", "root_0600_exact"),
        }
        for prefix in crash_prefixes:
            with self.subTest(prefix=prefix):
                self.assertEqual(reduce(*prefix, "prepare").disposition, "teardown_required")
                self.assertEqual(
                    reduce(*prefix, "remove").disposition,
                    "remove_image_and_capacity",
                )

    def test_every_pretruncate_cutpoint_is_teardown_only_and_removable(self) -> None:
        for owner_state, capacity_state in (
            ("caller_0600_incomplete_prepublication", "caller_0700"),
            ("root_0600_incomplete_prepublication", "root_0700"),
            ("root_0600_incomplete_prepublication", "root_0711"),
        ):
            for size in (0, 1, IMAGE_BYTES - 1):
                with self.subTest(owner=owner_state, capacity=capacity_state, size=size):
                    candidate_image = MODULE.NodeFacts(
                        **{**image(owner_state).__dict__, "size": size}
                    )
                    prefix = MODULE.CapacityPrefixFacts(
                        state_root_device=DEVICE,
                        capacity=capacity(capacity_state),
                        image=candidate_image,
                    )
                    prepare = MODULE.reduce_prefix_state(
                        prefix,
                        operation="prepare",
                        caller_uid=CALLER_UID,
                        caller_gid=CALLER_GID,
                        image_bytes=IMAGE_BYTES,
                    )
                    remove = MODULE.reduce_prefix_state(
                        prefix,
                        operation="remove",
                        caller_uid=CALLER_UID,
                        caller_gid=CALLER_GID,
                        image_bytes=IMAGE_BYTES,
                    )
                    self.assertEqual(prepare.disposition, "teardown_required")
                    self.assertEqual(remove.disposition, "remove_image_and_capacity")

        helper = SCRIPT.read_text()
        create = helper.index("prefix.image_fd = os.open(")
        truncate = helper.index("os.ftruncate(prefix.image_fd", create)
        self.assertLess(create, truncate)

    def test_unlink_before_rmdir_crash_prefix_is_recoverable(self) -> None:
        decision = reduce("root_0711", "absent", "remove")
        self.assertEqual(decision.disposition, "remove_empty_capacity")

    def test_foreign_capacity_children_always_fail_without_a_disposition(self) -> None:
        for operation in ("prepare", "remove"):
            with self.subTest(operation=operation):
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.reduce_prefix_state(
                        facts(
                            "root_0711",
                            "root_0600_exact",
                            foreign_entries=("foreign",),
                        ),
                        operation=operation,
                        caller_uid=CALLER_UID,
                        caller_gid=CALLER_GID,
                        image_bytes=IMAGE_BYTES,
                    )

    def test_capacity_identity_mutations_fail_closed(self) -> None:
        base = capacity("root_0711")
        mutations = {
            "kind": "symlink",
            "owner_uid": 7,
            "owner_gid": 7,
            "mode": 0o777,
            "device": DEVICE + 1,
            "inode": 0,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                candidate = MODULE.NodeFacts(
                    **{**base.__dict__, field: value}
                )
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.reduce_prefix_state(
                        MODULE.CapacityPrefixFacts(
                            state_root_device=DEVICE,
                            capacity=candidate,
                            image=MODULE.absent_node(),
                        ),
                        operation="remove",
                        caller_uid=CALLER_UID,
                        caller_gid=CALLER_GID,
                        image_bytes=IMAGE_BYTES,
                    )

    def test_image_identity_mutations_fail_closed(self) -> None:
        base = image("root_0600_exact")
        mutations = {
            "kind": "symlink",
            "owner_uid": 7,
            "owner_gid": 7,
            "mode": 0o666,
            "device": DEVICE + 1,
            "inode": 0,
            "size": IMAGE_BYTES + 1,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                candidate = MODULE.NodeFacts(
                    **{**base.__dict__, field: value}
                )
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.reduce_prefix_state(
                        MODULE.CapacityPrefixFacts(
                            state_root_device=DEVICE,
                            capacity=capacity("root_0711"),
                            image=candidate,
                        ),
                        operation="remove",
                        caller_uid=CALLER_UID,
                        caller_gid=CALLER_GID,
                        image_bytes=IMAGE_BYTES,
                    )

        negative = MODULE.NodeFacts(**{**base.__dict__, "size": -1})
        with self.assertRaises(MODULE.RunnerStorageLifecycleError):
            MODULE.reduce_prefix_state(
                MODULE.CapacityPrefixFacts(
                    state_root_device=DEVICE,
                    capacity=capacity("root_0700"),
                    image=negative,
                ),
                operation="remove",
                caller_uid=CALLER_UID,
                caller_gid=CALLER_GID,
                image_bytes=IMAGE_BYTES,
            )

    def test_mountinfo_escape_decoding_is_exact(self) -> None:
        self.assertEqual(
            MODULE.decode_mount_path(r"/home/a\040b\011c\012d\134e"),
            "/home/a b\tc\nd\\e",
        )

    def test_state_root_authority_rejects_owner_group_mode_and_inode_drift(self) -> None:
        base = {
            "descriptor_device": DEVICE,
            "descriptor_inode": 67,
            "path_device": DEVICE,
            "path_inode": 67,
            "path_owner_uid": CALLER_UID,
            "path_owner_gid": CALLER_GID,
            "path_mode": 0o700,
            "caller_uid": CALLER_UID,
            "caller_gid": CALLER_GID,
        }
        MODULE.validate_state_root_authority(**base)
        for field, value in (
            ("path_device", DEVICE + 1),
            ("path_inode", 68),
            ("path_owner_uid", CALLER_UID + 1),
            ("path_owner_gid", CALLER_GID + 1),
            ("path_mode", 0o770),
        ):
            with self.subTest(field=field):
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.validate_state_root_authority(
                        **{**base, field: value}
                    )

    def test_absent_nodes_cannot_smuggle_identity_fields(self) -> None:
        smuggled = MODULE.NodeFacts(kind="absent", owner_uid=0)
        for operation in ("prepare", "remove"):
            with self.subTest(operation=operation):
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.reduce_prefix_state(
                        MODULE.CapacityPrefixFacts(
                            state_root_device=DEVICE,
                            capacity=smuggled,
                            image=MODULE.absent_node(),
                        ),
                        operation=operation,
                        caller_uid=CALLER_UID,
                        caller_gid=CALLER_GID,
                        image_bytes=IMAGE_BYTES,
                    )

    def test_descriptor_relative_remove_closes_unlink_then_rmdir_prefixes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runner-lifecycle-test-") as directory:
            state_root = Path(directory)
            capacity_root = state_root / "capacity"
            capacity_root.mkdir(mode=0o700)
            image_path = capacity_root / "runner-docker.xfs"
            image_path.write_bytes(b"test")
            image_stat = image_path.stat()
            state_root_fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
            capacity_fd = os.open(
                "capacity",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=state_root_fd,
            )
            image_fd = os.open(
                "runner-docker.xfs",
                os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=capacity_fd,
            )
            prefix = MODULE.OpenPrefix(
                state_root_fd=state_root_fd,
                state_root_path=state_root,
                capacity_fd=capacity_fd,
                image_fd=image_fd,
                facts=MODULE.CapacityPrefixFacts(
                    state_root_device=image_stat.st_dev,
                    capacity=MODULE.facts_from_stat(capacity_root.stat()),
                    image=MODULE.facts_from_stat(image_stat),
                ),
            )
            with mock.patch.object(MODULE, "mounts_at_or_below", return_value=()), mock.patch.object(
                MODULE, "associated_loops", return_value=()
            ):
                MODULE.remove_objects(
                    prefix,
                    expected_device=image_stat.st_dev,
                    expected_inode=image_stat.st_ino,
                )
            self.assertFalse(capacity_root.exists())
            prefix.close()

    def test_foreign_observable_namespace_blocks_teardown_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="runner-lifecycle-mount-test-"
        ) as directory:
            state_root = Path(directory)
            image_path = state_root / "image"
            image_path.write_bytes(b"test")
            image_stat = image_path.stat()
            state_root_fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
            image_fd = os.open(image_path, os.O_RDWR | os.O_NOFOLLOW)
            prefix = MODULE.OpenPrefix(
                state_root_fd=state_root_fd,
                state_root_path=state_root,
                image_fd=image_fd,
                facts=MODULE.CapacityPrefixFacts(
                    state_root_device=image_stat.st_dev,
                    capacity=MODULE.absent_node(),
                    image=MODULE.facts_from_stat(image_stat),
                ),
            )
            target = str(state_root / "runner-docker")
            foreign_mount = MODULE.NamespaceMountOccurrence(
                namespace_id="47:9001",
                representative_pid=1234,
                target=target,
            )
            with mock.patch.object(
                MODULE, "associated_loops", return_value=("/dev/loop7",)
            ), mock.patch.object(
                MODULE,
                "observable_mounts_for_loop",
                return_value=(foreign_mount,),
            ), mock.patch.object(
                MODULE, "mounts_at_or_below", return_value=()
            ), mock.patch.object(
                MODULE, "mount_namespace_id", return_value="47:8001"
            ), mock.patch.object(MODULE, "run_tool") as run_tool:
                with self.assertRaises(MODULE.RunnerStorageLifecycleError):
                    MODULE.teardown_runtime(
                        prefix,
                        expected_device=image_stat.st_dev,
                        expected_inode=image_stat.st_ino,
                    )
                run_tool.assert_not_called()
            prefix.close()

    def test_unreadable_mount_namespace_roster_fails_closed(self) -> None:
        with mock.patch.object(
            MODULE.os, "listdir", side_effect=PermissionError("denied")
        ):
            with self.assertRaisesRegex(
                MODULE.RunnerStorageLifecycleError,
                "namespace roster is unreadable",
            ):
                MODULE.read_observable_mount_namespaces()

    def test_caller_owned_empty_capacity_is_sealed_before_image_creation(self) -> None:
        helper = SCRIPT.read_text()
        function_start = helper.index("def create_capacity_and_image(")
        seal = helper.index("os.fchown(prefix.capacity_fd, 0, 0)", function_start)
        closed_roster = helper.index("children = os.listdir(prefix.capacity_fd)", seal)
        image_create = helper.index("prefix.image_fd = os.open(", closed_roster)
        self.assertLess(seal, closed_roster)
        self.assertLess(closed_roster, image_create)
        self.assertIn("os.fchown(prefix.capacity_fd, caller_uid, caller_gid)", helper)

if __name__ == "__main__":
    unittest.main()
