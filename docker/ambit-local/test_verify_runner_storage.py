from __future__ import annotations

import copy
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-runner-storage.py")
PREPARE_SCRIPT = Path(__file__).with_name("prepare-runner-storage.sh")
REMOVE_SCRIPT = Path(__file__).with_name("remove-runner-storage.sh")
HOST_GATE_SCRIPT = Path(__file__).with_name("verify-host-capacity.sh")
SPEC = importlib.util.spec_from_file_location("ambit_verify_runner_storage", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("could not load verify-runner-storage.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VerifyRunnerStorageTest(unittest.TestCase):
    def observation(self) -> dict[str, object]:
        state_root = "/home/example/ambit-daytona/state"
        image = f"{state_root}/capacity/runner-docker.xfs"
        return {
            "stateRoot": state_root,
            "mountTarget": f"{state_root}/runner-docker",
            "imagePath": image,
            "loopDevice": "/dev/loop7",
            "loopMountTargets": [f"{state_root}/runner-docker"],
            "backingFile": image,
            "backingFilesystemFreeBytes": 700 * 1024**3,
            "backingFilesystemTotalBytes": 1024 * 1024**3,
            "filesystemType": "xfs",
            "mountOptions": ["rw", "pquota", "nodev", "nosuid"],
            "imageLogicalBytes": 60 * 1024**3,
            "imageAllocatedBytes": 512 * 1024**2,
            "imageMode": 0o600,
            "imageOwnerUid": 0,
            "imageDevice": 47,
            "imageInode": 89,
            "stateRootDevice": 47,
            "filesystemTotalBytes": 59 * 1024**3,
            "filesystemFreeBytes": 58 * 1024**3,
            "filesystemUuid": "12345678-1234-1234-1234-123456789abc",
            "xfsFeatures": ["crc=1", "finobt=1", "ftype=1", "projid32bit=1"],
        }

    def test_exact_xfs_project_quota_observation_passes(self) -> None:
        receipt = MODULE.validate_storage_identity_observation(self.observation())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["sandboxDiskPolicy"]["perSandboxBytes"], 20 * 1024**3)
        self.assertEqual(receipt["sandboxDiskPolicy"]["maximumSandboxes"], 2)

    def test_wrong_filesystem_backing_and_quota_are_rejected(self) -> None:
        for field, value in (
            ("filesystemType", "ext4"),
            ("backingFile", "/home/example/other.xfs"),
            ("loopDevice", "/dev/nvme0n1p4"),
        ):
            candidate = self.observation()
            candidate[field] = value
            with self.assertRaises(MODULE.RunnerStorageError):
                MODULE.validate_storage_identity_observation(candidate)
        candidate = self.observation()
        candidate["mountOptions"] = ["rw", "nodev", "nosuid"]
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)
        candidate = self.observation()
        candidate["mountOptions"] = ["ro", "pquota", "nodev", "nosuid"]
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)

    def test_identity_and_features_fail_closed(self) -> None:
        mutations = (
            ("imageLogicalBytes", 40 * 1024**3),
            ("imageMode", 0o644),
            ("stateRootDevice", 48),
            ("filesystemUuid", "not-a-uuid"),
        )
        for field, value in mutations:
            candidate = self.observation()
            candidate[field] = value
            with self.assertRaises(MODULE.RunnerStorageError):
                MODULE.validate_storage_identity_observation(candidate)
        candidate = self.observation()
        candidate["xfsFeatures"] = ["crc=1", "finobt=1", "ftype=1"]
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)

    def test_dynamic_capacity_exhaustion_does_not_change_storage_identity(self) -> None:
        candidate = self.observation()
        candidate["filesystemFreeBytes"] = 0
        candidate["backingFilesystemFreeBytes"] = 0
        candidate["imageAllocatedBytes"] = candidate["imageLogicalBytes"] + 1024**2
        receipt = MODULE.validate_storage_identity_observation(candidate)
        self.assertEqual(receipt["filesystem"]["freeBytes"], 0)
        self.assertEqual(receipt["backingFilesystem"]["freeBytes"], 0)

    def test_second_global_loop_mount_is_rejected(self) -> None:
        candidate = self.observation()
        candidate["loopMountTargets"] = [
            candidate["mountTarget"],
            "/home/example/foreign-runner-docker",
        ]
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)

    def test_invalid_dynamic_observation_ranges_fail_closed(self) -> None:
        for field, value in (
            ("filesystemFreeBytes", -1),
            ("backingFilesystemFreeBytes", -1),
            ("imageAllocatedBytes", -1),
        ):
            candidate = self.observation()
            candidate[field] = value
            with self.assertRaises(MODULE.RunnerStorageError):
                MODULE.validate_storage_identity_observation(candidate)
        candidate = self.observation()
        candidate["filesystemFreeBytes"] = candidate["filesystemTotalBytes"] + 1
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)
        candidate = self.observation()
        candidate["backingFilesystemFreeBytes"] = (
            candidate["backingFilesystemTotalBytes"] + 1
        )
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)

    def test_dynamic_readiness_thresholds_are_owned_only_by_host_gate(self) -> None:
        host_gate = HOST_GATE_SCRIPT.read_text()
        verifier = SCRIPT.read_text()
        self.assertIn(
            "runner_storage_filesystem_free_bytes >= required_storage", host_gate
        )
        self.assertIn("storage_available_bytes >= minimum_storage", host_gate)
        self.assertNotIn(
            'value["filesystemFreeBytes"] >= AGGREGATE_SANDBOX_BYTES', verifier
        )
        self.assertNotIn(
            'value["backingFilesystemFreeBytes"] >= IMAGE_BYTES', verifier
        )
        self.assertNotIn('df -PB1 "${state_root}"', host_gate)

    def test_mounted_recovery_precedes_underlying_target_emptiness_check(self) -> None:
        prepare = PREPARE_SCRIPT.read_text()
        existing_state = prepare.index('if [[ -e ${image} || -L ${image}')
        mounted_observation = prepare.index(
            'select_target_mount_sources "${target}"', existing_state
        )
        mounted_recovery = prepare.index(
            'if [[ ${#target_mount_sources[@]} -gt 0 ]]; then', mounted_observation
        )
        unmounted_target_proof = prepare.index(
            "  prove_unmounted_empty_target", mounted_recovery
        )
        self.assertLess(mounted_recovery, unmounted_target_proof)

    def test_lifecycle_mutation_is_serialized_on_the_state_root_descriptor(self) -> None:
        prepare = PREPARE_SCRIPT.read_text()
        remove = REMOVE_SCRIPT.read_text()
        self.assertLess(
            prepare.index('flock -x "${lifecycle_fd}"'),
            prepare.index('if [[ -e ${image} || -L ${image}'),
        )
        self.assertLess(
            remove.index('flock -x "${lifecycle_fd}"'),
            remove.index('associated_output=$(sudo -n losetup'),
        )

    def test_created_image_descriptor_remains_pinned_through_privileged_use(self) -> None:
        prepare = PREPARE_SCRIPT.read_text()
        create = prepare.index('exec {image_fd}>"${image}"')
        truncate = prepare.index('python3 - "${image_handle}"', create)
        chown = prepare.index('chown root:root -- "${capacity_handle}" "${image_handle}"')
        mkfs = prepare.index('mkfs.xfs', chown)
        attach = prepare.index('losetup --find --show --nooverlap "${image_handle}"')
        lifecycle_steps = [create, truncate, chown, mkfs, attach]
        self.assertEqual(lifecycle_steps, sorted(lifecycle_steps))
        self.assertNotIn('exec {image_fd}<>"${image}"', prepare)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runner-docker.xfs"
            replacement = Path(directory) / "replacement"
            with path.open("xb") as pinned:
                replacement.write_bytes(b"replacement")
                os.replace(replacement, path)
                os.ftruncate(pinned.fileno(), 4096)
                self.assertNotEqual(os.fstat(pinned.fileno()).st_ino, path.stat().st_ino)
                self.assertEqual(path.read_bytes(), b"replacement")

    def test_remove_proves_single_global_mount_before_exact_target_unmount(self) -> None:
        remove = REMOVE_SCRIPT.read_text()
        live_identity = remove.index('current=$(python3 "${verifier}" "${state_root}")')
        unmount = remove.index('sudo -n umount -- "${target}"')
        self.assertLess(live_identity, unmount)
        self.assertNotIn('umount -- "${loop_device}"', remove)

    def test_remove_confines_prepublication_crash_recovery(self) -> None:
        remove = REMOVE_SCRIPT.read_text()
        unpublished_identity = remove.index(
            '${capacity_mode}:${image_mode} == 700:600'
        )
        no_loop_or_mount = remove.index(
            'runner storage unpublished image unexpectedly reached a loop or mount'
        )
        delete = remove.index('sudo -n unlink -- "${image}"')
        self.assertLess(unpublished_identity, no_loop_or_mount)
        self.assertLess(no_loop_or_mount, delete)

    def test_extra_observation_fields_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.observation())
        candidate["unexpected"] = True
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)


if __name__ == "__main__":
    unittest.main()
