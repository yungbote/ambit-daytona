from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-runner-storage.py")
LIFECYCLE = Path(__file__).with_name("runner-storage-lifecycle.py")
PREPARE = Path(__file__).with_name("prepare-runner-storage.sh")
REMOVE = Path(__file__).with_name("remove-runner-storage.sh")
HOST_GATE = Path(__file__).with_name("verify-host-capacity.sh")
SPEC = importlib.util.spec_from_file_location("ambit_verify_runner_storage", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("could not load verify-runner-storage.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class VerifyRunnerStorageTest(unittest.TestCase):
    def observation(self) -> dict[str, object]:
        state_root = "/home/example/ambit-daytona/state"
        return {
            "stateRoot": state_root,
            "observerUid": 1000,
            "observerGid": 100,
            "stateRootDevice": 47,
            "stateRootInode": 67,
            "stateRootMode": 0o700,
            "stateRootOwnerUid": 1000,
            "stateRootOwnerGid": 100,
            "authorityDevice": 47,
            "authorityInode": 71,
            "authorityMode": 0o700,
            "authorityOwnerUid": 0,
            "authorityOwnerGid": 0,
            "imageLogicalBytes": 60 * 1024**3,
            "imageAllocatedBytes": 512 * 1024**2,
            "imageDevice": 47,
            "imageInode": 73,
            "imageMode": 0o600,
            "imageOwnerUid": 0,
            "imageOwnerGid": 0,
            "mountTargetDevice": os.makedev(7, 7),
            "mountTargetInode": 79,
            "mountTargetMode": 0o700,
            "mountTargetOwnerUid": 0,
            "mountTargetOwnerGid": 0,
            "loopDevice": "/dev/loop7",
            "loopDeviceNumber": "7:7",
            "loopMountTargets": [str(MODULE.TARGET)],
            "targetMountTree": [str(MODULE.TARGET)],
            "backingFile": str(MODULE.IMAGE),
            "filesystemType": "xfs",
            "mountOptions": ["rw", "pquota", "nodev", "nosuid"],
            "filesystemUuid": "12345678-1234-1234-1234-123456789abc",
            "xfsFeatures": ["crc=1", "finobt=1", "ftype=1", "projid32bit=1"],
            "filesystemTotalBytes": 59 * 1024**3,
            "filesystemFreeBytes": 58 * 1024**3,
            "backingFilesystemTotalBytes": 1024 * 1024**3,
            "backingFilesystemFreeBytes": 700 * 1024**3,
            "mountNamespaceDevice": 4,
            "mountNamespaceInode": 4026533000,
        }

    def test_exact_private_namespace_xfs_identity_passes(self) -> None:
        receipt = MODULE.validate_storage_identity_observation(self.observation())
        self.assertEqual(receipt["schema"], "ambit.local-daytona-runner-storage/v2")
        self.assertEqual(receipt["lifecycleState"], "attached")
        self.assertEqual(
            receipt["authorityRoot"]["path"],
            "/home/.ambit-c16b-runner-storage",
        )
        self.assertEqual(
            receipt["mountTarget"]["path"],
            "/home/.ambit-c16b-runner-storage/runner-docker",
        )
        self.assertEqual(receipt["loop"], {"device": "/dev/loop7", "major": 7, "minor": 7})
        self.assertEqual(
            receipt["mountNamespace"],
            {"device": 4, "inode": 4026533000},
        )

    def test_legacy_user_owned_target_cannot_be_current_authority(self) -> None:
        candidate = self.observation()
        candidate["loopMountTargets"] = [f'{candidate["stateRoot"]}/runner-docker']
        candidate["targetMountTree"] = [f'{candidate["stateRoot"]}/runner-docker']
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)

    def test_mount_namespace_and_loop_device_substitution_fail(self) -> None:
        for field, value in (
            ("mountNamespaceInode", 4026533001),
            ("loopDeviceNumber", "7:8"),
            ("mountTargetDevice", os.makedev(7, 8)),
        ):
            with self.subTest(field=field):
                candidate = self.observation()
                candidate[field] = value
                if field == "mountNamespaceInode":
                    receipt = MODULE.validate_storage_identity_observation(candidate)
                    self.assertEqual(receipt["mountNamespace"]["inode"], value)
                else:
                    with self.assertRaises(MODULE.RunnerStorageError):
                        MODULE.validate_storage_identity_observation(candidate)

    def test_owner_mode_path_and_size_mutations_fail_closed(self) -> None:
        for field, value in (
            ("stateRootMode", 0o755),
            ("stateRootOwnerUid", 1001),
            ("authorityOwnerUid", 1000),
            ("authorityMode", 0o711),
            ("imageOwnerGid", 100),
            ("imageLogicalBytes", 59 * 1024**3),
            ("mountTargetMode", 0o755),
            ("backingFile", "/home/example/runner-docker.xfs"),
        ):
            with self.subTest(field=field):
                candidate = self.observation()
                candidate[field] = value
                with self.assertRaises(MODULE.RunnerStorageError):
                    MODULE.validate_storage_identity_observation(candidate)

    def test_capacity_exhaustion_and_backing_resize_remain_observations(self) -> None:
        exhausted = self.observation()
        exhausted["filesystemFreeBytes"] = 0
        exhausted["backingFilesystemFreeBytes"] = 0
        receipt = MODULE.validate_storage_identity_observation(exhausted)
        self.assertEqual(receipt["filesystem"]["freeBytes"], 0)
        self.assertEqual(receipt["backingFilesystem"]["freeBytes"], 0)
        resized = self.observation()
        resized["backingFilesystemTotalBytes"] += 128 * 1024**3
        resized_receipt = MODULE.validate_storage_identity_observation(resized)
        self.assertNotEqual(
            receipt["backingFilesystem"]["totalBytes"],
            resized_receipt["backingFilesystem"]["totalBytes"],
        )
        self.assertEqual(receipt["authorityRoot"], resized_receipt["authorityRoot"])

    def test_extra_fields_and_invalid_dynamic_ranges_fail(self) -> None:
        extra = self.observation()
        extra["unexpected"] = True
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(extra)
        for field, value in (
            ("filesystemFreeBytes", -1),
            ("backingFilesystemFreeBytes", -1),
            ("imageAllocatedBytes", -1),
        ):
            candidate = self.observation()
            candidate[field] = value
            with self.assertRaises(MODULE.RunnerStorageError):
                MODULE.validate_storage_identity_observation(candidate)

    def test_lifecycle_pins_exact_identity_verifier_bytes(self) -> None:
        expected = hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
        source = LIFECYCLE.read_text()
        match = re.search(r'^IDENTITY_VERIFIER_SHA256 = "([0-9a-f]{64})"$', source, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), expected)

    def test_remove_wrapper_pins_helper_under_isolated_python(self) -> None:
        helper_digest = hashlib.sha256(LIFECYCLE.read_bytes()).hexdigest()
        source = REMOVE.read_text()
        match = re.search(r"^lifecycle_helper_sha256=([0-9a-f]{64})$", source, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), helper_digest)
        self.assertIn("/usr/bin/python3 -I -S -B -c", source)
        self.assertIn("/usr/bin/env -i -C /", source)

    def test_host_prepare_wrapper_cannot_mount(self) -> None:
        source = PREPARE.read_text()
        self.assertIn("owned by start-isolated-docker.sh", source)
        for forbidden in ("sudo -n", "/usr/bin/mount", "losetup", "mkfs.xfs"):
            self.assertNotIn(forbidden, source)

    def test_host_gate_brackets_private_namespace_observation_with_v4_identity(self) -> None:
        source = HOST_GATE.read_text()
        self.assertIn('ambit.local-daytona-host-capacity-headroom/v4', source)
        self.assertIn('ambit.local-daytona-isolated-docker/v4', source)
        self.assertIn('ambit.local-daytona-runner-storage/v2', source)
        self.assertNotIn('ambit.local-daytona-host-capacity-headroom/v3', source)
        self.assertIn('/usr/bin/nsenter --mount="/proc/${supervisor_pid}/ns/mnt"', source)
        first_supervisor = source.index(
            'verify_process "${supervisor_identity}" /usr/bin/python3'
        )
        observation = source.index('storage_operation=$(', first_supervisor)
        second_supervisor = source.index(
            'verify_process "${supervisor_identity}" /usr/bin/python3',
            observation,
        )
        self.assertLess(first_supervisor, observation)
        self.assertLess(observation, second_supervisor)
        self.assertIn('runtime storage helper snapshot digest differs', source)
        self.assertIn('projection_receipt_sha256=', source)
        self.assertIn('projection payload digest differs', source)
        self.assertIn("trap 'exit 130' INT", source)
        self.assertIn("trap 'exit 143' TERM", source)


if __name__ == "__main__":
    unittest.main()
