from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-runner-storage.py")
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
        receipt = MODULE.validate_storage_observation(self.observation())
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
                MODULE.validate_storage_observation(candidate)
        candidate = self.observation()
        candidate["mountOptions"] = ["rw", "nodev", "nosuid"]
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_observation(candidate)
        candidate = self.observation()
        candidate["mountOptions"] = ["ro", "pquota", "nodev", "nosuid"]
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_observation(candidate)

    def test_capacity_identity_and_features_fail_closed(self) -> None:
        mutations = (
            ("imageLogicalBytes", 40 * 1024**3),
            ("imageMode", 0o644),
            ("filesystemFreeBytes", 39 * 1024**3),
            ("backingFilesystemFreeBytes", 59 * 1024**3),
            ("stateRootDevice", 48),
            ("filesystemUuid", "not-a-uuid"),
        )
        for field, value in mutations:
            candidate = self.observation()
            candidate[field] = value
            with self.assertRaises(MODULE.RunnerStorageError):
                MODULE.validate_storage_observation(candidate)
        candidate = self.observation()
        candidate["xfsFeatures"] = ["crc=1", "finobt=1", "ftype=1"]
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_observation(candidate)

    def test_extra_observation_fields_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.observation())
        candidate["unexpected"] = True
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_observation(candidate)


if __name__ == "__main__":
    unittest.main()
