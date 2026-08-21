from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-runner-storage.py")
PREPARE_SCRIPT = Path(__file__).with_name("prepare-runner-storage.sh")
REMOVE_SCRIPT = Path(__file__).with_name("remove-runner-storage.sh")
HOST_GATE_SCRIPT = Path(__file__).with_name("verify-host-capacity.sh")
LIFECYCLE_HELPER_SCRIPT = Path(__file__).with_name("runner-storage-lifecycle.py")
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
            "capacityMode": 0o711,
            "capacityOwnerUid": 0,
            "capacityOwnerGid": 0,
            "capacityDevice": 47,
            "capacityInode": 73,
            "filesystemType": "xfs",
            "mountOptions": ["rw", "pquota", "nodev", "nosuid"],
            "imageLogicalBytes": 60 * 1024**3,
            "imageAllocatedBytes": 512 * 1024**2,
            "imageMode": 0o600,
            "imageOwnerUid": 0,
            "imageOwnerGid": 0,
            "imageDevice": 47,
            "imageInode": 89,
            "stateRootDevice": 47,
            "targetMountTree": [f"{state_root}/runner-docker"],
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
            ("capacityMode", 0o700),
            ("capacityOwnerUid", 1000),
            ("capacityOwnerGid", 1000),
            ("imageOwnerGid", 1000),
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

    def test_nested_or_foreign_target_mount_is_rejected(self) -> None:
        candidate = self.observation()
        candidate["targetMountTree"] = [
            candidate["mountTarget"],
            f'{candidate["mountTarget"]}/nested',
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
        existing_state = prepare.index("existing_published_candidate)")
        mounted_observation = prepare.index(
            "mount_observation=$(target_mount_observation)", existing_state
        )
        mounted_branch = prepare.index("if (( mounts > 0 )); then", mounted_observation)
        recovery = prepare.index("recover-and-mount", mounted_branch)
        self.assertLess(mounted_branch, recovery)
        helper = LIFECYCLE_HELPER_SCRIPT.read_text()
        self.assertIn("require_target_ready(prefix.state_root_fd", helper)

    def test_lifecycle_mutation_is_serialized_on_the_state_root_descriptor(self) -> None:
        prepare = PREPARE_SCRIPT.read_text()
        remove = REMOVE_SCRIPT.read_text()
        self.assertLess(
            prepare.index('flock -x "${lifecycle_fd}"'),
            prepare.index("inspection=$(inspect_state prepare)"),
        )
        self.assertLess(
            remove.index('flock -x "${lifecycle_fd}"'),
            remove.index("inspection=$(inspect_state)"),
        )
        host_gate = HOST_GATE_SCRIPT.read_text()
        self.assertLess(
            host_gate.index('flock -s "${lifecycle_fd}"'),
            host_gate.index('runner_storage=$(python3 "${runner_storage_tool}"'),
        )

    def test_int_and_term_exit_then_run_cleanup_exactly_once(self) -> None:
        prepare = PREPARE_SCRIPT.read_text()
        self.assertIn("trap cleanup_failed_prepare EXIT", prepare)
        self.assertIn("trap 'exit 130' INT", prepare)
        self.assertIn("trap 'exit 143' TERM", prepare)
        self.assertNotIn("trap cleanup_failed_prepare EXIT INT TERM", prepare)
        for signal, expected_status in (("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signal):
                result = subprocess.run(
                    [
                        "bash",
                        "-c",
                        f"""
cleanup() {{
  trap - EXIT INT TERM
  printf 'cleanup\\n'
}}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
kill -{signal} $$
printf 'continued\\n'
""",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, expected_status)
                self.assertEqual(result.stdout, "cleanup\n")

    def test_created_image_descriptor_remains_pinned_through_privileged_use(self) -> None:
        helper = LIFECYCLE_HELPER_SCRIPT.read_text()
        create = helper.index("prefix.image_fd = os.open(")
        truncate = helper.index("os.ftruncate(prefix.image_fd", create)
        chown = helper.index("os.fchown(prefix.image_fd", truncate)
        mkfs = helper.index('"mkfs.xfs"', chown)
        attach = helper.index("attach_image(prefix.image_fd)", mkfs)
        lifecycle_steps = [create, truncate, chown, mkfs, attach]
        self.assertEqual(lifecycle_steps, sorted(lifecycle_steps))
        self.assertIn('image_handle = f"/proc/self/fd/{prefix.image_fd}"', helper)

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
        teardown = remove.index("invoke_state_transition teardown-runtime")
        object_removal = remove.index("invoke_state_transition remove-objects")
        self.assertLess(teardown, object_removal)
        helper = LIFECYCLE_HELPER_SCRIPT.read_text()
        global_proof = helper.index('require(targets == (str(target),)')
        unmount = helper.index('run_tool("umount"', global_proof)
        self.assertLess(global_proof, unmount)

    def test_remove_confines_prepublication_crash_recovery(self) -> None:
        prepare = PREPARE_SCRIPT.read_text()
        remove = REMOVE_SCRIPT.read_text()
        helper = LIFECYCLE_HELPER_SCRIPT.read_text()
        for wrapper in (prepare, remove):
            for forbidden in (
                "sudo -n chown",
                "sudo -n chmod",
                "sudo -n mkfs",
                "sudo -n losetup",
                "sudo -n mount",
                "sudo -n umount",
                'sudo -n unlink -- "${image}"',
                "sudo -n rmdir",
            ):
                self.assertNotIn(forbidden, wrapper)
        self.assertIn("os.unlink(IMAGE_NAME, dir_fd=prefix.capacity_fd)", helper)
        self.assertIn("os.rmdir(CAPACITY_NAME, dir_fd=prefix.state_root_fd)", helper)
        self.assertIn("*_incomplete_prepublication", remove)
        self.assertIn("receipt_present} == false", remove)

    def test_wrappers_pin_and_execute_only_the_exact_helper_bytes(self) -> None:
        helper_sha256 = hashlib.sha256(LIFECYCLE_HELPER_SCRIPT.read_bytes()).hexdigest()
        launcher_pattern = re.compile(
            r"sudo -n python3 -c '\n(?P<program>.*?)\n' \"\$\{lifecycle_helper\}",
            re.DOTALL,
        )
        launchers: list[str] = []
        for wrapper_path in (PREPARE_SCRIPT, REMOVE_SCRIPT):
            wrapper = wrapper_path.read_text()
            digest_match = re.search(
                r"^lifecycle_helper_sha256=([0-9a-f]{64})$", wrapper, re.MULTILINE
            )
            self.assertIsNotNone(digest_match)
            self.assertEqual(digest_match.group(1), helper_sha256)
            launcher_match = launcher_pattern.search(wrapper)
            self.assertIsNotNone(launcher_match)
            launcher = launcher_match.group("program")
            self.assertLess(launcher.index("os.O_NOFOLLOW"), launcher.index("hashlib.sha256"))
            self.assertLess(
                launcher.index("hmac.compare_digest"), launcher.index("exec(compile")
            )
            launchers.append(launcher)
        self.assertEqual(launchers[0], launchers[1])

        accepted = subprocess.run(
            [
                sys.executable,
                "-c",
                launchers[0],
                str(LIFECYCLE_HELPER_SCRIPT),
                helper_sha256,
                "--help",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("create-and-mount", accepted.stdout)
        rejected = subprocess.run(
            [
                sys.executable,
                "-c",
                launchers[0],
                str(LIFECYCLE_HELPER_SCRIPT),
                "0" * 64,
                "--help",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("helper digest differs", rejected.stderr)

    def test_extra_observation_fields_are_rejected(self) -> None:
        candidate = copy.deepcopy(self.observation())
        candidate["unexpected"] = True
        with self.assertRaises(MODULE.RunnerStorageError):
            MODULE.validate_storage_identity_observation(candidate)


if __name__ == "__main__":
    unittest.main()
