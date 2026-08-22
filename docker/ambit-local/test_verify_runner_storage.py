from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-runner-storage.py")
LIFECYCLE = Path(__file__).with_name("runner-storage-lifecycle.py")
PREPARE = Path(__file__).with_name("prepare-runner-storage.sh")
REMOVE = Path(__file__).with_name("remove-runner-storage.sh")
HOST_GATE = Path(__file__).with_name("verify-host-capacity.sh")
HOST_GATE_EXECUTABLES = (
    "/usr/bin/awk",
    "/usr/bin/bash",
    "/usr/bin/chmod",
    "/usr/bin/containerd",
    "/usr/bin/date",
    "/usr/bin/dirname",
    "/usr/bin/docker",
    "/usr/bin/dockerd",
    "/usr/bin/env",
    "/usr/bin/id",
    "/usr/bin/jq",
    "/usr/bin/mktemp",
    "/usr/bin/mv",
    "/usr/bin/nproc",
    "/usr/bin/nsenter",
    "/usr/bin/python3",
    "/usr/bin/realpath",
    "/usr/bin/sed",
    "/usr/bin/sha256sum",
    "/usr/bin/stat",
    "/usr/bin/sudo",
    "/usr/bin/unlink",
)
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

    def test_host_gate_uses_only_exact_validated_evidence_tools(self) -> None:
        source = HOST_GATE.read_text()
        self.assertEqual(source.splitlines()[0], "#!/usr/bin/bash -p")
        sanitization = source.index("unset BASH_ENV ENV CDPATH GLOBIGNORE")
        argument_validation = source.index("if [[ $# -ne 2 ]]")
        self.assertLess(sanitization, argument_validation)
        self.assertIn("PATH=/usr/bin:/bin", source[:argument_validation])
        trusted_start = source.index("trusted_executables=(")
        trusted_end = source.index(")\nfor executable", trusted_start)
        trusted = source[trusted_start:trusted_end]
        self.assertEqual(
            set(re.findall(r"/usr/bin/[A-Za-z0-9._-]+", source)),
            set(HOST_GATE_EXECUTABLES),
        )
        for executable in HOST_GATE_EXECUTABLES:
            with self.subTest(executable=executable):
                self.assertIn(f"  {executable}\n", trusted)
        for caller_resolved_invocation in (
            "$(nproc)",
            "$(awk ",
            "| awk ",
            "| sed ",
            "| jq ",
            "$(mktemp ",
            "$(dirname ",
            "$(date ",
            "\nchmod ",
            "\nmv ",
            "\nunlink ",
        ):
            with self.subTest(invocation=caller_resolved_invocation):
                self.assertNotIn(caller_resolved_invocation, source)
        self.assertIn(
            "PATH=/usr/bin:/bin LC_ALL=C.UTF-8 /usr/bin/nproc",
            source,
        )
        self.assertIn(
            "/usr/bin/awk '$1 == \"MemAvailable:\" { print $2 }' /proc/meminfo",
            source,
        )
        self.assertIn("| /usr/bin/sed '/^$/d' | /usr/bin/jq -R .", source)
        self.assertIn("temporary=$(/usr/bin/mktemp --", source)
        self.assertIn("/usr/bin/chmod 0600", source)
        self.assertIn("/usr/bin/mv --no-copy --update=none-fail -T --", source)
        self.assertIn("/usr/bin/unlink --", source)
        self.assertIn("TZ=UTC /usr/bin/date -u", source)
        self.assertIn(
            'DOCKER_HOST="${DOCKER_HOST}" /usr/bin/docker info',
            source,
        )

    @staticmethod
    def _write_hostile_path(hostile_path: Path, marker: Path) -> None:
        hostile_path.mkdir(mode=0o700)
        marker_argument = shlex.quote(str(marker))
        for executable in HOST_GATE_EXECUTABLES:
            utility = Path(executable).name
            candidate = hostile_path / utility
            candidate.write_text(
                "#!/usr/bin/bash -p\n"
                f"printf '%s\\n' {shlex.quote(utility)} >> {marker_argument}\n"
                "printf '%s\\n' 999999999999\n"
            )
            candidate.chmod(0o755)

    def test_hostile_path_and_bash_env_cannot_preempt_gate_validation(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".ambit-host-gate-path-", dir=Path.home()
        ) as temporary:
            state_root = Path(temporary)
            evidence_root = state_root / "evidence"
            evidence_root.mkdir(mode=0o700)
            state_root.chmod(0o700)
            hostile_path = state_root / "hostile-bin"
            marker = state_root / "hostile-command-ran"
            self._write_hostile_path(hostile_path, marker)
            bash_env = state_root / "bash-env"
            bash_env.write_text(
                f"printf '%s\\n' BASH_ENV >> {shlex.quote(str(marker))}\n"
            )
            output = evidence_root / "host-capacity.json"
            completed = subprocess.run(
                [str(HOST_GATE.resolve()), str(state_root), str(output)],
                check=False,
                capture_output=True,
                text=True,
                env={
                    "PATH": str(hostile_path),
                    "BASH_ENV": str(bash_env),
                    "ENV": str(bash_env),
                    "BASH_FUNC_echo%%": (
                        "() { printf '%s\\n' EXPORTED_FUNCTION >> "
                        f"{shlex.quote(str(marker))}; }}"
                    ),
                    "DOCKER_HOST": "unix:///fabricated/docker.sock",
                },
            )
            self.assertEqual(completed.returncode, 66, completed.stderr)
            self.assertIn("required receipt authority differs", completed.stderr)
            self.assertFalse(marker.exists())
            self.assertFalse(output.exists())
            cpu = subprocess.run(
                [
                    "/usr/bin/env",
                    "-i",
                    "-C",
                    "/",
                    "PATH=/usr/bin:/bin",
                    "LC_ALL=C.UTF-8",
                    "/usr/bin/nproc",
                ],
                check=True,
                capture_output=True,
                text=True,
                env={
                    "PATH": str(hostile_path),
                    "OMP_NUM_THREADS": "999999999999",
                },
            )
            self.assertRegex(cpu.stdout.strip(), r"^[1-9][0-9]*$")
            self.assertNotEqual(cpu.stdout.strip(), "999999999999")
            memory = subprocess.run(
                [
                    "/usr/bin/env",
                    "-i",
                    "-C",
                    "/",
                    "PATH=/usr/bin:/bin",
                    "LC_ALL=C.UTF-8",
                    "/usr/bin/awk",
                    '$1 == "MemAvailable:" { print $2 }',
                    "/proc/meminfo",
                ],
                check=True,
                capture_output=True,
                text=True,
                env={"PATH": str(hostile_path)},
            )
            self.assertRegex(memory.stdout.strip(), r"^[0-9]+$")
            self.assertNotEqual(memory.stdout.strip(), "999999999999")
            self.assertFalse(marker.exists())
            pending = evidence_root / ".host-capacity.pending"
            pending.write_text("measured receipt\n")
            output.write_text("racing substitute\n")
            no_clobber = subprocess.run(
                [
                    "/usr/bin/mv",
                    "--no-copy",
                    "--update=none-fail",
                    "-T",
                    "--",
                    str(pending),
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": str(hostile_path)},
            )
            self.assertNotEqual(no_clobber.returncode, 0)
            self.assertEqual(output.read_text(), "racing substitute\n")
            self.assertEqual(pending.read_text(), "measured receipt\n")
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
