from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("isolated_runtime_supervisor.py")
SPEC = importlib.util.spec_from_file_location("ambit_isolated_runtime_supervisor", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("could not load isolated runtime supervisor module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


NAMESPACE = {"device": 4, "inode": 19}
STATE_ROOT = Path("/home/example/ambit-state")
DIGEST = "a" * 64


def storage_operation(outcome: str = "activated") -> dict[str, object]:
    return {
        "schema": MODULE.STORAGE_OPERATION_SCHEMA,
        "outcome": outcome,
        "authorityRoot": str(MODULE.AUTHORITY_ROOT),
        "mountTarget": str(MODULE.MOUNT_TARGET),
        "mountNamespace": "4:19",
        "authorityReceiptSha256": DIGEST,
        "receipt": {
            "schema": MODULE.STORAGE_RECEIPT_SCHEMA,
            "lifecycleState": "detached" if outcome == "deactivated" else "attached",
            "stateRoot": str(STATE_ROOT),
            "stateRootIdentity": {
                "device": 8,
                "inode": 10,
                "ownerUid": 1000,
                "ownerGid": 1000,
                "mode": "0700",
            },
            "authorityRoot": {
                "path": str(MODULE.AUTHORITY_ROOT),
                "device": 8,
                "inode": 11,
                "ownerUid": 0,
                "ownerGid": 0,
                "mode": "0700",
            },
            "mountTarget": {
                "path": str(MODULE.MOUNT_TARGET),
                "device": 9,
                "inode": 12,
                "ownerUid": 0,
                "ownerGid": 0,
                "mode": "0700",
            },
            "image": {
                "path": str(MODULE.STORAGE_IMAGE),
                "device": 8,
                "inode": 13,
                "logicalBytes": 60 * 1024**3,
                "allocatedBytes": 1024**3,
                "ownerUid": 0,
                "ownerGid": 0,
                "mode": "0600",
            },
            "loop": (
                None
                if outcome == "deactivated"
                else {"device": "/dev/loop7", "major": 7, "minor": 7}
            ),
            "filesystem": {
                "type": "xfs",
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "mountOptions": ["nodev", "nosuid", "pquota", "rw"],
                "totalBytes": 60 * 1024**3,
                "freeBytes": 59 * 1024**3,
                "features": ["crc=1", "ftype=1"],
            },
            "mountNamespace": NAMESPACE,
            "backingFilesystem": {
                "device": 8,
                "totalBytes": 200 * 1024**3,
                "freeBytes": 100 * 1024**3,
                "allocationDisposition": "sparse_current_headroom_not_preallocated",
                "minimumFreeBytes": 60 * 1024**3,
            },
            "sandboxDiskPolicy": {
                "perSandboxBytes": 20 * 1024**3,
                "maximumSandboxes": 2,
                "aggregateBytes": 40 * 1024**3,
                "enforcement": "xfs_project_quota_required",
                "backingCapacity": "current_headroom_with_visible_enospc_failure",
            },
        },
    }


class RuntimeSupervisorPureContractTest(unittest.TestCase):
    def test_private_mountinfo_accepts_only_nonpropagating_records(self) -> None:
        private = (
            "36 25 0:31 / / rw,relatime - ext4 /dev/root rw\n"
            "37 36 0:32 / /proc rw,nosuid,nodev,noexec - proc proc rw\n"
        )
        self.assertTrue(MODULE.mountinfo_is_private(private))
        for optional in ("shared:1", "master:2", "propagate_from:3"):
            with self.subTest(optional=optional):
                with self.assertRaises(MODULE.SupervisorError):
                    MODULE.mountinfo_is_private(
                        f"36 25 0:31 / / rw,relatime {optional} - ext4 /dev/root rw\n"
                    )

    def test_storage_projection_is_strict_and_provider_neutral(self) -> None:
        normalized = MODULE.normalize_storage_operation(
            storage_operation(),
            expected_outcome="activated",
            state_root=STATE_ROOT,
            caller_uid=1000,
            caller_gid=1000,
            expected_namespace=NAMESPACE,
        )
        self.assertEqual(
            set(normalized),
            {
                "lifecycleSchema",
                "receiptSchema",
                "projectionDigest",
                "authorityRoot",
                "target",
                "image",
                "loop",
                "filesystem",
                "mountNamespace",
            },
        )
        self.assertEqual(normalized["projectionDigest"], DIGEST)
        self.assertEqual(normalized["filesystem"]["type"], "xfs")
        detached = MODULE.normalize_storage_operation(
            storage_operation("deactivated"),
            expected_outcome="deactivated",
            state_root=STATE_ROOT,
            caller_uid=1000,
            caller_gid=1000,
            expected_namespace=NAMESPACE,
        )
        self.assertIsNone(detached["loop"])

    def test_storage_projection_rejects_each_authority_substitution(self) -> None:
        mutations = {
            "old schema": lambda value: value.update(schema="v1"),
            "wrong outcome": lambda value: value.update(outcome="passed"),
            "wrong target": lambda value: value.update(mountTarget="/tmp/runner-docker"),
            "wrong namespace": lambda value: value.update(
                mountNamespace="4:20"
            ),
            "wrong digest": lambda value: value.update(authorityReceiptSha256="A" * 64),
            "foreign receipt field": lambda value: value["receipt"].update(extra=True),
            "wrong state": lambda value: value["receipt"].update(stateRoot="/home/other/state"),
            "wrong root mode": lambda value: value["receipt"]["authorityRoot"].update(
                mode="0711"
            ),
            "wrong target owner": lambda value: value["receipt"]["mountTarget"].update(
                ownerUid=1000
            ),
            "wrong image": lambda value: value["receipt"]["image"].update(inode=0),
            "wrong loop": lambda value: value["receipt"]["loop"].update(
                device="/dev/sda"
            ),
            "wrong filesystem": lambda value: value["receipt"]["filesystem"].update(
                type="ext4"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = storage_operation()
                mutate(value)
                with self.assertRaises(MODULE.SupervisorError):
                    MODULE.normalize_storage_operation(
                        value,
                        expected_outcome="activated",
                        state_root=STATE_ROOT,
                        caller_uid=1000,
                        caller_gid=1000,
                        expected_namespace=NAMESPACE,
                    )

    def test_task_netns_parser_admits_only_direct_nsfs_mounts(self) -> None:
        runtime_root = Path("/run/ambit-c16b-docker-0123456789ab")
        target = runtime_root / "docker-exec/netns/task-1"
        raw = f"42 36 0:35 / {target} rw - nsfs nsfs rw\n"
        self.assertEqual(MODULE.task_netns_mounts(runtime_root, raw), (target,))
        for candidate in (
            f"42 36 0:35 / {target}/nested rw - nsfs nsfs rw\n",
            f"42 36 0:35 / {target} rw - tmpfs tmpfs rw\n",
        ):
            with self.assertRaises(MODULE.SupervisorError):
                MODULE.task_netns_mounts(runtime_root, candidate)

    def test_pinned_loader_ignores_hostile_cwd_and_pythonpath(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "hashlib.py").write_text(
                "raise RuntimeError('hostile module imported')\n", encoding="utf-8"
            )
            source = directory / "payload.py"
            source.write_text(
                "import hashlib; print(hashlib.sha256(b'proof').hexdigest())\n",
                encoding="utf-8",
            )
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            result = subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    MODULE.PINNED_EXEC_LOADER,
                    str(source),
                    digest,
                ],
                cwd=directory,
                env={"PATH": str(directory), "PYTHONPATH": str(directory)},
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.stdout.strip(), hashlib.sha256(b"proof").hexdigest())


class FakeState:
    def __init__(self) -> None:
        self.entries = {
            MODULE.START_RECEIPT_NAME,
            MODULE.CONTROL_RECEIPT_NAME,
        }
        self.events: list[tuple[str, object]] = []

    def write_json(self, name: str, value: dict[str, object]) -> None:
        self.events.append(("write", (name, value["outcome"])))
        self.entries.add(name)

    def exists(self, name: str) -> bool:
        return name in self.entries

    def unlink_regular(self, name: str) -> None:
        self.events.append(("unlink", name))
        self.entries.remove(name)


class RuntimeSupervisorShutdownTest(unittest.TestCase):
    def supervisor(self) -> MODULE.RuntimeSupervisor:
        value = MODULE.RuntimeSupervisor(STATE_ROOT, 1000, 1000)
        value.state = FakeState()
        value.namespace = NAMESPACE
        value.storage = {"projectionDigest": DIGEST}
        value.supervisor_identity = {"pid": 44}
        value.runtime_identity = MODULE.RuntimeIdentity(
            Path("/run/ambit-c16b-docker-0123456789ab"), 1, 2, 0, 0o700
        )
        return value

    def test_shutdown_order_keeps_storage_until_daemons_and_netns_are_gone(self) -> None:
        supervisor = self.supervisor()
        events: list[str] = []
        supervisor.terminate_daemon = lambda name, process: events.append(name)
        supervisor.cleanup_task_netns = lambda: events.append("netns")
        supervisor.invoke_storage = lambda command, outcome: (
            events.append(command)
            or {
                "projectionDigest": DIGEST,
            }
        )
        with (
            mock.patch.object(MODULE, "require_exact_children", lambda expected: events.append("reaped")),
            mock.patch.object(MODULE, "remove_runtime_root", lambda identity: events.append("runtime")),
            mock.patch.object(MODULE, "current_boot_id", return_value="12345678-1234-1234-1234-123456789abc"),
        ):
            self.assertTrue(supervisor.try_shutdown("operator_request"))
        self.assertEqual(
            events,
            ["dockerd", "containerd", "reaped", "netns", "deactivate-private", "runtime"],
        )
        self.assertEqual(
            supervisor.state.events,
            [
                ("write", (MODULE.STOP_RECEIPT_NAME, "passed")),
                ("unlink", MODULE.START_RECEIPT_NAME),
                ("unlink", MODULE.CONTROL_RECEIPT_NAME),
            ],
        )

    def test_failed_deactivation_keeps_control_receipts_and_supervisor_retryable(self) -> None:
        supervisor = self.supervisor()
        supervisor.terminate_daemon = lambda name, process: None
        supervisor.cleanup_task_netns = lambda: None

        def fail_deactivation(command: str, outcome: str) -> dict[str, object]:
            raise MODULE.SupervisorError("mount still busy")

        supervisor.invoke_storage = fail_deactivation
        with (
            mock.patch.object(MODULE, "require_exact_children"),
            mock.patch.object(MODULE, "current_boot_id", return_value="12345678-1234-1234-1234-123456789abc"),
        ):
            self.assertFalse(supervisor.try_shutdown("operator_request"))
        self.assertIn(MODULE.START_RECEIPT_NAME, supervisor.state.entries)
        self.assertIn(MODULE.CONTROL_RECEIPT_NAME, supervisor.state.entries)
        self.assertIn(
            ("write", (MODULE.STOP_RECEIPT_NAME, "retry_required")),
            supervisor.state.events,
        )


class RuntimeSupervisorSourceBoundaryTest(unittest.TestCase):
    def test_daemons_are_foreground_direct_children_and_never_sudo_background_jobs(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("sudo -b", source)
        self.assertNotIn("start_new_session=True", source)
        self.assertIn("self.containerd_process = subprocess.Popen(", source)
        self.assertIn("self.docker_process = subprocess.Popen(", source)
        self.assertIn("expected_parent_pid=os.getpid()", source)
        self.assertLess(
            source.index('self.invoke_storage("activate-private", "activated")'),
            source.index("self.start_daemons()"),
        )
        shutdown = source.index("def try_shutdown")
        self.assertLess(
            source.index('self.terminate_daemon("dockerd"', shutdown),
            source.index('self.terminate_daemon("containerd"', shutdown),
        )
        self.assertLess(
            source.index("self.cleanup_task_netns()", shutdown),
            source.index('self.invoke_storage("deactivate-private"', shutdown),
        )


if __name__ == "__main__":
    unittest.main()
