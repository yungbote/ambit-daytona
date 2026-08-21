from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
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
                "device": os.makedev(7, 7),
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
    def test_dockerd_managed_0710_data_root_is_the_stable_recovery_mode(self) -> None:
        before = os.stat_result((stat.S_IFDIR | 0o700, 2, 3, 1, 0, 0, 0, 0, 0, 0))
        after = os.stat_result((stat.S_IFDIR | 0o710, 2, 3, 1, 0, 0, 0, 0, 0, 0))
        with (
            mock.patch.object(MODULE.os, "mkdir", side_effect=FileExistsError),
            mock.patch.object(MODULE.os, "open", return_value=41),
            mock.patch.object(MODULE.os, "fstat", side_effect=(before, after)),
            mock.patch.object(MODULE.os, "fchmod") as fchmod,
            mock.patch.object(MODULE.os, "fsync"),
            mock.patch.object(MODULE.os, "close"),
        ):
            path = MODULE.ensure_storage_directory(
                40,
                "outer-docker",
                required_mode=0o710,
                recoverable_modes={0o700, 0o710},
            )
        self.assertEqual(path, MODULE.MOUNT_TARGET / "outer-docker")
        fchmod.assert_called_once_with(41, 0o710)

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

    def test_address_pool_proof_is_dual_stack_and_fails_on_ambiguous_routes(self) -> None:
        networks = MODULE.read_route_networks(
            json.dumps([{"dst": "2001:db8::/32"}, {"dst": "10.0.0.0/8"}])
        )
        self.assertEqual(tuple(value.version for value in networks), (6, 4))
        with self.assertRaises(MODULE.SupervisorError):
            MODULE.read_route_networks(json.dumps([{"dst": "not-a-network"}]))

        def overlapping(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps([{"dst": "172.30.42.0/24"}]),
                stderr="",
            )

        with self.assertRaises(MODULE.SupervisorError):
            MODULE.require_address_pool_available(overlapping)

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
        unpublished = storage_operation("deactivated")
        unpublished["receipt"] = None
        unpublished["authorityReceiptSha256"] = None
        with self.assertRaises(MODULE.SupervisorError):
            MODULE.normalize_storage_operation(
                unpublished,
                expected_outcome="deactivated",
                state_root=STATE_ROOT,
                caller_uid=1000,
                caller_gid=1000,
                expected_namespace=NAMESPACE,
            )
        aborted = MODULE.normalize_storage_operation(
            unpublished,
            expected_outcome="deactivated",
            state_root=STATE_ROOT,
            caller_uid=1000,
            caller_gid=1000,
            expected_namespace=NAMESPACE,
            allow_unpublished=True,
        )
        self.assertIsNone(aborted["projectionDigest"])
        self.assertIsNone(aborted["receiptSchema"])

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
        other = runtime_root / "containerd-state/residual"
        mixed = (
            f"42 36 0:35 / {target} rw - nsfs nsfs rw\n"
            f"43 36 0:36 / {other} rw - tmpfs tmpfs rw\n"
        )
        self.assertEqual(
            MODULE.mount_targets_below(runtime_root, mixed),
            (target, other),
        )

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
        value.storage_activation_attempted = True
        value.supervisor_identity = {"pid": 44}
        value.runtime_identity = MODULE.RuntimeIdentity(
            Path("/run/ambit-c16b-docker-0123456789ab"), 1, 2, 0, 0o700
        )
        return value

    def test_shutdown_order_keeps_storage_until_daemons_and_netns_are_gone(self) -> None:
        supervisor = self.supervisor()
        events: list[str] = []
        supervisor.write_control_receipt = lambda outcome="active": events.append(
            f"control-{outcome}"
        )
        supervisor.terminate_daemon = lambda name, process: events.append(name)
        supervisor.cleanup_task_netns = lambda: events.append("netns")
        supervisor.invoke_storage = lambda command, outcome, **kwargs: (
            events.append(command)
            or {
                "projectionDigest": DIGEST,
            }
        )
        with (
            mock.patch.object(
                MODULE,
                "wait_for_adopted_children",
                lambda expected: events.append("reaped"),
            ),
            mock.patch.object(MODULE, "remove_runtime_root", lambda identity: events.append("runtime")),
            mock.patch.object(MODULE, "current_boot_id", return_value="12345678-1234-1234-1234-123456789abc"),
        ):
            self.assertTrue(supervisor.try_shutdown("operator_request"))
        self.assertEqual(
            events,
            [
                "control-stopping",
                "dockerd",
                "containerd",
                "reaped",
                "netns",
                "deactivate-private",
                "runtime",
            ],
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
        supervisor.write_control_receipt = lambda outcome="active": None

        def fail_deactivation(
            command: str, outcome: str, **kwargs: object
        ) -> dict[str, object]:
            raise MODULE.SupervisorError("mount still busy")

        supervisor.invoke_storage = fail_deactivation
        with (
            mock.patch.object(MODULE, "wait_for_adopted_children"),
            mock.patch.object(MODULE, "current_boot_id", return_value="12345678-1234-1234-1234-123456789abc"),
        ):
            self.assertFalse(supervisor.try_shutdown("operator_request"))
        self.assertIn(MODULE.START_RECEIPT_NAME, supervisor.state.entries)
        self.assertIn(MODULE.CONTROL_RECEIPT_NAME, supervisor.state.entries)
        self.assertIn(
            ("write", (MODULE.STOP_RECEIPT_NAME, "retry_required")),
            supervisor.state.events,
        )

    def test_adopted_mutator_guardian_is_waited_and_reaped_without_a_signal(self) -> None:
        with (
            mock.patch.object(
                MODULE,
                "direct_children",
                side_effect=((41, 99), (41,)),
            ),
            mock.patch.object(MODULE.os, "waitpid", return_value=(99, 0)) as waitpid,
            mock.patch.object(MODULE.time, "sleep") as sleep,
            mock.patch.object(MODULE.os, "kill") as kill,
        ):
            MODULE.wait_for_adopted_children({41})
        waitpid.assert_called_once_with(99, os.WNOHANG)
        sleep.assert_not_called()
        kill.assert_not_called()

    def test_retry_after_later_cleanup_failure_does_not_repeat_deactivation(self) -> None:
        supervisor = self.supervisor()
        supervisor.terminate_daemon = lambda name, process: None
        supervisor.cleanup_task_netns = lambda: None
        supervisor.write_control_receipt = lambda outcome="active": None
        storage_calls: list[str] = []
        supervisor.invoke_storage = lambda command, outcome, **kwargs: (
            storage_calls.append(command) or {"projectionDigest": "b" * 64}
        )
        remove_calls = 0

        def remove_runtime(identity: object) -> None:
            nonlocal remove_calls
            remove_calls += 1
            if remove_calls == 1:
                raise MODULE.SupervisorError("runtime busy")

        with (
            mock.patch.object(MODULE, "wait_for_adopted_children"),
            mock.patch.object(MODULE, "remove_runtime_root", remove_runtime),
            mock.patch.object(
                MODULE,
                "current_boot_id",
                return_value="12345678-1234-1234-1234-123456789abc",
            ),
        ):
            self.assertFalse(supervisor.try_shutdown("operator_request"))
            self.assertTrue(supervisor.try_shutdown("operator_request"))
        self.assertEqual(storage_calls, ["deactivate-private"])
        self.assertEqual(remove_calls, 2)

    def test_pre_activation_failure_cleans_runtime_without_inventing_storage(self) -> None:
        supervisor = self.supervisor()
        supervisor.storage = None
        supervisor.storage_activation_attempted = False
        events: list[str] = []
        supervisor.write_control_receipt = lambda outcome="active": events.append(
            f"control-{outcome}"
        )
        supervisor.terminate_daemon = lambda name, process: events.append(name)
        supervisor.cleanup_task_netns = lambda: events.append("netns")
        supervisor.invoke_storage = lambda *args, **kwargs: self.fail(
            "pre-activation cleanup invoked storage"
        )
        with (
            mock.patch.object(MODULE, "wait_for_adopted_children"),
            mock.patch.object(MODULE, "remove_runtime_root", lambda identity: events.append("runtime")),
            mock.patch.object(
                MODULE,
                "current_boot_id",
                return_value="12345678-1234-1234-1234-123456789abc",
            ),
        ):
            self.assertTrue(supervisor.try_shutdown("startup_failure"))
        self.assertEqual(
            events,
            ["control-stopping", "dockerd", "containerd", "netns", "runtime"],
        )
        stop_values = [
            value
            for event, value in supervisor.state.events
            if event == "write" and value[0] == MODULE.STOP_RECEIPT_NAME
        ]
        self.assertEqual(stop_values, [(MODULE.STOP_RECEIPT_NAME, "passed")])


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
            source.index('"deactivate-private"', shutdown),
        )

    def test_launchers_share_the_exact_isolated_loader_and_stop_only_the_supervisor(self) -> None:
        start = SCRIPT.with_name("start-isolated-docker.sh").read_text(encoding="utf-8")
        stop = SCRIPT.with_name("stop-isolated-docker.sh").read_text(encoding="utf-8")

        def loader(source: str) -> str:
            prefix = "read -r -d '' pinned_loader <<'PY' || true\n"
            return source.split(prefix, 1)[1].split("\nPY\n", 1)[0]

        self.assertEqual(loader(start), MODULE.PINNED_EXEC_LOADER)
        self.assertEqual(loader(stop), MODULE.PINNED_EXEC_LOADER)
        self.assertIn("/usr/bin/unshare --mount --propagation private", start)
        self.assertIn("/usr/bin/python3 -I -S -B -c", start)
        self.assertIn("/usr/bin/env -i -C /", start)
        self.assertNotIn("sudo -b", start)
        self.assertIn("signal-exact", stop)
        self.assertNotIn("kill -TERM", stop)
        self.assertNotIn("dockerd --", stop)
        self.assertNotIn("containerd --", stop)
        pinned_supervisor = re.search(
            r"^supervisor_sha256=([0-9a-f]{64})$",
            start,
            re.MULTILINE,
        )
        self.assertIsNotNone(pinned_supervisor)
        assert pinned_supervisor is not None
        self.assertEqual(
            pinned_supervisor.group(1),
            hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
        )
        self.assertNotIn("REPLACE_", start)
        self.assertNotIn("REPLACE_", stop)

    def test_pinned_support_sources_match_the_frozen_storage_base(self) -> None:
        identity = SCRIPT.with_name(MODULE.PROCESS_IDENTITY_NAME)
        storage = SCRIPT.with_name(MODULE.STORAGE_LIFECYCLE_NAME)
        storage_verifier = SCRIPT.with_name(MODULE.STORAGE_IDENTITY_VERIFIER_NAME)
        self.assertEqual(hashlib.sha256(identity.read_bytes()).hexdigest(), MODULE.PROCESS_IDENTITY_SHA256)
        self.assertEqual(hashlib.sha256(storage.read_bytes()).hexdigest(), MODULE.STORAGE_LIFECYCLE_SHA256)
        self.assertEqual(
            hashlib.sha256(storage_verifier.read_bytes()).hexdigest(),
            MODULE.STORAGE_IDENTITY_VERIFIER_SHA256,
        )

    def test_storage_sources_are_snapshotted_before_the_first_private_mutation(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        setup = source.index("def setup")
        snapshot = source.index("self.snapshot_storage_sources()", setup)
        activate = source.index('self.invoke_storage("activate-private"', setup)
        self.assertLess(snapshot, activate)
        self.assertIn("mode=0o400", source[source.index("def snapshot_storage_sources") :])


if __name__ == "__main__":
    unittest.main()
