from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import json
import os
import re
import socket
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
BOOT_ID = "12345678-1234-1234-1234-123456789abc"


def recorded_process(
    pid: int,
    executable: str,
    namespace: dict[str, int] = NAMESPACE,
    *,
    parent_pid: int = 1,
) -> dict[str, object]:
    return {
        "pid": pid,
        "parentPid": parent_pid,
        "startTimeTicks": 2000 + pid,
        "executable": executable,
        "argumentsSha256": f"{pid % 16:x}" * 64,
        "mountNamespace": namespace,
        "cgroup": f"/{MODULE.cgroup_path_for(STATE_ROOT).name}/{MODULE.CGROUP_EXECUTION_NAME}",
    }


class ControlState:
    path = STATE_ROOT
    caller_uid = 1000
    caller_gid = 1000

    @staticmethod
    def identity_json() -> dict[str, object]:
        return {
            "stateRoot": {
                "path": str(STATE_ROOT),
                "device": 8,
                "inode": 10,
                "uid": 1000,
                "gid": 1000,
                "mode": 0o700,
            },
            "evidenceRoot": {
                "path": str(STATE_ROOT / "evidence"),
                "device": 8,
                "inode": 11,
                "uid": 1000,
                "gid": 1000,
                "mode": 0o700,
            },
        }


def control_authority() -> tuple[
    dict[str, object],
    MODULE.RuntimeIdentity,
    MODULE.SocketPathIdentity,
    MODULE.CgroupIdentity,
]:
    runtime = MODULE.RuntimeIdentity(
        MODULE.runtime_root_for(STATE_ROOT), 21, 22, 0, 0, 0o700
    )
    socket_root = MODULE.SocketPathIdentity(
        MODULE.socket_root_for(STATE_ROOT), 21, 23, 0, 1000, 0o750
    )
    cgroup = MODULE.CgroupIdentity(MODULE.cgroup_path_for(STATE_ROOT), 29, 30)
    value = {
        "schema": MODULE.CONTROL_SCHEMA,
        "outcome": "active",
        "observedAt": "2026-08-21T12:00:00Z",
        "bootId": BOOT_ID,
        "stateRoot": str(STATE_ROOT),
        "caller": {"uid": 1000, "gid": 1000},
        "stateRootIdentity": ControlState.identity_json()["stateRoot"],
        "evidenceRootIdentity": ControlState.identity_json()["evidenceRoot"],
        "supervisorSourceSha256": MODULE.verified_supervisor_source_sha256(),
        "processIdentitySourceSha256": MODULE.PROCESS_IDENTITY_SHA256,
        "storageLifecycleSourceSha256": MODULE.STORAGE_LIFECYCLE_SHA256,
        "runtimeRoot": str(runtime.path),
        "runtimeRootIdentity": runtime.json(),
        "socketRootIdentity": socket_root.json(),
        "cgroup": cgroup.json(),
        "mountNamespace": NAMESPACE,
        "supervisorProcessIdentity": recorded_process(41, "/usr/bin/python3"),
    }
    return value, runtime, socket_root, cgroup


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
            "authorityClaimSha256": "b" * 64,
            "caller": {"uid": 1000, "gid": 1000},
            "stateRootIdentity": {
                "path": str(STATE_ROOT),
                "device": 8,
                "inode": 10,
                "ownerUid": 1000,
                "ownerGid": 1000,
                "mode": "0700",
            },
            "evidenceDirectoryIdentity": {
                "path": str(STATE_ROOT / "evidence"),
                "device": 8,
                "inode": 9,
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
            "innerRunnerDataRoot": {
                "path": str(MODULE.MOUNT_TARGET / "inner-runner"),
                "device": os.makedev(7, 7),
                "inode": 14,
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
    def test_orphan_absent_cleanup_is_serialized_by_the_global_lease(self) -> None:
        lease = mock.Mock()
        with mock.patch.object(
            MODULE,
            "path_exists_nofollow",
            side_effect=(False, False, False, False),
        ), mock.patch.object(
            MODULE.RuntimeLease,
            "acquire",
            return_value=lease,
        ) as acquire, mock.patch.object(
            MODULE, "require_no_other_task_runtime"
        ) as singleton:
            result = MODULE.ensure_orphaned_runtime_stopped(STATE_ROOT, 1000, 1000)
        self.assertEqual(result["outcome"], "passed")
        acquire.assert_called_once_with(STATE_ROOT)
        self.assertEqual(
            singleton.call_args_list,
            [mock.call(STATE_ROOT), mock.call(STATE_ROOT)],
        )
        lease.close.assert_called_once_with()

        competing = mock.Mock()
        with mock.patch.object(
            MODULE,
            "path_exists_nofollow",
            side_effect=(False, True),
        ), mock.patch.object(
            MODULE.RuntimeLease,
            "acquire",
            return_value=competing,
        ), mock.patch.object(
            MODULE, "require_no_other_task_runtime"
        ), self.assertRaisesRegex(
            MODULE.SupervisorError,
            "appeared while acquiring the global lease",
        ):
            MODULE.ensure_orphaned_runtime_stopped(STATE_ROOT, 1000, 1000)
        competing.close.assert_called_once_with()

    def test_root_control_binds_boot_state_runtime_socket_cgroup_and_sources(self) -> None:
        value, runtime, socket_root, cgroup = control_authority()
        authority = {"validate_recorded_identity": lambda candidate: candidate}
        with mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID):
            parsed = MODULE.validate_control_authority(
                value,
                state=ControlState(),
                runtime_identity=runtime,
                process_authority=authority,
            )
        self.assertEqual(parsed["socketRoot"], socket_root)
        self.assertEqual(parsed["cgroup"], cgroup)
        self.assertEqual(parsed["supervisor"], value["supervisorProcessIdentity"])

        mutations = {
            "old schema": lambda candidate: candidate.update(
                schema="ambit.local-daytona-isolated-docker-control/v1"
            ),
            "other boot": lambda candidate: candidate.update(bootId="22345678-1234-1234-1234-123456789abc"),
            "other state inode": lambda candidate: candidate["stateRootIdentity"].update(inode=99),
            "other socket path": lambda candidate: candidate["socketRootIdentity"].update(
                path="/run/ambit-c16b-docker-api-deadbeef0000"
            ),
            "other cgroup path": lambda candidate: candidate["cgroup"].update(path="/sys/fs/cgroup/other"),
            "other source": lambda candidate: candidate.update(supervisorSourceSha256="f" * 64),
            "extra field": lambda candidate: candidate.update(extra=True),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = json.loads(json.dumps(value))
                mutate(candidate)
                with mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID):
                    with self.assertRaises(MODULE.SupervisorError):
                        MODULE.validate_control_authority(
                            candidate,
                            state=ControlState(),
                            runtime_identity=runtime,
                            process_authority=authority,
                        )

    def test_root_control_authorizes_remove_only_orphaned_state_recovery(self) -> None:
        control, _, _, _ = control_authority()
        stored = MODULE._stored_state_authority_from_control(
            control,
            STATE_ROOT,
            1000,
            1000,
        )
        self.assertEqual(stored.path, STATE_ROOT)
        self.assertEqual(stored.identity_json()["stateRoot"], control["stateRootIdentity"])
        for wrong_path, wrong_uid in (
            (Path("/home/example/other"), 1000),
            (STATE_ROOT, 1001),
        ):
            with self.assertRaises(MODULE.SupervisorError):
                MODULE._stored_state_authority_from_control(
                    control,
                    wrong_path,
                    wrong_uid,
                    1000,
                )

    def test_root_ready_separates_outer_daemon_roots_from_inner_runner_xfs(self) -> None:
        control, runtime, socket_root, cgroup = control_authority()
        socket_identity = MODULE.SocketPathIdentity(
            socket_root.path / MODULE.SOCKET_NAME,
            socket_root.device,
            24,
            0,
            1000,
            0o660,
        )
        ready = {
            "schema": MODULE.START_SCHEMA,
            "outcome": "passed",
            "observedAt": "2026-08-21T12:00:01Z",
            "bootId": control["bootId"],
            "stateRoot": control["stateRoot"],
            "caller": control["caller"],
            "supervisorSourceSha256": control["supervisorSourceSha256"],
            "processIdentitySourceSha256": control["processIdentitySourceSha256"],
            "storageLifecycleSourceSha256": control["storageLifecycleSourceSha256"],
            "runtimeRoot": control["runtimeRoot"],
            "runtimeRootIdentity": control["runtimeRootIdentity"],
            "rootControlSha256": DIGEST,
            "netnsBaselineSha256": "d" * 64,
            "supervisorProcessIdentity": control["supervisorProcessIdentity"],
            "mountNamespace": control["mountNamespace"],
            "cgroup": cgroup.json(),
            "workloadCgroupParent": f"/{cgroup.path.name}",
            "storage": MODULE.normalize_storage_operation(
                storage_operation(),
                expected_outcome="activated",
                state_root=STATE_ROOT,
                caller_uid=1000,
                caller_gid=1000,
                expected_namespace=NAMESPACE,
            ),
            "socket": str(socket_identity.path),
            "socketRootIdentity": socket_root.json(),
            "socketIdentity": socket_identity.json(),
            "dataRoot": str(MODULE.AUTHORITY_ROOT / "outer-docker"),
            "execRoot": str(runtime.path / "docker-exec"),
            "containerd": {
                "address": str(runtime.path / "containerd.sock"),
                "root": str(MODULE.AUTHORITY_ROOT / "outer-containerd"),
                "version": "containerd 2",
                "configSha256": "c" * 64,
                "processIdentity": recorded_process(42, "/usr/bin/containerd", parent_pid=41),
            },
            "network": {
                "defaultBridge": "disabled",
                "addressPool": "172.30.0.0/16",
                "hostFirewallMutation": False,
            },
            "serverId": "EKHL:QDUU:QZ7U:MKGD:VDXK:S27Q:GIPU:24B7:R7VT:DGN6:QCSF:2UBX",
            "serverVersion": "29.0.0",
            "configSha256": "d" * 64,
            "dockerProcessIdentity": recorded_process(43, "/usr/bin/dockerd", parent_pid=41),
        }
        authority = {"validate_recorded_identity": lambda candidate: candidate}
        parsed = MODULE.validate_ready_authority(
            ready,
            control=control,
            root_control_digest=DIGEST,
            process_authority=authority,
        )
        self.assertEqual(parsed["socket"], socket_identity)
        self.assertNotEqual(ready["dataRoot"], ready["storage"]["innerRunnerDataRoot"]["path"])
        for wrong_root in (
            str(MODULE.MOUNT_TARGET / "inner-runner"),
            str(MODULE.MOUNT_TARGET),
        ):
            candidate = json.loads(json.dumps(ready))
            candidate["dataRoot"] = wrong_root
            with self.assertRaises(MODULE.SupervisorError):
                MODULE.validate_ready_authority(
                    candidate,
                    control=control,
                    root_control_digest=DIGEST,
                    process_authority=authority,
                )
        for name, mutate in {
            "socket group": lambda candidate: candidate["socketIdentity"].update(gid=999),
            "socket mode": lambda candidate: candidate["socketIdentity"].update(mode=0o666),
            "socket path": lambda candidate: candidate.update(
                socket=str(runtime.path / "docker.sock")
            ),
            "old ready": lambda candidate: candidate.update(
                schema="ambit.local-daytona-isolated-docker/v4"
            ),
            "extra": lambda candidate: candidate.update(extra=True),
        }.items():
            with self.subTest(name=name):
                candidate = json.loads(json.dumps(ready))
                mutate(candidate)
                with self.assertRaises(MODULE.SupervisorError):
                    MODULE.validate_ready_authority(
                        candidate,
                        control=control,
                        root_control_digest=DIGEST,
                        process_authority=authority,
                    )

    def test_runtime_custody_socket_cgroup_and_lease_paths_are_distinct(self) -> None:
        runtime = MODULE.runtime_root_for(STATE_ROOT)
        socket_root = MODULE.socket_root_for(STATE_ROOT)
        cgroup = MODULE.cgroup_path_for(STATE_ROOT)
        lease = MODULE.lease_path_for(STATE_ROOT)
        self.assertRegex(str(runtime), MODULE.RUNTIME_ROOT_RE)
        self.assertRegex(str(socket_root), MODULE.SOCKET_ROOT_RE)
        self.assertRegex(str(cgroup), MODULE.CGROUP_PATH_RE)
        self.assertRegex(str(lease), MODULE.LEASE_PATH_RE)
        self.assertEqual(len({runtime, socket_root, cgroup, lease}), 4)
        self.assertEqual(
            lease,
            MODULE.lease_path_for(Path("/home/other/ambit-state")),
        )
        with mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(
                ["ambit-c16b-docker-deadbeef0000"],
                [],
                [],
                [],
            ),
        ):
            with self.assertRaisesRegex(MODULE.SupervisorError, "another C16b runtime"):
                MODULE.require_no_other_task_runtime(STATE_ROOT)
        with mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(
                [],
                [],
                [],
                ["ambit-c16b-docker-1577287b8182"],
            ),
        ):
            with self.assertRaisesRegex(MODULE.SupervisorError, "legacy /tmp C16b runtime"):
                MODULE.require_no_other_task_runtime(STATE_ROOT)

    def test_every_precontrol_runtime_roster_is_an_exact_creation_prefix(self) -> None:
        roster: set[str] = set()
        self.assertEqual(MODULE.classify_precontrol_roster(roster), 0)
        ordered = (
            "containerd-state",
            "docker-exec",
            MODULE.SUPERVISOR_SNAPSHOT_NAME,
            MODULE.PROCESS_IDENTITY_NAME,
            MODULE.STORAGE_LIFECYCLE_NAME,
            MODULE.STORAGE_IDENTITY_VERIFIER_NAME,
            MODULE._root_manifest_pending(MODULE.ROOT_CONTROL_NAME),
        )
        for index, name in enumerate(ordered, start=1):
            roster = roster | {name}
            self.assertEqual(MODULE.classify_precontrol_roster(roster), index)
        for invalid in (
            {"docker-exec"},
            {"containerd-state", MODULE.SUPERVISOR_SNAPSHOT_NAME},
            roster | {"dockerd.json"},
            {MODULE._root_manifest_pending(MODULE.ROOT_CONTROL_NAME)},
        ):
            with self.assertRaises(MODULE.SupervisorError):
                MODULE.classify_precontrol_roster(invalid)

    def test_legacy_v4_caller_receipts_cannot_authorize_signal_or_kill(self) -> None:
        runtime = MODULE.RuntimeIdentity(
            MODULE.runtime_root_for(STATE_ROOT), 1, 2, 0, 0, 0o700
        )
        with mock.patch.object(MODULE, "verify_runtime_root", return_value=31), mock.patch.object(
            MODULE.os,
            "listdir",
            return_value=["dockerd.json", "docker.sock", MODULE.STORAGE_LIFECYCLE_NAME],
        ), mock.patch.object(MODULE.os, "close"):
            with self.assertRaisesRegex(MODULE.SupervisorError, "legacy v4 runtime"):
                MODULE.reject_legacy_v4_runtime_roster(runtime)
        source = SCRIPT.read_text(encoding="utf-8")
        ensure = source[source.index("def ensure_runtime_stopped") : source.index("def ensure_orphaned_runtime_stopped")]
        validated = ensure.index("_validated_existing_authorities(")
        signal_call = ensure.index('process_authority["signal_recorded_process"]')
        self.assertLess(validated, signal_call)
        self.assertNotIn("kill_cgroup_and_wait(", ensure)
        self.assertLess(
            ensure.index("acquire_runtime_lease_until(", signal_call),
            ensure.index("supervisor.recover_existing_runtime()"),
        )
        self.assertNotIn("CONTROL_RECEIPT_NAME", ensure[:signal_call])

    def test_real_docker_daemon_id_contract_is_bounded_and_opaque(self) -> None:
        production = "EKHL:QDUU:QZ7U:MKGD:VDXK:S27Q:GIPU:24B7:R7VT:DGN6:QCSF:2UBX"
        self.assertEqual(MODULE.validate_docker_daemon_id(production), production)
        for candidate in (
            "12345678-1234-1234-1234-123456789abc",
            production.lower(),
            production + ":AAAA",
            production.replace(":", "", 1),
            production.replace("EKHL", "EKH0"),
            "",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(MODULE.SupervisorError):
                    MODULE.validate_docker_daemon_id(candidate)

    def test_containerd_v3_config_requires_a_v2_or_later_binary(self) -> None:
        observed = "containerd github.com/containerd/containerd/v2 v2.2.2 deadbeef"
        self.assertEqual(MODULE.require_containerd_v2_or_later(observed), observed)
        with self.assertRaises(MODULE.SupervisorError):
            MODULE.require_containerd_v2_or_later(
                "containerd github.com/containerd/containerd v1.7.27 deadbeef"
            )
        installed = subprocess.run(
            ["/usr/bin/containerd", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        self.assertEqual(MODULE.require_containerd_v2_or_later(installed), installed)

    def test_docker_config_uses_exact_caller_group_and_split_socket(self) -> None:
        encoded = MODULE.docker_config(
                data_root=MODULE.AUTHORITY_ROOT / "outer-docker",
                exec_root=Path("/run/ambit-c16b-docker-0123456789ab/docker-exec"),
                pidfile=Path("/run/ambit-c16b-docker-0123456789ab/docker.pid"),
                socket=Path("/run/ambit-c16b-docker-api-0123456789ab/docker.sock"),
                socket_gid=1000,
                containerd_socket=Path("/run/ambit-c16b-docker-0123456789ab/containerd.sock"),
                cgroup_parent="/ambit-c16b-docker-0123456789ab",
            )
        value = json.loads(encoded)
        self.assertEqual(value["group"], "1000")
        self.assertEqual(
            value["hosts"],
            ["unix:///run/ambit-c16b-docker-api-0123456789ab/docker.sock"],
        )
        self.assertEqual(value["data-root"], str(MODULE.AUTHORITY_ROOT / "outer-docker"))
        self.assertEqual(value["cgroup-parent"], "/ambit-c16b-docker-0123456789ab")
        self.assertEqual(value["exec-opts"], ["native.cgroupdriver=cgroupfs"])
        with tempfile.NamedTemporaryFile(
            mode="w",
            prefix="ambit-dockerd-config-",
            suffix=".json",
        ) as config:
            config.write(encoded)
            config.flush()
            completed = subprocess.run(
                ["/usr/bin/dockerd", "--validate", "--config-file", config.name],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_nonroot_caller_can_traverse_and_connect_to_split_api_socket(self) -> None:
        self.assertNotEqual(os.geteuid(), 0, "permission proof must run as the caller")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "api"
            root.mkdir(mode=0o750)
            endpoint = root / "docker.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                server.bind(str(endpoint))
                endpoint.chmod(0o660)
                server.listen(1)
                client.connect(str(endpoint))
                accepted, _ = server.accept()
                accepted.close()
            finally:
                client.close()
                server.close()
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(endpoint.stat().st_mode), 0o660)

    def test_task_cgroup_is_the_total_descendant_recovery_boundary(self) -> None:
        identity = MODULE.CgroupIdentity(
            Path("/sys/fs/cgroup/ambit-c16b-docker-0123456789ab"), 9, 10
        )
        with mock.patch.object(MODULE, "open_cgroup", return_value=31), mock.patch.object(
            MODULE, "_write_at"
        ) as write, mock.patch.object(MODULE.os, "close"), mock.patch.object(
            MODULE, "cgroup_is_populated", side_effect=(True, False)
        ):
            MODULE.kill_cgroup_and_wait(identity, timeout=1.0)
        write.assert_called_once_with(31, "cgroup.kill", b"1\n")

        with mock.patch.object(MODULE, "open_cgroup", return_value=31), mock.patch.object(
            MODULE, "_write_at"
        ) as write, mock.patch.object(MODULE.os, "close"), mock.patch.object(
            MODULE, "cgroup_events", side_effect=({"populated": "1", "frozen": "0"}, {"populated": "1", "frozen": "1"})
        ):
            MODULE.freeze_cgroup_and_wait(identity, timeout=1.0)
        write.assert_called_once_with(31, "cgroup.freeze", b"1\n")

        source = SCRIPT.read_text(encoding="utf-8")
        setup = source.index("def setup")
        create_cgroup = source.index("self.cgroup_identity = create_cgroup", setup)
        enter_cgroup = source.index("enter_cgroup(self.cgroup_identity)", create_cgroup)
        control = source.index("self.write_control_receipt()", enter_cgroup)
        first_child = source.index("self.containerd_process = subprocess.Popen", control)
        self.assertLess(create_cgroup, enter_cgroup)
        self.assertLess(enter_cgroup, control)
        self.assertLess(control, first_child)
        self.assertIn('"cgroup.kill"', source)
        self.assertIn('"cgroup.subtree_control"', source)
        self.assertIn('{"cpu", "memory", "pids"}', source)
        self.assertIn("CGROUP_EXECUTION_NAME", source)
        creation = source[source.index("def create_cgroup") : source.index("def open_cgroup")]
        self.assertLess(
            creation.index('"cgroup.subtree_control"'),
            creation.index("os.mkdir(CGROUP_EXECUTION_NAME"),
        )
        cleanup = source[
            source.index("def remove_empty_cgroup_children") : source.index("def create_runtime_root")
        ]
        self.assertLess(
            cleanup.index("remove_empty_cgroup_children(child)"),
            cleanup.index("os.rmdir(name"),
        )
        self.assertNotIn("systemctl", source)
        installed_controllers = set(
            Path("/sys/fs/cgroup/cgroup.controllers").read_text(encoding="ascii").split()
        )
        delegated_controllers = set(
            Path("/sys/fs/cgroup/cgroup.subtree_control").read_text(encoding="ascii").split()
        )
        self.assertTrue({"cpu", "memory", "pids"} <= installed_controllers)
        self.assertTrue({"cpu", "memory", "pids"} <= delegated_controllers)

    def test_boot_lifetime_lease_is_never_unlinked_or_inherited(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        lease = source[source.index("class RuntimeLease") : source.index("def runtime_id_for")]
        self.assertIn("fcntl.flock(descriptor, flags)", lease)
        self.assertNotIn("os.unlink", lease)
        run = source[source.index("def run(self)") : source.index("def _validated_existing_authorities")]
        self.assertLess(run.index("RuntimeLease.acquire"), run.index("self.setup()"))
        for child_start in (
            "self.containerd_process = subprocess.Popen(",
            "self.docker_process = subprocess.Popen(",
        ):
            region = source[source.index(child_start) : source.index(child_start) + 1400]
            self.assertIn("close_fds=True", region)
            self.assertNotIn("pass_fds", region)
        storage_child = source[
            source.index("def invoke_storage_helper(") : source.index("def docker_config(")
        ]
        self.assertIn("pass_fds = (runtime_lease_fd,)", storage_child)
        self.assertIn("or (not mutating and runtime_lease_fd is None)", storage_child)
        self.assertIn("str(runtime_lease_fd)", storage_child)

    def test_storage_lease_fd_is_inherited_only_by_mutations(self) -> None:
        process = mock.Mock(returncode=0)
        process.communicate.return_value = ("{}", "")
        normalized = {"projectionDigest": None}
        with mock.patch.object(
            MODULE.subprocess, "Popen", return_value=process
        ) as popen, mock.patch.object(
            MODULE, "wait_for_adopted_children"
        ), mock.patch.object(
            MODULE, "normalize_storage_operation", return_value=normalized
        ), mock.patch.object(MODULE.os, "fstat"):
            observed = MODULE.invoke_storage_helper(
                helper=Path("/run/helper.py"),
                command="observe-private",
                state_root=STATE_ROOT,
                caller_uid=1000,
                caller_gid=1000,
                namespace=NAMESPACE,
                expected_outcome="observed",
                expected_children=set(),
                runtime_lease_fd=None,
            )
            self.assertEqual(observed, normalized)
            self.assertEqual(popen.call_args.kwargs["pass_fds"], ())
            self.assertNotEqual(popen.call_args.args[0][-1], "77")

            MODULE.invoke_storage_helper(
                helper=Path("/run/helper.py"),
                command="deactivate-private",
                state_root=STATE_ROOT,
                caller_uid=1000,
                caller_gid=1000,
                namespace=NAMESPACE,
                expected_outcome="deactivated",
                expected_children=set(),
                runtime_lease_fd=77,
                allow_unpublished=True,
            )
            self.assertEqual(popen.call_args.kwargs["pass_fds"], (77,))
            self.assertEqual(popen.call_args.args[0][-1], "77")

        supervisor = MODULE.RuntimeSupervisor(STATE_ROOT, 1000, 1000)
        supervisor.namespace = NAMESPACE
        supervisor.storage_helper_path = Path("/run/helper.py")
        supervisor.lease = mock.Mock(descriptor=77)
        with mock.patch.object(
            MODULE, "invoke_storage_helper", return_value=normalized
        ) as invoke:
            supervisor.invoke_storage("activate-private", "activated")
            supervisor.invoke_storage("observe-private", "observed")
            supervisor.invoke_storage("deactivate-private", "deactivated")
        self.assertEqual(
            [call.kwargs["runtime_lease_fd"] for call in invoke.call_args_list],
            [77, None, 77],
        )

    def test_root_manifests_are_durable_authority_and_user_files_are_projections(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        writer = source[source.index("def write_root_manifest") : source.index("def _entry_exists")]
        self.assertIn('_root_manifest_pending(name)', writer)
        self.assertLess(writer.index("os.fsync(descriptor)"), writer.index("os.replace("))
        self.assertLess(writer.index("os.replace("), writer.index("os.fsync(runtime_fd)"))
        setup = source[source.index("def setup") : source.index("def snapshot_storage_sources")]
        self.assertLess(setup.index("self.snapshot_storage_sources()"), setup.index("self.write_control_receipt()"))
        self.assertLess(setup.index("self.write_control_receipt()"), setup.index('"activate-private"'))
        self.assertLess(
            setup.index("self.prepare_netns_baseline()"),
            setup.index("self.start_daemons()"),
        )
        ready = source[source.index("def write_start_receipt") : source.index("def monitor")]
        self.assertLess(ready.index("write_root_manifest("), ready.index("self.state.write_json("))
        recovery = source[source.index("def recover_existing_runtime") : source.index("def setup")]
        self.assertIn("read_root_manifest(runtime, ROOT_CONTROL_NAME)", recovery)
        self.assertNotIn("CONTROL_RECEIPT_NAME", recovery)
        shutdown = source[source.index("def try_shutdown") : source.index("def run(self)")]
        self.assertLess(
            shutdown.index("self.write_shutdown_intent(reason)"),
            shutdown.index('self.terminate_daemon("dockerd"'),
        )
        self.assertLess(
            shutdown.index("remove_socket_root("),
            shutdown.index("self.prepare_task_netns_detach()"),
        )
        self.assertLess(
            shutdown.index("self.prepare_task_netns_detach()"),
            shutdown.index('self.terminate_daemon("dockerd"'),
        )

    def test_root_stop_validator_binds_supervisor_and_observation(self) -> None:
        control, runtime, _, cgroup = control_authority()
        supervisor_identity = control["supervisorProcessIdentity"]
        with mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID):
            stopping = MODULE.stopping_authority_value(
                state_root=STATE_ROOT,
                reason="operator_request",
                control_digest=MODULE.canonical_document_digest(control),
                runtime=runtime,
                cgroup=cgroup,
                supervisor_identity=supervisor_identity,
            )
        stop = {
            "schema": MODULE.STOP_SCHEMA,
            "outcome": "quiesced",
            "observedAt": "2026-08-21T12:00:00+00:00",
            "bootId": BOOT_ID,
            "stateRoot": str(STATE_ROOT),
            "reason": "operator_request",
            "supervisorProcessIdentity": supervisor_identity,
            "runtimeRootIdentity": runtime.json(),
            "cgroup": cgroup.json(),
            "rootStoppingSha256": MODULE.canonical_document_digest(stopping),
            "netnsDetachSha256": "f" * 64,
            "storageProjectionDigest": "a" * 64,
            "socketRootRemoved": True,
            "externalFinalizationRequired": True,
        }
        MODULE.validate_stop_authority(
            stop,
            stopping=stopping,
            state_root=STATE_ROOT,
            runtime=runtime,
            cgroup=cgroup,
            supervisor_identity=supervisor_identity,
            boot_id=BOOT_ID,
            expected_netns_digest="f" * 64,
        )
        for field, value in (
            ("supervisorProcessIdentity", recorded_process(99, "/usr/bin/python3")),
            ("observedAt", 123),
        ):
            candidate = copy.deepcopy(stop)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(MODULE.SupervisorError):
                MODULE.validate_stop_authority(
                    candidate,
                    stopping=stopping,
                    state_root=STATE_ROOT,
                    runtime=runtime,
                    cgroup=cgroup,
                    supervisor_identity=supervisor_identity,
                    boot_id=BOOT_ID,
                    expected_netns_digest="f" * 64,
                )

    def test_daemon_preexec_sets_parent_death_signal_and_closes_fork_race(self) -> None:
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(MODULE, "LIBC", libc), mock.patch.object(
            MODULE.os, "getppid", return_value=123
        ), mock.patch.object(MODULE.os, "_exit") as exit_process, mock.patch.object(
            MODULE.signal, "signal"
        ) as reset_signal:
            MODULE.parent_death_preexec(123)()
        libc.prctl.assert_called_once_with(1, MODULE.signal.SIGTERM, 0, 0, 0)
        self.assertEqual(
            reset_signal.call_args_list,
            [
                mock.call(MODULE.signal.SIGTERM, MODULE.signal.SIG_DFL),
                mock.call(MODULE.signal.SIGINT, MODULE.signal.SIG_DFL),
                mock.call(MODULE.signal.SIGHUP, MODULE.signal.SIG_DFL),
                mock.call(MODULE.signal.SIGQUIT, MODULE.signal.SIG_DFL),
            ],
        )
        exit_process.assert_not_called()

        libc.reset_mock()
        with mock.patch.object(MODULE, "LIBC", libc), mock.patch.object(
            MODULE.os, "getppid", return_value=124
        ), mock.patch.object(MODULE.os, "_exit") as exit_process, mock.patch.object(
            MODULE.signal, "signal"
        ):
            MODULE.parent_death_preexec(123)()
        exit_process.assert_called_once_with(71)

    def test_supervisor_sets_secure_umask_before_argument_processing(self) -> None:
        source = SCRIPT.read_text()
        main = source.index("def main()")
        self.assertLess(
            source.index("os.umask(0o077)", main),
            source.index("parser().parse_args()", main),
        )

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
                MODULE.AUTHORITY_ROOT,
                "outer-docker",
                required_mode=0o710,
                recoverable_modes={0o700, 0o710},
            )
        self.assertEqual(path, MODULE.AUTHORITY_ROOT / "outer-docker")
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
        with self.assertRaises(MODULE.SupervisorError):
            MODULE.read_route_networks(json.dumps([{}]))

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
                "innerRunnerDataRoot",
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
        historical_detach = storage_operation("deactivated")
        historical_detach["receipt"]["mountNamespace"] = {
            "device": 9,
            "inode": 99,
        }
        replayed = MODULE.normalize_storage_operation(
            historical_detach,
            expected_outcome="deactivated",
            state_root=STATE_ROOT,
            caller_uid=1000,
            caller_gid=1000,
            expected_namespace=NAMESPACE,
        )
        self.assertEqual(replayed["mountNamespace"], {"device": 9, "inode": 99})
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
        raw = f"42 36 0:35 net:[4026533321] {target} rw - nsfs nsfs rw\n"
        self.assertEqual(MODULE.task_netns_mounts(runtime_root, raw), (target,))
        for candidate in (
            f"42 36 0:35 net:[4026533321] {target}/nested rw - nsfs nsfs rw\n",
            f"42 36 0:35 / {target} rw - tmpfs tmpfs rw\n",
        ):
            with self.assertRaises(MODULE.SupervisorError):
                MODULE.task_netns_mounts(runtime_root, candidate)
    def test_runtime_cleanup_detects_bind_sources_mounted_elsewhere(self) -> None:
        runtime = Path("/run/ambit-c16b-docker-0123456789ab")
        root_backed = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            f"21 20 8:1 {runtime}/isolated_runtime_supervisor.py /outside/snapshot.py rw - ext4 /dev/root rw\n"
        )
        self.assertEqual(
            MODULE.mount_references_under(root_backed, runtime),
            ("/outside/snapshot.py",),
        )
        run_backed = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            "21 20 0:31 / /run rw - tmpfs tmpfs rw\n"
            f"22 21 0:31 /{runtime.name}/docker.sock /outside/docker.sock rw - tmpfs tmpfs rw\n"
        )
        self.assertEqual(
            MODULE.mount_references_under(run_backed, runtime),
            ("/outside/docker.sock",),
        )
        task = runtime / "docker-exec/netns/task-1"
        source_namespace = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            "21 20 0:31 / /run rw - tmpfs tmpfs rw\n"
            f"22 21 0:42 net:[4026533321] {task} rw - nsfs nsfs rw\n"
        )
        source_anchors = MODULE.mount_source_anchors(source_namespace, runtime)
        self.assertIn(("0:42", Path("net:[4026533321]")), source_anchors)
        foreign_namespace_after_source_unmount = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            "21 20 0:31 / /run rw - tmpfs tmpfs rw\n"
            "22 20 0:42 net:[4026533321] /outside/task-1 rw - nsfs nsfs rw\n"
        )
        self.assertEqual(
            MODULE.mount_references_under(
                foreign_namespace_after_source_unmount,
                runtime,
                source_anchors,
            ),
            ("/outside/task-1",),
        )
        with self.assertRaisesRegex(MODULE.SupervisorError, "admitted opaque"):
            MODULE.mount_records(
                "20 1 8:1 net:[4026533321] /outside rw - ext4 /dev/root rw\n"
            )

    def test_task_netns_cleanup_carries_source_anchors_across_unmount(self) -> None:
        supervisor = MODULE.RuntimeSupervisor(STATE_ROOT, 1000, 1000)
        supervisor.runtime_identity = MODULE.RuntimeIdentity(
            MODULE.runtime_root_for(STATE_ROOT), 21, 22, 0, 0, 0o700
        )
        supervisor.namespace = NAMESPACE
        supervisor.root_control_digest = "a" * 64
        supervisor.root_stopping_digest = "b" * 64
        supervisor.root_netns_baseline_digest = "d" * 64
        supervisor.ambient_netns_sources = ()
        target = supervisor.runtime_identity.path / "docker-exec/netns/task-1"
        mounted = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            "21 20 0:31 / /run rw - tmpfs tmpfs rw\n"
            f"22 21 0:42 net:[4026533321] {target} rw - nsfs nsfs rw\n"
        )
        expected = (("4:19", str(target)),)
        anchors = (("0:42", Path("net:[4026533321]")),)
        plan = ((target, anchors, (), expected),)
        with mock.patch.object(
            MODULE,
            "ensure_task_netns_detach_manifest",
            return_value=("c" * 64, plan),
        ), mock.patch.object(
            MODULE.Path,
            "read_text",
            side_effect=(mounted, "20 1 8:1 / / rw - ext4 /dev/root rw\n"),
        ), mock.patch.object(
            MODULE,
            "stable_global_mount_targets",
            side_effect=(expected, (), ()),
        ) as stable, mock.patch.object(
            MODULE, "mount_namespace", return_value=NAMESPACE
        ), mock.patch.object(
            MODULE.subprocess, "run"
        ) as run, mock.patch.object(
            MODULE, "require_exact_children"
        ):
            supervisor.cleanup_task_netns()
        run.assert_called_once()
        self.assertEqual(stable.call_count, 3)
        first_anchors = stable.call_args_list[0].kwargs["source_anchors"]
        self.assertIn(("0:42", Path("net:[4026533321]")), first_anchors)
        self.assertEqual(stable.call_args_list[1].kwargs["source_anchors"], first_anchors)
        self.assertEqual(stable.call_args_list[2].kwargs["source_anchors"], first_anchors)

    def test_task_netns_detach_manifest_replays_after_source_unmount(self) -> None:
        runtime = MODULE.RuntimeIdentity(
            MODULE.runtime_root_for(STATE_ROOT), 21, 22, 0, 0, 0o700
        )
        target = runtime.path / "docker-exec/netns/task-1"
        anchor = ("0:42", Path("net:[4026533321]"))
        ambient = (("7:7", "/run/docker/netns/default"),)
        ambient_sources = ((anchor, ambient),)
        value = {
            "schema": MODULE.NETNS_DETACH_SCHEMA,
            "observedAt": "2026-08-21T12:00:00+00:00",
            "bootId": BOOT_ID,
            "stateRoot": str(STATE_ROOT),
            "runtimeRootIdentity": runtime.json(),
            "rootControlSha256": "a" * 64,
            "rootStoppingSha256": "b" * 64,
            "rootNetnsBaselineSha256": "d" * 64,
            "mountNamespace": NAMESPACE,
            "taskMounts": [
                {
                    "target": str(target),
                    "fsType": "nsfs",
                    "sourceAnchor": {
                        "kind": "opaque_nsfs_identity",
                        "device": "0:42",
                        "root": "net:[4026533321]",
                    },
                    "ownedOccurrences": [
                        {"mountNamespace": "4:19", "target": str(target)}
                    ],
                }
            ],
        }
        with mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID):
            plan = MODULE.validate_task_netns_detach_manifest(
                value,
                runtime=runtime,
                state_root=STATE_ROOT,
                control_digest="a" * 64,
                stopping_digest="b" * 64,
                baseline_digest="d" * 64,
                ambient_sources=ambient_sources,
                recorded_namespace=NAMESPACE,
            )
        self.assertEqual(
            plan,
            ((target, (anchor,), ambient, (("4:19", str(target)),)),),
        )
        source_absent = "20 1 8:1 / / rw - ext4 /dev/root rw\n"
        with mock.patch.object(
            MODULE.Path, "read_text", side_effect=(source_absent, source_absent)
        ), mock.patch.object(
            MODULE, "stable_global_mount_targets", side_effect=(ambient, ambient)
        ) as stable, mock.patch.object(MODULE.subprocess, "run") as run:
            MODULE.settle_task_netns_detach_manifest(
                runtime=runtime,
                recorded_namespace=NAMESPACE,
                task_mounts=plan,
                expected_children=set(),
            )
        run.assert_not_called()
        self.assertEqual(stable.call_count, 2)

    def test_task_netns_detach_manifest_is_final_before_cleanup(self) -> None:
        runtime = MODULE.RuntimeIdentity(
            MODULE.runtime_root_for(STATE_ROOT), 21, 22, 0, 0, 0o700
        )
        target = runtime.path / "docker-exec/netns/task-1"
        mounted = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            "21 20 0:31 / /run rw - tmpfs tmpfs rw\n"
            f"22 21 0:42 net:[4026533321] {target} rw - nsfs nsfs rw\n"
        )
        anchor = ("0:42", Path("net:[4026533321]"))
        ambient = (("7:7", "/run/docker/netns/default"),)
        ambient_sources = ((anchor, ambient),)
        with mock.patch.object(
            MODULE, "current_boot_id", return_value=BOOT_ID
        ), mock.patch.object(
            MODULE, "read_mountinfo_for_namespace", return_value=mounted
        ), mock.patch.object(
            MODULE, "runtime_netns_entry_roster", return_value=("task-1",)
        ), mock.patch.object(
            MODULE,
            "stable_global_mount_targets",
            return_value=tuple(sorted((*ambient, ("4:19", str(target))))),
        ):
            manifest = MODULE.build_task_netns_detach_manifest(
                runtime=runtime,
                state_root=STATE_ROOT,
                control_digest="a" * 64,
                stopping_digest="b" * 64,
                baseline_digest="d" * 64,
                ambient_sources=ambient_sources,
                recorded_namespace=NAMESPACE,
            )
        self.assertEqual(
            manifest["rootNetnsBaselineSha256"],
            "d" * 64,
        )
        self.assertEqual(
            manifest["taskMounts"],
            [
                {
                    "target": str(target),
                    "fsType": "nsfs",
                    "sourceAnchor": {
                        "kind": "opaque_nsfs_identity",
                        "device": "0:42",
                        "root": "net:[4026533321]",
                    },
                    "ownedOccurrences": [
                        {"mountNamespace": "4:19", "target": str(target)}
                    ],
                }
            ],
        )
        digest = MODULE.canonical_document_digest(manifest)
        with mock.patch.object(
            MODULE,
            "read_root_manifest",
            side_effect=(None, manifest),
        ), mock.patch.object(
            MODULE, "build_task_netns_detach_manifest", return_value=manifest
        ), mock.patch.object(
            MODULE, "write_root_manifest", return_value=digest
        ) as write, mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID):
            observed_digest, plan = MODULE.ensure_task_netns_detach_manifest(
                runtime=runtime,
                state_root=STATE_ROOT,
                control_digest="a" * 64,
                stopping_digest="b" * 64,
                baseline_digest="d" * 64,
                ambient_sources=ambient_sources,
                recorded_namespace=NAMESPACE,
            )
        self.assertEqual(observed_digest, digest)
        self.assertEqual(plan[0][0], target)
        write.assert_called_once_with(runtime, MODULE.ROOT_NETNS_DETACH_NAME, manifest)

    def test_ambient_netns_baseline_preserves_host_default_occurrence(self) -> None:
        runtime = MODULE.RuntimeIdentity(
            MODULE.runtime_root_for(STATE_ROOT), 21, 22, 0, 0, 0o700
        )
        ambient = (("7:7", "/run/docker/netns/default"),)
        namespace_stat = mock.Mock(
            st_dev=os.makedev(0, 4),
            st_ino=4026531833,
        )
        with mock.patch.object(
            MODULE.os, "readlink", return_value="net:[4026531833]"
        ), mock.patch.object(
            MODULE.os, "stat", return_value=namespace_stat
        ), mock.patch.object(
            MODULE, "stable_global_mount_targets", return_value=ambient
        ), mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID):
            manifest = MODULE.build_netns_baseline_manifest(
                runtime=runtime,
                state_root=STATE_ROOT,
                control_digest="a" * 64,
                recorded_namespace=NAMESPACE,
            )
            parsed = MODULE.validate_netns_baseline_manifest(
                manifest,
                runtime=runtime,
                state_root=STATE_ROOT,
                control_digest="a" * 64,
                recorded_namespace=NAMESPACE,
            )
        self.assertEqual(
            parsed,
            ((("0:4", Path("net:[4026531833]")), ambient),),
        )

    def test_same_namespace_representative_visibility_must_agree(self) -> None:
        root = Path("/run/ambit-c16b-docker-0123456789ab")
        mountinfo = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            "21 20 0:31 / /run rw - tmpfs tmpfs rw\n"
        )
        namespace_stat = mock.Mock(st_dev=4, st_ino=19)
        with mock.patch.object(
            MODULE.os, "stat", return_value=namespace_stat
        ), mock.patch.object(
            MODULE.Path, "read_text", return_value=mountinfo
        ), mock.patch.object(
            MODULE.os, "listdir", return_value=["1", "2"]
        ), mock.patch.object(
            MODULE,
            "_mount_targets_for_namespace",
            side_effect=((), ("/hidden-bind",)),
        ), self.assertRaisesRegex(
            MODULE.SupervisorError,
            "visibility differs across representatives",
        ):
            MODULE._global_mount_roster_once(root, (("0:31", Path(f"/{root.name}")),))

    def test_every_stop_route_scans_foreign_authorities_before_signal(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        bound = source[
            source.index("def ensure_runtime_stopped(") : source.index(
                "def ensure_orphaned_runtime_stopped("
            )
        ]
        orphaned = source[
            source.index("def ensure_orphaned_runtime_stopped(") : source.index(
                "def parser()"
            )
        ]
        for name, body in (("bound", bound), ("orphaned", orphaned)):
            with self.subTest(route=name):
                self.assertLess(
                    body.index("require_no_other_task_runtime(state_root)"),
                    body.index('process_authority["signal_recorded_process"]'),
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
        nested = value.get("stop")
        nested_outcome = nested.get("outcome") if isinstance(nested, dict) else None
        self.events.append(("write", (name, value.get("outcome", nested_outcome))))
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
            Path("/run/ambit-c16b-docker-0123456789ab"), 1, 2, 0, 0, 0o700
        )
        value.cgroup_identity = MODULE.CgroupIdentity(
            Path("/sys/fs/cgroup/ambit-c16b-docker-0123456789ab"), 3, 4
        )
        value.socket_root_identity = MODULE.SocketPathIdentity(
            Path("/run/ambit-c16b-docker-api-0123456789ab"),
            1,
            5,
            0,
            1000,
            0o750,
        )
        value.socket_identity = MODULE.SocketPathIdentity(
            Path("/run/ambit-c16b-docker-api-0123456789ab/docker.sock"),
            1,
            6,
            0,
            1000,
            0o660,
        )
        value.root_control_digest = DIGEST
        value.root_stopping_digest = None
        value.root_netns_baseline_digest = "d" * 64
        value.ambient_netns_sources = ()
        value.root_netns_detach_digest = "f" * 64
        value.task_netns_detach_manifest = ()
        value.write_shutdown_intent = lambda reason: setattr(
            value, "root_stopping_digest", "e" * 64
        )
        return value

    def test_shutdown_order_keeps_storage_until_daemons_and_netns_are_gone(self) -> None:
        supervisor = self.supervisor()
        events: list[str] = []
        supervisor.write_control_receipt = lambda outcome="active": events.append(
            f"control-{outcome}"
        )
        supervisor.write_shutdown_intent = lambda reason: (
            events.append("root-stopping"),
            setattr(supervisor, "root_stopping_digest", "e" * 64),
        )
        supervisor.terminate_daemon = lambda name, process: events.append(name)
        supervisor.prepare_task_netns_detach = lambda: events.append("netns-plan")
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
            mock.patch.object(MODULE, "remove_socket_root", lambda *args: events.append("socket")),
            mock.patch.object(MODULE, "read_root_manifest", return_value=None),
            mock.patch.object(MODULE, "write_root_manifest", return_value="c" * 64),
            mock.patch.object(MODULE, "current_boot_id", return_value="12345678-1234-1234-1234-123456789abc"),
        ):
            self.assertTrue(supervisor.try_shutdown("operator_request"))
        self.assertEqual(
            events,
            [
                "root-stopping",
                "control-stopping",
                "socket",
                "netns-plan",
                "dockerd",
                "containerd",
                "reaped",
                "netns",
                "deactivate-private",
            ],
        )
        self.assertEqual(
            supervisor.state.events,
            [
                ("write", (MODULE.STOP_RECEIPT_NAME, "quiesced")),
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
            mock.patch.object(MODULE, "remove_socket_root"),
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
        manifest_calls = 0

        def write_manifest(*args: object) -> str:
            nonlocal manifest_calls
            manifest_calls += 1
            if manifest_calls == 1:
                raise MODULE.SupervisorError("manifest publication interrupted")
            return "c" * 64

        with (
            mock.patch.object(MODULE, "wait_for_adopted_children"),
            mock.patch.object(MODULE, "remove_socket_root"),
            mock.patch.object(MODULE, "read_root_manifest", return_value=None),
            mock.patch.object(MODULE, "write_root_manifest", write_manifest),
            mock.patch.object(
                MODULE,
                "current_boot_id",
                return_value="12345678-1234-1234-1234-123456789abc",
            ),
        ):
            self.assertFalse(supervisor.try_shutdown("operator_request"))
            self.assertTrue(supervisor.try_shutdown("operator_request"))
        self.assertEqual(storage_calls, ["deactivate-private"])
        self.assertEqual(manifest_calls, 2)

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
            mock.patch.object(MODULE, "remove_socket_root", lambda *args: events.append("socket")),
            mock.patch.object(MODULE, "read_root_manifest", return_value=None),
            mock.patch.object(MODULE, "write_root_manifest", return_value="c" * 64),
            mock.patch.object(
                MODULE,
                "current_boot_id",
                return_value="12345678-1234-1234-1234-123456789abc",
            ),
        ):
            self.assertTrue(supervisor.try_shutdown("startup_failure"))
        self.assertEqual(
            events,
            ["control-stopping", "socket", "dockerd", "containerd", "netns"],
        )
        stop_values = [
            value
            for event, value in supervisor.state.events
            if event == "write" and value[0] == MODULE.STOP_RECEIPT_NAME
        ]
        self.assertEqual(stop_values, [(MODULE.STOP_RECEIPT_NAME, "quiesced")])

    def test_dead_supervisor_recovery_kills_bound_cgroup_before_storage_reduction(self) -> None:
        supervisor = self.supervisor()
        control, runtime, socket_root, cgroup = control_authority()
        supervisor.runtime_identity = None
        events: list[str] = []

        class ProcessGone(RuntimeError):
            pass

        process_authority = {
            "ProcessIdentityError": ProcessGone,
            "verify_recorded_process": lambda *args, **kwargs: (_ for _ in ()).throw(
                ProcessGone("gone")
            ),
        }
        validated = {
            "control": control,
            "runtime": runtime,
            "socketRoot": socket_root,
            "cgroup": cgroup,
            "namespace": NAMESPACE,
            "supervisor": control["supervisorProcessIdentity"],
        }
        supervisor.invoke_storage = lambda *args, **kwargs: (
            events.append("storage") or {"projectionDigest": None}
        )
        with (
            mock.patch.object(MODULE, "require_no_other_task_runtime"),
            mock.patch.object(MODULE, "existing_runtime_identity", return_value=runtime),
            mock.patch.object(MODULE, "load_process_authority", return_value=process_authority),
            mock.patch.object(
                MODULE,
                "read_root_manifest",
                side_effect=(control, None, None, None, None, None),
            ),
            mock.patch.object(MODULE, "validate_control_authority", return_value=validated),
            mock.patch.object(
                MODULE,
                "classify_recovery_socket",
                side_effect=lambda *args, **kwargs: events.append("socket-proof")
                or (True, None),
            ),
            mock.patch.object(
                MODULE,
                "write_root_manifest",
                side_effect=lambda *args: events.append("stopping-intent") or "e" * 64,
            ),
            mock.patch.object(
                MODULE,
                "freeze_cgroup_and_wait",
                side_effect=lambda *args, **kwargs: events.append("cgroup-freeze"),
            ),
            mock.patch.object(
                MODULE,
                "ensure_netns_baseline_manifest",
                side_effect=lambda **kwargs: events.append("netns-baseline")
                or ("d" * 64, ()),
            ),
            mock.patch.object(
                MODULE,
                "ensure_task_netns_detach_manifest",
                side_effect=lambda **kwargs: events.append("netns-plan") or ("f" * 64, ()),
            ),
            mock.patch.object(MODULE, "cgroup_is_populated", return_value=True),
            mock.patch.object(MODULE, "kill_cgroup_and_wait", side_effect=lambda *args, **kwargs: events.append("cgroup-kill")),
            mock.patch.object(
                MODULE,
                "settle_task_netns_detach_manifest",
                side_effect=lambda **kwargs: events.append("netns-settle"),
            ),
            mock.patch.object(MODULE.os, "stat", return_value=mock.Mock()),
            mock.patch.object(
                MODULE,
                "capture_socket_identity",
                return_value=MODULE.SocketPathIdentity(
                    socket_root.path / MODULE.SOCKET_NAME,
                    socket_root.device,
                    24,
                    0,
                    1000,
                    0o660,
                ),
            ),
            mock.patch.object(MODULE, "remove_socket_root", side_effect=lambda *args: events.append("socket-remove")),
            mock.patch.object(MODULE, "read_pinned_source", return_value=b"source"),
            mock.patch.object(MODULE, "remove_runtime_root", side_effect=lambda *args: events.append("runtime-remove")),
            mock.patch.object(MODULE, "remove_empty_cgroup", side_effect=lambda *args: events.append("cgroup-remove")),
            mock.patch.object(
                MODULE, "writable_state_authority", side_effect=lambda value: value
            ),
            mock.patch.object(MODULE, "remove_user_runtime_projections", side_effect=lambda *args: events.append("projection-remove")),
        ):
            supervisor.recover_existing_runtime()
        self.assertEqual(
            events,
            [
                "socket-proof",
                "stopping-intent",
                "cgroup-freeze",
                "netns-baseline",
                "netns-plan",
                "cgroup-kill",
                "netns-settle",
                "socket-remove",
                "storage",
                "netns-settle",
                "runtime-remove",
                "cgroup-remove",
                "projection-remove",
            ],
        )

    def test_dead_recovery_intent_replays_after_socket_removal_response_loss(self) -> None:
        supervisor = self.supervisor()
        control, runtime, socket_root, cgroup = control_authority()
        supervisor.runtime_identity = None

        class ProcessGone(RuntimeError):
            pass

        class InjectedCrash(RuntimeError):
            pass

        process_authority = {
            "ProcessIdentityError": ProcessGone,
            "verify_recorded_process": lambda *args, **kwargs: (_ for _ in ()).throw(
                ProcessGone("gone")
            ),
        }
        validated = {
            "control": control,
            "runtime": runtime,
            "socketRoot": socket_root,
            "cgroup": cgroup,
            "namespace": NAMESPACE,
            "supervisor": control["supervisorProcessIdentity"],
        }
        root_manifests: dict[str, dict[str, object]] = {}
        socket_present = True

        def read_manifest(_: object, name: str):
            if name == MODULE.ROOT_CONTROL_NAME:
                return control
            if name == MODULE.ROOT_READY_NAME:
                return None
            return root_manifests.get(name)

        def write_manifest(_: object, name: str, value: dict[str, object]) -> str:
            root_manifests[name] = value
            return MODULE.canonical_document_digest(value)

        def socket_stat(path: object, **_: object):
            if Path(path) == socket_root.path and not socket_present:
                raise FileNotFoundError
            return mock.Mock()

        def remove_socket(*_: object) -> None:
            nonlocal socket_present
            socket_present = False
            raise InjectedCrash("response lost after socket removal")

        common = (
            mock.patch.object(MODULE, "require_no_other_task_runtime"),
            mock.patch.object(MODULE, "existing_runtime_identity", return_value=runtime),
            mock.patch.object(MODULE, "load_process_authority", return_value=process_authority),
            mock.patch.object(MODULE, "read_root_manifest", side_effect=read_manifest),
            mock.patch.object(MODULE, "write_root_manifest", side_effect=write_manifest),
            mock.patch.object(MODULE, "validate_control_authority", return_value=validated),
            mock.patch.object(
                MODULE,
                "classify_recovery_socket",
                side_effect=lambda *args, **kwargs: (
                    socket_present,
                    MODULE.SocketPathIdentity(
                        socket_root.path / MODULE.SOCKET_NAME,
                        socket_root.device,
                        24,
                        0,
                        1000,
                        0o660,
                    )
                    if socket_present
                    else None,
                ),
            ),
            mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID),
            mock.patch.object(
                MODULE,
                "ensure_netns_baseline_manifest",
                return_value=("d" * 64, ()),
            ),
            mock.patch.object(
                MODULE,
                "ensure_task_netns_detach_manifest",
                return_value=("f" * 64, ()),
            ),
            mock.patch.object(MODULE, "settle_task_netns_detach_manifest"),
            mock.patch.object(MODULE, "cgroup_is_populated", return_value=False),
            mock.patch.object(MODULE.os, "stat", side_effect=socket_stat),
            mock.patch.object(MODULE, "read_pinned_source", return_value=b"source"),
            mock.patch.object(MODULE, "remove_runtime_root"),
            mock.patch.object(MODULE, "remove_empty_cgroup"),
            mock.patch.object(
                MODULE, "writable_state_authority", side_effect=lambda value: value
            ),
            mock.patch.object(MODULE, "remove_user_runtime_projections"),
        )
        supervisor.invoke_storage = lambda *args, **kwargs: {"projectionDigest": None}
        with contextlib.ExitStack() as stack:
            for patcher in common:
                stack.enter_context(patcher)
            stack.enter_context(
                mock.patch.object(MODULE, "remove_socket_root", side_effect=remove_socket)
            )
            with self.assertRaisesRegex(InjectedCrash, "response lost"):
                supervisor.recover_existing_runtime()
        self.assertIn(MODULE.ROOT_STOPPING_NAME, root_manifests)
        self.assertFalse(socket_present)

        with contextlib.ExitStack() as stack:
            for patcher in common:
                stack.enter_context(patcher)
            stack.enter_context(mock.patch.object(MODULE, "remove_socket_root"))
            supervisor.recover_existing_runtime()

    def test_substituted_socket_root_blocks_before_cgroup_kill(self) -> None:
        supervisor = self.supervisor()
        control, runtime, socket_root, cgroup = control_authority()
        validated = {
            "control": control,
            "runtime": runtime,
            "socketRoot": socket_root,
            "cgroup": cgroup,
            "namespace": NAMESPACE,
            "supervisor": control["supervisorProcessIdentity"],
        }
        with mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID):
            stopping = MODULE.stopping_authority_value(
                state_root=STATE_ROOT,
                reason="operator_request",
                control_digest=MODULE.canonical_document_digest(control),
                runtime=runtime,
                cgroup=cgroup,
                supervisor_identity=control["supervisorProcessIdentity"],
            )
        with (
            mock.patch.object(MODULE, "require_no_other_task_runtime"),
            mock.patch.object(MODULE, "existing_runtime_identity", return_value=runtime),
            mock.patch.object(MODULE, "load_process_authority", return_value={}),
            mock.patch.object(
                MODULE,
                "read_root_manifest",
                side_effect=(control, None, stopping, None),
            ),
            mock.patch.object(MODULE, "validate_control_authority", return_value=validated),
            mock.patch.object(MODULE, "current_boot_id", return_value=BOOT_ID),
            mock.patch.object(MODULE.os, "stat", return_value=mock.Mock()),
            mock.patch.object(
                MODULE,
                "verify_socket_root",
                side_effect=MODULE.SupervisorError("socket inode changed"),
            ),
            mock.patch.object(MODULE, "kill_cgroup_and_wait") as kill,
            mock.patch.object(MODULE, "freeze_cgroup_and_wait") as freeze,
        ):
            with self.assertRaisesRegex(MODULE.SupervisorError, "socket inode changed"):
                supervisor.recover_existing_runtime()
        kill.assert_not_called()
        freeze.assert_not_called()


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
        self.assertNotIn("read -r -d '' pinned_loader", stop)
        self.assertIn("/usr/bin/unshare --mount --propagation private", start)
        self.assertIn("/usr/bin/python3 -I -S -B -c", start)
        self.assertNotIn("/usr/bin/env -i", start)
        self.assertIn('os.environ.get("SUDO_UID") == args.caller_uid', SCRIPT.read_text())
        self.assertNotIn("sudo -b", start)
        self.assertIn("ensure-stopped", stop)
        self.assertIn("ensure-stopped-orphaned", stop)
        self.assertNotIn("signal-exact", stop)
        self.assertNotIn("signal-recorded", stop)
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
        self.assertIn("/run/ambit-c16b-docker-api-", start)
        self.assertIn("runtime_snapshot_loader", start)
        self.assertIn("runtime_snapshot_loader", stop)
        self.assertIn('os.open("isolated_runtime_supervisor.py"', start)
        self.assertIn("control_present", start)
        self.assertIn("fallback_source.startswith(source)", start)
        self.assertIn("identity.st_size == 0 and (chosen == fallback_path or control_present)", start)
        self.assertIn('__fallback_script_directory__', start)
        recovery = SCRIPT.read_text()[
            SCRIPT.read_text().index("def recover_existing_runtime") : SCRIPT.read_text().index("def setup")
        ]
        self.assertIn("self.precontrol_source_directory", recovery)
        self.assertNotIn("/docker.sock", str(MODULE.runtime_root_for(STATE_ROOT)))
        self.assertIn("recover_existing_runtime(orphaned=True)", SCRIPT.read_text())
        self.assertIn("legacy /tmp C16b runtime", SCRIPT.read_text())
        self.assertIn("blocked:", start)

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
        snapshot_region = source[
            source.index("def snapshot_storage_sources") : source.index("def prepare_daemon_configuration")
        ]
        for name in (
            "SUPERVISOR_SNAPSHOT_NAME",
            "PROCESS_IDENTITY_NAME",
            "STORAGE_LIFECYCLE_NAME",
            "STORAGE_IDENTITY_VERIFIER_NAME",
        ):
            self.assertIn(name, snapshot_region)


if __name__ == "__main__":
    unittest.main()
