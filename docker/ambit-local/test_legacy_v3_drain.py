from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import os
import signal
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("legacy_v3_drain.py")
SPEC = importlib.util.spec_from_file_location("legacy_v3_drain", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
WRAPPER = Path(__file__).with_name("drain-legacy-v3-runtime.sh")


def process(
    pid: int,
    start: int,
    executable: str,
    arguments_sha: str,
    proc_inode: int,
) -> dict[str, object]:
    return {
        "pid": pid,
        "procInode": proc_inode,
        "startTimeTicks": start,
        "executable": executable,
        "argumentsSha256": arguments_sha,
    }


def receipt() -> dict[str, object]:
    return {
        "schema": MODULE.LEGACY_SCHEMA,
        "outcome": "passed",
        "observedAt": "2026-08-20T22:35:43Z",
        "runtimeRoot": str(MODULE.EXPECTED_RUNTIME_ROOT),
        "runtimeRootIdentity": {
            "device": 44,
            "inode": 12496265,
            "uid": 1000,
            "mode": 0o700,
        },
        "socket": str(MODULE.DOCKER_SOCKET),
        "dataRoot": str(MODULE.EXPECTED_STATE_ROOT / "outer-docker"),
        "execRoot": str(MODULE.EXPECTED_RUNTIME_ROOT / "docker-exec"),
        "containerd": {
            "address": str(MODULE.CONTAINERD_SOCKET),
            "root": str(MODULE.EXPECTED_STATE_ROOT / "outer-containerd"),
            "version": "containerd github.com/containerd/containerd/v2 v2.2.2 exact",
            "pid": 960166,
            "configSha256": MODULE.EXPECTED_CONTAINERD_CONFIG_SHA256,
            "processIdentity": process(
                960166,
                80959891,
                "/usr/bin/containerd",
                str(MODULE.EXPECTED_PROCESS_CANDIDATES["containerd"]["argumentsSha256"]),
                371201959,
            ),
        },
        "network": {
            "defaultBridge": "disabled",
            "addressPool": "172.30.0.0/16",
            "hostFirewallMutation": False,
        },
        "serverId": "a17a383f-d290-4e63-9e0d-3c8cf0a9b4a6",
        "serverVersion": "29.3.1",
        "dockerPid": 960217,
        "dockerProcessIdentity": process(
            960217,
            80959925,
            "/usr/bin/dockerd",
            str(MODULE.EXPECTED_PROCESS_CANDIDATES["dockerd"]["argumentsSha256"]),
            371193648,
        ),
        "configSha256": MODULE.EXPECTED_DOCKER_CONFIG_SHA256,
    }


def encoded_receipt(value: dict[str, object] | None = None) -> bytes:
    return MODULE.canonical_json(receipt() if value is None else value)


def captured_process(
    *,
    pid: int = 960217,
    parent: int = 960215,
    start: int = 80959925,
    executable: str = "/usr/bin/dockerd",
    arguments_sha: str | None = None,
    proc_inode: int = 406763182,
) -> MODULE.CapturedProcess:
    return MODULE.CapturedProcess(
        authority={
            "pid": pid,
            "parentPid": parent,
            "startTimeTicks": start,
            "executable": executable,
            "argumentsSha256": arguments_sha
            or str(MODULE.EXPECTED_PROCESS_CANDIDATES["dockerd"]["argumentsSha256"]),
            "mountNamespace": {"device": 4, "inode": 19},
            "networkNamespace": {"device": 4, "inode": 20},
            "pidNamespace": {"device": 4, "inode": 21},
            "userNamespace": {"device": 4, "inode": 22},
            "cgroup": "/user.slice/task.scope",
        },
        observed_proc_inode=proc_inode,
    )


class ReceiptContractTest(unittest.TestCase):
    def test_exact_v3_receipt_passes(self) -> None:
        parsed = MODULE.parse_legacy_receipt(encoded_receipt())
        self.assertEqual(parsed["dockerd"]["pid"], 960217)
        self.assertEqual(parsed["containerd"]["pid"], 960166)

    def test_only_proc_inode_drift_is_explicitly_observational(self) -> None:
        parsed = MODULE.parse_legacy_receipt(encoded_receipt())
        disposition = MODULE.validate_receipt_process(
            parsed["dockerd"], captured_process(proc_inode=406763182)
        )
        self.assertEqual(disposition["legacyProcInode"], 371193648)
        self.assertEqual(disposition["observedProcInode"], 406763182)
        self.assertEqual(disposition["disposition"], "ignored_unstable_procfs_dentry")

    def test_start_ticks_substitution_rejects(self) -> None:
        value = receipt()
        value["dockerProcessIdentity"]["startTimeTicks"] = 80959926
        with self.assertRaisesRegex(MODULE.DrainError, "stable identity"):
            MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_argument_digest_substitution_rejects(self) -> None:
        value = receipt()
        value["dockerProcessIdentity"]["argumentsSha256"] = "0" * 64
        with self.assertRaisesRegex(MODULE.DrainError, "stable identity"):
            MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_executable_substitution_rejects(self) -> None:
        value = receipt()
        value["dockerProcessIdentity"]["executable"] = "/usr/bin/false"
        with self.assertRaisesRegex(MODULE.DrainError, "stable identity"):
            MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_receipt_extra_field_rejects(self) -> None:
        value = receipt()
        value["foreign"] = True
        with self.assertRaisesRegex(MODULE.DrainError, "field roster"):
            MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_receipt_missing_field_rejects(self) -> None:
        value = receipt()
        del value["network"]
        with self.assertRaisesRegex(MODULE.DrainError, "field roster"):
            MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_receipt_duplicate_field_rejects(self) -> None:
        raw = encoded_receipt().rstrip(b"\n")
        duplicate = raw[:-1] + b',"schema":"ambit.local-daytona-isolated-docker/v3"}'
        with self.assertRaisesRegex(MODULE.DrainError, "duplicate JSON"):
            MODULE.parse_legacy_receipt(duplicate)

    def test_v2_and_v5_receipts_reject(self) -> None:
        for schema in (
            "ambit.local-daytona-isolated-docker/v2",
            "ambit.local-daytona-isolated-docker-start/v5",
        ):
            with self.subTest(schema=schema):
                value = receipt()
                value["schema"] = schema
                with self.assertRaisesRegex(MODULE.DrainError, "unsupported"):
                    MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_runtime_root_identity_substitution_rejects(self) -> None:
        for field, substituted in (
            ("device", 45),
            ("inode", 12496266),
            ("uid", 0),
            ("mode", 0o755),
        ):
            with self.subTest(field=field):
                value = receipt()
                value["runtimeRootIdentity"][field] = substituted
                with self.assertRaisesRegex(MODULE.DrainError, "task candidate"):
                    MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_config_digest_substitution_rejects(self) -> None:
        for location in ("docker", "containerd"):
            with self.subTest(location=location):
                value = receipt()
                if location == "docker":
                    value["configSha256"] = "1" * 64
                else:
                    value["containerd"]["configSha256"] = "1" * 64
                with self.assertRaises(MODULE.DrainError):
                    MODULE.parse_legacy_receipt(encoded_receipt(value))

    def test_false_numeric_fields_reject(self) -> None:
        value = receipt()
        value["dockerPid"] = True
        with self.assertRaises(MODULE.DrainError):
            MODULE.parse_legacy_receipt(encoded_receipt(value))


class ProcessAuthorityTest(unittest.TestCase):
    def test_stable_process_field_substitution_rejects(self) -> None:
        parsed = MODULE.parse_legacy_receipt(encoded_receipt())["dockerd"]
        for field, captured in (
            ("pid", captured_process(pid=1)),
            ("startTimeTicks", captured_process(start=1)),
            ("executable", captured_process(executable="/usr/bin/false")),
            ("argumentsSha256", captured_process(arguments_sha="1" * 64)),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(MODULE.DrainError, field):
                    MODULE.validate_receipt_process(parsed, captured)

    def test_pid_reuse_after_pidfd_open_sends_no_signal(self) -> None:
        recorded = captured_process().authority
        foreign = MODULE.CapturedProcess(
            authority={**recorded, "startTimeTicks": 99},
            observed_proc_inode=1,
        )
        with mock.patch.object(MODULE, "process_exists", return_value=True), mock.patch.object(
            MODULE.os, "pidfd_open", return_value=31
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE, "capture_process", return_value=foreign
        ), mock.patch.object(
            MODULE.signal, "pidfd_send_signal"
        ) as send, mock.patch.object(MODULE.os, "close"):
            with self.assertRaisesRegex(MODULE.DrainError, "changed"):
                MODULE.signal_exact_process(recorded)
        send.assert_not_called()

    def test_identity_proof_failure_sends_no_signal(self) -> None:
        recorded = captured_process().authority
        with mock.patch.object(MODULE, "process_exists", return_value=True), mock.patch.object(
            MODULE.os, "pidfd_open", return_value=31
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE, "capture_process", side_effect=MODULE.DrainError("argv differs")
        ), mock.patch.object(
            MODULE.signal, "pidfd_send_signal"
        ) as send, mock.patch.object(MODULE.os, "close"):
            with self.assertRaisesRegex(MODULE.DrainError, "argv differs"):
                MODULE.signal_exact_process(recorded)
        send.assert_not_called()

    def test_absent_recorded_process_is_idempotent(self) -> None:
        with mock.patch.object(MODULE, "process_exists", return_value=False), mock.patch.object(
            MODULE.signal, "pidfd_send_signal"
        ) as send:
            MODULE.signal_exact_process(captured_process().authority)
        send.assert_not_called()

    def test_signal_is_term_only(self) -> None:
        recorded = captured_process().authority
        with mock.patch.object(MODULE, "process_exists", return_value=True), mock.patch.object(
            MODULE.os, "pidfd_open", return_value=31
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE, "capture_process", return_value=captured_process()
        ), mock.patch.object(
            MODULE.signal, "pidfd_send_signal"
        ) as send, mock.patch.object(
            MODULE.select, "poll"
        ) as poll_type, mock.patch.object(MODULE.os, "close"):
            poll_type.return_value.poll.return_value = [(31, 1)]
            MODULE.signal_exact_process(recorded)
        send.assert_called_once_with(31, signal.SIGTERM)

    def test_process_timeout_is_manual_and_never_force_kills(self) -> None:
        control = {"authority": {"processGraph": {"processes": {"dockerd": {"pid": 1}}}}}
        with mock.patch.object(MODULE, "exact_process_status", return_value="exact"), mock.patch.object(
            MODULE.time, "monotonic", side_effect=(0.0, 2.0)
        ), mock.patch.object(MODULE.time, "sleep"):
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "without force"):
                MODULE.wait_for_roles_absent(
                    control, ("dockerd",), timeout_seconds=1.0
                )

    def test_shared_cgroup_is_observation_never_mutation_authority(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"cgroupMutationAuthorized": False', source)
        self.assertIn('"forbidden_shared_66_process_observation"', source)


class MountAuthorityTest(unittest.TestCase):
    def test_opaque_nsfs_root_is_exact_not_path_like(self) -> None:
        raw = (
            "20 1 8:1 / / rw - ext4 /dev/root rw\n"
            f"21 20 0:4 net:[4026531833] {MODULE.TASK_NETNS_TARGET} rw - nsfs nsfs rw\n"
        )
        records = MODULE.mount_records(raw)
        nsfs = next(record for record in records if record.filesystem == "nsfs")
        self.assertEqual(nsfs.root, "net:[4026531833]")
        self.assertTrue(MODULE.mount_root_at_or_below("net:[4026531833]", "net:[4026531833]"))
        self.assertFalse(MODULE.mount_root_at_or_below("net:[4026531834]", "net:[4026531833]"))

    def test_non_nsfs_opaque_root_rejects(self) -> None:
        with self.assertRaisesRegex(MODULE.DrainError, "opaque"):
            MODULE.mount_records("20 1 0:4 net:[1] /x rw - ext4 ext4 rw\n")

    def test_foreign_netns_target_blocks_before_unmount(self) -> None:
        control = {
            "authority": {
                "mounts": {
                    "networkNamespace": {
                        "sourceAnchor": {"device": "0:4", "root": "net:[4026531833]"},
                        "ambientTargets": ["/run/docker/netns/default"],
                        "ownedTarget": str(MODULE.TASK_NETNS_TARGET),
                    }
                }
            }
        }
        roster = {
            "occurrences": [
                {"mountNamespace": "4:19", "target": str(MODULE.TASK_NETNS_TARGET)},
                {"mountNamespace": "4:19", "target": "/run/docker/netns/default"},
                {"mountNamespace": "4:19", "target": "/outside/foreign"},
            ]
        }
        with mock.patch.object(MODULE, "stable_global_mount_roster", return_value=roster), mock.patch.object(
            MODULE.subprocess, "run"
        ) as run:
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "foreign"):
                MODULE.settle_task_netns(control)
        run.assert_not_called()

    def test_ambient_target_disappearance_blocks(self) -> None:
        control = {
            "authority": {
                "mounts": {
                    "networkNamespace": {
                        "sourceAnchor": {"device": "0:4", "root": "net:[4026531833]"},
                        "ambientTargets": ["/run/docker/netns/default"],
                        "ownedTarget": str(MODULE.TASK_NETNS_TARGET),
                    }
                }
            }
        }
        first = {
            "occurrences": [
                {"mountNamespace": "4:19", "target": str(MODULE.TASK_NETNS_TARGET)},
                {"mountNamespace": "4:19", "target": "/run/docker/netns/default"},
            ]
        }
        final = {"occurrences": []}
        completed = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(
            MODULE, "stable_global_mount_roster", side_effect=(first, final)
        ), mock.patch.object(MODULE, "trusted_umount", return_value=Path("/usr/bin/umount")), mock.patch.object(
            MODULE.subprocess, "run", return_value=completed
        ):
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "ambient"):
                MODULE.settle_task_netns(control)

    def test_exact_residual_nsfs_unmount_preserves_ambient(self) -> None:
        control = {
            "authority": {
                "mounts": {
                    "networkNamespace": {
                        "sourceAnchor": {"device": "0:4", "root": "net:[4026531833]"},
                        "ambientTargets": ["/run/docker/netns/default"],
                        "ownedTarget": str(MODULE.TASK_NETNS_TARGET),
                    }
                }
            }
        }
        first = {
            "occurrences": [
                {"mountNamespace": "4:19", "target": str(MODULE.TASK_NETNS_TARGET)},
                {"mountNamespace": "4:19", "target": "/run/docker/netns/default"},
            ]
        }
        final = {
            "occurrences": [
                {"mountNamespace": "8:88", "target": "/run/docker/netns/default"}
            ]
        }
        completed = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with mock.patch.object(
            MODULE, "stable_global_mount_roster", side_effect=(first, final)
        ), mock.patch.object(MODULE, "trusted_umount", return_value=Path("/usr/bin/umount")), mock.patch.object(
            MODULE.subprocess, "run", return_value=completed
        ) as run:
            MODULE.settle_task_netns(control)
        self.assertEqual(run.call_args.args[0][-1], str(MODULE.TASK_NETNS_TARGET))

    def test_netns_unmount_response_loss_is_idempotent(self) -> None:
        control = {
            "authority": {
                "mounts": {
                    "networkNamespace": {
                        "sourceAnchor": {"device": "0:4", "root": "net:[4026531833]"},
                        "ambientTargets": ["/run/docker/netns/default"],
                        "ownedTarget": str(MODULE.TASK_NETNS_TARGET),
                    }
                }
            }
        }
        ambient = {
            "occurrences": [
                {"mountNamespace": "8:88", "target": "/run/docker/netns/default"}
            ]
        }
        with mock.patch.object(
            MODULE, "stable_global_mount_roster", side_effect=(ambient, ambient)
        ), mock.patch.object(MODULE.subprocess, "run") as run:
            MODULE.settle_task_netns(control)
        run.assert_not_called()

    def test_mount_visibility_disagreement_is_manual(self) -> None:
        raw = "20 1 8:1 / / rw - ext4 /dev/root rw\n"
        with mock.patch.object(MODULE.Path, "read_text", return_value=raw), mock.patch.object(
            MODULE.os, "getpid", return_value=10
        ), mock.patch.object(MODULE, "mount_namespace_key", return_value="4:19"), mock.patch.object(
            MODULE, "source_anchors", return_value=(("8:1", "/x"),)
        ), mock.patch.object(MODULE.os, "listdir", return_value=("11",)), mock.patch.object(
            MODULE.os, "stat", return_value=mock.Mock(st_dev=4, st_ino=19)
        ), mock.patch.object(
            MODULE,
            "mount_references",
            side_effect=(("/one",), ("/two",)),
        ):
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "visibility"):
                MODULE.global_mount_roster_once(Path("/x"))

    def test_registry_listener_must_be_exact_loopback_and_task_owned(self) -> None:
        tcp = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:8CA0 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 77\n"
        )
        tcp6 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        with mock.patch.object(
            MODULE.Path,
            "read_text",
            side_effect=(tcp, tcp6),
        ), mock.patch.object(
            MODULE, "socket_inode_owners", return_value={77: (964683,)}
        ):
            observed = MODULE.tcp_registry_snapshot(964683)
        self.assertEqual(observed["address"], "0100007F")
        self.assertEqual(observed["owners"], [964683])

    def test_public_or_foreign_registry_listener_blocks(self) -> None:
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        public = header + (
            "   0: 00000000:8CA0 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 77\n"
        )
        with mock.patch.object(
            MODULE.Path,
            "read_text",
            side_effect=(public, header),
        ), mock.patch.object(
            MODULE, "socket_inode_owners", return_value={77: (999,)}
        ):
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "loopback"):
                MODULE.tcp_registry_snapshot(964683)

    def test_foreign_docker_api_connection_blocks(self) -> None:
        listener = {
            "flags": "00010000",
            "state": "01",
            "inode": 1,
            "path": str(MODULE.DOCKER_SOCKET),
        }
        connected = {
            "flags": "00000000",
            "state": "03",
            "inode": 2,
            "path": str(MODULE.DOCKER_SOCKET),
        }
        with mock.patch.object(MODULE, "socket_identity", return_value={}), mock.patch.object(
            MODULE, "proc_unix_records", return_value=(listener, connected)
        ), mock.patch.object(
            MODULE, "socket_inode_owners", return_value={1: (960217,), 2: (42, 960217)}
        ), mock.patch.object(
            MODULE, "tcp_registry_snapshot", return_value={}
        ), mock.patch.object(
            MODULE.Path, "exists", return_value=True
        ):
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "already connected"):
                MODULE.runtime_socket_snapshot(960217)


class ReducerStateMachineTest(unittest.TestCase):
    class FakeControl:
        def __init__(self) -> None:
            self.state = {"phase": MODULE.PHASES[0]}
            self.control_digest = "c" * 64
            self.events: list[str] = []
            self.control = {
                "authority": {
                    "processGraph": {
                        "processes": {
                            role: {"pid": index + 1}
                            for index, role in enumerate(MODULE.EXPECTED_PROCESS_CANDIDATES)
                        }
                    }
                }
            }

        @property
        def phase(self) -> str:
            return str(self.state["phase"])

        def advance(self, phase: str) -> None:
            self.events.append(f"phase:{phase}")
            self.state = {"phase": phase}

    def common_patches(self, control: "ReducerStateMachineTest.FakeControl") -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "process_authority",
                side_effect=lambda value, role: {"role": role, "pid": 1},
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "remove_bound_socket",
                side_effect=lambda *args: control.events.append("socket-revoked"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "signal_exact_process",
                side_effect=lambda value: control.events.append(f"signal:{value['role']}"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "wait_for_roles_absent",
                side_effect=lambda value, roles, **kwargs: control.events.append(
                    "wait:" + ",".join(roles)
                ),
            )
        )
        stack.enter_context(mock.patch.object(MODULE, "require_mounts_absent"))
        stack.enter_context(mock.patch.object(MODULE, "require_registry_listener_absent"))
        stack.enter_context(mock.patch.object(MODULE, "registry_inventory_matches"))
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "settle_task_netns",
                side_effect=lambda *args: control.events.append("netns-settled"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "reduce_runtime_tree",
                side_effect=lambda *args: control.events.append("runtime-reduced"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "unlink_containerd_pidfile",
                side_effect=lambda *args: control.events.append("pidfile-removed"),
            )
        )
        stack.enter_context(
            mock.patch.object(MODULE, "exists_nofollow", return_value=False)
        )
        stack.enter_context(
            mock.patch.object(MODULE, "exact_process_status", return_value="absent")
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "archive_receipt",
                side_effect=lambda *args: control.events.append("receipt-archived"),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "write_projection",
                side_effect=lambda *args: control.events.append("projection-written"),
            )
        )
        return stack

    def test_success_order_is_dockerd_graph_containerd_mount_runtime_archive(self) -> None:
        control = self.FakeControl()
        with self.common_patches(control):
            result = MODULE.run_reducer(control)
        self.assertEqual(result["outcome"], "drained")
        self.assertLess(control.events.index("signal:dockerd"), control.events.index("signal:containerd"))
        self.assertLess(control.events.index("signal:containerd"), control.events.index("netns-settled"))
        self.assertLess(control.events.index("netns-settled"), control.events.index("runtime-reduced"))
        self.assertLess(control.events.index("runtime-reduced"), control.events.index("receipt-archived"))

    def test_registry_task_survival_never_signals_containerd(self) -> None:
        control = self.FakeControl()
        with self.common_patches(control), mock.patch.object(
            MODULE,
            "wait_for_roles_absent",
            side_effect=MODULE.ManualRecoveryRequired("registry task survived"),
        ), self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "survived"):
            MODULE.run_reducer(control)
        self.assertNotIn("signal:containerd", control.events)

    def test_overlay_mount_survival_never_signals_containerd(self) -> None:
        control = self.FakeControl()

        def mounts(*args: object, **kwargs: object) -> None:
            if args[1] == "outerDocker":
                raise MODULE.ManualRecoveryRequired("overlay survived")

        with self.common_patches(control), mock.patch.object(
            MODULE, "require_mounts_absent", side_effect=mounts
        ), self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "overlay"):
            MODULE.run_reducer(control)
        self.assertNotIn("signal:containerd", control.events)

    def test_dockerd_signal_response_loss_replays_requested_phase(self) -> None:
        control = self.FakeControl()
        control.state = {"phase": "dockerd_stop_requested"}
        with self.common_patches(control):
            MODULE.run_reducer(control)
        self.assertEqual(control.events[0], "signal:dockerd")

    def test_runtime_partial_reduction_replays_runtime_phase(self) -> None:
        control = self.FakeControl()
        control.state = {"phase": "runtime_reducing"}
        with self.common_patches(control):
            MODULE.run_reducer(control)
        self.assertEqual(control.events[0], "runtime-reduced")
        self.assertIn("receipt-archived", control.events)

    def test_crash_after_runtime_rmdir_finishes_from_total_absence(self) -> None:
        control = self.FakeControl()
        control.state = {"phase": "runtime_removed"}
        with self.common_patches(control):
            MODULE.run_reducer(control)
        self.assertNotIn("runtime-reduced", control.events)
        self.assertIn("receipt-archived", control.events)

    def test_foreign_reused_pid_blocks_terminal_completion(self) -> None:
        control = self.FakeControl()
        control.state = {"phase": "runtime_removed"}
        with self.common_patches(control), mock.patch.object(
            MODULE,
            "exact_process_status",
            side_effect=MODULE.ManualRecoveryRequired("foreign identity"),
        ), self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "foreign"):
            MODULE.run_reducer(control)
        self.assertNotIn("receipt-archived", control.events)

    def test_registry_inventory_change_blocks_before_archive(self) -> None:
        control = self.FakeControl()
        control.state = {"phase": "runtime_reducing"}
        with self.common_patches(control), mock.patch.object(
            MODULE,
            "registry_inventory_matches",
            side_effect=MODULE.DrainError("registry custody changed"),
        ), self.assertRaisesRegex(MODULE.DrainError, "custody"):
            MODULE.run_reducer(control)
        self.assertNotIn("receipt-archived", control.events)

    def test_complete_response_loss_is_terminal_noop(self) -> None:
        control = self.FakeControl()
        control.state = {"phase": "complete"}
        with self.common_patches(control):
            result = MODULE.run_reducer(control)
        self.assertEqual(result["outcome"], "drained")
        self.assertEqual(control.events, [])

    def test_phase_regression_and_skip_reject(self) -> None:
        authority = object.__new__(MODULE.ControlAuthority)
        authority.state = {"phase": "dockerd_stopped"}
        authority.control_digest = "c" * 64
        authority.descriptor = 31
        with self.assertRaisesRegex(MODULE.DrainError, "regress"):
            authority.advance("dockerd_stop_requested")
        with self.assertRaisesRegex(MODULE.DrainError, "skip"):
            authority.advance("containerd_stop_requested")


class DestructiveBoundaryTest(unittest.TestCase):
    def test_bound_leaf_swap_rejects(self) -> None:
        expected = {
            "device": 1,
            "inode": 2,
            "uid": 0,
            "gid": 0,
            "type": stat.S_IFREG,
        }
        observed = mock.Mock(
            st_dev=1,
            st_ino=3,
            st_uid=0,
            st_gid=0,
            st_mode=stat.S_IFREG | 0o600,
        )
        with mock.patch.object(MODULE.os, "stat", return_value=observed), mock.patch.object(
            MODULE.os, "unlink"
        ) as unlink:
            with self.assertRaisesRegex(MODULE.DrainError, "changed"):
                MODULE.remove_tree_entry(31, "leaf", expected)
        unlink.assert_not_called()

    def test_symlink_runtime_leaf_is_never_reduced(self) -> None:
        expected = {
            "device": 1,
            "inode": 2,
            "uid": 0,
            "gid": 0,
            "type": stat.S_IFLNK,
        }
        observed = mock.Mock(
            st_dev=1,
            st_ino=2,
            st_uid=0,
            st_gid=0,
            st_mode=stat.S_IFLNK | 0o777,
        )
        with mock.patch.object(MODULE.os, "stat", return_value=observed), mock.patch.object(
            MODULE.os, "unlink"
        ) as unlink:
            with self.assertRaisesRegex(MODULE.DrainError, "leaf type"):
                MODULE.remove_tree_entry(31, "leaf", expected)
        unlink.assert_not_called()

    def test_unknown_runtime_entry_is_manual(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "foreign").write_text("x", encoding="utf-8")
            with mock.patch.object(MODULE, "EXPECTED_RUNTIME_ROOT", root), mock.patch.object(
                MODULE.os,
                "fstat",
                side_effect=lambda fd: mock.Mock(
                    st_dev=44,
                    st_ino=12496265,
                    st_uid=1000,
                    st_gid=1000,
                    st_mode=stat.S_IFDIR | 0o700,
                    st_nlink=2,
                ),
            ):
                with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "foreign"):
                    MODULE.runtime_tree_snapshot()

    def test_persistent_roots_are_never_runtime_reducer_targets(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        reducer = source[source.index("def reduce_runtime_tree") : source.index("def unlink_containerd_pidfile")]
        for path in MODULE.PERSISTENT_ROOTS:
            self.assertNotIn(str(path), reducer)

    def test_source_has_no_cgroup_mutation_force_kill_or_broad_delete(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("SIGKILL", source)
        self.assertNotIn("cgroup.kill", source)
        self.assertNotIn("cgroup.freeze", source)
        self.assertNotIn("find -delete", source)
        self.assertNotIn("rm -rf", source)
        self.assertEqual(source.count("pidfd_send_signal"), 2)

    def test_v5_authority_and_second_legacy_runtime_are_manual_blockers(self) -> None:
        listdir = mock.Mock(
            side_effect=(
                ["ambit-c16b-docker-api-1577287b8182"],
                [],
                [MODULE.EXPECTED_RUNTIME_ROOT.name],
            )
        )
        with mock.patch.object(MODULE.os, "listdir", listdir), mock.patch.object(
            MODULE, "exists_nofollow", return_value=False
        ):
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "v5"):
                MODULE.require_v5_absent()

        with mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(
                [],
                [],
                [MODULE.EXPECTED_RUNTIME_ROOT.name, "ambit-c16b-docker-aaaaaaaaaaaa"],
            ),
        ), mock.patch.object(MODULE, "exists_nofollow", return_value=False):
            with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "legacy runtime roster"):
                MODULE.require_v5_absent()

    def test_only_exact_task_nsfs_can_invoke_umount(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        calls = [line for line in source.splitlines() if "subprocess.run(" in line]
        self.assertEqual(calls, ["        result = subprocess.run("])
        self.assertIn("settle_task_netns", source)

    def test_verify_only_has_no_lease_control_write_signal_or_unmount(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        verify = source[
            source.index("def operation_verify") : source.index("def operation_drain")
        ]
        self.assertIn("return collect_verification", verify)
        for forbidden in (
            "RuntimeLease",
            "ControlAuthority",
            "signal_exact_process",
            "settle_task_netns",
            "atomic_write_at",
        ):
            self.assertNotIn(forbidden, verify)

    def test_drain_recomputes_exact_digest_under_global_lease(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        drain = source[source.index("def operation_drain") : source.index("def operation_resume")]
        self.assertLess(drain.index("RuntimeLease.acquire"), drain.index("collect_verification"))
        self.assertLess(drain.index("collect_verification"), drain.index("ControlAuthority.create"))
        self.assertIn('verification["verificationSha256"] == expected_verification_sha256', drain)


class WrapperBoundaryTest(unittest.TestCase):
    def test_wrapper_exposes_only_verify_drain_resume(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("verify-only)", source)
        self.assertIn("drain)", source)
        self.assertIn("resume)", source)
        for forbidden in ("start)", "activate)", "docker stop", "kill -TERM", "umount --"):
            self.assertNotIn(forbidden, source)

    def test_wrapper_pins_tool_and_sanitizes_root_environment(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        observed = hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest()
        self.assertIn(f"tool_sha256={observed}", source)
        self.assertIn("/usr/bin/env -i", source)
        self.assertIn("/usr/bin/python3 -I -S", source)
        self.assertIn("SUDO_UID=", source)
        self.assertIn("SUDO_GID=", source)

    def test_resume_uses_root_snapshot_not_mutable_repo_source(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        resume = source[source.index("  resume)") : source.index("  *)")]
        self.assertIn('snapshot = control_root / "legacy_v3_drain.py"', resume)
        self.assertIn("sourceSha256", resume)
        self.assertIn("os.execv(", resume)
        self.assertNotIn('sha256sum -- "${tool}"', resume)

    def test_verify_only_has_no_output_file_argument(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        verify = source[source.index("  verify-only)") : source.index("  drain)")]
        self.assertNotIn(">", verify)
        self.assertIn("run_repo_tool verify-only", verify)


if __name__ == "__main__":
    unittest.main()
