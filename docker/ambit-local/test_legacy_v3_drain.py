from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import json
import os
import signal
import socket
import stat
import struct
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
class ProcessUniverseTest(unittest.TestCase):
    def test_structured_arguments_do_not_use_substring_authority(self) -> None:
        exact = (
            b"/usr/bin/containerd-shim-runc-v2\0-address\0"
            + str(MODULE.CONTAINERD_SOCKET).encode()
            + b"\0-namespace\0ambit-c16b\0"
        )
        relations = MODULE._structured_argument_relations(exact)
        self.assertIn("containerdSocketArgv", relations)
        self.assertIn("namespaceArgv", relations)
        self.assertNotIn(
            "namespaceArgv",
            MODULE._structured_argument_relations(b"/bin/echo\0not-ambit-c16b-extra\0"),
        )

    def test_universe_requires_two_identical_complete_passes(self) -> None:
        processes: dict[str, dict[str, object]] = {}
        runtime = {"tree": [], "rootIdentity": {"device": 1, "inode": 2}}
        sockets = {"unixRecords": []}
        stable = {"allowedRoles": [], "related": [], "proofSha256": "a" * 64}
        with mock.patch.object(
            MODULE, "_related_process_universe_once", side_effect=(stable, stable)
        ) as once:
            self.assertEqual(
                MODULE.related_process_universe(
                    processes, runtime, sockets, allowed_roles=set()
                ),
                stable,
            )
        self.assertEqual(once.call_count, 2)
        changed = {**stable, "proofSha256": "b" * 64}
        with mock.patch.object(
            MODULE, "_related_process_universe_once", side_effect=(stable, changed)
        ), self.assertRaisesRegex(MODULE.DrainError, "across proof passes"):
            MODULE.related_process_universe(
                processes, runtime, sockets, allowed_roles=set()
            )

    def test_allowed_pidfds_remain_held_through_action(self) -> None:
        closed: list[int] = []
        roles = {"dockerd", "containerd"}
        with mock.patch.object(
            MODULE, "require_related_process_cutoff", return_value={"proof": True}
        ), mock.patch.object(
            MODULE,
            "process_authority",
            side_effect=lambda _control, role: {"pid": 1 if role == "dockerd" else 2},
        ), mock.patch.object(
            MODULE.os, "pidfd_open", side_effect=(31, 32)
        ), mock.patch.object(
            MODULE, "exact_process_status", return_value="exact"
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE.os, "close", side_effect=closed.append
        ):
            with MODULE.hold_related_process_cutoff(
                {"authority": {}}, allowed_roles=roles
            ):
                self.assertEqual(closed, [])
        self.assertEqual(sorted(closed), [31, 32])

    def test_source_covers_empty_argv_maps_namespace_fds_and_pid_reuse(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"runtimeMappedPath"', source)
        self.assertIn('"runtimeNamespaceFd"', source)
        self.assertIn('"privateRuntimeNamespace"', source)
        self.assertIn("recorded legacy process PID was reused", source)
        self.assertNotIn("if not raw_arguments:\n                second_parent", source)

    def test_exact_process_status_uses_the_real_exact_vocabulary(self) -> None:
        recorded = captured_process().authority
        with mock.patch.object(MODULE, "process_exists", return_value=True), mock.patch.object(
            MODULE, "capture_process", return_value=captured_process()
        ):
            self.assertEqual(MODULE.exact_process_status(recorded), "exact")


class MountAuthorityTest(unittest.TestCase):
    def test_mount_records_preserve_ids_and_stacked_multiplicity(self) -> None:
        raw = (
            "21 20 0:4 net:[4026531833] /x rw - nsfs nsfs rw\n"
            "22 21 0:4 net:[4026531833] /x rw - nsfs nsfs rw\n"
        )
        records = MODULE.mount_records(raw)
        self.assertEqual([(row.mount_id, row.parent_id) for row in records], [(21, 20), (22, 21)])
        references = MODULE.mount_reference_records(
            raw,
            Path("/x"),
            (("0:4", "net:[4026531833]"),),
        )
        self.assertEqual(len(references), 2)

    def test_opaque_nsfs_is_exact_and_non_nsfs_opaque_rejects(self) -> None:
        raw = "21 20 0:4 net:[4026531833] /x rw - nsfs nsfs rw\n"
        record = MODULE.mount_records(raw)[0]
        self.assertEqual(record.root, "net:[4026531833]")
        self.assertTrue(
            MODULE.mount_root_at_or_below(
                "net:[4026531833]", "net:[4026531833]"
            )
        )
        with self.assertRaisesRegex(MODULE.DrainError, "opaque"):
            MODULE.mount_records("20 1 0:4 net:[1] /x rw - ext4 ext4 rw\n")

    def test_fd_umount_uses_only_the_held_procfd(self) -> None:
        function = mock.Mock(return_value=0)
        with mock.patch.object(MODULE.LIBC, "umount2", function, create=True):
            MODULE.fd_umount(31)
        path_arg, flag_arg = function.call_args.args
        self.assertEqual(path_arg.value, b"/proc/self/fd/31")
        self.assertEqual(flag_arg.value, 0)

    def test_marker_transition_is_exact(self) -> None:
        values = {
            "st_mode": stat.S_IFREG | 0o600,
            "st_uid": 0,
            "st_gid": 0,
            "st_nlink": 1,
            "st_size": 0,
        }
        MODULE._require_task_netns_marker(mock.Mock(**values))
        for field, value in (
            ("st_uid", 1000),
            ("st_gid", 1000),
            ("st_nlink", 2),
            ("st_size", 1),
            ("st_mode", stat.S_IFREG | 0o644),
        ):
            with self.subTest(field=field):
                invalid = {**values, field: value}
                with self.assertRaisesRegex(MODULE.DrainError, "marker"):
                    MODULE._require_task_netns_marker(mock.Mock(**invalid))

    def test_netns_action_compares_full_roster_and_uses_no_path_subprocess(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        body = source[
            source.index("def settle_task_netns")
            : source.index("def _require_task_netns_marker")
        ]
        self.assertIn('observed["occurrences"] == recorded_occurrences', body)
        self.assertIn("fd_umount(target_fd)", body)
        self.assertNotIn("subprocess.run", body)
        self.assertNotIn("/usr/bin/umount", body)

    def test_foreign_stack_at_ambient_target_is_selected(self) -> None:
        raw = (
            "21 20 0:4 net:[1] /owned rw - nsfs nsfs rw\n"
            "22 20 0:4 net:[1] /ambient rw - nsfs nsfs rw\n"
            "23 20 8:1 /foreign /ambient rw - ext4 /dev/root rw\n"
        )
        records = MODULE.mount_reference_records(
            raw,
            Path("/owned"),
            (("0:4", "net:[1]"),),
            ("/owned", "/ambient"),
        )
        self.assertEqual([row.mount_id for row in records], [21, 22, 23])

    def test_held_fd_exposes_a_kernel_mount_id(self) -> None:
        with tempfile.NamedTemporaryFile() as value:
            descriptor = os.open(value.name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                self.assertGreater(MODULE.fd_mount_id(descriptor), 0)
            finally:
                os.close(descriptor)

    def test_unix_diag_parser_preserves_peer_and_pending_icons(self) -> None:
        sequence = 7
        attributes = (
            struct.pack("=HHI", 8, 3, 42)
            + struct.pack("=HHII", 12, 4, 43, 44)
            + struct.pack("=HHI", 8, 8, 1000)
        )
        payload = struct.pack("=BBBBIII", socket.AF_UNIX, 1, 1, 0, 41, 1, 2) + attributes
        message = struct.pack("=IHHII", 16 + len(payload), MODULE.SOCK_DIAG_BY_FAMILY, 0, sequence, 0) + payload
        done = struct.pack("=IHHII", 16, MODULE.NLMSG_DONE, 0, sequence, 0)
        rows, complete = MODULE.parse_unix_diag_datagram(message + done, expected_sequence=sequence)
        self.assertTrue(complete)
        self.assertEqual(rows[0]["peer"], 42)
        self.assertEqual(rows[0]["icons"], [43, 44])
        self.assertEqual(rows[0]["uid"], 1000)


class ReducerStateMachineTest(unittest.TestCase):
    class FakeControl:
        def __init__(self, phase: str | None = None) -> None:
            self.state = {
                "phase": phase or MODULE.PHASES[0],
                "observedAt": "2026-08-22T00:00:00+00:00",
                "bootId": "b" * 36,
                "netnsMarkerIdentity": (
                    {"device": 44, "inode": 99}
                    if MODULE.PHASES.index(phase or MODULE.PHASES[0])
                    >= MODULE.PHASES.index("mounts_settled")
                    else None
                ),
            }
            self.control_digest = "c" * 64
            self.control = {
                "sourceSha256": "d" * 64,
                "authority": {
                    "processGraph": {
                        "processes": {
                            role: {"pid": index + 1}
                            for index, role in enumerate(
                                MODULE.EXPECTED_PROCESS_CANDIDATES
                            )
                        }
                    }
                },
            }
            self.events: list[str] = []

        @property
        def phase(self) -> str:
            return str(self.state["phase"])

        def advance(self, phase: str, **kwargs: object) -> None:
            current = MODULE.PHASES.index(self.phase)
            target = MODULE.PHASES.index(phase)
            if target != current + 1:
                raise AssertionError(f"nonadjacent transition {self.phase}->{phase}")
            self.events.append(f"phase:{phase}")
            self.state = {**self.state, "phase": phase}
            if kwargs.get("netns_marker_identity") is not None:
                self.state["netnsMarkerIdentity"] = kwargs["netns_marker_identity"]

    def patches(
        self, control: "ReducerStateMachineTest.FakeControl"
    ) -> contextlib.ExitStack:
        stack = contextlib.ExitStack()
        event_functions = {
            "transfer_runtime_custody": "custody",
            "remove_bound_socket": "socket",
            "runtime_reduction_preflight": "preflight",
            "reduce_runtime_tree": "runtime-reduced",
            "remove_empty_runtime_root": "runtime-root-removed",
            "require_terminal_reproof": "terminal-reproof",
            "transfer_receipt_custody": "receipt-custody",
        }
        for name, event in event_functions.items():
            stack.enter_context(
                mock.patch.object(
                    MODULE,
                    name,
                    side_effect=lambda *_args, marker=event, **_kwargs: control.events.append(marker),
                )
            )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "settle_task_netns",
                side_effect=lambda *_args: (
                    control.events.append("netns")
                    or {
                        "device": 44,
                        "inode": 99,
                        "uid": 0,
                        "gid": 0,
                        "mode": 0o600,
                        "type": stat.S_IFREG,
                        "links": 1,
                        "size": 0,
                    }
                ),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "process_authority",
                side_effect=lambda _value, role: {"role": role, "pid": 1},
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "signal_exact_process",
                side_effect=lambda value: control.events.append(
                    "signal:" + str(value["role"])
                ),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "wait_for_roles_absent",
                side_effect=lambda _value, roles, **_kwargs: control.events.append(
                    "wait:" + ",".join(roles)
                ),
            )
        )
        stack.enter_context(mock.patch.object(MODULE, "require_mounts_absent"))
        stack.enter_context(mock.patch.object(MODULE, "require_registry_listener_absent"))
        stack.enter_context(mock.patch.object(MODULE, "post_revocation_socket_snapshot"))
        stack.enter_context(mock.patch.object(MODULE, "registry_inventory_matches"))
        stack.enter_context(mock.patch.object(MODULE, "require_related_process_cutoff"))
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "hold_related_process_cutoff",
                side_effect=lambda *_args, **_kwargs: contextlib.nullcontext({}),
            )
        )
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "archive_receipt",
                side_effect=lambda *_args: (
                    control.events.append("archive")
                    or {"schema": MODULE.PROJECTION_SCHEMA, "outcome": "drained"}
                ),
            )
        )
        return stack

    def test_success_order_and_archive_is_final_mutation(self) -> None:
        control = self.FakeControl()
        with self.patches(control):
            result = MODULE.run_reducer(control)
        self.assertEqual(result["outcome"], "drained")
        self.assertLess(control.events.index("custody"), control.events.index("socket"))
        self.assertLess(control.events.index("signal:dockerd"), control.events.index("signal:containerd"))
        self.assertLess(control.events.index("netns"), control.events.index("preflight"))
        self.assertLess(control.events.index("preflight"), control.events.index("runtime-reduced"))
        self.assertLess(control.events.index("runtime-root-removed"), control.events.index("receipt-custody"))
        self.assertEqual(control.events[-1], "archive")
        self.assertEqual(control.phase, "archive_intent_final")

    def test_every_phase_replays_to_same_terminal_result(self) -> None:
        for phase in MODULE.PHASES:
            with self.subTest(phase=phase):
                control = self.FakeControl(phase)
                with self.patches(control):
                    result = MODULE.run_reducer(control)
                self.assertEqual(result["outcome"], "drained")
                self.assertEqual(control.phase, "archive_intent_final")
                self.assertEqual(control.events[-1], "archive")

    def test_container_graph_blocker_precedes_containerd_signal(self) -> None:
        control = self.FakeControl("dockerd_stopped")
        with self.patches(control), mock.patch.object(
            MODULE,
            "wait_for_roles_absent",
            side_effect=MODULE.ManualRecoveryRequired("registry survived"),
        ), self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "survived"):
            MODULE.run_reducer(control)
        self.assertNotIn("signal:containerd", control.events)

    def test_real_advance_rejects_regression_and_skip(self) -> None:
        authority = object.__new__(MODULE.ControlAuthority)
        authority.state = {"phase": "dockerd_stopped"}
        authority.control_digest = "c" * 64
        authority.descriptor = 31
        with self.assertRaisesRegex(MODULE.DrainError, "regress"):
            authority.advance("dockerd_stop_requested")
        with self.assertRaisesRegex(MODULE.DrainError, "skip"):
            authority.advance("containerd_stop_requested")


class DestructiveBoundaryTest(unittest.TestCase):
    def test_no_replace_rename_preserves_foreign_destination(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "source").write_bytes(b"source")
            (root / "destination").write_bytes(b"foreign")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(FileExistsError):
                    MODULE.rename_noreplace_at(descriptor, "source", descriptor, "destination")
            finally:
                os.close(descriptor)
            self.assertEqual((root / "source").read_bytes(), b"source")
            self.assertEqual((root / "destination").read_bytes(), b"foreign")

    def test_no_replace_rename_success_preserves_inode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "source"
            source.write_bytes(b"source")
            before = source.stat()
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                MODULE.rename_noreplace_at(descriptor, "source", descriptor, "destination")
            finally:
                os.close(descriptor)
            self.assertFalse(source.exists())
            after = (root / "destination").stat()
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))

    def test_unnamed_tmpfile_link_is_source_fd_bound_and_no_replace(self) -> None:
        if not hasattr(os, "O_TMPFILE"):
            self.skipTest("O_TMPFILE is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            temporary_fd = os.open(
                ".", os.O_TMPFILE | os.O_RDWR, 0o600, dir_fd=directory_fd
            )
            try:
                os.write(temporary_fd, b"exact")
                os.fsync(temporary_fd)
                MODULE.link_tmpfile_noreplace_at(
                    temporary_fd, directory_fd, "published"
                )
                self.assertEqual((root / "published").read_bytes(), b"exact")
                with self.assertRaises(FileExistsError):
                    MODULE.link_tmpfile_noreplace_at(
                        temporary_fd, directory_fd, "published"
                    )
            finally:
                os.close(temporary_fd)
                os.close(directory_fd)

    def test_receipt_custody_admits_original_intermediate_and_final_only(self) -> None:
        raw = b"receipt\n"
        digest = hashlib.sha256(raw).hexdigest()
        expected = {
            "device": 7,
            "inode": 9,
            "uid": 1000,
            "gid": 1000,
            "mode": 0o600,
            "size": len(raw),
        }
        with mock.patch.object(MODULE, "EXPECTED_RECEIPT_SHA256", digest):
            for uid, gid, mode in ((1000, 1000, 0o600), (0, 0, 0o600), (0, 0, 0o400)):
                with self.subTest(uid=uid, mode=mode):
                    observed = mock.Mock(
                        st_mode=stat.S_IFREG | mode,
                        st_uid=uid,
                        st_gid=gid,
                        st_nlink=1,
                        st_dev=7,
                        st_ino=9,
                        st_size=len(raw),
                    )
                    MODULE._require_legacy_receipt(
                        observed, raw, expected, terminal=False
                    )
            invalid = mock.Mock(
                st_mode=stat.S_IFREG | 0o644,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_dev=7,
                st_ino=9,
                st_size=len(raw),
            )
            with self.assertRaises(MODULE.DrainError):
                MODULE._require_legacy_receipt(
                    invalid, raw, expected, terminal=False
                )

    def test_receipt_tombstone_prefixes_are_total_replay_states(self) -> None:
        raw = b'{"legacy":true}\n'
        digest = hashlib.sha256(raw).hexdigest()
        control = {
            "authority": {
                "legacyReceipt": {
                    "device": 7,
                    "inode": 9,
                    "uid": 1000,
                    "gid": 1000,
                    "mode": 0o600,
                    "size": len(raw),
                },
                "legacyReceiptBytes": raw.decode(),
            }
        }
        observed = mock.Mock(
            st_mode=stat.S_IFREG | 0o400,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_dev=7,
            st_ino=9,
            st_size=0,
        )
        with mock.patch.object(MODULE, "EXPECTED_RECEIPT_SHA256", digest):
            tombstone = MODULE.receipt_tombstone_bytes(control)
            for length in (0, 1, len(tombstone) - 1):
                with self.subTest(length=length):
                    observed.st_size = length
                    self.assertEqual(
                        MODULE._live_receipt_disposition(
                            observed, tombstone[:length], control
                        ),
                        "tombstone_prefix",
                    )
            observed.st_size = len(tombstone)
            self.assertEqual(
                MODULE._live_receipt_disposition(observed, tombstone, control),
                "tombstone",
            )

    def test_archived_response_loss_is_read_only_and_byte_stable(self) -> None:
        control = ReducerStateMachineTest.FakeControl("archive_intent_final")
        expected = {"schema": MODULE.PROJECTION_SCHEMA, "outcome": "drained"}
        with mock.patch.object(
            MODULE, "legacy_receipt_state", return_value=("archived", b"x")
        ), mock.patch.object(
            MODULE, "read_projection", return_value=expected
        ) as read, mock.patch.object(
            MODULE, "write_projection"
        ) as write, mock.patch.object(
            MODULE, "rename_noreplace_at"
        ) as rename:
            first = MODULE.archive_receipt(control)
            second = MODULE.archive_receipt(control)
        self.assertEqual(first, second)
        self.assertEqual(read.call_count, 2)
        write.assert_not_called()
        rename.assert_not_called()

    def test_projection_is_deterministic_and_precedes_archive(self) -> None:
        control = ReducerStateMachineTest.FakeControl("archive_intent_final")
        first = MODULE.terminal_projection_value(control)
        second = MODULE.terminal_projection_value(control)
        self.assertEqual(MODULE.canonical_json(first), MODULE.canonical_json(second))
        self.assertEqual(first["observedAt"], control.state["observedAt"])
        source = MODULE_PATH.read_text(encoding="utf-8")
        archive = source[
            source.index("def archive_receipt")
            : source.index("def registry_inventory_matches")
        ]
        self.assertLess(
            archive.index("terminal = write_projection(control)"),
            archive.index("link_tmpfile_noreplace_at("),
        )

    def test_runtime_and_pidfile_have_complete_preflight_before_unlink(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        reducer = source[source.index("def run_reducer") : source.index("def require_root")]
        self.assertLess(reducer.index("runtime_reduction_preflight"), reducer.index("reduce_runtime_tree"))
        self.assertNotIn("unlink_containerd_pidfile", source)
        self.assertIn("require_containerd_pidfile_exact", source)
        runtime = source[source.index("def _scan_runtime_directory") : source.index("def _read_regular_at")]
        self.assertNotIn("os.walk", runtime)
        self.assertNotIn("shutil.rmtree", runtime)
        self.assertIn("dir_fd=", runtime)

    def test_source_has_no_cgroup_mutation_force_kill_or_broad_delete(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("cgroup.kill", source)
        self.assertNotIn("SIGKILL", source)
        self.assertNotIn("killpg", source)
        self.assertNotIn("shutil.rmtree", source)
        self.assertIn('"cgroup": "forbidden_shared_66_process_observation"', source)

    def test_capsule_publication_is_atomic_and_boot_bound(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        publish = source[source.index("def publish_control_capsule") : source.index("def validate_control")]
        self.assertIn("CONTROL_PENDING_NAME", publish)
        self.assertIn("rename_noreplace_at(", publish)
        self.assertIn("os.fsync(parent_fd)", publish)
        self.assertLess(publish.index("atomic_write_at(descriptor, STATE_NAME"), publish.index("rename_noreplace_at("))
        self.assertIn('control["bootId"] == current_boot_id()', source)
        self.assertIn('state["bootId"] == current_boot_id()', source)

    def test_projection_and_archive_publish_only_from_unnamed_fds(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        projection = source[source.index("def write_projection") : source.index("def archive_receipt")]
        archive = source[source.index("def archive_receipt") : source.index("def registry_inventory_matches")]
        self.assertIn("_create_root_tmpfile", projection)
        self.assertIn("link_tmpfile_noreplace_at", projection)
        self.assertNotIn("pending_name", projection)
        self.assertIn("complete_receipt_tombstone", archive)
        self.assertIn("link_tmpfile_noreplace_at", archive)
        self.assertNotIn("rename_noreplace_at(\n                evidence_fd,\n                RECEIPT_PATH.name", archive)


class WrapperBoundaryTest(unittest.TestCase):
    def test_wrapper_exposes_only_verify_drain_resume(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        cases = set()
        for line in source.splitlines():
            if line in ("  verify-only)", "  drain)", "  resume)"):
                cases.add(line.strip().removesuffix(")"))
        self.assertEqual(cases, {"verify-only", "drain", "resume"})

    def test_wrapper_pin_matches_source(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        observed = hashlib.sha256(MODULE_PATH.read_bytes()).hexdigest()
        self.assertIn(f"tool_sha256={observed}", source)

    def test_verified_bytes_are_executed_in_sudo_and_snapshotted(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn("/usr/bin/sudo -n -- /usr/bin/python3 -I -S -B -c", source)
        self.assertIn("exec(compile(source, display_name, \"exec\")", source)
        self.assertIn('"__legacy_pinned_source_bytes__": source', source)
        self.assertIn('"__legacy_control_root_fd__"', source)
        self.assertNotIn("os.execv", source)
        self.assertNotIn('/usr/bin/python3 -I -S "${tool}"', source)

    def test_resume_boot_gate_precedes_source_execution(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertLess(
            source.index('control["bootId"] == state["bootId"] == boot_id'),
            source.index("exec(compile(source, display_name"),
        )
        self.assertLess(
            source.index("control_root_fd = os.open("),
            source.index('read_bound_at(control_root_fd, "legacy_v3_drain.py"'),
        )

    def test_loader_and_reducer_share_exact_canonical_bytes(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        loader = source.split("read -r -d '' pinned_loader <<'PY' || true\n", 1)[1].split("\nPY\n", 1)[0]
        tree = ast.parse(loader)
        canonical = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "canonical"
        )
        module = ast.fix_missing_locations(ast.Module(body=[canonical], type_ignores=[]))
        namespace = {"json": json}
        exec(compile(module, "<loader-canonical>", "exec"), namespace, namespace)
        value = {"nested": {"b": 2}, "a": [1, True, None]}
        self.assertEqual(namespace["canonical"](value), MODULE.canonical_json(value))

    def test_verify_only_has_no_output_file_argument(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        verify = source[source.index("  verify-only)") : source.index("  drain)")]
        self.assertIn('invoke_tool repo "${tool}"', verify)
        self.assertNotIn("output", verify.lower())


if __name__ == "__main__":
    unittest.main()
