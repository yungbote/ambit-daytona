from __future__ import annotations

import ast
import collections
import contextlib
import dis
import errno
import functools
import hashlib
import importlib.util
import itertools
import json
import os
import operator
import signal
import socket
import stat
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable
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


def task_namespaces(*, first_inode: int = 19) -> dict[str, dict[str, object]]:
    return {
        entry: {
            "kind": kind,
            "device": 4,
            "inode": first_inode + index,
        }
        for index, (entry, kind) in enumerate(MODULE.TASK_NAMESPACE_ENTRIES)
    }


def task_namespace_binding(
    *,
    thread_group_id: int = 100,
    task_id: int = 100,
    inode: int = 100,
) -> dict[str, object]:
    return {
        "threadGroupId": thread_group_id,
        "taskId": task_id,
        "namespaces": {
            entry: {"kind": kind, "device": 4, "inode": inode}
            for entry, kind in MODULE.TASK_NAMESPACE_ENTRIES
        },
    }


def task_namespace_bindings_for_kinds(
    identities: dict[str, MODULE.NamespaceIdentity],
    coordinates: tuple[tuple[int, int], ...],
) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "threadGroupId": thread_group_id,
            "taskId": task_id,
            "namespaces": {
                entry: {
                    "kind": kind,
                    "device": identities[kind].device,
                    "inode": identities[kind].inode,
                }
                for entry, kind in MODULE.TASK_NAMESPACE_ENTRIES
            },
        }
        for thread_group_id, task_id in coordinates
    )


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
            "taskNamespaces": task_namespaces(),
            "cgroup": "/user.slice/task.scope",
            "credentialProfile": "root-runtime-full-capability",
            "credentialProfileSha256": MODULE.MEASURED_TASK_SECURITY_PROFILE_SHA256[
                "root-runtime-full-capability"
            ],
            "credentials": json.loads(
                json.dumps(
                    MODULE.MEASURED_TASK_SECURITY_PROFILES[
                        "root-runtime-full-capability"
                    ]
                )
            ),
        },
        observed_proc_inode=proc_inode,
    )


def namespace_census(
    *,
    current: tuple[MODULE.NamespaceIdentity, ...] = (),
    namespace_fds: tuple[MODULE.NamespaceIdentity, ...] = (),
    mounts: tuple[MODULE.MountNamespaceAuthority, ...] = (),
    digest: str = "9" * 64,
    task_namespace_rows: tuple[dict[str, object], ...] = (),
) -> MODULE.TaskNamespaceCensus:
    result = MODULE.TaskNamespaceCensus(
        frozenset(current),
        frozenset(namespace_fds),
        mounts,
        digest,
        {
            "processBoundNamespaceCount": len(current),
            "namespaceFdCount": len(namespace_fds),
            "mountNamespaceCount": len(mounts),
            "proofSha256": digest,
        },
        task_namespaces=task_namespace_rows,
    )
    result.require_open = mock.Mock()  # type: ignore[method-assign]
    return result


def acquire_test_descriptor(
    custody: MODULE.ResourceCustody,
    descriptor: int,
) -> int:
    """Acquire a synthetic descriptor through the same public custody boundary."""

    with mock.patch.object(MODULE.os, "open", return_value=descriptor):
        return custody.open("test-owned-descriptor", os.O_RDONLY)


def acquire_test_descriptors(
    custody: MODULE.ResourceCustody,
    *descriptors: int,
) -> tuple[int, ...]:
    return tuple(acquire_test_descriptor(custody, value) for value in descriptors)


@contextlib.contextmanager
def interrupt_once_on_line(
    code: object,
    line: int,
    message: str,
):  # type: ignore[no-untyped-def]
    """Inject one asynchronous-style interruption at an AST-derived boundary."""

    previous = sys.gettrace()
    fired = [False]

    def trace(frame: object, event: str, _argument: object):  # type: ignore[no-untyped-def]
        if (
            not fired[0]
            and event == "line"
            and getattr(frame, "f_code") is code
            and getattr(frame, "f_lineno") == line
        ):
            fired[0] = True
            sys.settrace(previous)
            raise KeyboardInterrupt(message)
        return trace

    sys.settrace(trace)
    try:
        yield fired
    finally:
        sys.settrace(previous)


@contextlib.contextmanager
def interrupt_once_on_opcode(
    code: object,
    offset: int,
    message: str,
):  # type: ignore[no-untyped-def]
    """Inject once after a selected instruction has made its state durable."""

    previous = sys.gettrace()
    fired = [False]

    def trace(frame: object, event: str, _argument: object):  # type: ignore[no-untyped-def]
        if getattr(frame, "f_code") is code:
            setattr(frame, "f_trace_opcodes", True)
            if (
                not fired[0]
                and event == "opcode"
                and getattr(frame, "f_lasti") == offset
            ):
                fired[0] = True
                raise KeyboardInterrupt(message)
        return trace

    sys.settrace(trace)
    try:
        yield fired
    finally:
        sys.settrace(previous)


def class_method_ast(
    source: str,
    class_name: str,
    method_name: str,
) -> ast.FunctionDef:
    tree = ast.parse(source)
    selected_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return next(
        node
        for node in selected_class.body
        if isinstance(node, ast.FunctionDef) and node.name == method_name
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
    def test_process_capture_failure_attempts_procfd_and_pidfd_cleanup(self) -> None:
        candidate = MODULE.EXPECTED_PROCESS_CANDIDATES["dockerd"]
        with mock.patch.object(
            MODULE.os,
            "pidfd_open",
            return_value=30,
        ), mock.patch.object(
            MODULE,
            "pidfd_exited",
            return_value=False,
        ), mock.patch.object(
            MODULE.os,
            "open",
            return_value=31,
        ), mock.patch.object(
            MODULE.os,
            "fstat",
            side_effect=RuntimeError("capture failed"),
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(OSError("proc close failed"), None),
        ) as close, self.assertRaisesRegex(RuntimeError, "capture failed"):
            MODULE.capture_process(candidate)
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

    def test_disappeared_process_with_ambiguous_cleanup_is_not_reported_absent(self) -> None:
        candidate = MODULE.EXPECTED_PROCESS_CANDIDATES["dockerd"]
        with mock.patch.object(
            MODULE.os,
            "pidfd_open",
            return_value=30,
        ), mock.patch.object(
            MODULE,
            "pidfd_exited",
            return_value=False,
        ), mock.patch.object(
            MODULE.os,
            "open",
            side_effect=FileNotFoundError("process disappeared"),
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=OSError("pidfd close is ambiguous"),
        ) as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "cleanup is ambiguous",
        ) as raised:
            MODULE.capture_process(candidate)
        close.assert_called_once_with(30)
        self.assertNotIsInstance(raised.exception, MODULE.ProcessUnavailable)
        self.assertIsInstance(raised.exception.__cause__, OSError)

    def test_process_capture_success_tail_interruption_still_settles_owner(self) -> None:
        candidate = MODULE.EXPECTED_PROCESS_CANDIDATES["dockerd"]

        def interrupt_after_capture(
            _candidate: object,
            _pid: int,
            custody: MODULE.ResourceCustody,
        ) -> object:
            custody.pidfd_open(960217, 0)
            custody.open("/proc/960217", os.O_RDONLY)
            raise KeyboardInterrupt("after captured process construction")

        with mock.patch.object(
            MODULE.os,
            "pidfd_open",
            return_value=30,
        ), mock.patch.object(
            MODULE.os,
            "open",
            return_value=31,
        ), mock.patch.object(
            MODULE,
            "_capture_process_owned",
            side_effect=interrupt_after_capture,
        ), mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            KeyboardInterrupt,
            "after captured process construction",
        ):
            MODULE.capture_process(candidate)
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

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


class ProcessCredentialAuthorityTest(unittest.TestCase):
    @staticmethod
    def contract(value: object) -> dict[str, object]:
        return json.loads(json.dumps(value))

    @classmethod
    def status(
        cls,
        value: object,
        *,
        thread_group_id: int = 100,
        task_id: int = 100,
        omit: str | None = None,
        duplicate: str | None = None,
        raw_override: dict[str, str] | None = None,
    ) -> str:
        contract = cls.contract(value)
        uids = contract["uids"]
        gids = contract["gids"]
        capabilities = contract["capabilities"]
        assert isinstance(uids, dict) and isinstance(gids, dict)
        assert isinstance(capabilities, dict)
        fields = {
            "Tgid": str(thread_group_id),
            "Pid": str(task_id),
            "Uid": "\t".join(
                str(uids[name])
                for name in ("real", "effective", "saved", "filesystem")
            ),
            "Gid": "\t".join(
                str(gids[name])
                for name in ("real", "effective", "saved", "filesystem")
            ),
            "Groups": " ".join(
                str(value) for value in contract["supplementaryGroups"]
            ),
            "CapInh": str(capabilities["inheritable"]),
            "CapPrm": str(capabilities["permitted"]),
            "CapEff": str(capabilities["effective"]),
            "CapBnd": str(capabilities["bounding"]),
            "CapAmb": str(capabilities["ambient"]),
            "NoNewPrivs": str(contract["noNewPrivileges"]),
            "Seccomp": str(contract["seccompMode"]),
            "Seccomp_filters": str(contract["seccompFilterCount"]),
        }
        fields.update(raw_override or {})
        lines = ["Name:\ttest"]
        for name, raw in fields.items():
            if name == omit:
                continue
            lines.append(f"{name}:\t{raw}")
            if name == duplicate:
                lines.append(f"{name}:\t{raw}")
        return "\n".join(lines) + "\n"

    def test_every_recorded_role_has_its_explicit_measured_profile(self) -> None:
        expected_profiles = {
            "containerdWrapperOuter": "sudo-wrapper-caller-real-root-effective",
            "containerdWrapperInner": "sudo-wrapper-caller-real-root-effective",
            "containerd": "root-runtime-full-capability",
            "dockerdWrapperOuter": "sudo-wrapper-caller-real-root-effective",
            "dockerdWrapperInner": "sudo-wrapper-caller-real-root-effective",
            "dockerd": "root-runtime-full-capability",
            "registryShim": "root-runtime-full-capability",
            "registryTask": "registry-task-container-security",
        }
        self.assertEqual(
            {
                role: candidate["credentialProfile"]
                for role, candidate in MODULE.EXPECTED_PROCESS_CANDIDATES.items()
            },
            expected_profiles,
        )
        for role, candidate in MODULE.EXPECTED_PROCESS_CANDIDATES.items():
            with self.subTest(role=role):
                expected = MODULE.MEASURED_TASK_SECURITY_PROFILES[
                    expected_profiles[role]
                ]
                parsed = MODULE.parse_task_status(self.status(expected))
                profile, profile_sha256, observed = MODULE.require_expected_task_security(
                    candidate,
                    parsed.security_state,
                )
                self.assertEqual(profile, expected_profiles[role])
                self.assertEqual(
                    profile_sha256,
                    MODULE.MEASURED_TASK_SECURITY_PROFILE_SHA256[profile],
                )
                self.assertEqual(observed, expected)

    def test_exactly_three_measured_profiles_have_fixed_canonical_seals(self) -> None:
        self.assertEqual(
            set(MODULE.MEASURED_TASK_SECURITY_PROFILES),
            {
                "sudo-wrapper-caller-real-root-effective",
                "root-runtime-full-capability",
                "registry-task-container-security",
            },
        )
        self.assertEqual(
            set(MODULE.MEASURED_TASK_SECURITY_PROFILE_SHA256),
            set(MODULE.MEASURED_TASK_SECURITY_PROFILES),
        )
        for profile, expected in MODULE.MEASURED_TASK_SECURITY_PROFILES.items():
            with self.subTest(profile=profile):
                observed_sha256, observed = MODULE.measured_task_security_profile(
                    profile
                )
                self.assertEqual(observed, expected)
                self.assertEqual(
                    observed_sha256,
                    hashlib.sha256(MODULE.canonical_json(expected)).hexdigest(),
                )

    def test_sudo_wrapper_real_uid_is_caller_but_gid_tuple_is_independent(self) -> None:
        candidate = MODULE.EXPECTED_PROCESS_CANDIDATES["containerdWrapperOuter"]
        sudo_security = MODULE.MEASURED_TASK_SECURITY_PROFILES[
            "sudo-wrapper-caller-real-root-effective"
        ]
        root_security = MODULE.MEASURED_TASK_SECURITY_PROFILES[
            "root-runtime-full-capability"
        ]
        parsed = MODULE.parse_task_status(self.status(sudo_security))
        profile, _profile_sha256, observed = MODULE.require_expected_task_security(
            candidate,
            parsed.security_state,
        )
        self.assertEqual(profile, "sudo-wrapper-caller-real-root-effective")
        self.assertEqual(observed["uids"], {
            "real": 1000,
            "effective": 0,
            "saved": 0,
            "filesystem": 0,
        })
        self.assertEqual(set(observed["gids"].values()), {0})
        with self.assertRaisesRegex(MODULE.DrainError, "security state differ"):
            MODULE.require_expected_task_security(
                candidate,
                MODULE.parse_task_status(self.status(root_security)).security_state,
            )

    def test_uid_gid_group_capability_and_security_substitutions_reject(self) -> None:
        candidate = MODULE.EXPECTED_PROCESS_CANDIDATES["containerdWrapperOuter"]
        mutations: list[tuple[str, Callable[[dict[str, object]], None]]] = [
            ("real_uid", lambda value: value["uids"].__setitem__("real", 999)),
            ("effective_uid", lambda value: value["uids"].__setitem__("effective", 1000)),
            ("saved_uid", lambda value: value["uids"].__setitem__("saved", 1000)),
            ("filesystem_uid", lambda value: value["uids"].__setitem__("filesystem", 1000)),
            ("real_gid", lambda value: value["gids"].__setitem__("real", 1000)),
            ("groups", lambda value: value["supplementaryGroups"].append(1000)),
            (
                "capability",
                lambda value: value["capabilities"].__setitem__(
                    "effective", "0000000000000000"
                ),
            ),
            ("no_new_privileges", lambda value: value.__setitem__("noNewPrivileges", 1)),
            ("seccomp", lambda value: value.__setitem__("seccompMode", 2)),
            ("seccomp_filters", lambda value: value.__setitem__("seccompFilterCount", 1)),
        ]
        for label, mutate in mutations:
            value = self.contract(
                MODULE.MEASURED_TASK_SECURITY_PROFILES[
                    "sudo-wrapper-caller-real-root-effective"
                ]
            )
            mutate(value)
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.DrainError,
                "security state differ",
            ):
                MODULE.require_expected_task_security(
                    candidate,
                    MODULE.parse_task_status(self.status(value)).security_state,
                )

    def test_registry_task_duplicate_group_and_reduced_security_contract_is_exact(self) -> None:
        candidate = MODULE.EXPECTED_PROCESS_CANDIDATES["registryTask"]
        registry_security = MODULE.MEASURED_TASK_SECURITY_PROFILES[
            "registry-task-container-security"
        ]
        _profile, _profile_sha256, observed = MODULE.require_expected_task_security(
            candidate,
            MODULE.parse_task_status(self.status(registry_security)).security_state,
        )
        self.assertEqual(
            observed["supplementaryGroups"],
            [0, 0, 1, 2, 3, 4, 6, 10, 11, 20, 26, 27],
        )
        self.assertEqual(observed["seccompMode"], 2)
        self.assertEqual(observed["seccompFilterCount"], 1)
        with self.assertRaisesRegex(MODULE.DrainError, "security state differ"):
            MODULE.require_expected_task_security(
                candidate,
                MODULE.parse_task_status(
                    self.status(
                        MODULE.MEASURED_TASK_SECURITY_PROFILES[
                            "root-runtime-full-capability"
                        ]
                    )
                ).security_state,
            )

    def test_missing_duplicate_and_malformed_status_fields_reject(self) -> None:
        candidate = MODULE.EXPECTED_PROCESS_CANDIDATES["dockerd"]
        root_security = MODULE.MEASURED_TASK_SECURITY_PROFILES[
            "root-runtime-full-capability"
        ]
        for label, kwargs in (
            ("missing_tgid", {"omit": "Tgid"}),
            ("duplicate_pid", {"duplicate": "Pid"}),
            ("missing", {"omit": "Uid"}),
            ("duplicate", {"duplicate": "Gid"}),
            ("task_id", {"raw_override": {"Pid": "0"}}),
            ("uid", {"raw_override": {"Uid": "00\t0\t0\t0"}}),
            ("capability", {"raw_override": {"CapEff": "ABC"}}),
            ("security", {"raw_override": {"Seccomp": "-1"}}),
        ):
            with self.subTest(label=label), self.assertRaises(MODULE.DrainError):
                parsed = MODULE.parse_task_status(
                    self.status(root_security, **kwargs)
                )
                MODULE.require_expected_task_security(
                    candidate,
                    parsed.security_state,
                )

    def test_credentials_are_persisted_and_reproved_inside_pidfd_cutoffs(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        task_capture = source[
            source.index("def capture_task") : source.index("class CapturedProcess")
        ]
        capture = source[
            source.index("def _capture_process_owned")
            : source.index("def validate_receipt_process")
        ]
        cutoff = source[
            source.index("def hold_related_process_cutoff")
            : source.index("def exact_process_status")
        ]
        self.assertIn('"credentialProfile": credential_profile', capture)
        self.assertIn('"credentialProfileSha256": credential_profile_sha256', capture)
        self.assertIn('"credentials": credentials', capture)
        self.assertIn('"securityState": task.security_state', source)
        self.assertIn("require_recorded_role_task_security", source)
        self.assertIn("parse_task_status", task_capture)
        self.assertIn("parse_task_status", capture)
        self.assertNotIn("normalize_process_credentials", source)
        self.assertTrue(
            all(
                "credentials" not in candidate
                for candidate in MODULE.EXPECTED_PROCESS_CANDIDATES.values()
            )
        )
        self.assertGreaterEqual(cutoff.count("reprove_captured_task"), 4)
        self.assertGreaterEqual(cutoff.count("exact_process_status"), 2)


class ProcessUniverseTest(unittest.TestCase):
    @staticmethod
    def _root_security() -> dict[str, object]:
        return json.loads(
            json.dumps(
                MODULE.MEASURED_TASK_SECURITY_PROFILES[
                    "root-runtime-full-capability"
                ]
            )
        )

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
        census = namespace_census()
        stable = {"allowedRoles": [], "related": [], "proofSha256": "a" * 64}
        with mock.patch.object(
            MODULE, "_related_process_universe_once", side_effect=(stable, stable)
        ) as once:
            self.assertEqual(
                MODULE.related_process_universe(
                    processes,
                    runtime,
                    sockets,
                    allowed_roles=set(),
                    namespace_census=census,
                ),
                stable,
            )
        self.assertEqual(once.call_count, 2)
        changed = {**stable, "proofSha256": "b" * 64}
        with mock.patch.object(
            MODULE, "_related_process_universe_once", side_effect=(stable, changed)
        ), self.assertRaisesRegex(MODULE.DrainError, "across proof passes"):
            MODULE.related_process_universe(
                processes,
                runtime,
                sockets,
                allowed_roles=set(),
                namespace_census=census,
            )
        leader_only = {
            **stable,
            "related": [{"pid": 10, "taskId": 10}],
            "proofSha256": "c" * 64,
        }
        nonleader_appeared = {
            **stable,
            "related": [{"pid": 10, "taskId": 10}, {"pid": 10, "taskId": 11}],
            "proofSha256": "d" * 64,
        }
        with mock.patch.object(
            MODULE,
            "_related_process_universe_once",
            side_effect=(leader_only, nonleader_appeared),
        ), self.assertRaisesRegex(MODULE.DrainError, "across proof passes"):
            MODULE.related_process_universe(
                processes,
                runtime,
                sockets,
                allowed_roles=set(),
                namespace_census=census,
            )

        first_security = self._root_security()
        second_security = self._root_security()
        second_security["seccompMode"] = 2
        security_first = {
            **stable,
            "related": [
                {"pid": 10, "taskId": 11, "securityState": first_security}
            ],
            "proofSha256": "e" * 64,
        }
        security_second = {
            **stable,
            "related": [
                {"pid": 10, "taskId": 11, "securityState": second_security}
            ],
            "proofSha256": "f" * 64,
        }
        with mock.patch.object(
            MODULE,
            "_related_process_universe_once",
            side_effect=(security_first, security_second),
        ), self.assertRaisesRegex(MODULE.DrainError, "across proof passes"):
            MODULE.related_process_universe(
                processes,
                runtime,
                sockets,
                allowed_roles=set(),
                namespace_census=census,
            )

    def test_allowed_pidfds_remain_held_through_action(self) -> None:
        roles = {"dockerd", "containerd"}
        security_state = self._root_security()
        rows = [
            {"pid": 1, "taskId": 1, "parentPid": 0, "startTimeTicks": 10, "securityState": security_state},
            {"pid": 1, "taskId": 3, "parentPid": 0, "startTimeTicks": 11, "securityState": security_state},
            {"pid": 2, "taskId": 2, "parentPid": 0, "startTimeTicks": 20, "securityState": security_state},
        ]
        tasks = []
        for row in rows:
            task = mock.Mock(
                parent_pid=row["parentPid"],
                start_ticks=row["startTimeTicks"],
                pidfd=30 + row["taskId"],
                process_fd=130 + row["taskId"],
                security_state=row["securityState"],
            )
            tasks.append(task)

        def capture(
            custody: MODULE.ResourceCustody,
            _thread_group_id: int,
            _task_id: int,
        ) -> object:
            task = tasks.pop(0)
            acquire_test_descriptors(custody, task.pidfd, task.process_fd)
            return task

        with mock.patch.object(
            MODULE,
            "require_related_process_cutoff",
            return_value={"related": rows},
        ), mock.patch.object(
            MODULE,
            "capture_task",
            side_effect=capture,
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE, "reprove_captured_task"
        ), mock.patch.object(
            MODULE, "process_authority", return_value={}
        ), mock.patch.object(
            MODULE, "exact_process_status", return_value="exact"
        ), mock.patch.object(MODULE.os, "close") as close:
            with MODULE.hold_related_process_cutoff(
                {"authority": {}}, allowed_roles=roles
            ):
                close.assert_not_called()
        self.assertCountEqual(
            close.call_args_list,
            [
                mock.call(31),
                mock.call(131),
                mock.call(33),
                mock.call(133),
                mock.call(32),
                mock.call(132),
            ],
        )

    def test_action_cutoff_rejects_a_new_unheld_thread(self) -> None:
        security_state = self._root_security()
        original = {
            "related": [
                {"pid": 1, "taskId": 1, "parentPid": 0, "startTimeTicks": 10, "securityState": security_state}
            ]
        }
        changed = {
            "related": [
                *original["related"],
                {"pid": 1, "taskId": 2, "parentPid": 0, "startTimeTicks": 11, "securityState": security_state},
            ]
        }
        task = mock.Mock(
            parent_pid=0,
            start_ticks=10,
            pidfd=31,
            process_fd=131,
            security_state=security_state,
        )

        def capture(
            custody: MODULE.ResourceCustody,
            _thread_group_id: int,
            _task_id: int,
        ) -> object:
            acquire_test_descriptors(custody, task.pidfd, task.process_fd)
            return task

        with mock.patch.object(
            MODULE,
            "require_related_process_cutoff",
            side_effect=(original, changed),
        ), mock.patch.object(
            MODULE, "capture_task", side_effect=capture
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE, "reprove_captured_task"
        ), mock.patch.object(
            MODULE, "process_authority", return_value={}
        ), mock.patch.object(
            MODULE, "exact_process_status", return_value="exact"
        ), mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "entering the action cutoff",
        ):
            with MODULE.hold_related_process_cutoff(
                {"authority": {}},
                allowed_roles={"dockerd"},
            ):
                self.fail("a changed task roster reached the action")
        self.assertEqual(close.call_args_list, [mock.call(131), mock.call(31)])

    def test_action_cutoff_rejects_held_nonleader_security_drift(self) -> None:
        security_state = self._root_security()
        proof = {
            "related": [
                {"pid": 1, "taskId": 2, "parentPid": 0, "startTimeTicks": 10, "securityState": security_state}
            ]
        }
        task = mock.Mock(
            parent_pid=0,
            start_ticks=10,
            pidfd=31,
            process_fd=131,
            security_state=security_state,
        )

        def capture(
            custody: MODULE.ResourceCustody,
            _thread_group_id: int,
            _task_id: int,
        ) -> object:
            acquire_test_descriptors(custody, task.pidfd, task.process_fd)
            return task

        with mock.patch.object(
            MODULE, "require_related_process_cutoff", return_value=proof
        ), mock.patch.object(
            MODULE, "capture_task", side_effect=capture
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE,
            "reprove_captured_task",
            side_effect=(
                None,
                None,
                MODULE.ManualRecoveryRequired("held process task identity or security state changed"),
            ),
        ), mock.patch.object(
            MODULE, "process_authority", return_value={}
        ), mock.patch.object(
            MODULE, "exact_process_status", return_value="exact"
        ), self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "security state changed",
        ), mock.patch.object(MODULE.os, "close") as close:
            with MODULE.hold_related_process_cutoff(
                {"authority": {}},
                allowed_roles={"dockerd"},
            ):
                pass
        self.assertEqual(close.call_args_list, [mock.call(131), mock.call(31)])

    def test_action_error_remains_primary_while_post_cutoff_reproof_runs(self) -> None:
        security_state = self._root_security()
        proof = {
            "related": [
                {
                    "pid": 1,
                    "taskId": 2,
                    "parentPid": 0,
                    "startTimeTicks": 10,
                    "securityState": security_state,
                }
            ]
        }
        task = mock.Mock(
            parent_pid=0,
            start_ticks=10,
            pidfd=31,
            process_fd=131,
            security_state=security_state,
        )

        def capture(
            custody: MODULE.ResourceCustody,
            _thread_group_id: int,
            _task_id: int,
        ) -> object:
            acquire_test_descriptors(custody, task.pidfd, task.process_fd)
            return task

        with mock.patch.object(
            MODULE,
            "require_related_process_cutoff",
            side_effect=(
                proof,
                proof,
                MODULE.ManualRecoveryRequired("post-action universe drift"),
            ),
        ) as cutoff, mock.patch.object(
            MODULE,
            "capture_task",
            side_effect=capture,
        ), mock.patch.object(
            MODULE,
            "pidfd_exited",
            return_value=False,
        ), mock.patch.object(
            MODULE,
            "reprove_captured_task",
        ) as reprove, mock.patch.object(
            MODULE,
            "process_authority",
            return_value={},
        ), mock.patch.object(
            MODULE,
            "exact_process_status",
            return_value="exact",
        ), self.assertRaisesRegex(
            RuntimeError,
            "action failed after mutation",
        ) as raised, mock.patch.object(MODULE.os, "close") as close:
            with MODULE.hold_related_process_cutoff(
                {"authority": {}},
                allowed_roles={"dockerd"},
            ):
                raise RuntimeError("action failed after mutation")
        self.assertEqual(cutoff.call_count, 3)
        self.assertEqual(reprove.call_count, 3)
        self.assertIn("post-action universe drift", "\n".join(raised.exception.__notes__))
        self.assertEqual(close.call_args_list, [mock.call(131), mock.call(31)])

    def test_task_roster_includes_nonleader_threads(self) -> None:
        with mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(("10", "20", "self"), ("10", "11"), ("20", "21", "22")),
        ):
            self.assertEqual(
                MODULE.process_task_coordinates_once(),
                ((10, 10), (10, 11), (20, 20), (20, 21), (20, 22)),
            )

    def test_live_group_with_unenumerable_task_roster_rejects(self) -> None:
        with mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(("10",), FileNotFoundError()),
        ), mock.patch.object(
            MODULE.os,
            "stat",
            return_value=mock.Mock(),
        ), self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "thread-group task roster is unavailable",
        ):
            MODULE.process_task_coordinates_once()

        with mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(("10",), FileNotFoundError()),
        ), mock.patch.object(
            MODULE.os,
            "stat",
            side_effect=FileNotFoundError(),
        ):
            self.assertEqual(MODULE.process_task_coordinates_once(), ())

    def test_nonleader_task_identity_is_bound_to_a_thread_pidfd(self) -> None:
        identity = mock.Mock(st_dev=1, st_ino=2)
        fields = [b"S", b"1", *([b"0"] * 17), b"77"]
        raw_stat = b"101 (worker) " + b" ".join(fields)

        def read(_directory_fd: int, name: str, maximum: int = 0) -> bytes:
            del maximum
            if name == "status":
                return ProcessCredentialAuthorityTest.status(
                    self._root_security(),
                    thread_group_id=100,
                    task_id=101,
                ).encode()
            self.assertEqual(name, "stat")
            return raw_stat

        with mock.patch.object(
            MODULE.os, "pidfd_open", return_value=30
        ) as pidfd_open, mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE.os, "open", return_value=31
        ), mock.patch.object(
            MODULE.os, "fstat", return_value=identity
        ), mock.patch.object(
            MODULE.os, "stat", return_value=identity
        ), mock.patch.object(
            MODULE, "read_at", side_effect=read
        ), mock.patch.object(MODULE.os, "close") as close:
            with MODULE.ResourceCustody(label="captured task test") as custody:
                task = MODULE.capture_task(custody, 100, 101)
                self.assertIsNotNone(task)
                assert task is not None
                self.assertEqual((task.parent_pid, task.start_ticks), (1, 77))
                self.assertEqual(task.security_state, self._root_security())
                close.assert_not_called()
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])
        pidfd_open.assert_called_once_with(101, MODULE.PIDFD_THREAD)

    def test_task_capture_failure_attempts_procfd_and_pidfd_cleanup(self) -> None:
        with mock.patch.object(
            MODULE.os,
            "pidfd_open",
            return_value=30,
        ), mock.patch.object(
            MODULE,
            "pidfd_exited",
            return_value=False,
        ), mock.patch.object(
            MODULE.os,
            "open",
            return_value=31,
        ), mock.patch.object(
            MODULE.os,
            "fstat",
            side_effect=RuntimeError("capture failed"),
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(OSError("proc close failed"), None),
        ) as close, self.assertRaisesRegex(RuntimeError, "capture failed"):
            with MODULE.ResourceCustody(label="captured task failure") as custody:
                MODULE.capture_task(custody, 100, 101)
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

    def test_caller_interrupt_immediately_after_task_capture_closes_both(self) -> None:
        status = mock.Mock(
            thread_group_id=100,
            task_id=101,
            security_state=self._root_security(),
        )
        identity = mock.Mock(st_dev=1, st_ino=2)
        with mock.patch.object(MODULE.os, "pidfd_open", return_value=30), mock.patch.object(
            MODULE,
            "pidfd_exited",
            return_value=False,
        ), mock.patch.object(MODULE.os, "open", return_value=31), mock.patch.object(
            MODULE.os,
            "fstat",
            return_value=identity,
        ), mock.patch.object(MODULE.os, "stat", return_value=identity), mock.patch.object(
            MODULE,
            "read_at",
            return_value=b"captured",
        ), mock.patch.object(MODULE, "parse_task_status", return_value=status), mock.patch.object(
            MODULE,
            "stat_identity",
            return_value=(1, 77),
        ), mock.patch.object(MODULE, "reprove_captured_task"), mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(KeyboardInterrupt, "caller interrupted"):
            with MODULE.ResourceCustody(label="task capture caller") as custody:
                captured = MODULE.capture_task(custody, 100, 101)
                self.assertIsNotNone(captured)
                raise KeyboardInterrupt("caller interrupted")
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

    def test_task_capture_partial_acquisition_interrupt_closes_pidfd(self) -> None:
        with mock.patch.object(MODULE.os, "pidfd_open", return_value=30), mock.patch.object(
            MODULE,
            "pidfd_exited",
            return_value=False,
        ), mock.patch.object(
            MODULE.os,
            "open",
            side_effect=KeyboardInterrupt("task directory acquisition interrupted"),
        ), mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            KeyboardInterrupt,
            "task directory acquisition interrupted",
        ):
            with MODULE.ResourceCustody(label="partial task capture") as custody:
                MODULE.capture_task(custody, 100, 101)
        close.assert_called_once_with(30)

    def test_task_capture_none_churn_retires_each_acquisition_once(self) -> None:
        with mock.patch.object(MODULE.os, "pidfd_open", return_value=30), mock.patch.object(
            MODULE,
            "pidfd_exited",
            return_value=True,
        ), mock.patch.object(MODULE.os, "close") as close:
            with MODULE.ResourceCustody(label="already exited task") as custody:
                self.assertIsNone(MODULE.capture_task(custody, 100, 101))
            close.assert_called_once_with(30)

        with mock.patch.object(MODULE.os, "pidfd_open", return_value=30), mock.patch.object(
            MODULE,
            "pidfd_exited",
            side_effect=(False, True),
        ), mock.patch.object(MODULE.os, "open", return_value=31), mock.patch.object(
            MODULE.os,
            "fstat",
            side_effect=FileNotFoundError(),
        ), mock.patch.object(MODULE.os, "close") as close:
            with MODULE.ResourceCustody(label="vanished task") as custody:
                self.assertIsNone(MODULE.capture_task(custody, 100, 101))
            self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

    def test_held_thread_pidfd_reproof_reads_current_nonleader_security(self) -> None:
        expected = self._root_security()
        changed = self._root_security()
        changed["noNewPrivileges"] = 1
        fields = [b"S", b"1", *([b"0"] * 17), b"77"]
        raw_stat = b"101 (worker) " + b" ".join(fields)
        task = MODULE.CapturedTask(100, 101, 30, 31, 1, 77, expected)

        def read(_directory_fd: int, name: str, maximum: int = 0) -> bytes:
            del maximum
            if name == "status":
                return ProcessCredentialAuthorityTest.status(
                    changed,
                    thread_group_id=100,
                    task_id=101,
                ).encode()
            self.assertEqual(name, "stat")
            return raw_stat

        with mock.patch.object(
            MODULE, "read_at", side_effect=read
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE.os, "pidfd_open"
        ) as reopened, self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "identity or security state changed",
        ):
            MODULE.reprove_captured_task(
                task,
                expected_security_state=expected,
            )
        reopened.assert_not_called()

    def test_nonleader_edge_is_in_the_related_task_proof(self) -> None:
        root_security = self._root_security()
        namespaces = {"taskNamespaces": task_namespaces(first_inode=1)}
        processes = {
            "dockerd": {
                "pid": 100,
                "parentPid": 1,
                "startTimeTicks": 10,
                "credentialProfile": "root-runtime-full-capability",
                "credentialProfileSha256": MODULE.MEASURED_TASK_SECURITY_PROFILE_SHA256[
                    "root-runtime-full-capability"
                ],
                "credentials": root_security,
                **namespaces,
            }
        }
        leader = {
            "pid": 100,
            "taskId": 100,
            "parentPid": 1,
            "startTimeTicks": 10,
            "securityState": root_security,
            "namespaces": namespaces["taskNamespaces"],
            "namespaceFds": [],
            "relations": [],
        }
        worker = {
            "pid": 100,
            "taskId": 101,
            "parentPid": 1,
            "startTimeTicks": 11,
            "securityState": root_security,
            "namespaces": namespaces["taskNamespaces"],
            "namespaceFds": [],
            "relations": ["runtimeFdInode"],
        }
        verifier = {
            "pid": 999,
            "taskId": 999,
            "parentPid": 1,
            "startTimeTicks": 12,
            "securityState": root_security,
            "namespaces": namespaces["taskNamespaces"],
            "namespaceFds": [],
            "relations": [],
        }

        def observation(row: dict[str, object], offset: int) -> object:
            return MODULE.ProcessReferenceObservation(row, 30 + offset, 40 + offset)

        scans = iter((
            observation(leader, 0),
            observation(worker, 1),
            observation(verifier, 2),
            observation(dict(leader), 3),
            observation(dict(worker), 4),
        ))

        def scan(
            custody: MODULE.ResourceCustody,
            *_args: object,
            **_kwargs: object,
        ) -> object:
            value = next(scans)
            acquire_test_descriptors(custody, value.pidfd, value.process_fd)
            return value

        with mock.patch.object(
            MODULE,
            "process_task_coordinates_once",
            return_value=((100, 100), (100, 101), (999, 999)),
        ), mock.patch.object(
            MODULE, "process_reference_scan", side_effect=scan
        ), mock.patch.object(
            MODULE.os, "getpid", return_value=999
        ), mock.patch.object(
            MODULE.os,
            "stat",
            side_effect=lambda path: mock.Mock(
                st_dev=4,
                st_ino=int(
                    namespaces["taskNamespaces"][Path(path).name]["inode"]
                ),
            ),
        ), mock.patch.object(
            MODULE.os,
            "readlink",
            side_effect=lambda path: (
                f"{MODULE.TASK_NAMESPACE_ENTRY_KINDS[Path(path).name]}:"
                f"[{namespaces['taskNamespaces'][Path(path).name]['inode']}]"
            ),
        ), mock.patch.object(
            MODULE, "reprove_captured_task"
        ), mock.patch.object(MODULE.os, "close"):
            proof = MODULE._related_process_universe_once(
                processes,
                {"tree": [], "rootIdentity": {"device": 1, "inode": 2}},
                {"unixRecords": []},
                namespace_census(
                    current=tuple(
                        MODULE.NamespaceIdentity(
                            str(identity["kind"]),
                            int(identity["device"]),
                            int(identity["inode"]),
                        )
                        for identity in namespaces["taskNamespaces"].values()
                    ),
                    task_namespace_rows=tuple(
                        {
                            "threadGroupId": int(row["pid"]),
                            "taskId": int(row["taskId"]),
                            "namespaces": row["namespaces"],
                        }
                        for row in (leader, worker, verifier)
                    ),
                ),
                allowed_roles={"dockerd"},
            )
        self.assertEqual(
            [(row["pid"], row["taskId"]) for row in proof["related"]],
            [(100, 100), (100, 101)],
        )

    def test_foreign_sharer_of_any_role_task_namespace_kind_rejects(self) -> None:
        root_security = self._root_security()
        ambient = task_namespaces(first_inode=1)
        process = {
            "pid": 100,
            "parentPid": 1,
            "startTimeTicks": 10,
            "credentialProfile": "root-runtime-full-capability",
            "credentialProfileSha256": MODULE.MEASURED_TASK_SECURITY_PROFILE_SHA256[
                "root-runtime-full-capability"
            ],
            "credentials": root_security,
            "taskNamespaces": ambient,
        }

        for kind_index, kind in enumerate(MODULE.NAMESPACE_KINDS, start=1):
            entry = next(
                entry
                for entry, entry_kind in MODULE.TASK_NAMESPACE_ENTRIES
                if entry_kind == kind
            )
            private = json.loads(json.dumps(ambient))
            private[entry]["inode"] = 10_000 + kind_index
            rows = (
                {
                    "pid": 100,
                    "taskId": 100,
                    "parentPid": 1,
                    "startTimeTicks": 10,
                    "securityState": root_security,
                    "namespaces": ambient,
                    "namespaceFds": [],
                    "relations": [],
                },
                {
                    "pid": 100,
                    "taskId": 101,
                    "parentPid": 1,
                    "startTimeTicks": 11,
                    "securityState": root_security,
                    "namespaces": private,
                    "namespaceFds": [],
                    "relations": [],
                },
                {
                    "pid": 999,
                    "taskId": 999,
                    "parentPid": 1,
                    "startTimeTicks": 12,
                    "securityState": root_security,
                    "namespaces": private,
                    "namespaceFds": [],
                    "relations": [],
                },
            )
            observations = tuple(
                MODULE.ProcessReferenceObservation(row, 30 + index, 40 + index)
                for index, row in enumerate(rows)
            )
            observation_values = iter(observations)

            def scan(
                custody: MODULE.ResourceCustody,
                *_args: object,
                **_kwargs: object,
            ) -> object:
                value = next(observation_values)
                acquire_test_descriptors(custody, value.pidfd, value.process_fd)
                return value

            current = {
                MODULE.NamespaceIdentity(
                    str(identity["kind"]),
                    int(identity["device"]),
                    int(identity["inode"]),
                )
                for row in rows
                for identity in row["namespaces"].values()
            }
            with self.subTest(kind=kind), mock.patch.object(
                MODULE,
                "process_task_coordinates_once",
                return_value=((100, 100), (100, 101), (999, 999)),
            ), mock.patch.object(
                MODULE,
                "process_reference_scan",
                side_effect=scan,
            ), mock.patch.object(
                MODULE.os,
                "getpid",
                return_value=999,
            ), mock.patch.object(
                MODULE.os,
                "stat",
                side_effect=lambda path: mock.Mock(
                    st_dev=4,
                    st_ino=int(ambient[Path(path).name]["inode"]),
                ),
            ), mock.patch.object(
                MODULE.os,
                "readlink",
                side_effect=lambda path: (
                    f"{MODULE.TASK_NAMESPACE_ENTRY_KINDS[Path(path).name]}:"
                    f"[{ambient[Path(path).name]['inode']}]"
                ),
            ), mock.patch.object(
                MODULE,
                "reprove_captured_task",
            ), mock.patch.object(
                MODULE.os,
                "close",
            ), self.assertRaisesRegex(
                MODULE.ManualRecoveryRequired,
                "unrecognized legacy-related task: 999/999",
            ):
                MODULE._related_process_universe_once(
                    {"dockerd": process},
                    {"tree": [], "rootIdentity": {"device": 1, "inode": 2}},
                    {"unixRecords": []},
                    namespace_census(
                        current=tuple(current),
                        task_namespace_rows=tuple(
                            {
                                "threadGroupId": int(row["pid"]),
                                "taskId": int(row["taskId"]),
                                "namespaces": row["namespaces"],
                            }
                            for row in rows
                        ),
                    ),
                    allowed_roles={"dockerd"},
                )

    def test_recorded_role_rejects_every_nonleader_security_divergence(self) -> None:
        expected = self._root_security()
        recorded = {
            "credentialProfile": "root-runtime-full-capability",
            "credentialProfileSha256": MODULE.MEASURED_TASK_SECURITY_PROFILE_SHA256[
                "root-runtime-full-capability"
            ],
            "credentials": expected,
        }
        mutations: list[tuple[str, Callable[[dict[str, object]], None]]] = [
            ("uid", lambda value: value["uids"].__setitem__("effective", 1000)),
            ("gid", lambda value: value["gids"].__setitem__("saved", 1000)),
            ("groups", lambda value: value["supplementaryGroups"].append(1000)),
            (
                "capabilities",
                lambda value: value["capabilities"].__setitem__(
                    "bounding", "0000000000000000"
                ),
            ),
            ("nnp", lambda value: value.__setitem__("noNewPrivileges", 1)),
            ("seccomp", lambda value: value.__setitem__("seccompMode", 2)),
            (
                "seccomp_filters",
                lambda value: value.__setitem__("seccompFilterCount", 1),
            ),
        ]
        MODULE.require_recorded_role_task_security(
            "dockerd",
            recorded,
            expected,
            thread_group_id=100,
            task_id=101,
        )
        for label, mutate in mutations:
            observed = self._root_security()
            mutate(observed)
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.ManualRecoveryRequired,
                "task security state differs",
            ):
                MODULE.require_recorded_role_task_security(
                    "dockerd",
                    recorded,
                    observed,
                    thread_group_id=100,
                    task_id=101,
                )

    def test_recorded_role_rejects_wrong_profile_or_profile_seal(self) -> None:
        expected = self._root_security()
        for label, recorded in (
            (
                "profile",
                {
                    "credentialProfile": "registry-task-container-security",
                    "credentialProfileSha256": MODULE.MEASURED_TASK_SECURITY_PROFILE_SHA256[
                        "registry-task-container-security"
                    ],
                    "credentials": MODULE.MEASURED_TASK_SECURITY_PROFILES[
                        "registry-task-container-security"
                    ],
                },
            ),
            (
                "seal",
                {
                    "credentialProfile": "root-runtime-full-capability",
                    "credentialProfileSha256": "0" * 64,
                    "credentials": expected,
                },
            ),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                MODULE.DrainError,
                "role security contract differs",
            ):
                MODULE.require_recorded_role_task_security(
                    "dockerd",
                    recorded,
                    expected,
                    thread_group_id=100,
                    task_id=101,
                )

    def test_task_roster_drives_process_socket_and_mount_censuses(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        namespace_census_source = source[
            source.index("def _held_task_namespace_observations")
            : source.index("def stable_task_namespace_census")
        ]
        self.assertIn("process_task_coordinates_once()", namespace_census_source)
        self.assertIn("capture_task", namespace_census_source)
        held_commit = source[
            source.index("def _held_task_namespace_observations")
            : source.index("def task_namespace_census_once")
        ]
        self.assertIn("_task_mount_view(task) == view", held_commit)
        self.assertIn("_namespace_fd_records(", held_commit)
        self.assertIn("== namespace_fd_rows", held_commit)
        self.assertIn("destination_custody", held_commit)
        self.assertIn("capture_task(custody,", held_commit)
        self.assertIn("open_current_task_namespace(", held_commit)
        self.assertNotIn(".close()", held_commit)
        mount_projection = source[
            source.index("def global_mount_roster_once")
            : source.index("def stable_global_mount_roster")
        ]
        self.assertIn("namespace_census", mount_projection)
        self.assertNotIn("process_task_coordinates_once()", mount_projection)
        socket_census = source[
            source.index("def socket_inode_owners")
            : source.index("def tcp_registry_snapshot")
        ]
        self.assertIn("process_task_coordinates_once()", socket_census)
        self.assertIn("capture_task", socket_census)
        related = source[
            source.index("def _related_process_universe_once")
            : source.index("def related_process_universe")
        ]
        self.assertIn("process_task_coordinates_once()", related)
        self.assertIn("process_reference_scan", related)
        process_scan = source[
            source.index("def process_reference_scan")
            : source.index("def _related_process_universe_once")
        ]
        self.assertIn("capture_task", process_scan)
        self.assertIn("taskId", process_scan)
        self.assertIn("PIDFD_THREAD", source)
        collection = source[
            source.index("def collect_authority")
            : source.index("def collect_verification")
        ]
        self.assertEqual(collection.count("stable_task_namespace_census(custody)"), 1)
        self.assertIn("namespace_census = stable_task_namespace_census(custody)", collection)
        finish = source[
            source.index("def _finish_authority_with_namespace_census")
            : source.index("def collect_authority")
        ]
        self.assertGreaterEqual(finish.count("namespace_census="), 4)
        netns = source[
            source.index("def _netns_baseline_from_census")
            : source.index("def require_mount_targets_within")
        ]
        self.assertNotIn('/proc/self/mountinfo', netns)
        self.assertIn("census.mounts", netns)

    def test_source_covers_empty_argv_maps_namespace_fds_and_pid_reuse(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"runtimeMappedPath"', source)
        self.assertIn('"runtimeNamespaceFd"', source)
        self.assertIn('"privateRuntimeNamespace"', source)
        self.assertIn("recorded legacy process PID was reused", source)
        self.assertNotIn("if not raw_arguments:\n                second_parent", source)
        self.assertNotIn("admitted_namespace_tokens", source)
        self.assertNotIn("recorded_namespace_tokens", source)
        self.assertNotIn("private_namespace_tokens", source)
        self.assertIn("owned_relation_namespace_identities", source)
        self.assertIn("proof_owned_namespace_fds", source)
        process_scan = source[
            source.index("def process_reference_scan")
            : source.index("def _related_process_universe_once")
        ]
        self.assertLess(
            process_scan.index("proof-owned namespace FD identity changed"),
            process_scan.index('relations.add("runtimeFdInode")'),
        )
        self.assertNotIn("unclassifiedNamespaceFd", source)
        self.assertNotIn("mount namespace visibility differs across representatives", source)
        self.assertIn('"ambient_process_bound"', source)
        self.assertIn('"queuedScmRightsNamespaceFds"', source)
        self.assertNotIn("def source_anchors(", source)
        self.assertNotIn("def mount_reference_records(", source)
        self.assertNotIn("def mount_references(", source)

    def test_namespace_fd_current_owned_and_detached_classification_is_exact(self) -> None:
        ambient = MODULE.NamespaceIdentity("mnt", 4, 100)
        owned = MODULE.NamespaceIdentity("mnt", 4, 101)
        detached = MODULE.NamespaceIdentity("mnt", 4, 102)
        current = frozenset((ambient, owned))
        self.assertEqual(
            MODULE.classify_namespace_fd(
                ambient,
                process_bound=current,
                owned=frozenset((owned,)),
            ),
            "ambient_process_bound",
        )
        self.assertEqual(
            MODULE.classify_namespace_fd(
                owned,
                process_bound=current,
                owned=frozenset((owned,)),
            ),
            "owned",
        )
        self.assertEqual(
            MODULE.classify_namespace_fd(
                detached,
                process_bound=current,
                owned=frozenset((owned,)),
            ),
            "detached",
        )
        recorded = frozenset((ambient, owned))
        drain_self = frozenset((ambient,))
        owned_relation = recorded - drain_self
        self.assertEqual(
            MODULE.classify_namespace_fd(
                ambient,
                process_bound=current,
                owned=owned_relation,
            ),
            "ambient_process_bound",
        )
        self.assertEqual(
            MODULE.classify_namespace_fd(
                owned,
                process_bound=current,
                owned=owned_relation,
            ),
            "owned",
        )
        self.assertEqual(
            MODULE.classify_namespace_fd(
                owned,
                process_bound=frozenset((ambient,)),
                owned=frozenset((owned,)),
            ),
            "detached",
        )

    def test_namespace_fd_text_type_and_inode_are_one_typed_identity(self) -> None:
        observed = mock.Mock(
            st_mode=stat.S_IFREG | 0o444,
            st_dev=4,
            st_ino=100,
        )
        self.assertEqual(
            MODULE.namespace_fd_identity(
                "mnt:[100]",
                observed,
                label="test",
            ),
            MODULE.NamespaceIdentity("mnt", 4, 100),
        )
        self.assertIsNone(
            MODULE.namespace_fd_identity(
                "socket:[100]",
                observed,
                label="test",
            )
        )
        for changed in (
            mock.Mock(st_mode=stat.S_IFSOCK | 0o600, st_dev=4, st_ino=100),
            mock.Mock(st_mode=stat.S_IFREG | 0o444, st_dev=4, st_ino=101),
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                MODULE.DrainError,
                "namespace FD identity differs",
            ):
                MODULE.namespace_fd_identity(
                    "mnt:[100]",
                    changed,
                    label="test",
                )

    def test_every_process_bound_linux_namespace_entry_is_typed_and_censused(self) -> None:
        self.assertEqual(
            MODULE.NAMESPACE_KINDS,
            ("cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"),
        )
        observed = mock.Mock(
            st_mode=stat.S_IFREG | 0o444,
            st_dev=4,
            st_ino=100,
        )
        for kind in MODULE.NAMESPACE_KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(
                    MODULE.namespace_fd_identity(
                        f"{kind}:[100]",
                        observed,
                        label="test",
                    ),
                    MODULE.NamespaceIdentity(kind, 4, 100),
                )
        source = MODULE_PATH.read_text(encoding="utf-8")
        census = source[
            source.index("def _held_task_namespace_observations")
            : source.index("def _task_namespace_census_from_observations")
        ]
        process_scan = source[
            source.index("def process_reference_scan")
            : source.index("def _related_process_universe_once")
        ]
        self.assertEqual(
            MODULE.TASK_NAMESPACE_ENTRY_KINDS["pid_for_children"],
            "pid",
        )
        self.assertEqual(
            MODULE.TASK_NAMESPACE_ENTRY_KINDS["time_for_children"],
            "time",
        )
        self.assertIn("for entry, _kind in TASK_NAMESPACE_ENTRIES", census)
        self.assertIn("for entry, _kind in TASK_NAMESPACE_ENTRIES", process_scan)

        task = mock.Mock(thread_group_id=100, task_id=101, process_fd=31)
        with mock.patch.object(
            MODULE.os,
            "stat",
            return_value=mock.Mock(st_dev=4, st_ino=100),
        ), mock.patch.object(
            MODULE.os,
            "readlink",
            return_value="pid:[100]",
        ):
            self.assertEqual(
                MODULE.current_task_namespace_identity(task, "pid_for_children"),
                MODULE.NamespaceIdentity("pid", 4, 100),
            )

    def test_recorded_role_ownership_covers_every_kind_and_child_alias(self) -> None:
        process = {"taskNamespaces": task_namespaces(first_inode=100)}
        owned = MODULE.recorded_process_namespace_identities(process)
        self.assertEqual({identity.kind for identity in owned}, set(MODULE.NAMESPACE_KINDS))
        self.assertEqual(len(owned), len(MODULE.TASK_NAMESPACE_ENTRIES))
        for kind in MODULE.NAMESPACE_KINDS:
            target = next(identity for identity in owned if identity.kind == kind)
            drain_current = frozenset(owned - {target})
            private = owned - drain_current
            with self.subTest(kind=kind):
                self.assertTrue(frozenset({target}) & private)
                self.assertEqual(
                    MODULE.classify_namespace_fd(
                        target,
                        process_bound=owned,
                        owned=private,
                    ),
                    "owned",
                )

    def test_census_owned_namespace_pins_are_excluded_from_self_fd_roster(self) -> None:
        task = mock.Mock(process_fd=10, pidfd=11, thread_group_id=100, task_id=100)
        observed = mock.Mock(
            st_mode=stat.S_IFREG | 0o444,
            st_dev=4,
            st_ino=101,
        )
        with mock.patch.object(
            MODULE.os,
            "open",
            return_value=12,
        ), mock.patch.object(
            MODULE.os,
            "listdir",
            return_value=("40", "41"),
        ), mock.patch.object(
            MODULE.os,
            "readlink",
            return_value="mnt:[101]",
        ) as readlink, mock.patch.object(
            MODULE.os,
            "stat",
            return_value=observed,
        ), mock.patch.object(MODULE.os, "close"):
            rows = MODULE._namespace_fd_records(
                task,
                excluded_fds=frozenset((40,)),
            )
        self.assertEqual([row["fd"] for row in rows], [41])
        readlink.assert_called_once_with("41", dir_fd=12)

    def test_namespace_census_churn_between_passes_rejects(self) -> None:
        stable = namespace_census(digest="1" * 64)
        changed = namespace_census(digest="2" * 64)
        values = iter((stable, changed))

        def once(custody: MODULE.ResourceCustody, **_kwargs: object) -> object:
            value = next(values)
            return value

        with mock.patch.object(
            MODULE,
            "task_namespace_census_once",
            side_effect=once,
        ), self.assertRaisesRegex(
            MODULE.DrainError,
            "changed across proof passes",
        ):
            with MODULE.ResourceCustody(label="changed namespace census") as custody:
                MODULE.stable_task_namespace_census(custody)

    def test_second_namespace_pass_excludes_first_pass_proof_descriptors(self) -> None:
        first = mock.Mock(proof_sha256="a" * 64, namespace_descriptors=(40, 41))
        second = mock.Mock(proof_sha256="a" * 64, namespace_descriptors=(50,))
        values = iter((first, second))

        def census_once(
            custody: MODULE.ResourceCustody,
            **_kwargs: object,
        ) -> object:
            value = next(values)
            acquire_test_descriptors(custody, *value.namespace_descriptors)
            return value

        with mock.patch.object(
            MODULE,
            "task_namespace_census_once",
            side_effect=census_once,
        ) as once, mock.patch.object(MODULE.os, "close") as close:
            with MODULE.ResourceCustody(label="second namespace census") as custody:
                self.assertIs(MODULE.stable_task_namespace_census(custody), second)
                self.assertEqual(close.call_args_list, [mock.call(41), mock.call(40)])
            self.assertEqual(
                close.call_args_list,
                [mock.call(41), mock.call(40), mock.call(50)],
            )
        self.assertEqual(len(once.call_args_list[0].args), 1)
        self.assertIsInstance(once.call_args_list[0].args[0], MODULE.ResourceCustody)
        self.assertEqual(once.call_args_list[0].kwargs, {})
        self.assertIs(once.call_args_list[1].args[0], custody)
        self.assertEqual(
            once.call_args_list[1].kwargs,
            {"external_self_excluded_fds": frozenset((40, 41))},
        )

    def test_first_census_cleanup_failure_still_closes_second_before_rejecting(self) -> None:
        first = mock.Mock(proof_sha256="a" * 64, namespace_descriptors=(40,))
        second = mock.Mock(proof_sha256="a" * 64, namespace_descriptors=(50,))
        values = iter((first, second))

        def census_once(
            custody: MODULE.ResourceCustody,
            **_kwargs: object,
        ) -> object:
            value = next(values)
            acquire_test_descriptors(custody, *value.namespace_descriptors)
            return value

        with mock.patch.object(
            MODULE,
            "task_namespace_census_once",
            side_effect=census_once,
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(OSError("first close failed"), None),
        ) as close, self.assertRaisesRegex(MODULE.DrainError, "cleanup failed"):
            with MODULE.ResourceCustody(label="second namespace census") as custody:
                MODULE.stable_task_namespace_census(custody)
        self.assertEqual(close.call_args_list, [mock.call(40), mock.call(50)])

    def test_borrowed_namespace_census_reproves_held_descriptor_identity(self) -> None:
        identities = tuple(
            MODULE.NamespaceIdentity(kind, 4, 100)
            for kind in MODULE.NAMESPACE_KINDS
        )
        binding = task_namespace_binding()
        preimage = MODULE.task_namespace_census_preimage(
            set(identities),
            set(),
            (),
            1,
            (binding,),
        )
        digest = hashlib.sha256(MODULE.canonical_json(preimage)).hexdigest()
        summary = {
            "processBoundNamespaceCount": len(identities),
            "namespaceFdCount": 0,
            "mountNamespaceCount": 0,
            "proofSha256": digest,
            "processlessMountNamespaces": "not_observable_and_not_admitted",
            "queuedScmRightsNamespaceFds": "not_observable_and_not_admitted",
            "taskCount": 1,
            "taskNamespaceBindingCount": 1,
        }
        census = MODULE.TaskNamespaceCensus(
            frozenset(identities),
            frozenset(),
            (),
            digest,
            summary,
            tuple(range(40, 40 + len(identities))),
            preimage,
            (binding,),
        )
        observed = mock.Mock(
            st_mode=stat.S_IFREG | 0o444,
            st_dev=4,
            st_ino=100,
        )
        with mock.patch.object(
            MODULE.os,
            "fstat",
            return_value=observed,
        ), mock.patch.object(
            MODULE.os,
            "readlink",
            side_effect=[f"{identity.kind}:[100]" for identity in sorted(identities)],
        ):
            census.require_open()
        with mock.patch.object(
            MODULE.os,
            "fstat",
            return_value=observed,
        ), mock.patch.object(
            MODULE.os,
            "readlink",
            return_value="mnt:[101]",
        ), self.assertRaisesRegex(MODULE.DrainError, "identity differs"):
            census.require_open()

    def test_caller_custody_closes_namespace_descriptors_once(self) -> None:
        census = MODULE.TaskNamespaceCensus(
            frozenset(),
            frozenset(),
            (),
            "a" * 64,
            {},
            (40, 41),
        )
        with mock.patch.object(census, "require_open"), mock.patch.object(
            MODULE.os,
            "close",
        ) as close:
            with MODULE.ResourceCustody(label="namespace census caller") as custody:
                acquire_test_descriptors(custody, 40, 41)
                census.require_open()
                close.assert_not_called()
        self.assertEqual(close.call_args_list, [mock.call(41), mock.call(40)])

    def test_borrowed_census_rejects_mutated_digest_preimage(self) -> None:
        preimage = MODULE.task_namespace_census_preimage(
            set(),
            set(),
            (),
            0,
        )
        digest = hashlib.sha256(MODULE.canonical_json(preimage)).hexdigest()
        summary = {
            "processBoundNamespaceCount": 0,
            "namespaceFdCount": 0,
            "mountNamespaceCount": 0,
            "proofSha256": digest,
            "processlessMountNamespaces": "not_observable_and_not_admitted",
            "queuedScmRightsNamespaceFds": "not_observable_and_not_admitted",
            "taskCount": 0,
            "taskNamespaceBindingCount": 0,
        }
        census = MODULE.TaskNamespaceCensus(
            frozenset(),
            frozenset(),
            (),
            digest,
            summary,
            (),
            preimage,
        )
        census.require_open()
        preimage["taskCount"] = 1
        with self.assertRaisesRegex(MODULE.DrainError, "digest or summary differs"):
            census.require_open()

    def test_child_namespace_alias_swap_changes_census_preimage(self) -> None:
        namespaces = task_namespaces(first_inode=100)
        binding = {
            "threadGroupId": 100,
            "taskId": 100,
            "namespaces": namespaces,
        }
        current = {
            MODULE.NamespaceIdentity(
                str(identity["kind"]),
                int(identity["device"]),
                int(identity["inode"]),
            )
            for identity in namespaces.values()
        }
        first = MODULE.task_namespace_census_preimage(
            current,
            set(),
            (),
            1,
            (binding,),
        )
        changed = json.loads(json.dumps(binding))
        changed_namespaces = changed["namespaces"]
        changed_namespaces["pid"], changed_namespaces["pid_for_children"] = (
            changed_namespaces["pid_for_children"],
            changed_namespaces["pid"],
        )
        second = MODULE.task_namespace_census_preimage(
            current,
            set(),
            (),
            1,
            (changed,),
        )
        self.assertNotEqual(
            MODULE.sha256_bytes(MODULE.canonical_json(first)),
            MODULE.sha256_bytes(MODULE.canonical_json(second)),
        )

    def test_census_validation_failure_leaves_cleanup_with_caller(self) -> None:
        preimage = MODULE.task_namespace_census_preimage(set(), set(), (), 0)
        digest = hashlib.sha256(MODULE.canonical_json(preimage)).hexdigest()
        census = MODULE.TaskNamespaceCensus(
            frozenset(),
            frozenset(),
            (),
            digest,
            {
                "processBoundNamespaceCount": 0,
                "namespaceFdCount": 0,
                "mountNamespaceCount": 0,
                "proofSha256": digest,
                "processlessMountNamespaces": "not_observable_and_not_admitted",
                "queuedScmRightsNamespaceFds": "not_observable_and_not_admitted",
                "taskCount": 0,
                "taskNamespaceBindingCount": 0,
            },
            (40,),
            preimage,
        )
        with mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "descriptor roster differs",
        ):
            with MODULE.ResourceCustody(label="invalid namespace census") as custody:
                acquire_test_descriptor(custody, 40)
                census.require_open()
        close.assert_called_once_with(40)

    def test_current_namespace_change_inside_one_task_capture_rejects(self) -> None:
        task = mock.Mock(thread_group_id=100, task_id=101, process_fd=31)
        expected = MODULE.NamespaceIdentity("mnt", 4, 100)
        with mock.patch.object(
            MODULE.os,
            "stat",
            return_value=mock.Mock(st_dev=4, st_ino=101),
        ), mock.patch.object(
            MODULE.os,
            "readlink",
            return_value="mnt:[101]",
        ), self.assertRaisesRegex(
            MODULE.DrainError,
            "namespace entry changed during census",
        ):
            MODULE.require_current_task_namespace_identity(task, "mnt", expected)

    def test_namespace_census_fd_budget_fails_before_descriptor_custody(self) -> None:
        with mock.patch.object(
            MODULE.resource,
            "getrlimit",
            return_value=(250, 256),
        ), mock.patch.object(
            MODULE.os,
            "listdir",
            return_value=("0", "1", "2", "3"),
        ):
            self.assertEqual(
                MODULE.require_task_namespace_census_fd_budget(10),
                {
                    "taskCount": 10,
                    "baselineDescriptorReserve": 128,
                    "perTaskDescriptorReserve": 12,
                    "transientDescriptorReserve": 2,
                    "externallyHeldDescriptorCount": 0,
                    "requiredDescriptorLimit": 250,
                    "softDescriptorLimit": 250,
                    "hardDescriptorLimit": 256,
                },
            )
        with mock.patch.object(
            MODULE.resource,
            "getrlimit",
            return_value=(249, 256),
        ), mock.patch.object(
            MODULE.os,
            "listdir",
            return_value=("0", "1", "2", "3"),
        ), self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "file-descriptor limit is insufficient",
        ):
            MODULE.require_task_namespace_census_fd_budget(10)

        with mock.patch.object(
            MODULE.resource,
            "getrlimit",
            return_value=(250, 256),
        ), mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(
                ("0", "1", "2", "3"),
                ("0", "1", "2", "3", "4"),
            ),
        ):
            verify = MODULE.require_task_namespace_census_fd_budget(10)
            drain_with_lease = MODULE.require_task_namespace_census_fd_budget(10)
        self.assertEqual(verify, drain_with_lease)

        with mock.patch.object(
            MODULE.resource,
            "getrlimit",
            return_value=(252, 256),
        ), mock.patch.object(
            MODULE.os,
            "listdir",
            return_value=("0", "1", "2", "3"),
        ):
            self.assertEqual(
                MODULE.require_task_namespace_census_fd_budget(
                    10,
                    externally_held=2,
                )["requiredDescriptorLimit"],
                252,
            )

    def test_self_fd_exclusion_requires_a_single_threaded_drain(self) -> None:
        with mock.patch.object(MODULE.os, "getpid", return_value=100):
            MODULE.require_single_threaded_drain_coordinates(((100, 100), (200, 200)))
            with self.assertRaisesRegex(
                MODULE.DrainError,
                "not single-threaded",
            ):
                MODULE.require_single_threaded_drain_coordinates(
                    ((100, 100), (100, 101))
                )

    def test_duplicate_namespace_descriptor_closes_on_divergence(self) -> None:
        identity = MODULE.NamespaceIdentity("mnt", 4, 100)
        held = {identity: 40}
        with mock.patch.object(MODULE.os, "close") as close:
            with MODULE.ResourceCustody(label="namespace admission test") as custody:
                acquire_test_descriptor(custody, 41)
                with mock.patch.object(
                    MODULE.os,
                    "fstat",
                    side_effect=(
                        mock.Mock(st_dev=4, st_ino=100, st_mode=stat.S_IFREG),
                        mock.Mock(st_dev=4, st_ino=101, st_mode=stat.S_IFREG),
                    ),
                ), self.assertRaisesRegex(
                    MODULE.DrainError,
                    "descriptor identity diverges",
                ):
                    MODULE.admit_held_namespace_descriptor(
                        custody,
                        held,
                        identity,
                        41,
                    )
        close.assert_called_once_with(41)
        self.assertEqual(held, {identity: 40})

    def test_resource_custody_cleanup_attempts_every_owned_resource(self) -> None:
        first = mock.Mock()
        second = mock.Mock()
        first.close.side_effect = MODULE.DrainError("task close failed")
        custody = MODULE.ResourceCustody(label="namespace observation")
        acquire_test_descriptors(custody, 40, 41)
        with mock.patch.object(MODULE._socket, "socket", side_effect=(first, second)):
            custody.socket()
            custody.socket()
        with mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(OSError("namespace close failed"), None),
        ) as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "namespace observation cleanup failed",
        ):
            custody.close()
        self.assertEqual(close.call_args_list, [mock.call(41), mock.call(40)])
        second.close.assert_called_once_with()
        first.close.assert_called_once_with()

    def test_resource_custody_preserves_primary_and_surfaces_normal_cleanup(self) -> None:
        primary = RuntimeError("body failed")
        custody = MODULE.ResourceCustody(label="fault injection")
        acquire_test_descriptor(custody, 40)
        with mock.patch.object(
            MODULE.os,
            "close",
            side_effect=OSError("close failed"),
        ):
            custody.__exit__(RuntimeError, primary, None)
        self.assertIn("cleanup also failed", "\n".join(primary.__notes__))

        custody = MODULE.ResourceCustody(label="fault injection")
        acquire_test_descriptor(custody, 41)
        with mock.patch.object(
            MODULE.os,
            "close",
            side_effect=OSError("close failed"),
        ), self.assertRaisesRegex(MODULE.DrainError, "cleanup failed"):
            custody.__exit__(None, None, None)

    def test_resource_acquisition_copy_swap_ignores_hostile_private_roster(self) -> None:
        prior = MODULE.ResourceRegistration("descriptor", 39)
        prior.published = True

        class SubstitutingRoster(list[object]):
            def copy(self) -> object:
                raise AssertionError("virtual copy must not control publication")

            def append(self, _value: object) -> None:
                raise AssertionError("private roster append must not be used")

            def __iter__(self):  # type: ignore[no-untyped-def]
                raise AssertionError("private roster scan must not be used")

            def __getitem__(self, _index: object) -> object:
                raise AssertionError("private roster token substitution must not run")

        custody = MODULE.ResourceCustody(label="generation publication")
        hostile = SubstitutingRoster([prior])
        custody._resources = hostile  # type: ignore[assignment]
        with mock.patch.object(MODULE.os, "open", return_value=40), mock.patch.object(
            MODULE.os,
            "close",
        ) as close:
            self.assertEqual(custody.open("descriptor", os.O_RDONLY), 40)
            self.assertIs(type(custody._resources), list)
            self.assertEqual(len(custody._resources), 2)
            self.assertIs(custody._resources[0], prior)
            fresh = custody._resources[1]
            self.assertIsNot(fresh, prior)
            self.assertEqual(fresh.value, 40)
            self.assertTrue(fresh.published)
            self.assertEqual(hostile, [prior])
            custody.close()
        self.assertEqual(close.call_args_list, [mock.call(40), mock.call(39)])

    def test_resource_acquisition_has_no_roster_scan_or_rollback_fallback(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        custody = next(
            node
            for node in ast.parse(source).body
            if isinstance(node, ast.ClassDef) and node.name == "ResourceCustody"
        )
        methods = {
            node.name
            for node in custody.body
            if isinstance(node, ast.FunctionDef)
        }
        self.assertFalse(
            methods
            & {
                "_register",
                "_rollback",
                "_rollback_registration",
                "_builtin_roster_snapshot",
            }
        )
        acquire = next(
            node
            for node in custody.body
            if isinstance(node, ast.FunctionDef) and node.name == "_acquire"
        )
        publish = next(
            node
            for node in custody.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_publish_registration"
        )
        self.assertFalse(
            any(isinstance(node, (ast.ListComp, ast.GeneratorExp)) for node in ast.walk(acquire))
        )
        self.assertFalse(
            any(isinstance(node, (ast.ListComp, ast.GeneratorExp)) for node in ast.walk(publish))
        )

    def test_resource_acquisition_generation_boundary_matrix_is_failure_total(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        acquire = class_method_ast(source, "ResourceCustody", "_acquire")
        publish = class_method_ast(source, "ResourceCustody", "_publish_registration")
        acquire_registration = next(
            node
            for node in ast.walk(acquire)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "registration"
                for target in node.targets
            )
            and isinstance(node.value, ast.Call)
        )
        acquire_publish = next(
            node
            for node in ast.walk(acquire)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "_publish_registration"
        )
        acquire_return = next(
            node
            for node in ast.walk(acquire)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Name)
        )
        candidate_assignment = next(
            node
            for node in ast.walk(publish)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "candidate"
                for target in node.targets
            )
        )
        candidate_append = next(
            node
            for node in ast.walk(publish)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "append"
        )
        roster_swap = next(
            node
            for node in ast.walk(publish)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "_resources"
                for target in node.targets
            )
        )
        published = next(
            node
            for node in ast.walk(publish)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "published"
                for target in node.targets
            )
        )
        cases = (
            (
                "after_syscall_before_token",
                MODULE.ResourceCustody._acquire.__code__,
                acquire_registration.lineno,
            ),
            (
                "after_token_before_publication",
                MODULE.ResourceCustody._acquire.__code__,
                acquire_publish.lineno,
            ),
            (
                "before_candidate_copy",
                MODULE.ResourceCustody._publish_registration.__code__,
                candidate_assignment.lineno,
            ),
            (
                "before_candidate_append",
                MODULE.ResourceCustody._publish_registration.__code__,
                candidate_append.lineno,
            ),
            (
                "before_roster_swap",
                MODULE.ResourceCustody._publish_registration.__code__,
                roster_swap.lineno,
            ),
            (
                "after_swap_before_published",
                MODULE.ResourceCustody._publish_registration.__code__,
                published.lineno,
            ),
            (
                "after_publication_before_return",
                MODULE.ResourceCustody._acquire.__code__,
                acquire_return.lineno,
            ),
        )
        for label, code, line in cases:
            prior = MODULE.ResourceRegistration("descriptor", 39)
            prior.published = True
            custody = MODULE.ResourceCustody(label=label)
            custody._resources = [prior]
            with self.subTest(boundary=label), mock.patch.object(
                MODULE.os,
                "open",
                return_value=40,
            ), mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
                KeyboardInterrupt,
                label,
            ):
                with interrupt_once_on_line(code, line, label) as fired:
                    custody.open("descriptor", os.O_RDONLY)
            self.assertTrue(fired[0])
            close.assert_called_once_with(40)
            self.assertEqual(custody._resources, [prior])
            self.assertTrue(prior.published)

    def test_resource_roster_restore_boundary_matrix_preserves_primary(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        restore = class_method_ast(source, "ResourceCustody", "_restore_roster")
        restore_assignment = next(
            node
            for node in ast.walk(restore)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "_resources"
                for target in node.targets
            )
        )
        restore_return = next(
            node
            for node in ast.walk(restore)
            if isinstance(node, ast.Return) and node.lineno > restore_assignment.lineno
        )
        after_restore = min(
            (
                node
                for node in ast.walk(restore)
                if isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and any(
                    isinstance(value, ast.Name) and value.id == "first_error"
                    for value in ast.walk(node.test)
                )
                and restore_assignment.lineno < node.lineno < restore_return.lineno
            ),
            key=lambda node: node.lineno,
        )
        for label, line in (
            ("before_restore_swap", restore_assignment.lineno),
            ("after_restore_swap", after_restore.lineno),
            ("before_restore_return", restore_return.lineno),
        ):
            prior = MODULE.ResourceRegistration("descriptor", 39)
            prior.published = True
            custody = MODULE.ResourceCustody(label=label)
            custody._resources = [prior]
            primary = RuntimeError("publication remains primary")
            with self.subTest(boundary=label), mock.patch.object(
                MODULE.os,
                "open",
                return_value=40,
            ), mock.patch.object(
                custody,
                "_publish_registration",
                side_effect=primary,
            ), mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
                RuntimeError,
                "publication remains primary",
            ) as raised:
                with interrupt_once_on_line(
                    MODULE.ResourceCustody._restore_roster.__code__,
                    line,
                    label,
                ) as fired:
                    custody.open("descriptor", os.O_RDONLY)
            self.assertTrue(fired[0])
            self.assertIs(raised.exception, primary)
            self.assertIn(label, "\n".join(raised.exception.__notes__))
            close.assert_called_once_with(40)
            self.assertEqual(custody._resources, [prior])

    def test_c_capture_guards_acquisition_before_python_opcode_resumes(self) -> None:
        capture_code = MODULE.ResourceCustody._capture_producer_result.__code__
        capture_complete = next(
            instruction.offset
            for instruction in dis.get_instructions(capture_code)
            if instruction.opname == "POP_TOP"
        )
        source = MODULE_PATH.read_text(encoding="utf-8")
        acquire_ast = class_method_ast(source, "ResourceCustody", "_acquire")
        custody_ast = next(
            node
            for node in ast.parse(source).body
            if isinstance(node, ast.ClassDef) and node.name == "ResourceCustody"
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Name) and node.id == "acquired"
                for node in ast.walk(acquire_ast)
            )
        )
        self.assertFalse(any(isinstance(node, ast.Lambda) for node in ast.walk(custody_ast)))
        partial_targets = {
            (node.args[0].value.id, node.args[0].attr)
            for node in ast.walk(custody_ast)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "functools"
            and node.func.attr == "partial"
            and node.args
            and isinstance(node.args[0], ast.Attribute)
            and isinstance(node.args[0].value, ast.Name)
        }
        self.assertTrue(
            {
                ("os", "open"),
                ("os", "pidfd_open"),
                ("os", "dup"),
                ("_socket", "socket"),
            }
            <= partial_targets
        )
        acquire_instructions = list(
            dis.get_instructions(MODULE.ResourceCustody._acquire)
        )
        capture_load = next(
            index
            for index, instruction in enumerate(acquire_instructions)
            if instruction.argval == "_capture_producer_result"
        )
        capture_call = next(
            index
            for index in range(capture_load, len(acquire_instructions))
            if acquire_instructions[index].opname.startswith("CALL")
        )
        after_capture_call = acquire_instructions[capture_call + 1].offset

        real_open = os.open
        real_close = os.close
        for label, code, offset in (
            ("inside C capture", capture_code, capture_complete),
            (
                "after capture helper call",
                MODULE.ResourceCustody._acquire.__code__,
                after_capture_call,
            ),
        ):
            opened: list[int] = []

            def observed_open(*args: object, **kwargs: object) -> int:
                descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
                opened.append(descriptor)
                return descriptor

            custody = MODULE.ResourceCustody(label=label)
            try:
                with self.subTest(boundary=label), mock.patch.object(
                    MODULE.os,
                    "open",
                    side_effect=observed_open,
                ), self.assertRaisesRegex(KeyboardInterrupt, label):
                    with interrupt_once_on_opcode(
                        code,
                        offset,
                        label,
                    ) as fired:
                        custody.open("/dev/null", os.O_RDONLY)
                self.assertTrue(fired[0])
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError):
                    os.fstat(opened[0])
                self.assertEqual(custody._resources, [])
                self.assertEqual(custody._state, "open")
            finally:
                for descriptor in opened:
                    try:
                        os.fstat(descriptor)
                    except OSError:
                        continue
                    real_close(descriptor)

    def test_pending_acquisition_survives_handler_entry_interruption(self) -> None:
        acquire_code = MODULE.ResourceCustody._acquire.__code__
        acquire_instructions = list(dis.get_instructions(acquire_code))
        handler_start = next(
            index
            for index, instruction in enumerate(acquire_instructions)
            if instruction.opname == "PUSH_EXC_INFO"
        )
        handler_entry = next(
            instruction.offset
            for instruction in acquire_instructions[handler_start:]
            if instruction.opname == "STORE_FAST"
        )
        real_open = os.open
        real_close = os.close
        opened: list[int] = []

        def observed_open(*args: object, **kwargs: object) -> int:
            descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
            opened.append(descriptor)
            return descriptor

        custody = MODULE.ResourceCustody(label="pending handler entry")
        custody._state = "closed"
        try:
            with mock.patch.object(
                MODULE.os,
                "open",
                side_effect=observed_open,
            ), self.assertRaisesRegex(KeyboardInterrupt, "handler entry"):
                with interrupt_once_on_opcode(
                    acquire_code,
                    handler_entry,
                    "handler entry",
                ) as fired:
                    custody.open("/dev/null", os.O_RDONLY)
            self.assertTrue(fired[0])
            self.assertEqual(len(opened), 1)
            self.assertIsNotNone(custody._pending_acquisition)
            os.fstat(opened[0])
            custody.close()
            with self.assertRaises(OSError):
                os.fstat(opened[0])
            self.assertIsNone(custody._pending_acquisition)
            self.assertEqual(custody._resources, [])
            self.assertEqual(custody._state, "closed")
        finally:
            for descriptor in opened:
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                real_close(descriptor)

    def test_reentrant_close_cannot_consume_an_active_acquisition(self) -> None:
        acquire_code = MODULE.ResourceCustody._acquire.__code__
        instructions = list(dis.get_instructions(acquire_code))
        capture_load = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.argval == "_capture_producer_result"
        )
        capture_call = next(
            index
            for index in range(capture_load, len(instructions))
            if instructions[index].opname.startswith("CALL")
        )
        boundaries = (
            ("after active capture", instructions[capture_call + 1].offset),
            (
                "at active return",
                next(
                    instruction.offset
                    for instruction in instructions
                    if instruction.opname == "RETURN_VALUE"
                ),
            ),
        )
        real_close = os.close
        for label, offset in boundaries:
            custody = MODULE.ResourceCustody(label=label)
            observed: list[BaseException] = []
            fired = [False]

            def trace(frame: object, event: str, _argument: object):  # type: ignore[no-untyped-def]
                if getattr(frame, "f_code") is acquire_code:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not fired[0]
                        and event == "opcode"
                        and getattr(frame, "f_lasti") == offset
                    ):
                        fired[0] = True
                        try:
                            custody.close()
                        except BaseException as error:
                            observed.append(error)
                return trace

            descriptor: int | None = None
            calls: list[int] = []

            def observed_close(value: int) -> None:
                calls.append(value)
                real_close(value)

            previous = sys.gettrace()
            try:
                sys.settrace(trace)
                descriptor = custody.open("/dev/null", os.O_RDONLY)
            finally:
                sys.settrace(previous)
            try:
                self.assertTrue(fired[0])
                self.assertEqual(len(observed), 1)
                self.assertIsInstance(observed[0], MODULE.DrainError)
                self.assertIn("acquisition is still active", str(observed[0]))
                assert descriptor is not None
                os.fstat(descriptor)
                with mock.patch.object(
                    MODULE.os,
                    "close",
                    side_effect=observed_close,
                ):
                    custody.close()
                self.assertEqual(calls, [descriptor])
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            finally:
                if descriptor is not None:
                    try:
                        os.fstat(descriptor)
                    except OSError:
                        pass
                    else:
                        real_close(descriptor)

    def test_bool_alias_does_not_hide_the_exact_integer_descriptor(self) -> None:
        custody = MODULE.ResourceCustody(label="exact descriptor roster")
        acquire_test_descriptor(custody, 1)
        with mock.patch.object(MODULE.os, "close") as close:
            with self.assertRaisesRegex(MODULE.DrainError, "close roster is invalid"):
                custody.close_descriptors((True, 1))
            close.assert_not_called()
            custody.close()
        close.assert_called_once_with(1)

    def test_socket_constructor_cannot_adopt_a_caller_owned_descriptor(self) -> None:
        existing = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        custody = MODULE.ResourceCustody(label="socket adoption")
        try:
            descriptor = existing.fileno()
            with mock.patch.object(MODULE._socket, "socket") as constructor:
                with self.assertRaisesRegex(MODULE.DrainError, "adoption is forbidden"):
                    custody.socket(fileno=descriptor)
                with self.assertRaisesRegex(MODULE.DrainError, "adoption is forbidden"):
                    custody.socket(
                        socket.AF_UNIX,
                        socket.SOCK_STREAM,
                        0,
                        descriptor,
                    )
            constructor.assert_not_called()
            self.assertEqual(existing.fileno(), descriptor)
            self.assertEqual(custody._resources, [])
        finally:
            existing.close()

    def test_hostile_int_subclass_rejects_before_equality_or_close(self) -> None:
        equality_called = False

        class HostileDescriptor(int):
            def __eq__(self, _other: object) -> bool:
                nonlocal equality_called
                equality_called = True
                raise KeyboardInterrupt("hostile equality ran")

        custody = MODULE.ResourceCustody(label="exact descriptor")
        with mock.patch.object(
            MODULE.os,
            "open",
            return_value=HostileDescriptor(40),
        ), mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "descriptor registration is invalid",
        ):
            custody.open("descriptor", os.O_RDONLY)
        self.assertFalse(equality_called)
        self.assertEqual(close.call_count, 1)
        closed_value = close.call_args.args[0]
        self.assertIs(type(closed_value), HostileDescriptor)
        self.assertEqual(int(closed_value), 40)

    def test_all_public_close_paths_cover_preinvoke_and_postinvoke_boundaries(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        cleanup = class_method_ast(
            source,
            "ResourceCustody",
            "_cleanup_registration_once",
        )
        invoke_line = next(
            node.lineno
            for node in ast.walk(cleanup)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_invoke_closer"
        )
        finished_line = next(
            node.lineno
            for node in ast.walk(cleanup)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "close_finished"
                for target in node.targets
            )
            and node.lineno > invoke_line
        )

        def close_one(custody: MODULE.ResourceCustody) -> None:
            custody.close_descriptor(40)

        def close_many(custody: MODULE.ResourceCustody) -> None:
            custody.close_descriptors((40,))

        def close_all(custody: MODULE.ResourceCustody) -> None:
            custody.close()

        for path_name, close_path in (
            ("close_descriptor", close_one),
            ("close_descriptors", close_many),
            ("close", close_all),
        ):
            for boundary, line in (
                ("pre_close_before_syscall", invoke_line),
                ("after_close_before_finished", finished_line),
            ):
                custody = MODULE.ResourceCustody(
                    label=f"{path_name} {boundary}"
                )
                acquire_test_descriptor(custody, 40)
                with self.subTest(path=path_name, boundary=boundary), mock.patch.object(
                    MODULE.os,
                    "close",
                ) as close:
                    with self.assertRaisesRegex(
                        MODULE.DrainError,
                        "close failed|cleanup failed",
                    ) as first:
                        with interrupt_once_on_line(
                            MODULE.ResourceCustody._cleanup_registration_once.__code__,
                            line,
                            f"{path_name} {boundary}",
                        ) as fired:
                            close_path(custody)
                    self.assertTrue(fired[0])
                    close.assert_called_once_with(40)
                    persisted = first.exception.__cause__
                    self.assertIsInstance(persisted, KeyboardInterrupt)
                    self.assertIn(boundary, str(persisted))
                    self.assertEqual(custody._resources, [])
                    expected_state = "closed" if path_name == "close" else "open"
                    self.assertEqual(custody._state, expected_state)
                    with self.assertRaisesRegex(MODULE.DrainError, "cleanup failed") as retried:
                        custody.close()
                    self.assertIs(retried.exception.__cause__, persisted)
                    close.assert_called_once_with(40)

        for boundary, line in (
            ("closeable_pre_close_before_syscall", invoke_line),
            ("closeable_after_close_before_finished", finished_line),
        ):
            custody = MODULE.ResourceCustody(label=boundary)
            resource_value = mock.Mock()
            with mock.patch.object(
                MODULE._socket,
                "socket",
                return_value=resource_value,
            ):
                custody.socket()
            with self.subTest(path="closeable", boundary=boundary), self.assertRaisesRegex(
                MODULE.DrainError,
                "cleanup failed",
            ) as first:
                with interrupt_once_on_line(
                    MODULE.ResourceCustody._cleanup_registration_once.__code__,
                    line,
                    boundary,
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            resource_value.close.assert_called_once_with()
            self.assertIsInstance(first.exception.__cause__, KeyboardInterrupt)
            self.assertEqual(custody._resources, [])
            self.assertEqual(custody._state, "closed")

    def test_c_closer_guard_and_invocation_precede_python_opcode_resumption(
        self,
    ) -> None:
        invoke_code = MODULE.ResourceCustody._invoke_closer.__code__
        inside_invoke = next(
            instruction.offset
            for instruction in dis.get_instructions(invoke_code)
            if instruction.opname == "POP_TOP"
        )
        cleanup_instructions = list(
            dis.get_instructions(MODULE.ResourceCustody._cleanup_registration_once)
        )
        invoke_load = next(
            index
            for index, instruction in enumerate(cleanup_instructions)
            if instruction.argval == "_invoke_closer"
        )
        invoke_call = next(
            index
            for index in range(invoke_load, len(cleanup_instructions))
            if cleanup_instructions[index].opname.startswith("CALL")
        )
        after_invoke_call = cleanup_instructions[invoke_call + 1].offset

        real_close = os.close
        for label, code, offset in (
            ("inside C closer invocation", invoke_code, inside_invoke),
            (
                "after C closer helper call",
                MODULE.ResourceCustody._cleanup_registration_once.__code__,
                after_invoke_call,
            ),
        ):
            custody = MODULE.ResourceCustody(label=label)
            descriptor = custody.open("/dev/null", os.O_RDONLY)
            calls: list[int] = []

            def observed_close(value: int) -> None:
                calls.append(value)
                real_close(value)

            try:
                with self.subTest(boundary=label), mock.patch.object(
                    MODULE.os,
                    "close",
                    side_effect=observed_close,
                ), self.assertRaisesRegex(MODULE.DrainError, "cleanup failed") as raised:
                    with interrupt_once_on_opcode(
                        code,
                        offset,
                        label,
                    ) as fired:
                        custody.close()
                self.assertTrue(fired[0])
                self.assertIsInstance(raised.exception.__cause__, KeyboardInterrupt)
                self.assertEqual(calls, [descriptor])
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                self.assertEqual(custody._resources, [])
                self.assertEqual(custody._state, "closed")
            finally:
                try:
                    os.fstat(descriptor)
                except OSError:
                    pass
                else:
                    real_close(descriptor)

    def test_close_open_to_closing_and_final_settlement_are_resumable(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        close_ast = class_method_ast(source, "ResourceCustody", "close")
        transition = next(
            node
            for node in ast.walk(close_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "_state"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and node.value.value == "closing"
        )
        after_transition = min(
            node.lineno
            for node in ast.walk(close_ast)
            if isinstance(node, ast.stmt) and node.lineno > transition.lineno
        )
        completed = next(
            node
            for node in ast.walk(close_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "completed"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        )
        final_settlement = min(
            node.lineno
            for node in ast.walk(close_ast)
            if isinstance(node, ast.stmt) and node.lineno > completed.lineno
        )
        for label, line in (
            ("after_open_to_closing", after_transition),
            ("after_completed_before_settlement", final_settlement),
        ):
            custody = MODULE.ResourceCustody(label=label)
            acquire_test_descriptor(custody, 40)
            with self.subTest(boundary=label), mock.patch.object(
                MODULE.os,
                "close",
            ) as close:
                with self.assertRaisesRegex(KeyboardInterrupt, label):
                    with interrupt_once_on_line(
                        MODULE.ResourceCustody.close.__code__,
                        line,
                        label,
                    ) as fired:
                        custody.close()
                self.assertTrue(fired[0])
                custody.close()
                close.assert_called_once_with(40)
                self.assertEqual(custody._resources, [])
                self.assertEqual(custody._state, "closed")

    def test_cleanup_entry_retries_before_start_but_return_does_not_retry_after_start(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        cleanup_ast = class_method_ast(
            source,
            "ResourceCustody",
            "_cleanup_registration_once",
        )
        entry_line = min(
            node.lineno
            for node in cleanup_ast.body
            if isinstance(node, ast.stmt)
        )
        return_line = max(
            node.lineno
            for node in ast.walk(cleanup_ast)
            if isinstance(node, ast.Return)
        )
        for label, line, expected_calls in (
            ("cleanup_entry_before_start", entry_line, 2),
            ("cleanup_return_after_start", return_line, 1),
        ):
            custody = MODULE.ResourceCustody(label=label)
            acquire_test_descriptor(custody, 40)
            cleanup = custody._cleanup_registration_once
            with self.subTest(boundary=label), mock.patch.object(
                custody,
                "_cleanup_registration_once",
                wraps=cleanup,
            ) as cleanup_calls, mock.patch.object(
                MODULE.os,
                "close",
            ) as close, self.assertRaisesRegex(
                MODULE.DrainError,
                "cleanup failed",
            ) as raised:
                with interrupt_once_on_line(
                    MODULE.ResourceCustody._cleanup_registration_once.__code__,
                    line,
                    label,
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            self.assertEqual(cleanup_calls.call_count, expected_calls)
            close.assert_called_once_with(40)
            self.assertIsInstance(raised.exception.__cause__, KeyboardInterrupt)
            self.assertEqual(custody._resources, [])
            self.assertEqual(custody._state, "closed")

    def test_cleanup_error_return_interruption_preserves_syscall_failure(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        cleanup_ast = class_method_ast(
            source,
            "ResourceCustody",
            "_cleanup_registration_once",
        )
        descriptor_close_line = next(
            node.lineno
            for node in ast.walk(cleanup_ast)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_invoke_closer"
        )
        error_return = min(
            (
                node
                for node in ast.walk(cleanup_ast)
                if isinstance(node, ast.Return)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "close_error"
                and node.lineno > descriptor_close_line
            ),
            key=lambda node: node.lineno,
        )
        error_persistence = min(
            (
                node
                for node in ast.walk(cleanup_ast)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Attribute)
                    and target.attr == "close_error"
                    for target in node.targets
                )
                and node.lineno > descriptor_close_line
            ),
            key=lambda node: node.lineno,
        )
        for label, line in (
            ("before_cleanup_error_persistence", error_persistence.lineno),
            ("cleanup_error_return_interrupted", error_return.lineno),
        ):
            first = OSError("descriptor close failed first")
            custody = MODULE.ResourceCustody(label=label)
            acquire_test_descriptor(custody, 40)
            with self.subTest(boundary=label), mock.patch.object(
                MODULE.os,
                "close",
                side_effect=first,
            ) as close, self.assertRaises(BaseException) as raised:
                with interrupt_once_on_line(
                    MODULE.ResourceCustody._cleanup_registration_once.__code__,
                    line,
                    label,
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            close.assert_called_once_with(40)
            self.assertIsInstance(raised.exception, MODULE.DrainError)
            self.assertIs(raised.exception.__cause__, first)
            self.assertIn(label, "\n".join(first.__notes__))
            self.assertEqual(custody._resources, [])
            self.assertEqual(custody._state, "closed")

    def test_cleanup_activation_bookkeeping_cannot_veto_the_syscall(self) -> None:
        class FailingActivationRoster(set[int]):
            def add(self, _value: int) -> None:
                raise MemoryError("activation roster allocation failed")

        custody = MODULE.ResourceCustody(label="cleanup activation")
        custody._active_cleanup_tokens = FailingActivationRoster()
        acquire_test_descriptor(custody, 40)
        with mock.patch.object(MODULE.os, "close") as close:
            custody.close()
        close.assert_called_once_with(40)
        self.assertEqual(custody._resources, [])
        self.assertEqual(custody._state, "closed")
        source = MODULE_PATH.read_text(encoding="utf-8")
        cleanup_ast = class_method_ast(
            source,
            "ResourceCustody",
            "_cleanup_registration_once",
        )
        self.assertNotIn("_active_cleanup_tokens", source)
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"add", "discard"}
                for node in ast.walk(cleanup_ast)
            )
        )
        self.assertNotIn("_active_cleanup", source)
        self.assertTrue(hasattr(MODULE.ResourceCustody, "_cleanup_is_active"))

        custody = MODULE.ResourceCustody(label="abandoned cleanup generation")
        acquire_test_descriptor(custody, 41)
        registration = custody._resources[0]
        registration.close_started = True
        registration.close_finished = False
        registration.close_error = None
        self.assertFalse(custody._cleanup_is_active(registration))
        with mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "cleanup failed",
        ) as raised:
            custody.close()
        close.assert_not_called()
        self.assertIsInstance(raised.exception.__cause__, MODULE.DrainError)
        self.assertIn("invocation is ambiguous", str(raised.exception.__cause__))
        self.assertIs(registration.close_error, raised.exception.__cause__)
        self.assertTrue(registration.close_finished)
        self.assertEqual(custody._resources, [])
        self.assertEqual(custody._state, "closed")

    def test_incomplete_close_remains_closing_and_rejects_new_generation(self) -> None:
        close_ast = class_method_ast(
            MODULE_PATH.read_text(encoding="utf-8"),
            "ResourceCustody",
            "close",
        )
        transition = next(
            node
            for node in ast.walk(close_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "_state"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and node.value.value == "closing"
        )
        after_transition = min(
            node.lineno
            for node in ast.walk(close_ast)
            if isinstance(node, ast.stmt) and node.lineno > transition.lineno
        )
        custody = MODULE.ResourceCustody(label="incomplete close")
        acquire_test_descriptor(custody, 40)
        with mock.patch.object(MODULE.os, "close") as close:
            with self.assertRaisesRegex(KeyboardInterrupt, "close interrupted"):
                with interrupt_once_on_line(
                    MODULE.ResourceCustody.close.__code__,
                    after_transition,
                    "close interrupted",
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            self.assertEqual(custody._state, "closing")
            self.assertEqual(len(custody._resources), 1)
            with mock.patch.object(
                MODULE.os,
                "open",
                return_value=41,
            ), self.assertRaisesRegex(MODULE.DrainError, "unavailable"):
                custody.open("new generation", os.O_RDONLY)
            self.assertEqual(close.call_args_list, [mock.call(41)])
            custody.close()
        self.assertEqual(close.call_args_list, [mock.call(41), mock.call(40)])
        self.assertEqual(custody._state, "closed")

    def test_interrupted_close_error_persistence_poison_rejects_fd_reuse(self) -> None:
        close_many = class_method_ast(
            MODULE_PATH.read_text(encoding="utf-8"),
            "ResourceCustody",
            "close_descriptors",
        )
        settle = next(
            node
            for node in ast.walk(close_many)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "cleanup_error"
                for target in node.targets
            )
            and isinstance(node.value, ast.Call)
        )
        after_settle = min(
            node.lineno
            for node in ast.walk(close_many)
            if isinstance(node, ast.If) and node.lineno > settle.lineno
        )
        first = OSError("original close is ambiguous")
        custody = MODULE.ResourceCustody(label="interrupted close persistence")
        acquire_test_descriptor(custody, 40)
        with mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(first, None),
        ) as close:
            with self.assertRaisesRegex(KeyboardInterrupt, "before persistence"):
                with interrupt_once_on_line(
                    MODULE.ResourceCustody.close_descriptors.__code__,
                    after_settle,
                    "before persistence",
                ) as fired:
                    custody.close_descriptors((40,))
            self.assertTrue(fired[0])
            self.assertEqual(custody._state, "closing")
            self.assertIsNone(custody._cleanup_error)
            self.assertIs(custody._resources[0].close_error, first)
            with mock.patch.object(
                MODULE.os,
                "open",
                return_value=40,
            ), self.assertRaisesRegex(MODULE.DrainError, "unavailable"):
                custody.open("reused generation", os.O_RDONLY)
            self.assertEqual(close.call_args_list, [mock.call(40), mock.call(40)])
            with self.assertRaisesRegex(MODULE.DrainError, "cleanup failed") as raised:
                custody.close()
        self.assertIs(raised.exception.__cause__, first)
        self.assertEqual(close.call_args_list, [mock.call(40), mock.call(40)])
        self.assertEqual(custody._state, "closed")

    def test_three_resource_cleanup_preserves_first_error_and_formats_hostile_error(self) -> None:
        class HostileCleanupError(OSError):
            def __str__(self) -> str:
                raise MemoryError("hostile cleanup rendering")

        first = OSError("first cleanup failure")
        hostile = HostileCleanupError()
        custody = MODULE.ResourceCustody(label="three-resource cleanup")
        acquire_test_descriptors(custody, 40, 41, 42)
        with mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(first, hostile, None),
        ) as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "descriptor close failed",
        ) as raised:
            custody.close_descriptors((40, 41, 42))
        self.assertEqual(close.call_args_list, [mock.call(40), mock.call(41), mock.call(42)])
        self.assertIs(raised.exception.__cause__, first)
        self.assertIn(
            "<unprintable HostileCleanupError>",
            "\n".join(first.__notes__),
        )
        self.assertEqual(custody._resources, [])

    def test_actual_kernel_reentrant_same_fd_generation_is_closed(self) -> None:
        baseline = set(os.listdir("/proc/self/fd"))
        custody = MODULE.ResourceCustody(label="same-fd generation")
        observed_error: list[BaseException] = []
        opened_generations: list[int] = []
        leaked: int | None = None
        kernel_open = os.open

        def observed_open(*args: object, **kwargs: object) -> int:
            descriptor = kernel_open(*args, **kwargs)  # type: ignore[arg-type]
            opened_generations.append(descriptor)
            return descriptor

        class ReusingCloseable:
            def close(self) -> None:
                nonlocal leaked
                try:
                    leaked = custody.open("/dev/null", os.O_RDONLY)
                except BaseException as error:
                    observed_error.append(error)

        reusing = ReusingCloseable()
        try:
            with mock.patch.object(
                MODULE._socket,
                "socket",
                return_value=reusing,
            ), mock.patch.object(MODULE.os, "open", side_effect=observed_open):
                custody.socket()
                old_generation = custody.open("/dev/null", os.O_RDONLY)
                custody.close()
            self.assertEqual(len(observed_error), 1)
            self.assertIsInstance(observed_error[0], MODULE.DrainError)
            self.assertIn("while custody is closing", str(observed_error[0]))
            self.assertEqual(opened_generations, [old_generation, old_generation])
            self.assertEqual(custody._resources, [])
            self.assertEqual(custody._state, "closed")
            with self.assertRaises(OSError):
                os.fstat(old_generation)
            self.assertEqual(set(os.listdir("/proc/self/fd")), baseline)
        finally:
            if custody._state != "closed":
                try:
                    custody.close()
                except BaseException:
                    pass
            if leaked is not None:
                try:
                    os.close(leaked)
                except OSError:
                    pass

    def test_alias_terminal_error_publication_is_resumable_at_every_boundary(self) -> None:
        close_ast = class_method_ast(
            MODULE_PATH.read_text(encoding="utf-8"),
            "ResourceCustody",
            "close",
        )
        alias_error = next(
            node
            for node in ast.walk(close_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "alias_error"
                for target in node.targets
            )
        )
        publish_ast = class_method_ast(
            MODULE_PATH.read_text(encoding="utf-8"),
            "ResourceCustody",
            "_publish_terminal_error",
        )
        terminal_publish = next(
            node
            for node in ast.walk(publish_ast)
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Tuple)
        )
        self.assertEqual(
            [target.attr for target in terminal_publish.targets[0].elts],
            ["close_error", "close_finished"],
        )
        self.assertEqual(terminal_publish.lineno, terminal_publish.end_lineno)
        self.assertIsInstance(terminal_publish.value, ast.Tuple)
        self.assertEqual(
            [
                value.id if isinstance(value, ast.Name) else value.value
                for value in terminal_publish.value.elts
            ],
            ["error", True],
        )
        publish_call = min(
            (
                node
                for node in ast.walk(close_ast)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_publish_terminal_error"
                and len(node.args) == 2
                and isinstance(node.args[1], ast.Name)
                and node.args[1].id == "alias_error"
                and node.lineno > alias_error.lineno
            ),
            key=lambda node: node.lineno,
        )
        record_call = min(
            (
                node
                for node in ast.walk(close_ast)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "_preserve_cleanup_error"
                and node.lineno > publish_call.lineno
            ),
            key=lambda node: node.lineno,
        )
        preserve_ast = class_method_ast(
            MODULE_PATH.read_text(encoding="utf-8"),
            "ResourceCustody",
            "_preserve_cleanup_error",
        )
        record_inner = next(
            node
            for node in ast.walk(preserve_ast)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_record_cleanup_error"
        )
        for label, code, line in (
            (
                "before_alias_error",
                MODULE.ResourceCustody.close.__code__,
                alias_error.lineno,
            ),
            (
                "before_alias_terminal_publish",
                MODULE.ResourceCustody.close.__code__,
                publish_call.lineno,
            ),
            (
                "after_alias_publish_before_record",
                MODULE.ResourceCustody.close.__code__,
                record_call.lineno,
            ),
            (
                "during_alias_error_recording",
                MODULE.ResourceCustody._preserve_cleanup_error.__code__,
                record_inner.lineno,
            ),
        ):
            first = MODULE.ResourceRegistration("descriptor", 41)
            second = MODULE.ResourceRegistration("descriptor", 41)
            first.published = second.published = True
            custody = MODULE.ResourceCustody(label=label)
            custody._resources = [first, second]
            with self.subTest(boundary=label), mock.patch.object(
                MODULE.os,
                "close",
            ) as close:
                if label == "during_alias_error_recording":
                    with self.assertRaisesRegex(
                        MODULE.DrainError,
                        "cleanup failed",
                    ) as raised:
                        with interrupt_once_on_line(
                            code,
                            line,
                            label,
                        ) as fired:
                            custody.close()
                else:
                    with self.assertRaisesRegex(KeyboardInterrupt, label):
                        with interrupt_once_on_line(
                            code,
                            line,
                            label,
                        ) as fired:
                            custody.close()
                    if label == "after_alias_publish_before_record":
                        self.assertIsInstance(first.close_error, MODULE.DrainError)
                        self.assertFalse(first.close_started)
                        self.assertTrue(first.close_finished)
                    else:
                        self.assertIsNone(first.close_error)
                        self.assertFalse(first.close_started)
                        self.assertFalse(first.close_finished)
                    self.assertIsNone(custody._cleanup_error)
                    close.assert_not_called()
                    self.assertEqual(custody._state, "closing")
                    self.assertEqual(len(custody._resources), 2)
                    with self.assertRaisesRegex(
                        MODULE.DrainError,
                        "cleanup failed",
                    ) as raised:
                        custody.close()
                self.assertTrue(fired[0])
            close.assert_called_once_with(41)
            self.assertIsNotNone(custody._cleanup_error)
            self.assertIs(first.close_error, custody._cleanup_error)
            self.assertFalse(first.close_started)
            self.assertTrue(first.close_finished)
            self.assertTrue(second.close_started)
            self.assertTrue(second.close_finished)
            self.assertIs(raised.exception.__cause__, custody._cleanup_error)
            self.assertIn("roster aliases", str(custody._cleanup_error))
            self.assertEqual(custody._resources, [])
            self.assertEqual(custody._state, "closed")

    def test_terminal_error_publication_prefixes_are_resumable(self) -> None:
        publish_ast = class_method_ast(
            MODULE_PATH.read_text(encoding="utf-8"),
            "ResourceCustody",
            "_publish_terminal_error",
        )
        terminal_publications = [
            node
            for node in ast.walk(publish_ast)
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Tuple)
        ]
        self.assertEqual(len(terminal_publications), 1)
        terminal_publish = terminal_publications[0]
        self.assertEqual(
            [target.attr for target in terminal_publish.targets[0].elts],
            ["close_error", "close_finished"],
        )
        self.assertEqual(terminal_publish.lineno, terminal_publish.end_lineno)
        self.assertIsInstance(terminal_publish.value, ast.Tuple)
        self.assertEqual(
            [
                value.id if isinstance(value, ast.Name) else value.value
                for value in terminal_publish.value.elts
            ],
            ["error", True],
        )

        for scenario in (
            "alias_seeded_first",
            "alias_seeded_last",
            "invalid_descriptor_text",
            "invalid_closeable",
        ):
            for seeded_error, close_started, close_finished in (
                (False, False, False),
                (True, False, False),
                (False, False, True),
                (False, True, False),
                (False, True, True),
                (True, True, False),
                (True, True, True),
            ):
                if scenario.startswith("alias"):
                    registration = MODULE.ResourceRegistration("descriptor", 41)
                    unique = MODULE.ResourceRegistration("descriptor", 41)
                    registration.published = unique.published = True
                    resources = (
                        [registration, unique]
                        if scenario == "alias_seeded_first"
                        else [unique, registration]
                    )
                    error_pattern = "roster aliases"
                elif scenario.startswith("invalid_descriptor"):
                    registration = MODULE.ResourceRegistration(
                        "descriptor",
                        "invalid",
                    )
                    registration.published = True
                    resources = [registration]
                    error_pattern = "descriptor is invalid"
                else:
                    registration = MODULE.ResourceRegistration("closeable", 7)
                    registration.published = True
                    resources = [registration]
                    error_pattern = "closeable is invalid"
                if seeded_error:
                    registration.close_error = MODULE.DrainError(
                        f"seeded {error_pattern}"
                    )
                registration.close_started = close_started
                registration.close_finished = close_finished
                custody = MODULE.ResourceCustody(
                    label=f"{scenario} prefix {seeded_error} "
                    f"{close_started} {close_finished}"
                )
                custody._resources = resources
                with self.subTest(
                    scenario=scenario,
                    seeded_error=seeded_error,
                    close_started=close_started,
                    close_finished=close_finished,
                ), mock.patch.object(MODULE.os, "close") as close:
                    with self.assertRaisesRegex(
                        MODULE.DrainError,
                        "cleanup failed",
                    ) as raised:
                        custody.close()
                if scenario.startswith("alias"):
                    authority_is_seeded = (
                        close_started or scenario == "alias_seeded_last"
                    )
                    seeded_is_terminal = (
                        seeded_error or close_started or close_finished
                    )
                    expected_calls = (
                        []
                        if authority_is_seeded and seeded_is_terminal
                        else [mock.call(41)]
                    )
                else:
                    expected_calls = []
                self.assertEqual(close.call_args_list, expected_calls)
                self.assertIs(raised.exception.__cause__, custody._cleanup_error)
                self.assertIn(error_pattern, str(custody._cleanup_error))
                registration_was_invoked = (
                    scenario == "alias_seeded_last" and not seeded_is_terminal
                    if scenario.startswith("alias")
                    else False
                )
                self.assertEqual(
                    registration.close_started,
                    close_started or registration_was_invoked,
                )
                self.assertTrue(
                    all(owned.close_finished for owned in resources)
                )
                if not scenario.startswith("alias"):
                    self.assertIs(registration.close_error, custody._cleanup_error)
                self.assertEqual(custody._resources, [])
                self.assertEqual(custody._state, "closed")

    def test_cleanup_retires_identity_and_resource_aliases_at_most_once(self) -> None:
        same_token = MODULE.ResourceRegistration("descriptor", 40)
        same_token.published = True
        custody = MODULE.ResourceCustody(label="same token aliases")
        custody._resources = [same_token, same_token]
        with mock.patch.object(MODULE.os, "close") as close:
            custody.close()
        close.assert_called_once_with(40)

        first = MODULE.ResourceRegistration("descriptor", 41)
        second = MODULE.ResourceRegistration("descriptor", 41)
        first.published = second.published = True
        custody = MODULE.ResourceCustody(label="same descriptor aliases")
        custody._resources = [first, second]
        with mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "cleanup failed",
        ):
            custody.close()
        close.assert_called_once_with(41)
        self.assertEqual(custody._resources, [])

        first = MODULE.ResourceRegistration("descriptor", 42)
        started = MODULE.ResourceRegistration("descriptor", 42)
        third = MODULE.ResourceRegistration("descriptor", 42)
        first.published = started.published = third.published = True
        started.close_started = True
        started.close_finished = True
        custody = MODULE.ResourceCustody(label="started descriptor alias group")
        custody._resources = [first, started, third]
        with mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "cleanup failed",
        ):
            custody.close()
        close.assert_not_called()
        self.assertTrue(all(item.close_finished for item in (first, started, third)))
        self.assertFalse(first.close_started)
        self.assertTrue(started.close_started)
        self.assertFalse(third.close_started)
        self.assertEqual(custody._resources, [])

    def test_closeable_reentrancy_cannot_register_or_recurse_cleanup(self) -> None:
        custody = MODULE.ResourceCustody(label="reentrant closeable")

        class ReentrantCloseable:
            calls = 0

            def close(self) -> None:
                self.calls += 1
                custody.close()

        reentrant = ReentrantCloseable()
        with mock.patch.object(MODULE._socket, "socket", return_value=reentrant):
            self.assertIs(custody.socket(), reentrant)
        custody.close()
        self.assertEqual(reentrant.calls, 1)
        self.assertEqual(custody._state, "closed")

        custody = MODULE.ResourceCustody(label="self-registering closeable")
        intruder = mock.Mock()

        class SelfRegisteringCloseable:
            calls = 0

            def close(self) -> None:
                self.calls += 1
                custody.socket()

        self_registering = SelfRegisteringCloseable()
        with mock.patch.object(
            MODULE._socket,
            "socket",
            side_effect=(self_registering, intruder),
        ):
            custody.socket()
            with self.assertRaisesRegex(MODULE.DrainError, "cleanup failed"):
                custody.close()
        self.assertEqual(self_registering.calls, 1)
        intruder.close.assert_called_once_with()
        self.assertEqual(custody._state, "closed")

    def test_closed_custody_rejects_new_acquisition_and_cleans_raw_result(self) -> None:
        custody = MODULE.ResourceCustody(label="closed custody")
        custody.close()
        with mock.patch.object(MODULE.os, "open", return_value=40), mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(MODULE.DrainError, "while custody is closed"):
            custody.open("descriptor", os.O_RDONLY)
        close.assert_called_once_with(40)
        custody.close()
        close.assert_called_once_with(40)

    def test_hostile_add_note_override_cannot_mask_primary_error(self) -> None:
        class HostilePrimary(RuntimeError):
            def add_note(self, _note: str) -> None:
                raise MemoryError("hostile add_note override")

        primary = HostilePrimary("body remains primary")
        custody = MODULE.ResourceCustody(label="primary preservation")
        acquire_test_descriptor(custody, 40)
        with mock.patch.object(
            MODULE.os,
            "close",
            side_effect=OSError("cleanup failed"),
        ):
            custody.__exit__(HostilePrimary, primary, None)
        self.assertEqual(str(primary), "body remains primary")
        self.assertIn("cleanup also failed", "\n".join(primary.__notes__))

    def test_custody_api_has_no_raw_adoption_release_or_transfer_escape(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
        custody_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ResourceCustody"
        )
        public_methods = {
            node.name
            for node in custody_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and not node.name.startswith("_")
        }
        self.assertEqual(
            public_methods,
            {
                "open",
                "pidfd_open",
                "dup",
                "socket",
                "close_descriptor",
                "close_descriptors",
                "close",
            },
        )
        forbidden_attributes = {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr.startswith(("own_", "release_", "transfer_"))
        }
        self.assertEqual(forbidden_attributes, set())
        self.assertNotIn(
            "RuntimeLease",
            {
                node.name
                for node in tree.body
                if isinstance(node, ast.ClassDef)
            },
        )

    def test_borrowed_views_have_no_cleanup_or_context_authority(self) -> None:
        for borrowed in (
            MODULE.CapturedTask,
            MODULE.ProcessReferenceObservation,
            MODULE.TaskNamespaceCensus,
            MODULE.ControlAuthority,
            MODULE.RecordedPersistentRoots,
            MODULE.RuntimeEntryProof,
        ):
            with self.subTest(borrowed=borrowed.__name__):
                self.assertFalse(hasattr(borrowed, "close"))
                self.assertFalse(hasattr(borrowed, "__enter__"))
                self.assertFalse(hasattr(borrowed, "__exit__"))

    def test_every_descriptor_producing_helper_takes_caller_custody_first(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        expected = {
            "capture_task",
            "open_current_task_namespace",
            "stable_task_namespace_census",
            "process_reference_scan",
            "runtime_root_descriptors",
            "_recorded_directory_pair",
            "recorded_evidence_descriptors",
            "recorded_config_descriptors",
            "recorded_persistent_root_descriptors",
            "_verify_runtime_entry_no_follow",
            "_open_bound_runtime_directory",
            "_read_regular_at",
            "_create_root_tmpfile",
            "open_or_publish_prepared_archive",
            "publish_control_capsule",
            "acquire_runtime_lease",
            "open_run_parent",
            "open_control_root",
        }
        self.assertTrue(expected <= functions.keys())
        for name in sorted(expected):
            arguments = functions[name].args.args
            with self.subTest(helper=name):
                self.assertGreaterEqual(len(arguments), 1)
                self.assertTrue(arguments[0].arg.endswith("custody"))

        control_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "ControlAuthority"
        )
        methods = {
            node.name: node
            for node in control_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for name in ("create", "open"):
            arguments = methods[name].args.args
            with self.subTest(helper=f"ControlAuthority.{name}"):
                self.assertGreaterEqual(len(arguments), 2)
                self.assertEqual(arguments[0].arg, "cls")
                self.assertEqual(arguments[1].arg, "custody")

    def test_exact_process_status_uses_the_real_exact_vocabulary(self) -> None:
        recorded = captured_process().authority
        with mock.patch.object(MODULE, "process_exists", return_value=True), mock.patch.object(
            MODULE, "capture_process", return_value=captured_process()
        ):
            self.assertEqual(MODULE.exact_process_status(recorded), "exact")

    def test_socket_owner_permission_denial_is_not_treated_as_absence(self) -> None:
        task = mock.Mock(process_fd=10, pidfd=11)

        def capture(custody: MODULE.ResourceCustody, *_args: object) -> object:
            acquire_test_descriptors(custody, task.pidfd, task.process_fd)
            return task

        with mock.patch.object(
            MODULE, "process_task_coordinates_once", return_value=((1, 3),)
        ), mock.patch.object(
            MODULE, "capture_task", side_effect=capture
        ), mock.patch.object(
            MODULE.os, "open", return_value=12
        ), mock.patch.object(
            MODULE.os, "listdir", return_value=("4",)
        ), mock.patch.object(
            MODULE.os, "stat", return_value=mock.Mock()
        ), mock.patch.object(
            MODULE.os, "readlink", side_effect=PermissionError("denied")
        ), mock.patch.object(
            MODULE.os, "close"
        ), self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "unreadable"):
            MODULE.socket_inode_owners({99})

    def test_nonleader_unshared_socket_fd_is_owned_by_its_thread_group(self) -> None:
        task = mock.Mock(process_fd=10, pidfd=11)
        edge = mock.Mock(st_dev=1, st_ino=2, st_mode=stat.S_IFSOCK | 0o600)

        def capture(custody: MODULE.ResourceCustody, *_args: object) -> object:
            acquire_test_descriptors(custody, task.pidfd, task.process_fd)
            return task

        with mock.patch.object(
            MODULE, "process_task_coordinates_once", return_value=((100, 101),)
        ), mock.patch.object(
            MODULE, "capture_task", side_effect=capture
        ), mock.patch.object(
            MODULE.os, "open", return_value=12
        ), mock.patch.object(
            MODULE.os, "listdir", return_value=("4",)
        ), mock.patch.object(
            MODULE.os, "stat", side_effect=(edge, edge)
        ), mock.patch.object(
            MODULE.os, "readlink", return_value="socket:[99]"
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(MODULE.os, "close"):
            self.assertEqual(MODULE.socket_inode_owners({99})[99], (100,))

    def test_global_lease_classifies_flock_not_path_presence(self) -> None:
        parent = mock.Mock(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        leaf = mock.Mock(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_dev=1,
            st_ino=2,
        )
        with mock.patch.object(MODULE.os, "open", side_effect=(10, 11)), mock.patch.object(
            MODULE.os, "fstat", side_effect=(parent, leaf)
        ), mock.patch.object(MODULE.os, "stat", return_value=leaf), mock.patch.object(
            MODULE.fcntl, "flock"
        ) as flock, mock.patch.object(MODULE.os, "close"):
            self.assertFalse(MODULE.global_runtime_lease_busy())
        self.assertEqual(flock.call_count, 2)

        with mock.patch.object(MODULE.os, "open", side_effect=(10, 11)), mock.patch.object(
            MODULE.os, "fstat", side_effect=(parent, leaf)
        ), mock.patch.object(MODULE.os, "stat", return_value=leaf), mock.patch.object(
            MODULE.fcntl,
            "flock",
            side_effect=BlockingIOError(),
        ), mock.patch.object(MODULE.os, "close"):
            self.assertTrue(MODULE.global_runtime_lease_busy())


class RuntimeSymlinkAuthorityTest(unittest.TestCase):
    @staticmethod
    def symlink_identity(**changes: object) -> object:
        values: dict[str, object] = {
            "st_mode": stat.S_IFLNK | 0o777,
            "st_uid": 0,
            "st_gid": 0,
            "st_nlink": 1,
            "st_size": len(os.fsencode(MODULE.EXPECTED_CONTAINERD_WORK_TARGET)),
            "st_dev": 44,
            "st_ino": 12496406,
        }
        values.update(changes)
        return mock.Mock(**values)

    def test_exact_containerd_work_symlink_is_the_only_admitted_symlink(self) -> None:
        observed = self.symlink_identity()
        MODULE._require_runtime_entry_contract(
            MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE,
            observed,
            MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
        )
        self.assertEqual(
            hashlib.sha256(os.fsencode(MODULE.EXPECTED_CONTAINERD_WORK_TARGET)).hexdigest(),
            MODULE.EXPECTED_CONTAINERD_WORK_TARGET_SHA256,
        )
        with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "coordinate is foreign"):
            MODULE._require_runtime_entry_contract(
                MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE + "-foreign",
                observed,
                MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
            )

    def test_wrong_relative_parent_and_prefix_sibling_targets_reject(self) -> None:
        observed = self.symlink_identity()
        for target in (
            "outer-containerd/io.containerd.runtime.v2.task/ambit-c16b/" + MODULE.EXPECTED_CONTAINER_ID,
            MODULE.EXPECTED_CONTAINERD_WORK_TARGET + "-foreign",
            str(MODULE.EXPECTED_STATE_ROOT / "outer-containerd-foreign" / MODULE.EXPECTED_CONTAINER_ID),
            str(MODULE.EXPECTED_STATE_ROOT / "outer-containerd/../outer-docker" / MODULE.EXPECTED_CONTAINER_ID),
        ):
            with self.subTest(target=target), self.assertRaisesRegex(
                MODULE.DrainError,
                "work symlink authority differs",
            ):
                MODULE._require_runtime_entry_contract(
                    MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE,
                    observed,
                    target,
                )

    def test_symlink_metadata_and_exact_coordinate_type_are_closed(self) -> None:
        for changes in (
            {"st_uid": 1000},
            {"st_gid": 1000},
            {"st_mode": stat.S_IFLNK | 0o700},
            {"st_nlink": 2},
            {"st_size": 1},
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                MODULE.DrainError,
                "work symlink authority differs",
            ):
                MODULE._require_runtime_entry_contract(
                    MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE,
                    self.symlink_identity(**changes),
                    MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
                )
        with self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "not its exact symlink"):
            MODULE._require_runtime_entry_contract(
                MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE,
                self.symlink_identity(st_mode=stat.S_IFREG | 0o600),
                None,
            )

    def test_link_text_swap_during_no_follow_capture_rejects(self) -> None:
        observed = self.symlink_identity()
        with mock.patch.object(
            MODULE.os, "stat", side_effect=(observed, observed)
        ), mock.patch.object(
            MODULE.os, "open", return_value=31
        ) as opened, mock.patch.object(
            MODULE.os, "fstat", return_value=observed
        ), mock.patch.object(
            MODULE.os,
            "readlink",
            side_effect=(
                MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
                MODULE.EXPECTED_CONTAINERD_WORK_TARGET + "-swapped",
            ),
        ), mock.patch.object(MODULE.os, "close") as closed, self.assertRaisesRegex(
            MODULE.DrainError,
            "link authority changed",
        ):
            with MODULE.ResourceCustody(label="runtime entry test") as custody:
                MODULE._verify_runtime_entry_no_follow(
                    custody,
                    20,
                    "work",
                    MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE,
                    expected=None,
                    marker_identity=None,
                    forbid_docker_socket=False,
                    label="test work",
                )
        opened.assert_called_once_with(
            "work",
            os.O_PATH | os.O_NOFOLLOW,
            dir_fd=20,
        )
        closed.assert_called_once_with(31)

    def test_reducer_reproves_and_unlinks_only_the_symlink_entry(self) -> None:
        events: list[str] = []
        proof = mock.Mock(
            descriptor=31,
            observed=self.symlink_identity(),
            link_target=MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
        )

        def verify(custody: MODULE.ResourceCustody, *_args: object, **_kwargs: object) -> object:
            acquire_test_descriptor(custody, proof.descriptor)
            return proof

        with mock.patch.object(
            MODULE.os, "listdir", return_value=("work",)
        ), mock.patch.object(
            MODULE, "_verify_runtime_entry_no_follow", side_effect=verify
        ), mock.patch.object(
            MODULE,
            "_reprove_runtime_entry_name",
            side_effect=lambda *_args, **_kwargs: events.append("reprove"),
        ), mock.patch.object(
            MODULE.os,
            "unlink",
            side_effect=lambda *_args, **_kwargs: events.append("unlink"),
        ) as unlink, mock.patch.object(
            MODULE.os, "rmdir"
        ) as rmdir, mock.patch.object(
            MODULE.os, "open"
        ) as opened, mock.patch.object(MODULE.os, "fsync"), mock.patch.object(
            MODULE.os,
            "close",
        ) as close:
            MODULE._reduce_runtime_directory(
                20,
                {MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE: {}},
                prefix=str(Path(MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE).parent),
                marker_identity={},
            )
        self.assertEqual(events, ["reprove", "unlink"])
        unlink.assert_called_once_with("work", dir_fd=20)
        rmdir.assert_not_called()
        opened.assert_not_called()
        close.assert_called_once_with(31)

    def test_name_swap_blocks_before_unlink_and_absence_is_replay(self) -> None:
        proof = mock.Mock(
            descriptor=31,
            observed=self.symlink_identity(),
            link_target=MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
        )

        def verify(custody: MODULE.ResourceCustody, *_args: object, **_kwargs: object) -> object:
            acquire_test_descriptor(custody, proof.descriptor)
            return proof

        with mock.patch.object(
            MODULE.os, "listdir", return_value=("work",)
        ), mock.patch.object(
            MODULE, "_verify_runtime_entry_no_follow", side_effect=verify
        ), mock.patch.object(
            MODULE,
            "_reprove_runtime_entry_name",
            side_effect=MODULE.DrainError("name binding differs"),
        ), mock.patch.object(MODULE.os, "unlink") as unlink, mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "name binding differs",
        ):
            MODULE._reduce_runtime_directory(
                20,
                {MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE: {}},
                prefix=str(Path(MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE).parent),
                marker_identity={},
            )
        unlink.assert_not_called()
        close.assert_called_once_with(31)

        with mock.patch.object(
            MODULE.os, "listdir", return_value=()
        ), mock.patch.object(MODULE.os, "unlink") as absent_unlink:
            MODULE._reduce_runtime_directory(
                20,
                {MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE: {}},
                prefix=str(Path(MODULE.EXPECTED_CONTAINERD_WORK_RELATIVE).parent),
                marker_identity={},
            )
        absent_unlink.assert_not_called()

    def test_capture_preflight_and_reducer_share_one_no_follow_verifier(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        capture = source[
            source.index("def runtime_tree_snapshot")
            : source.index("def registry_inventory")
        ]
        preflight = source[
            source.index("def _scan_runtime_directory")
            : source.index("def runtime_reduction_preflight")
        ]
        reducer = source[
            source.index("def _reduce_runtime_directory")
            : source.index("def reduce_runtime_tree")
        ]
        for region in (capture, preflight, reducer):
            self.assertIn("_verify_runtime_entry_no_follow", region)
        self.assertNotIn("require_recorded_entry", preflight)
        self.assertNotIn("require_recorded_entry", reducer)
        verifier = source[
            source.index("def _verify_runtime_entry_no_follow")
            : source.index("def transfer_runtime_custody")
        ]
        self.assertIn("os.O_PATH | os.O_NOFOLLOW", verifier)
        self.assertIn("os.readlink(name, dir_fd=directory_fd)", verifier)
        self.assertNotIn("os.stat(EXPECTED_CONTAINERD_WORK_TARGET", verifier)
        self.assertNotIn("os.open(EXPECTED_CONTAINERD_WORK_TARGET", verifier)
        self.assertIn('os.unlink(name, dir_fd=directory_fd)', reducer)
        self.assertNotIn("proof.link_target", reducer)


class MountAuthorityTest(unittest.TestCase):
    @staticmethod
    def canonical_and_restricted_views() -> tuple[
        MODULE.NamespaceIdentity,
        MODULE.MountNamespaceView,
        MODULE.MountNamespaceView,
    ]:
        records = (
            MODULE.MountRecord(1, 0, "8:1", "/", "/", "ext4"),
            MODULE.MountRecord(2, 1, "0:23", "/", "/proc", "proc"),
            MODULE.MountRecord(
                3,
                1,
                "0:4",
                "net:[4026531833]",
                str(MODULE.TASK_NETNS_TARGET),
                "nsfs",
            ),
        )
        full = MODULE.MountNamespaceView(
            "/",
            (8, 10, stat.S_IFDIR, 0, 0),
            True,
            records,
        )
        restricted = MODULE.MountNamespaceView(
            "/proc/67958/fdinfo",
            (23, 20, stat.S_IFDIR, 0, 0),
            False,
            (
                MODULE.MountRecord(
                    2,
                    1,
                    "0:23",
                    "/67958/fdinfo",
                    "/",
                    "proc",
                ),
            ),
        )
        return MODULE.NamespaceIdentity("mnt", 4, 100), full, restricted

    def test_nonleader_unshared_mount_namespace_is_in_the_global_roster(self) -> None:
        records = (
            MODULE.MountRecord(1, 0, "0:1", "/", "/", "tmpfs"),
            MODULE.MountRecord(
                10,
                1,
                "0:1",
                "/",
                str(MODULE.EXPECTED_RUNTIME_ROOT),
                "tmpfs",
            ),
        )
        identity = MODULE.NamespaceIdentity("mnt", 1, 2)
        view = MODULE.MountNamespaceView(
            "/",
            (1, 10, stat.S_IFDIR, 0, 0),
            True,
            records,
        )
        authority = MODULE.MountNamespaceAuthority(
            identity,
            view.root_identity,
            records,
            (view,),
        )
        census = namespace_census(current=(identity,), mounts=(authority,))
        with mock.patch.object(
            MODULE.os,
            "stat",
            return_value=mock.Mock(st_dev=1, st_ino=2),
        ):
            anchors, namespaces = MODULE.global_mount_roster_once(
                MODULE.EXPECTED_RUNTIME_ROOT,
                anchors=(("0:1", "/"),),
                namespace_census=census,
            )
        self.assertEqual(anchors, (("0:1", "/"),))
        self.assertEqual(namespaces[0][0], "1:2")
        self.assertIn(
            str(MODULE.EXPECTED_RUNTIME_ROOT),
            {record.target for record in namespaces[0][1]},
        )

    def test_full_root_and_restricted_subset_form_one_canonical_authority(self) -> None:
        identity, full, restricted = self.canonical_and_restricted_views()
        authority = MODULE.build_mount_namespace_authority(
            identity,
            (restricted, full),
        )
        self.assertEqual(authority.records, full.records)
        self.assertEqual(len(authority.views), 2)
        self.assertEqual(
            [record.mount_id for record in authority.records],
            [1, 2, 3],
        )

    def test_restricted_subset_cannot_erase_canonical_presence(self) -> None:
        identity, full, restricted = self.canonical_and_restricted_views()
        authority = MODULE.build_mount_namespace_authority(
            identity,
            (full, restricted),
        )
        census = namespace_census(current=(identity,), mounts=(authority,))
        with mock.patch.object(
            MODULE.os,
            "stat",
            return_value=mock.Mock(st_dev=4, st_ino=100),
        ):
            _anchors, namespaces = MODULE.global_mount_roster_once(
                MODULE.TASK_NETNS_TARGET,
                anchors=(("0:4", "net:[4026531833]"),),
                namespace_census=census,
            )
        self.assertEqual(
            [record.mount_id for record in namespaces[0][1]],
            [3],
        )
        self.assertEqual(restricted.records[0].mount_id, 2)

    def test_restricted_projection_with_an_unexplained_record_rejects(self) -> None:
        identity, full, restricted = self.canonical_and_restricted_views()
        foreign = MODULE.MountNamespaceView(
            restricted.root_link,
            restricted.root_identity,
            False,
            (
                *restricted.records,
                MODULE.MountRecord(99, 2, "0:99", "/", "/foreign", "tmpfs"),
            ),
        )
        with self.assertRaisesRegex(MODULE.DrainError, "not a projection"):
            MODULE.build_mount_namespace_authority(identity, (full, foreign))

    def test_restricted_view_preserves_an_opaque_nsfs_source(self) -> None:
        target = str(MODULE.TASK_NETNS_TARGET)
        canonical = (
            MODULE.MountRecord(
                7,
                1,
                "0:4",
                "net:[4026531833]",
                target,
                "nsfs",
            ),
        )
        projected = MODULE.MountNamespaceView(
            str(MODULE.TASK_NETNS_TARGET.parent),
            (44, 99, stat.S_IFDIR, 0, 0),
            False,
            (
                MODULE.MountRecord(
                    7,
                    1,
                    "0:4",
                    "net:[4026531833]",
                    "/default",
                    "nsfs",
                ),
            ),
        )
        MODULE.require_mount_view_projection(canonical, projected)

    def test_mount_namespace_without_full_root_representative_rejects(self) -> None:
        identity, _full, restricted = self.canonical_and_restricted_views()
        with self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "no proven full-root representative",
        ):
            MODULE.build_mount_namespace_authority(identity, (restricted,))

    def test_chroot_at_a_nested_filesystem_root_is_not_full_root_authority(self) -> None:
        identity, full, _restricted = self.canonical_and_restricted_views()
        root_record = full.records[0]
        self.assertTrue(MODULE.is_proven_full_root_view("/", root_record))
        self.assertFalse(
            MODULE.is_proven_full_root_view("/mnt/nested-root", root_record)
        )
        nested = MODULE.MountNamespaceView(
            "/mnt/nested-root",
            full.root_identity,
            MODULE.is_proven_full_root_view("/mnt/nested-root", root_record),
            full.records,
        )
        with self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "no proven full-root representative",
        ):
            MODULE.build_mount_namespace_authority(identity, (nested,))

    def test_divergent_full_root_representatives_reject(self) -> None:
        identity, full, _restricted = self.canonical_and_restricted_views()
        changed = MODULE.MountNamespaceView(
            full.root_link,
            full.root_identity,
            True,
            full.records[:-1],
        )
        with self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "full-root mount namespace representatives diverge",
        ):
            MODULE.build_mount_namespace_authority(identity, (full, changed))

    def test_full_root_canonical_roster_rejects_duplicate_mount_ids(self) -> None:
        identity, full, _restricted = self.canonical_and_restricted_views()
        duplicate = MODULE.MountNamespaceView(
            full.root_link,
            full.root_identity,
            True,
            (
                full.records[0],
                MODULE.MountRecord(1, 0, "8:1", "/", "/duplicate", "ext4"),
            ),
        )
        with self.assertRaisesRegex(
            MODULE.DrainError,
            "canonical mount roster reuses a mount ID",
        ):
            MODULE.build_mount_namespace_authority(identity, (duplicate,))

    def test_mounted_nsfs_requires_a_live_current_namespace_representative(self) -> None:
        identity, full, restricted = self.canonical_and_restricted_views()
        authority = MODULE.build_mount_namespace_authority(
            identity,
            (full, restricted),
        )
        net = MODULE.NamespaceIdentity("net", 4, 4026531833)
        self.assertEqual(
            MODULE.require_mounted_namespace_representatives(
                (authority,),
                {net},
            ),
            {net},
        )
        with self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "no live representative",
        ):
            MODULE.require_mounted_namespace_representatives(
                (authority,),
                set(),
            )
        wrong_device = MODULE.NamespaceIdentity("net", 5, 4026531833)
        with self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "no live representative",
        ):
            MODULE.require_mounted_namespace_representatives(
                (authority,),
                {wrong_device},
            )

    def test_root_descriptor_mount_id_must_match_the_root_mount_record(self) -> None:
        observed = mock.Mock(
            st_dev=os.makedev(8, 1),
            st_mode=stat.S_IFDIR | 0o755,
        )
        record = MODULE.MountRecord(7, 1, "8:1", "/", "/", "ext4")
        MODULE.require_root_mount_binding(
            observed,
            7,
            record,
            label="test",
        )
        with self.assertRaisesRegex(MODULE.DrainError, "root mount identity differs"):
            MODULE.require_root_mount_binding(
                observed,
                8,
                record,
                label="test",
            )

    def test_action_roster_persists_propagation_options_and_source(self) -> None:
        identity = MODULE.NamespaceIdentity("mnt", 4, 100)

        def roster(optional: tuple[str, ...]) -> dict[str, object]:
            record = MODULE.MountRecord(
                7,
                1,
                "0:4",
                "net:[4026531833]",
                str(MODULE.TASK_NETNS_TARGET),
                "nsfs",
                ("rw",),
                optional,
                "nsfs",
                ("rw",),
            )
            view = MODULE.MountNamespaceView(
                "/",
                (8, 10, stat.S_IFDIR, 0, 0),
                True,
                (record,),
            )
            authority = MODULE.MountNamespaceAuthority(
                identity,
                view.root_identity,
                (record,),
                (view,),
            )
            census = namespace_census(current=(identity,), mounts=(authority,))
            with mock.patch.object(
                MODULE.os,
                "stat",
                return_value=mock.Mock(st_dev=4, st_ino=100),
            ):
                return MODULE.stable_global_mount_roster(
                    MODULE.TASK_NETNS_TARGET,
                    (("0:4", "net:[4026531833]"),),
                    namespace_census=census,
                )

        recorded = roster(("shared:10", "master:9"))
        changed = roster(("private",))
        self.assertNotEqual(recorded["occurrences"], changed["occurrences"])
        occurrence = recorded["occurrences"][0]
        self.assertEqual(occurrence["optionalFields"], ["shared:10", "master:9"])
        self.assertEqual(occurrence["mountOptions"], ["rw"])
        self.assertEqual(occurrence["source"], "nsfs")
        self.assertEqual(occurrence["superOptions"], ["rw"])

    def test_namespace_census_emits_the_exact_digest_preimage_outside_control(self) -> None:
        identity, full, _restricted = self.canonical_and_restricted_views()
        net = MODULE.NamespaceIdentity("net", 4, 4026531833)
        identities = {
            kind: MODULE.NamespaceIdentity(kind, 4, 500 + index)
            for index, kind in enumerate(MODULE.NAMESPACE_KINDS)
        }
        identities.update({"mnt": identity, "net": net})
        bindings = task_namespace_bindings_for_kinds(
            identities,
            ((100, 100), (200, 200)),
        )
        census = MODULE._task_namespace_census_from_observations(
            set(identities.values()),
            set(),
            {identity: [full]},
            2,
            (),
            bindings,
        )
        self.assertEqual(
            hashlib.sha256(MODULE.canonical_json(census.preimage)).hexdigest(),
            census.proof_sha256,
        )
        self.assertNotIn("mountNamespaces", census.proof)

    def test_borrowed_census_rejects_same_count_mount_and_fd_replacements(self) -> None:
        identity, full, _restricted = self.canonical_and_restricted_views()
        net = MODULE.NamespaceIdentity("net", 4, 4026531833)
        identities = {
            kind: MODULE.NamespaceIdentity(kind, 4, 500 + index)
            for index, kind in enumerate(MODULE.NAMESPACE_KINDS)
        }
        identities.update({"mnt": identity, "net": net})
        bindings = task_namespace_bindings_for_kinds(
            identities,
            ((100, 100), (200, 200)),
        )

        def fresh() -> MODULE.TaskNamespaceCensus:
            return MODULE._task_namespace_census_from_observations(
                set(identities.values()),
                {net},
                {identity: [full]},
                2,
                (),
                bindings,
            )

        changed_fd = fresh()
        changed_fd.namespace_fds = frozenset(
            (MODULE.NamespaceIdentity("net", 4, 4026531834),)
        )
        with self.assertRaisesRegex(MODULE.DrainError, "digest or summary differs"):
            changed_fd.require_open()

        changed_mount = fresh()
        original = changed_mount.mounts[0]
        replacement_record = MODULE.MountRecord(
            99,
            1,
            "0:99",
            "/",
            "/replacement",
            "tmpfs",
        )
        changed_mount.mounts = (
            MODULE.MountNamespaceAuthority(
                original.identity,
                original.root_identity,
                (replacement_record,),
                original.views,
            ),
        )
        with self.assertRaisesRegex(MODULE.DrainError, "digest or summary differs"):
            changed_mount.require_open()

    def test_mount_records_preserve_ids_and_stacked_multiplicity(self) -> None:
        raw = (
            "21 20 0:4 net:[4026531833] /x rw shared:7 - nsfs nsfs rw\n"
            "22 21 0:4 net:[4026531833] /x rw - nsfs nsfs rw\n"
        )
        records = MODULE.mount_records(raw)
        self.assertEqual([(row.mount_id, row.parent_id) for row in records], [(21, 20), (22, 21)])
        self.assertEqual(records[0].mount_options, ("rw",))
        self.assertEqual(records[0].optional_fields, ("shared:7",))
        self.assertEqual(records[0].source, "nsfs")
        self.assertEqual(records[0].super_options, ("rw",))
        references = MODULE.mount_reference_records_from_records(
            records,
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
        self.assertIn('ResourceCustody(label="legacy task netns transition")', body)
        self.assertNotIn("subprocess.run", body)
        self.assertNotIn("/usr/bin/umount", body)

    def test_foreign_stack_at_ambient_target_is_selected(self) -> None:
        raw = (
            "21 20 0:4 net:[1] /owned rw - nsfs nsfs rw\n"
            "22 20 0:4 net:[1] /ambient rw - nsfs nsfs rw\n"
            "23 20 8:1 /foreign /ambient rw - ext4 /dev/root rw\n"
        )
        records = MODULE.mount_reference_records_from_records(
            MODULE.mount_records(raw),
            Path("/owned"),
            (("0:4", "net:[1]"),),
            ("/owned", "/ambient"),
        )
        self.assertEqual([row.mount_id for row in records], [21, 22, 23])

    def test_duplicate_same_source_ambient_occurrence_is_rejected(self) -> None:
        owned = str(MODULE.TASK_NETNS_TARGET)
        record = MODULE.MountRecord(
            21,
            20,
            "0:4",
            "net:[4026531833]",
            owned,
            "nsfs",
        )
        identity = MODULE.NamespaceIdentity("mnt", 1, 2)
        view = MODULE.MountNamespaceView(
            "/",
            (1, 10, stat.S_IFDIR, 0, 0),
            True,
            (record,),
        )
        authority = MODULE.MountNamespaceAuthority(
            identity,
            view.root_identity,
            (record,),
            (view,),
        )
        census = namespace_census(current=(identity,), mounts=(authority,))
        occurrences = [
            {
                "mountNamespace": "4:19",
                "mountId": mount_id,
                "parentId": 20,
                "device": "0:4",
                "root": "net:[4026531833]",
                "target": target,
                "filesystem": "nsfs",
            }
            for mount_id, target in (
                (21, owned),
                (22, "/run/docker/netns/default"),
                (23, "/run/docker/netns/default"),
            )
        ]
        with mock.patch.object(
            MODULE.os,
            "stat",
            return_value=mock.Mock(st_dev=1, st_ino=2),
        ), mock.patch.object(
            MODULE,
            "stable_global_mount_roster",
            return_value={"occurrences": occurrences},
        ), self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "foreign target"):
            MODULE._netns_baseline_from_census(census)

    def test_held_fd_exposes_a_kernel_mount_id(self) -> None:
        with tempfile.NamedTemporaryFile() as value:
            descriptor = os.open(value.name, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                self.assertGreater(MODULE.fd_mount_id(descriptor), 0)
            finally:
                os.close(descriptor)

    def test_unix_diag_parser_preserves_peer_and_pending_icons(self) -> None:
        sequence = 7
        port_id = 55
        attributes = (
            struct.pack("=HHI", 8, MODULE.UNIX_DIAG_PEER, 42)
            + struct.pack("=HHII", 12, MODULE.UNIX_DIAG_ICONS, 43, 44)
            + struct.pack("=HHI", 8, MODULE.UNIX_DIAG_UID, 1000)
        )
        payload = struct.pack("=BBBBIII", socket.AF_UNIX, 1, 1, 0, 41, 1, 2) + attributes
        message = struct.pack(
            "=IHHII",
            16 + len(payload),
            MODULE.SOCK_DIAG_BY_FAMILY,
            MODULE.NLM_F_MULTI,
            sequence,
            port_id,
        ) + payload
        done = struct.pack("=IHHII", 16, MODULE.NLMSG_DONE, 0, sequence, port_id)
        rows, complete = MODULE.parse_unix_diag_datagram(
            message + done,
            expected_sequence=sequence,
            expected_port_id=port_id,
        )
        self.assertTrue(complete)
        self.assertEqual(rows[0]["peer"], 42)
        self.assertEqual(rows[0]["icons"], [43, 44])
        self.assertEqual(rows[0]["uid"], 1000)

    def test_unix_diag_rejects_interrupted_or_non_kernel_dump(self) -> None:
        sequence = 7
        interrupted = struct.pack(
            "=IHHII", 16, MODULE.NLMSG_DONE, MODULE.NLM_F_DUMP_INTR, sequence, 0
        )
        with self.assertRaisesRegex(MODULE.DrainError, "interrupted"):
            MODULE.parse_unix_diag_datagram(
                interrupted, expected_sequence=sequence
            )
        foreign = struct.pack(
            "=IHHII", 16, MODULE.NLMSG_DONE, 0, sequence, 123
        )
        with self.assertRaisesRegex(MODULE.DrainError, "header port"):
            MODULE.parse_unix_diag_datagram(
                foreign, expected_sequence=sequence
            )

    def test_unix_diag_done_status_must_be_zero_and_complete(self) -> None:
        sequence = 7
        zero = struct.pack("=IHHIIi", 20, MODULE.NLMSG_DONE, 0, sequence, 0, 0)
        rows, complete = MODULE.parse_unix_diag_datagram(
            zero, expected_sequence=sequence
        )
        self.assertEqual(rows, [])
        self.assertTrue(complete)
        failed = struct.pack("=IHHIIi", 20, MODULE.NLMSG_DONE, 0, sequence, 0, -5)
        with self.assertRaisesRegex(MODULE.DrainError, "error"):
            MODULE.parse_unix_diag_datagram(
                failed, expected_sequence=sequence
            )
        truncated = struct.pack("=IHHII", 17, MODULE.NLMSG_DONE, 0, sequence, 0) + b"x\0\0\0"
        with self.assertRaisesRegex(MODULE.DrainError, "error"):
            MODULE.parse_unix_diag_datagram(
                truncated, expected_sequence=sequence
            )

    def test_unix_diag_rejects_truncated_kernel_datagram(self) -> None:
        fake = mock.Mock()
        fake.sendto.side_effect = lambda request, _address: len(request)
        fake.getsockname.return_value = (123, 0)
        sequence = 123
        done = struct.pack("=IHHII", 16, MODULE.NLMSG_DONE, 0, sequence, 123)
        fake.recvmsg.return_value = (done, [], socket.MSG_TRUNC, (0, 0))
        with mock.patch.object(MODULE._socket, "socket", return_value=fake), mock.patch.object(
            MODULE.os, "getpid", return_value=123
        ), mock.patch.object(MODULE.time, "monotonic_ns", return_value=0), self.assertRaisesRegex(
            MODULE.DrainError, "truncated"
        ):
            MODULE.unix_diag_records_once()


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
        stack.enter_context(mock.patch.object(MODULE, "exact_process_status", return_value="exact"))
        stack.enter_context(
            mock.patch.object(
                MODULE,
                "exact_live_roles",
                side_effect=lambda _control, roles: set(roles),
            )
        )
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

    def test_dockerd_signal_response_loss_advances_without_resignal(self) -> None:
        control = self.FakeControl("dockerd_stop_requested")
        with self.patches(control), mock.patch.object(
            MODULE, "exact_process_status", return_value="absent"
        ), mock.patch.object(
            MODULE, "exists_nofollow", return_value=False
        ):
            MODULE.run_reducer(control)
        self.assertNotIn("signal:dockerd", control.events)
        self.assertIn("phase:dockerd_stopped", control.events)

    def test_response_loss_accepts_fresh_exact_census_but_not_detached_authority(self) -> None:
        control = self.FakeControl("dockerd_stop_requested")
        control.control["authority"]["namespaceCensus"] = {
            "proofSha256": "a" * 64
        }
        current = {
            "namespaceCensusSha256": "b" * 64,
            "processBoundNamespaces": [],
            "namespaceFds": [],
            "related": [],
        }
        with self.patches(control), mock.patch.object(
            MODULE,
            "exact_process_status",
            return_value="absent",
        ), mock.patch.object(
            MODULE,
            "exists_nofollow",
            return_value=False,
        ), mock.patch.object(
            MODULE,
            "require_related_process_cutoff",
            return_value=current,
        ) as current_cutoff:
            MODULE.run_reducer(control)
        self.assertGreaterEqual(current_cutoff.call_count, 1)
        self.assertIn("phase:dockerd_stopped", control.events)

        blocked = self.FakeControl("dockerd_stop_requested")
        with self.patches(blocked), mock.patch.object(
            MODULE,
            "exact_process_status",
            return_value="absent",
        ), mock.patch.object(
            MODULE,
            "exists_nofollow",
            return_value=False,
        ), mock.patch.object(
            MODULE,
            "require_related_process_cutoff",
            side_effect=MODULE.ManualRecoveryRequired(
                "detached or processless namespace FD"
            ),
        ), self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "detached or processless",
        ):
            MODULE.run_reducer(blocked)
        self.assertNotIn("phase:dockerd_stopped", blocked.events)

    def test_containerd_signal_response_loss_advances_without_resignal(self) -> None:
        control = self.FakeControl("containerd_stop_requested")
        with self.patches(control), mock.patch.object(
            MODULE, "exact_process_status", return_value="absent"
        ):
            MODULE.run_reducer(control)
        self.assertNotIn("signal:containerd", control.events)
        self.assertIn("phase:containerd_stopped", control.events)

    def test_real_advance_rejects_regression_and_skip(self) -> None:
        authority = object.__new__(MODULE.ControlAuthority)
        authority.state = {"phase": "dockerd_stopped"}
        authority.control_digest = "c" * 64
        authority.descriptor = 31
        with self.assertRaisesRegex(MODULE.DrainError, "regress"):
            authority.advance("dockerd_stop_requested")
        with self.assertRaisesRegex(MODULE.DrainError, "skip"):
            authority.advance("containerd_stop_requested")

    def test_persisted_marker_state_is_exact_and_path_free(self) -> None:
        digest = "c" * 64
        base = {
            "schema": MODULE.STATE_SCHEMA,
            "observedAt": "2026-08-22T00:00:00+00:00",
            "bootId": "boot",
            "stateRoot": str(MODULE.EXPECTED_STATE_ROOT),
            "controlSha256": digest,
            "phase": "mounts_settled",
            "netnsMarkerIdentity": {
                "device": 44,
                "inode": 99,
                "uid": 0,
                "gid": 0,
                "mode": 0o600,
                "type": stat.S_IFREG,
                "links": 1,
                "size": 0,
            },
        }
        with mock.patch.object(MODULE, "current_boot_id", return_value="boot"):
            self.assertEqual(MODULE.validate_state(base, digest), base)
            foreign = json.loads(json.dumps(base))
            foreign["netnsMarkerIdentity"]["path"] = str(MODULE.TASK_NETNS_TARGET)
            with self.assertRaisesRegex(MODULE.DrainError, "field roster"):
                MODULE.validate_state(foreign, digest)

    def test_real_control_authority_walks_every_phase_adjacently(self) -> None:
        authority = object.__new__(MODULE.ControlAuthority)
        authority.state = {
            "schema": MODULE.STATE_SCHEMA,
            "observedAt": "2026-08-22T00:00:00+00:00",
            "bootId": "boot",
            "stateRoot": str(MODULE.EXPECTED_STATE_ROOT),
            "controlSha256": "c" * 64,
            "phase": MODULE.PHASES[0],
            "netnsMarkerIdentity": None,
        }
        authority.control_digest = "c" * 64
        authority.descriptor = 31
        marker = {
            "device": 44,
            "inode": 99,
            "uid": 0,
            "gid": 0,
            "mode": 0o600,
            "type": stat.S_IFREG,
            "links": 1,
            "size": 0,
        }
        with mock.patch.object(MODULE, "current_boot_id", return_value="boot"), mock.patch.object(
            MODULE, "utc_now", return_value="2026-08-22T00:00:00+00:00"
        ), mock.patch.object(MODULE, "atomic_write_at") as write:
            for phase in MODULE.PHASES[1:]:
                authority.advance(
                    phase,
                    netns_marker_identity=(marker if phase == "mounts_settled" else None),
                )
        self.assertEqual(authority.phase, "archive_intent_final")
        self.assertEqual(write.call_count, len(MODULE.PHASES) - 1)


class DestructiveBoundaryTest(unittest.TestCase):
    def test_v5_barrier_covers_root_pending_and_final_claim_names(self) -> None:
        names = (
            ".ambit-c16b-runner-storage",
            ".ambit-c16b-runner-storage.pending-claim",
            f".ambit-c16b-runner-storage.claim.{'a' * 64}",
            ".ambit-c16b-runner-storage.claim.malformed",
        )
        for name in names:
            with self.subTest(name=name), mock.patch.object(
                MODULE.os,
                "listdir",
                side_effect=((), (name,), (), (MODULE.EXPECTED_RUNTIME_ROOT.name,)),
            ), self.assertRaisesRegex(
                MODULE.ManualRecoveryRequired,
                "current v5 authority coexists",
            ):
                MODULE.require_v5_absent(allow_global_lease=True)

        with mock.patch.object(
            MODULE.os,
            "listdir",
            side_effect=(
                (),
                (".unrelated-runner-storage.claim",),
                (),
                (MODULE.EXPECTED_RUNTIME_ROOT.name,),
            ),
        ):
            self.assertEqual(
                MODULE.require_v5_absent(allow_global_lease=True)["v5Authorities"],
                [],
            )

    def test_persistent_root_reproof_rejects_same_content_name_swap(self) -> None:
        state = mock.Mock(
            st_mode=stat.S_IFDIR | 0o700,
            st_dev=1,
            st_ino=2,
            st_uid=1000,
            st_gid=1000,
            st_nlink=5,
        )
        expected_roots: dict[str, object] = {}
        roots: dict[str, int] = {}
        observed_roots: list[object] = []
        literal_roots: list[object] = []
        for index, path in enumerate(MODULE.PERSISTENT_ROOTS, start=1):
            expected_roots[str(path)] = {
                "device": 1,
                "inode": 10 + index,
                "uid": 1000,
                "gid": 1000,
                "mode": 0o700,
                "type": stat.S_IFDIR,
                "links": 2,
            }
            roots[str(path)] = 20 + index
            observed_roots.append(
                mock.Mock(
                    st_mode=stat.S_IFDIR | 0o700,
                    st_dev=1,
                    st_ino=10 + index,
                    st_uid=1000,
                    st_gid=1000,
                    st_nlink=2,
                )
            )
            literal_roots.append(mock.Mock(st_dev=1, st_ino=10 + index))
        literal_roots[-1] = mock.Mock(st_dev=1, st_ino=999)
        control = {
            "authority": {
                "stateRootIdentity": {
                    "device": 1,
                    "inode": 2,
                    "uid": 1000,
                    "gid": 1000,
                    "mode": 0o700,
                    "type": stat.S_IFDIR,
                    "links": 5,
                },
                "persistentRoots": expected_roots,
            }
        }
        with mock.patch.object(
            MODULE.os,
            "fstat",
            side_effect=(state, *observed_roots),
        ), mock.patch.object(
            MODULE.os,
            "stat",
            side_effect=(mock.Mock(st_dev=1, st_ino=2), *literal_roots),
        ), self.assertRaisesRegex(
            MODULE.DrainError,
            "name binding differs",
        ):
            MODULE.require_recorded_persistent_root_bindings(control, 20, roots)

    def test_archive_holds_and_reproofs_persistent_registry_on_action_error(self) -> None:
        control = ReducerStateMachineTest.FakeControl("archive_intent_final")
        roots = {str(MODULE.EXPECTED_STATE_ROOT / "registry"): 30}
        with mock.patch.object(
            MODULE,
            "hold_recorded_persistent_roots",
            return_value=contextlib.nullcontext(roots),
        ), mock.patch.object(
            MODULE,
            "registry_inventory_matches",
            side_effect=(None, MODULE.DrainError("registry changed after action")),
        ) as registry, mock.patch.object(
            MODULE,
            "_archive_receipt_with_persistent_roots",
            side_effect=RuntimeError("archive action failed"),
        ), self.assertRaisesRegex(
            RuntimeError,
            "archive action failed",
        ) as raised:
            MODULE.archive_receipt(control)
        self.assertEqual(registry.call_count, 2)
        self.assertIn("registry changed after action", "\n".join(raised.exception.__notes__))
        self.assertEqual(
            MODULE.bound_registry_storage(roots),
            Path("/proc/self/fd/30/docker/registry/v2"),
        )

    def test_root_pair_acquisition_failure_attempts_every_descriptor_close(self) -> None:
        runtime_control = {
            "authority": {
                "runtime": {
                    "rootIdentity": {"device": 1, "inode": 2, "uid": 1000, "gid": 1000}
                }
            }
        }
        with mock.patch.object(
            MODULE.os,
            "open",
            side_effect=(30, 31),
        ), mock.patch.object(
            MODULE.os,
            "fstat",
            side_effect=RuntimeError("root capture failed"),
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(OSError("root close failed"), None),
        ) as close, self.assertRaisesRegex(RuntimeError, "root capture failed"):
            with MODULE.ResourceCustody(label="runtime root caller") as custody:
                MODULE.runtime_root_descriptors(
                    custody,
                    runtime_control,
                    require_root_owned=None,
                )
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

    def test_runtime_root_helper_is_caller_owned_across_return_and_partial_interrupt(self) -> None:
        runtime_control = {
            "authority": {
                "runtime": {
                    "rootIdentity": {
                        "device": 1,
                        "inode": 2,
                        "uid": 1000,
                        "gid": 1000,
                    }
                }
            }
        }
        observed = mock.Mock(
            st_mode=stat.S_IFDIR | 0o700,
            st_dev=1,
            st_ino=2,
            st_uid=1000,
            st_gid=1000,
        )
        literal = mock.Mock(st_dev=1, st_ino=2)
        with mock.patch.object(MODULE.os, "open", side_effect=(30, 31)), mock.patch.object(
            MODULE.os,
            "fstat",
            return_value=observed,
        ), mock.patch.object(MODULE.os, "stat", return_value=literal), mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(KeyboardInterrupt, "caller interrupted"):
            with MODULE.ResourceCustody(label="runtime root caller") as custody:
                self.assertEqual(
                    MODULE.runtime_root_descriptors(
                        custody,
                        runtime_control,
                        require_root_owned=False,
                    ),
                    (30, 31),
                )
                raise KeyboardInterrupt("caller interrupted")
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

        with mock.patch.object(
            MODULE.os,
            "open",
            side_effect=(30, KeyboardInterrupt("root open interrupted")),
        ), mock.patch.object(MODULE.os, "close") as close, self.assertRaisesRegex(
            KeyboardInterrupt,
            "root open interrupted",
        ):
            with MODULE.ResourceCustody(label="partial runtime root") as custody:
                MODULE.runtime_root_descriptors(
                    custody,
                    runtime_control,
                    require_root_owned=False,
                )
        close.assert_called_once_with(30)

        state = mock.Mock(st_mode=stat.S_IFDIR, st_dev=1, st_ino=2)
        literal = mock.Mock(st_dev=1, st_ino=2)
        directory_control = {
            "authority": {
                "stateRootIdentity": {"device": 1, "inode": 2},
                "evidenceRootIdentity": {
                    "device": 1,
                    "inode": 3,
                    "uid": 1000,
                    "gid": 1000,
                    "mode": 0o700,
                },
            }
        }
        with mock.patch.object(
            MODULE.os,
            "open",
            side_effect=(30, 31),
        ), mock.patch.object(
            MODULE.os,
            "fstat",
            side_effect=(state, RuntimeError("child capture failed")),
        ), mock.patch.object(
            MODULE.os,
            "stat",
            return_value=literal,
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(OSError("child close failed"), None),
        ) as close, self.assertRaisesRegex(RuntimeError, "child capture failed"):
            with MODULE.ResourceCustody(label="recorded root caller") as custody:
                MODULE._recorded_directory_pair(
                    custody,
                    directory_control,
                    child_name="evidence",
                    authority_key="evidenceRootIdentity",
                )
        self.assertEqual(close.call_args_list, [mock.call(31), mock.call(30)])

    def test_source_has_one_explicit_descriptor_ownership_authority(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        offenders: list[tuple[int, list[int]]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try) or not node.finalbody:
                continue
            close_lines = [
                child.lineno
                for child in ast.walk(
                    ast.Module(body=node.finalbody, type_ignores=[])
                )
                if isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "close"
            ]
            if len(close_lines) > 1:
                offenders.append((node.lineno, close_lines))
        self.assertEqual(offenders, [])
        raw_acquisitions: list[tuple[int, str]] = []
        observed_raw_acquisitions: list[tuple[str, str]] = []
        parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            call: tuple[str, str] | None = None
            if isinstance(node.func.value, ast.Name):
                call = (node.func.value.id, node.func.attr)
                if (
                    call == ("functools", "partial")
                    and node.args
                    and isinstance(node.args[0], ast.Attribute)
                    and isinstance(node.args[0].value, ast.Name)
                ):
                    call = (node.args[0].value.id, node.args[0].attr)
            if call not in {
                ("os", "open"),
                ("os", "pidfd_open"),
                ("os", "dup"),
                ("_socket", "socket"),
            }:
                continue
            assert call is not None
            observed_raw_acquisitions.append(call)
            parent: ast.AST | None = node
            function: ast.FunctionDef | None = None
            class_name: str | None = None
            while parent is not None:
                if function is None and isinstance(parent, ast.FunctionDef):
                    function = parent
                if isinstance(parent, ast.ClassDef):
                    class_name = parent.name
                    break
                parent = parents.get(parent)
            if class_name != "ResourceCustody":
                raw_acquisitions.append(
                    (node.lineno, function.name if function is not None else "<module>")
                )
        self.assertEqual(raw_acquisitions, [])
        self.assertEqual(
            sorted(observed_raw_acquisitions),
            sorted(
                [
                    ("os", "open"),
                    ("os", "pidfd_open"),
                    ("os", "dup"),
                    ("_socket", "socket"),
                ]
            ),
        )
        self.assertNotIn("sys.exception()", source)
        self.assertNotIn("close_all_descriptors_preserving_active", source)
        self.assertNotIn("close_closeable_preserving_active", source)
        forbidden_path_traversal = [
            (node.lineno, node.attr)
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and node.attr in {"glob", "rglob", "read_text", "read_bytes"}
        ]
        self.assertEqual(forbidden_path_traversal, [])

    def test_local_custody_acquisition_never_precedes_its_settlement_scope(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        local_custodies: list[tuple[ast.FunctionDef, ast.Assign, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            if not isinstance(node.value.func, ast.Name) or node.value.func.id != "ResourceCustody":
                continue
            target = next(
                (
                    target.id
                    for target in node.targets
                    if isinstance(target, ast.Name)
                ),
                None,
            )
            if target is None:
                continue
            parent: ast.AST | None = node
            while parent is not None and not isinstance(parent, ast.FunctionDef):
                parent = parents.get(parent)
            self.assertIsInstance(parent, ast.FunctionDef)
            assert isinstance(parent, ast.FunctionDef)
            local_custodies.append((parent, node, target))

        self.assertEqual(
            [(function.name, target) for function, _assignment, target in local_custodies],
            [("capture_process", "custody")],
        )
        function, assignment, target = local_custodies[0]
        containing_body = function.body
        assignment_index = containing_body.index(assignment)
        self.assertIsInstance(containing_body[assignment_index + 1], ast.Try)
        settlement_scope = containing_body[assignment_index + 1]
        assert isinstance(settlement_scope, ast.Try)
        self.assertTrue(settlement_scope.body)
        self.assertIsInstance(settlement_scope.body[0], ast.With)
        lexical_owner = settlement_scope.body[0]
        assert isinstance(lexical_owner, ast.With)
        self.assertTrue(
            any(
                isinstance(node, ast.Name) and node.id == target
                for node in ast.walk(lexical_owner.items[0].context_expr)
            )
        )
        helpers = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
        }
        owned_capture = helpers["_capture_process_owned"]
        self.assertEqual(owned_capture.args.args[2].arg, target)
        acquisitions = {
            node.attr
            for node in ast.walk(owned_capture)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == target
            and node.attr in {"open", "pidfd_open", "dup", "socket"}
        }
        self.assertEqual(acquisitions, {"open", "pidfd_open"})
        unprotected = [
            (node.lineno, node.attr)
            for node in ast.walk(function)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == target
            and node.attr in {"open", "pidfd_open", "dup", "socket"}
        ]
        self.assertEqual(unprotected, [])

    def test_bound_regular_tree_is_no_follow_bounded_and_failure_total(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "nested"
            deeper = nested / "deeper"
            deeper.mkdir(parents=True)
            (root / "a.txt").write_bytes(b"a")
            (nested / "b.bin").write_bytes(b"b")
            (deeper / "c.dat").write_bytes(b"c")
            (root / "file-link").symlink_to(root / "a.txt")
            (root / "directory-link").symlink_to(nested, target_is_directory=True)
            baseline = set(os.listdir("/proc/self/fd"))

            self.assertEqual(
                MODULE.bound_regular_tree(
                    root,
                    maximum_depth=3,
                    maximum_entries=16,
                ),
                (
                    root / "a.txt",
                    nested / "b.bin",
                    deeper / "c.dat",
                ),
            )
            self.assertEqual(set(os.listdir("/proc/self/fd")), baseline)

            with self.assertRaisesRegex(MODULE.DrainError, "too deep"):
                MODULE.bound_regular_tree(
                    root,
                    maximum_depth=1,
                    maximum_entries=16,
                )
            self.assertEqual(set(os.listdir("/proc/self/fd")), baseline)

            with self.assertRaisesRegex(MODULE.DrainError, "entry capacity"):
                MODULE.bound_regular_tree(
                    root,
                    maximum_depth=3,
                    maximum_entries=1,
                )
            self.assertEqual(set(os.listdir("/proc/self/fd")), baseline)

    def test_control_publication_closes_initial_existing_validation_failure(self) -> None:
        def open_parent(custody: MODULE.ResourceCustody) -> int:
            return acquire_test_descriptor(custody, 10)

        with mock.patch.object(
            MODULE,
            "open_run_parent",
            side_effect=open_parent,
        ), mock.patch.object(
            MODULE.os,
            "open",
            return_value=11,
        ), mock.patch.object(
            MODULE,
            "_validate_control_root_descriptor",
            side_effect=RuntimeError("existing validation failed"),
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(OSError("existing close failed"), None),
        ) as close, self.assertRaisesRegex(
            RuntimeError,
            "existing validation failed",
        ) as raised:
            with MODULE.ResourceCustody(label="control publication caller") as custody:
                MODULE.publish_control_capsule(custody, {}, {})
        self.assertEqual(close.call_args_list, [mock.call(11), mock.call(10)])
        self.assertIn("cleanup also failed", "\n".join(raised.exception.__notes__))

    def test_control_publication_closes_raced_existing_validation_failure(self) -> None:
        control = {"sourceSha256": "d" * 64}
        allowed = {MODULE.SNAPSHOT_NAME, MODULE.CONTROL_NAME, MODULE.STATE_NAME}

        def open_parent(custody: MODULE.ResourceCustody) -> int:
            return acquire_test_descriptor(custody, 10)

        with mock.patch.object(
            MODULE,
            "open_run_parent",
            side_effect=open_parent,
        ), mock.patch.object(
            MODULE.os,
            "open",
            side_effect=(FileNotFoundError(), 12, 13),
        ), mock.patch.object(
            MODULE,
            "_reduce_pending_control_capsule",
        ), mock.patch.object(
            MODULE.os,
            "mkdir",
        ), mock.patch.object(
            MODULE.os,
            "fsync",
        ), mock.patch.object(
            MODULE,
            "_validate_control_root_descriptor",
            side_effect=(None, RuntimeError("race validation failed")),
        ), mock.patch.object(
            MODULE,
            "snapshot_source",
            return_value="d" * 64,
        ), mock.patch.object(
            MODULE,
            "atomic_write_at",
        ), mock.patch.object(
            MODULE.os,
            "listdir",
            return_value=allowed,
        ), mock.patch.object(
            MODULE,
            "rename_noreplace_at",
            side_effect=FileExistsError(errno.EEXIST, "exists"),
        ), mock.patch.object(
            MODULE.os,
            "close",
            side_effect=(None, OSError("race close failed"), None),
        ) as close, self.assertRaisesRegex(
            RuntimeError,
            "race validation failed",
        ) as raised:
            with MODULE.ResourceCustody(label="control publication caller") as custody:
                MODULE.publish_control_capsule(custody, control, {})
        self.assertEqual(
            close.call_args_list,
            [mock.call(12), mock.call(13), mock.call(10)],
        )
        self.assertIn("cleanup also failed", "\n".join(raised.exception.__notes__))

    def test_recovery_second_descriptor_acquisition_failure_closes_state(self) -> None:
        with mock.patch.object(
            MODULE,
            "exists_nofollow",
            return_value=False,
        ), mock.patch.object(
            MODULE,
            "require_v5_absent",
            return_value={"legacyRuntime": None},
        ), mock.patch.object(
            MODULE,
            "require_registry_listener_absent",
        ), mock.patch.object(
            MODULE.os,
            "open",
            side_effect=(30, OSError("evidence open failed")),
        ), mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(
            OSError,
            "evidence open failed",
        ):
            MODULE.recover_terminal_archive_without_control()
        close.assert_called_once_with(30)

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
            observed.st_uid = 1000
            observed.st_gid = 1000
            observed.st_mode = stat.S_IFREG | 0o600
            self.assertEqual(
                MODULE._live_receipt_disposition(observed, tombstone, control),
                "tombstone",
            )

    def test_recovery_tombstone_rejects_byte_identical_substituted_inode(self) -> None:
        raw = b"receipt\n"
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
        projection = {
            "controlSha256": MODULE.sha256_bytes(MODULE.canonical_json(control)),
            "control": control,
        }
        substituted = mock.Mock(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=1000,
            st_gid=1000,
            st_nlink=1,
            st_dev=7,
            st_ino=10,
            st_size=len(raw),
        )

        def read(
            custody: MODULE.ResourceCustody,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[int, object, bytes]:
            acquire_test_descriptor(custody, 31)
            return 31, substituted, raw

        with mock.patch.object(
            MODULE,
            "EXPECTED_RECEIPT_SHA256",
            digest,
        ), mock.patch.object(
            MODULE,
            "_read_regular_at",
            side_effect=read,
        ), mock.patch.object(
            MODULE.os,
            "close",
        ) as close, mock.patch.object(
            MODULE.os,
            "ftruncate",
        ) as truncate, mock.patch.object(
            MODULE,
            "_write_all",
        ) as write, mock.patch.object(
            MODULE.os,
            "fchown",
        ) as chown, mock.patch.object(
            MODULE.os,
            "fchmod",
        ) as chmod, self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "live receipt is foreign",
        ):
            MODULE.complete_terminal_tombstone_without_control(20, projection)
        close.assert_called_once_with(31)
        truncate.assert_not_called()
        write.assert_not_called()
        chown.assert_not_called()
        chmod.assert_not_called()

    def test_recovery_prepared_archive_rejects_substituted_live_inode(self) -> None:
        raw = b"receipt\n"
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
        substituted = mock.Mock(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=1000,
            st_gid=1000,
            st_nlink=1,
            st_dev=7,
            st_ino=10,
            st_size=len(raw),
        )
        custody = MODULE.ResourceCustody(label="recovery test")

        def read(
            owner: MODULE.ResourceCustody,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[int, object, bytes]:
            acquire_test_descriptor(owner, 31)
            return 31, substituted, raw

        with mock.patch.object(
            MODULE,
            "EXPECTED_RECEIPT_SHA256",
            digest,
        ), mock.patch.object(
            MODULE,
            "_read_regular_at",
            side_effect=read,
        ), mock.patch.object(
            MODULE,
            "_create_root_tmpfile",
        ) as create, mock.patch.object(
            MODULE,
            "link_tmpfile_noreplace_at",
        ) as link, mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "live identity differs",
        ):
            with custody:
                MODULE.recover_prepared_archive_from_live(control, 20, custody)
        create.assert_not_called()
        link.assert_not_called()
        close.assert_called_once_with(31)

    def test_recovery_tombstone_rejects_post_mutation_name_substitution(self) -> None:
        raw = b"receipt\n"
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
        projection = {
            "controlSha256": MODULE.sha256_bytes(MODULE.canonical_json(control)),
            "control": control,
        }
        initial = mock.Mock(
            st_mode=stat.S_IFREG | 0o600,
            st_uid=1000,
            st_gid=1000,
            st_nlink=1,
            st_dev=7,
            st_ino=9,
            st_size=len(raw),
        )
        with mock.patch.object(MODULE, "EXPECTED_RECEIPT_SHA256", digest):
            tombstone = MODULE.receipt_tombstone_bytes_for_control_digest(
                str(projection["controlSha256"])
            )
            final = mock.Mock(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=1000,
                st_gid=1000,
                st_nlink=1,
                st_dev=7,
                st_ino=9,
                st_size=len(tombstone),
            )
            substituted = mock.Mock(st_dev=7, st_ino=10)

            def read(
                custody: MODULE.ResourceCustody,
                *_args: object,
                **_kwargs: object,
            ) -> tuple[int, object, bytes]:
                acquire_test_descriptor(custody, 31)
                return 31, initial, raw

            with mock.patch.object(
                MODULE,
                "_read_regular_at",
                side_effect=read,
            ), mock.patch.object(
                MODULE.os,
                "read",
                side_effect=(tombstone, b""),
            ), mock.patch.object(
                MODULE.os,
                "ftruncate",
            ), mock.patch.object(
                MODULE.os,
                "lseek",
            ), mock.patch.object(
                MODULE,
                "_write_all",
            ), mock.patch.object(
                MODULE.os,
                "fsync",
            ), mock.patch.object(
                MODULE.os,
                "fchown",
            ), mock.patch.object(
                MODULE.os,
                "fchmod",
            ), mock.patch.object(
                MODULE.os,
                "fstat",
                return_value=final,
            ), mock.patch.object(
                MODULE.os,
                "stat",
                return_value=substituted,
            ), mock.patch.object(
                MODULE.os,
                "close",
            ), mock.patch.object(
                MODULE,
                "require_exact_live_receipt_tombstone",
            ) as reproof, self.assertRaisesRegex(
                MODULE.DrainError,
                "tombstone binding differs",
            ):
                MODULE.complete_terminal_tombstone_without_control(20, projection)
            reproof.assert_not_called()

    def test_archived_response_loss_is_namespace_read_only_and_byte_stable(self) -> None:
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
        ) as rename, mock.patch.object(
            MODULE,
            "hold_recorded_persistent_roots",
            return_value=contextlib.nullcontext({}),
        ), mock.patch.object(
            MODULE,
            "registry_inventory_matches",
        ):
            first = MODULE.archive_receipt(control)
            second = MODULE.archive_receipt(control)
        self.assertEqual(first, second)
        self.assertEqual(read.call_count, 2)
        write.assert_not_called()
        rename.assert_not_called()

    def test_linked_publication_replay_fsyncs_before_reproof(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        regions = (
            source[
                source.index("def legacy_receipt_state")
                : source.index("def transfer_receipt_custody")
            ],
            source[
                source.index("def open_or_publish_prepared_archive")
                : source.index("def _live_path_has_exact_legacy_bytes")
            ],
            source[
                source.index("def read_projection")
                : source.index("def read_terminal_projection_without_control")
            ],
            source[
                source.index("def read_terminal_projection_without_control")
                : source.index("def complete_terminal_tombstone_without_control")
            ],
            source[
                source.index("def write_projection")
                : source.index("def archive_receipt")
            ],
        )
        for region in regions:
            with self.subTest(header=region.splitlines()[0]):
                self.assertLess(
                    region.index("settle_linked_publication_replay(evidence_fd)"),
                    region.index("_read_regular_at("),
                )

    def test_prepared_archive_response_loss_is_settled_before_return(self) -> None:
        events: list[str] = []
        observed = mock.Mock()

        def read(
            custody: MODULE.ResourceCustody,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[int, object, bytes]:
            events.append("read")
            acquire_test_descriptor(custody, 31)
            return 31, observed, b"receipt"

        with mock.patch.object(
            MODULE, "recorded_legacy_receipt_bytes", return_value=b"receipt"
        ), mock.patch.object(
            MODULE,
            "_read_regular_at",
            side_effect=read,
        ), mock.patch.object(
            MODULE, "_require_legacy_receipt"
        ), mock.patch.object(
            MODULE.os,
            "fsync",
            side_effect=lambda _fd: events.append("fsync"),
        ), mock.patch.object(MODULE.os, "close"):
            with MODULE.ResourceCustody(label="prepared archive caller") as custody:
                descriptor = MODULE.open_or_publish_prepared_archive(
                    custody,
                    {"authority": {"legacyReceipt": {}}},
                    20,
                )
        self.assertEqual(descriptor, 31)
        self.assertEqual(events[:2], ["fsync", "read"])

    def test_terminal_archive_response_loss_settles_and_rejects_live_original(self) -> None:
        events: list[str] = []
        observed = mock.Mock()
        values = iter((None, (31, observed, b"archive")))

        def evidence(
            custody: MODULE.ResourceCustody,
            _control: object,
        ) -> tuple[int, int]:
            return acquire_test_descriptors(custody, 10, 20)

        def read(
            custody: MODULE.ResourceCustody,
            *_args: object,
            **_kwargs: object,
        ) -> object:
            events.append("read")
            value = next(values)
            if value is not None:
                acquire_test_descriptor(custody, value[0])
            return value

        with mock.patch.object(
            MODULE, "recorded_evidence_descriptors", side_effect=evidence
        ), mock.patch.object(
            MODULE,
            "_read_regular_at",
            side_effect=read,
        ), mock.patch.object(
            MODULE, "_require_legacy_receipt"
        ), mock.patch.object(
            MODULE.os,
            "fsync",
            side_effect=lambda _fd: events.append("fsync"),
        ), mock.patch.object(MODULE.os, "close"):
            state, raw = MODULE.legacy_receipt_state(
                {"authority": {"legacyReceipt": {}}}
            )
        self.assertEqual((state, raw), ("archived", b"archive"))
        self.assertEqual(events[:3], ["fsync", "read", "read"])

        live_and_archive = iter(
            ((30, observed, b"legacy"), (31, observed, b"archive"))
        )

        def read_coexisting(
            custody: MODULE.ResourceCustody,
            *_args: object,
            **_kwargs: object,
        ) -> object:
            value = next(live_and_archive)
            acquire_test_descriptor(custody, value[0])
            return value

        with mock.patch.object(
            MODULE, "recorded_evidence_descriptors", side_effect=evidence
        ), mock.patch.object(
            MODULE, "_read_regular_at", side_effect=read_coexisting
        ), mock.patch.object(
            MODULE, "_require_legacy_receipt"
        ), mock.patch.object(
            MODULE, "sha256_bytes", return_value=MODULE.EXPECTED_RECEIPT_SHA256
        ), mock.patch.object(MODULE.os, "fsync"), mock.patch.object(MODULE.os, "close"), self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "coexist",
        ):
            MODULE.legacy_receipt_state(
                {"authority": {"legacyReceipt": {}}}
            )

    def test_projection_is_deterministic_and_precedes_archive(self) -> None:
        control = ReducerStateMachineTest.FakeControl("archive_intent_final")
        first = MODULE.terminal_projection_value(control)
        second = MODULE.terminal_projection_value(control)
        self.assertEqual(MODULE.canonical_json(first), MODULE.canonical_json(second))
        self.assertEqual(first["observedAt"], control.state["observedAt"])
        self.assertEqual(first["control"], control.control)
        source = MODULE_PATH.read_text(encoding="utf-8")
        archive = source[
            source.index("def archive_receipt")
            : source.index("def registry_inventory_matches")
        ]
        self.assertLess(
            archive.index("terminal = write_projection(control)"),
            archive.index("link_tmpfile_noreplace_at("),
        )
        self.assertLess(
            archive.index("open_or_publish_prepared_archive"),
            archive.index("complete_receipt_tombstone"),
        )
        self.assertLess(
            archive.index("complete_receipt_tombstone"),
            archive.rindex("link_tmpfile_noreplace_at"),
        )

    def test_terminal_projection_capacity_has_exact_maximum_boundary(self) -> None:
        self.assertEqual(len(MODULE.utc_now()), len(MODULE.TERMINAL_TIMESTAMP_SENTINEL))

        def control_with_padding(padding: str) -> dict[str, object]:
            authority = {"padding": padding}
            return {
                "schema": MODULE.CONTROL_SCHEMA,
                "observedAt": MODULE.TERMINAL_TIMESTAMP_SENTINEL,
                "bootId": "b" * 36,
                "stateRoot": str(MODULE.EXPECTED_STATE_ROOT),
                "caller": {"uid": 1000, "gid": 1000},
                "verificationSha256": MODULE.sha256_bytes(
                    MODULE.canonical_json(authority)
                ),
                "sourceSha256": "d" * 64,
                "authority": authority,
            }

        state = {
            "phase": "stopping_intent_final",
            "observedAt": "ignored-for-nonterminal-capacity",
            "bootId": "b" * 36,
        }
        base = control_with_padding("")
        base_size = len(
            MODULE.canonical_json(
                MODULE.terminal_projection_value_for(
                    base,
                    observed_at=MODULE.TERMINAL_TIMESTAMP_SENTINEL,
                    boot_id="b" * 36,
                )
            )
        )
        exact = control_with_padding("x" * (MODULE.MAX_JSON_BYTES - base_size))
        self.assertEqual(
            MODULE.require_terminal_projection_capacity(exact, state),
            MODULE.MAX_JSON_BYTES,
        )
        over = control_with_padding(
            "x" * (MODULE.MAX_JSON_BYTES - base_size + 1)
        )
        with self.assertRaisesRegex(MODULE.DrainError, "projection is too large"):
            MODULE.require_terminal_projection_capacity(over, state)

        terminal_state = {
            "phase": "archive_intent_final",
            "observedAt": "terminal-observation-with-a-different-width",
            "bootId": "b" * 36,
        }
        self.assertEqual(
            MODULE.require_terminal_projection_capacity(base, terminal_state),
            len(
                MODULE.canonical_json(
                    MODULE.terminal_projection_value_for(
                        base,
                        observed_at=str(terminal_state["observedAt"]),
                        boot_id="b" * 36,
                    )
                )
            ),
        )

    def test_oversized_projection_blocks_before_control_publication(self) -> None:
        boot_id = "b" * 36
        source = b"pinned source"

        def authority_with_padding(padding: str) -> dict[str, object]:
            return {"padding": padding}

        def candidate(authority: dict[str, object]) -> dict[str, object]:
            return {
                "schema": MODULE.CONTROL_SCHEMA,
                "observedAt": MODULE.TERMINAL_TIMESTAMP_SENTINEL,
                "bootId": boot_id,
                "stateRoot": str(MODULE.EXPECTED_STATE_ROOT),
                "caller": {"uid": 1000, "gid": 1000},
                "verificationSha256": MODULE.sha256_bytes(
                    MODULE.canonical_json(authority)
                ),
                "sourceSha256": MODULE.sha256_bytes(source),
                "authority": authority,
            }

        base_authority = authority_with_padding("")
        base = candidate(base_authority)
        base_size = len(
            MODULE.canonical_json(
                MODULE.terminal_projection_value_for(
                    base,
                    observed_at=MODULE.TERMINAL_TIMESTAMP_SENTINEL,
                    boot_id=boot_id,
                )
            )
        )
        authority = authority_with_padding(
            "x" * (MODULE.MAX_JSON_BYTES - base_size + 1)
        )
        digest = MODULE.sha256_bytes(MODULE.canonical_json(authority))
        verification = {
            "verificationSha256": digest,
            "authority": authority,
        }
        with mock.patch.dict(
            MODULE.__dict__,
            {"__legacy_pinned_source_bytes__": source},
        ), mock.patch.object(
            MODULE,
            "open_control_root",
            side_effect=FileNotFoundError,
        ), mock.patch.object(
            MODULE,
            "current_boot_id",
            return_value=boot_id,
        ), mock.patch.object(
            MODULE,
            "utc_now",
            return_value=MODULE.TERMINAL_TIMESTAMP_SENTINEL,
        ), mock.patch.object(
            MODULE,
            "publish_control_capsule",
        ) as publish, self.assertRaisesRegex(
            MODULE.DrainError,
            "projection is too large",
        ):
            with MODULE.ResourceCustody(label="control creation caller") as custody:
                MODULE.ControlAuthority.create(
                    custody,
                    verification,
                    expected_verification_sha256=digest,
                )
        publish.assert_not_called()

    def test_existing_oversized_projection_closes_authority_before_return(self) -> None:
        boot_id = "b" * 36
        source = b"pinned source"

        def control_with_padding(padding: str) -> dict[str, object]:
            authority = {"padding": padding}
            return {
                "schema": MODULE.CONTROL_SCHEMA,
                "observedAt": MODULE.TERMINAL_TIMESTAMP_SENTINEL,
                "bootId": boot_id,
                "stateRoot": str(MODULE.EXPECTED_STATE_ROOT),
                "caller": {"uid": 1000, "gid": 1000},
                "verificationSha256": MODULE.sha256_bytes(
                    MODULE.canonical_json(authority)
                ),
                "sourceSha256": MODULE.sha256_bytes(source),
                "authority": authority,
            }

        base = control_with_padding("")
        base_size = len(
            MODULE.canonical_json(
                MODULE.terminal_projection_value_for(
                    base,
                    observed_at=MODULE.TERMINAL_TIMESTAMP_SENTINEL,
                    boot_id=boot_id,
                )
            )
        )
        control = control_with_padding(
            "x" * (MODULE.MAX_JSON_BYTES - base_size + 1)
        )
        state = {
            "schema": MODULE.STATE_SCHEMA,
            "observedAt": MODULE.TERMINAL_TIMESTAMP_SENTINEL,
            "bootId": boot_id,
            "stateRoot": str(MODULE.EXPECTED_STATE_ROOT),
            "controlSha256": MODULE.sha256_bytes(MODULE.canonical_json(control)),
            "phase": "stopping_intent_final",
            "netnsMarkerIdentity": None,
        }
        verification = {
            "verificationSha256": control["verificationSha256"],
            "authority": control["authority"],
        }

        def open_control(custody: MODULE.ResourceCustody) -> int:
            return acquire_test_descriptor(custody, 31)

        with mock.patch.dict(
            MODULE.__dict__,
            {"__legacy_pinned_source_bytes__": source},
        ), mock.patch.object(
            MODULE,
            "open_control_root",
            side_effect=open_control,
        ), mock.patch.object(
            MODULE,
            "read_at",
            return_value=source,
        ), mock.patch.object(
            MODULE,
            "read_json_at",
            side_effect=(control, state),
        ), mock.patch.object(
            MODULE,
            "current_boot_id",
            return_value=boot_id,
        ), mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "projection is too large",
        ):
            with MODULE.ResourceCustody(label="existing control caller") as custody:
                MODULE.ControlAuthority.create(
                    custody,
                    verification,
                    expected_verification_sha256=str(control["verificationSha256"]),
                )
        close.assert_called_once_with(31)

        held_owner = mock.Mock()
        with mock.patch.dict(
            MODULE.__dict__,
            {
                "__legacy_control_root_fd__": 30,
                "__legacy_control_root_owner__": held_owner,
            },
        ), mock.patch.object(
            MODULE.os,
            "dup",
            return_value=31,
        ), mock.patch.object(
            MODULE,
            "read_at",
            return_value=source,
        ), mock.patch.object(
            MODULE,
            "read_json_at",
            side_effect=(control, state),
        ), mock.patch.object(
            MODULE,
            "current_boot_id",
            return_value=boot_id,
        ), mock.patch.object(
            MODULE.os,
            "close",
        ) as close, self.assertRaisesRegex(
            MODULE.DrainError,
            "projection is too large",
        ):
            with MODULE.ResourceCustody(label="resume control caller") as custody:
                MODULE.ControlAuthority.open(custody)
        close.assert_called_once_with(31)
        held_owner.close.assert_called_once_with()

    def test_runtime_and_pidfile_have_complete_preflight_before_unlink(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        reducer_start = source.index("def run_reducer")
        reducer = source[
            reducer_start : source.index("def require_root", reducer_start)
        ]
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

    def test_reboot_recovery_is_bound_before_terminal_mutation(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        recovery = source[
            source.index("def recover_terminal_archive_without_control")
            : source.index("def write_projection")
        ]
        self.assertLess(
            recovery.index("state_fd = custody.open("),
            recovery.index("read_terminal_projection_without_control(evidence_fd)"),
        )
        self.assertIn('stored_control = projection["control"]', recovery)
        self.assertIn('v5_state["legacyRuntime"] is None', recovery)
        self.assertIn("require_related_process_cutoff(\n            stored_control", recovery)
        self.assertIn("process_cutoff[\"related\"] == []", recovery)
        self.assertNotIn("require_no_boot_recovery_related_processes", recovery)
        self.assertIn(
            "persistent_owner = recorded_persistent_root_descriptors(\n"
            "            custody,\n"
            "            stored_control,\n"
            "        )",
            recovery,
        )
        self.assertIn(
            "registry_inventory_matches(stored_control, persistent_roots)",
            recovery,
        )
        self.assertIn("anchors_from_document(recorded_mounts)", recovery)
        last_binding = recovery.rindex("require_recovery_state_binding")
        self.assertLess(last_binding, recovery.index("link_tmpfile_noreplace_at(\n            prepared_fd"))
        self.assertIn("recover_prepared_archive_from_live(", recovery)
        prepared_recovery = source[
            source.index("def recover_prepared_archive_from_live")
            : source.index("def recover_terminal_archive_without_control")
        ]
        self.assertLess(
            prepared_recovery.index("_require_legacy_receipt("),
            prepared_recovery.index("_create_root_tmpfile("),
        )


class WrapperBoundaryTest(unittest.TestCase):
    @staticmethod
    def _descriptor_custody_type() -> type:
        source = WRAPPER.read_text(encoding="utf-8")
        loader = source.split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        tree = ast.parse(loader)
        selected = [
            node
            for node in tree.body
            if (
                isinstance(node, ast.FunctionDef)
                and node.name == "add_error_note"
            )
            or (
                isinstance(node, ast.ClassDef)
                and node.name
                in {
                    "DescriptorRegistration",
                    "PendingDescriptorAcquisition",
                    "DescriptorCustody",
                }
            )
        ]
        extracted = ast.fix_missing_locations(
            ast.Module(body=selected, type_ignores=[])
        )
        namespace = {
            "ACQUISITION_EMPTY": object(),
            "collections": collections,
            "functools": functools,
            "itertools": itertools,
            "os": os,
            "operator": operator,
            "sys": sys,
        }
        exec(compile(extracted, "<loader-custody>", "exec"), namespace, namespace)
        return namespace["DescriptorCustody"]

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
        resume = source[source.index("  resume)") : source.index("  *)")]
        self.assertIn('invoke_tool resume "${control_root}"', resume)
        self.assertIn('invoke_tool repo "${tool}"', resume)

    def test_resume_boot_gate_precedes_source_execution(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        resume = source[
            source.index("def execute_resume_owned")
            : source.index('if mode == "repo":\n    execute_source')
        ]
        self.assertLess(
            resume.index('control["bootId"] == state["bootId"] == boot_id'),
            resume.index("execute_source(source, display_name, control_root_fd, custody)"),
        )
        self.assertLess(
            resume.index("control_root_fd = custody.open("),
            resume.index('read_bound_at(control_root_fd, "legacy_v3_drain.py"'),
        )
        self.assertLess(
            resume.index("terminal_projection = terminal_projection_value_for("),
            resume.index("execute_source(source, display_name, control_root_fd, custody)"),
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

    def test_loader_and_reducer_share_terminal_projection_capacity_bytes(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        loader = source.split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        tree = ast.parse(loader)
        selected: list[ast.stmt] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in {
                "canonical",
                "terminal_projection_value_for",
            }:
                selected.append(node)
            elif isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name)
                and target.id == "TERMINAL_TIMESTAMP_SENTINEL"
                for target in node.targets
            ):
                selected.append(node)
        extracted = ast.fix_missing_locations(
            ast.Module(body=selected, type_ignores=[])
        )
        namespace = {"json": json, "hashlib": hashlib}
        exec(compile(extracted, "<loader-projection>", "exec"), namespace, namespace)
        authority = {"padding": "x" * 100}
        control = {
            "schema": MODULE.CONTROL_SCHEMA,
            "observedAt": MODULE.TERMINAL_TIMESTAMP_SENTINEL,
            "bootId": "b" * 36,
            "stateRoot": str(MODULE.EXPECTED_STATE_ROOT),
            "caller": {"uid": 1000, "gid": 1000},
            "verificationSha256": MODULE.sha256_bytes(
                MODULE.canonical_json(authority)
            ),
            "sourceSha256": "d" * 64,
            "authority": authority,
        }
        loader_value = namespace["terminal_projection_value_for"](
            control,
            observed_at=namespace["TERMINAL_TIMESTAMP_SENTINEL"],
            boot_id="b" * 36,
        )
        module_value = MODULE.terminal_projection_value_for(
            control,
            observed_at=MODULE.TERMINAL_TIMESTAMP_SENTINEL,
            boot_id="b" * 36,
        )
        self.assertEqual(namespace["canonical"](loader_value), MODULE.canonical_json(module_value))
        self.assertEqual(
            namespace["TERMINAL_TIMESTAMP_SENTINEL"],
            MODULE.TERMINAL_TIMESTAMP_SENTINEL,
        )
        base_size = len(namespace["canonical"](loader_value)) - 100
        exact_padding = "x" * (MODULE.MAX_JSON_BYTES - base_size)
        exact_authority = {"padding": exact_padding}
        exact_control = {
            **control,
            "authority": exact_authority,
            "verificationSha256": MODULE.sha256_bytes(
                MODULE.canonical_json(exact_authority)
            ),
        }
        exact_loader = namespace["terminal_projection_value_for"](
            exact_control,
            observed_at=namespace["TERMINAL_TIMESTAMP_SENTINEL"],
            boot_id="b" * 36,
        )
        exact_module = MODULE.terminal_projection_value_for(
            exact_control,
            observed_at=MODULE.TERMINAL_TIMESTAMP_SENTINEL,
            boot_id="b" * 36,
        )
        self.assertEqual(len(namespace["canonical"](exact_loader)), MODULE.MAX_JSON_BYTES)
        self.assertEqual(len(MODULE.canonical_json(exact_module)), MODULE.MAX_JSON_BYTES)
        over_authority = {"padding": exact_padding + "x"}
        over_control = {
            **control,
            "authority": over_authority,
            "verificationSha256": MODULE.sha256_bytes(
                MODULE.canonical_json(over_authority)
            ),
        }
        over_loader = namespace["terminal_projection_value_for"](
            over_control,
            observed_at=namespace["TERMINAL_TIMESTAMP_SENTINEL"],
            boot_id="b" * 36,
        )
        over_module = MODULE.terminal_projection_value_for(
            over_control,
            observed_at=MODULE.TERMINAL_TIMESTAMP_SENTINEL,
            boot_id="b" * 36,
        )
        self.assertEqual(
            len(namespace["canonical"](over_loader)), MODULE.MAX_JSON_BYTES + 1
        )
        self.assertEqual(
            len(MODULE.canonical_json(over_module)), MODULE.MAX_JSON_BYTES + 1
        )

    def test_loader_phase_roster_matches_reducer_exactly(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        loader = source.split("read -r -d '' pinned_loader <<'PY' || true\n", 1)[1].split("\nPY\n", 1)[0]
        tree = ast.parse(loader)
        phase_assignment = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "phases"
                for target in node.targets
            )
        )
        self.assertEqual(ast.literal_eval(phase_assignment.value), set(MODULE.PHASES))
        self.assertIn('"netnsMarkerIdentity"', loader)

    def test_loader_raw_descriptor_operations_are_custody_only(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        loader = source.split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        tree = ast.parse(loader)
        parents: dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        offenders: list[tuple[int, str]] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id == "open":
                offenders.append((node.lineno, "builtins.open"))
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if not isinstance(node.func.value, ast.Name):
                continue
            if (node.func.value.id, node.func.attr) not in {
                ("os", "open"),
                ("os", "close"),
            }:
                continue
            parent: ast.AST | None = node
            class_name: str | None = None
            while parent in parents:
                parent = parents[parent]
                if isinstance(parent, ast.ClassDef):
                    class_name = parent.name
                    break
            if class_name != "DescriptorCustody":
                offenders.append((node.lineno, node.func.attr))
        self.assertEqual(offenders, [])

    def test_loader_custody_preserves_body_error_on_close_failure(self) -> None:
        custody = self._descriptor_custody_type()("loader fault injection")
        with mock.patch.object(os, "open", return_value=40):
            custody.open("ignored", os.O_RDONLY)
        primary = RuntimeError("loader body failed")
        with mock.patch.object(os, "close", side_effect=OSError("close failed")):
            custody.__exit__(RuntimeError, primary, None)
        self.assertIn("cleanup also failed", "\n".join(primary.__notes__))

    def test_loader_copy_swap_ignores_hostile_private_roster_and_has_no_fallback(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        registration_type = descriptor_custody.close.__globals__["DescriptorRegistration"]
        prior = registration_type(39)
        prior.published = True

        class SubstitutingRoster(list[object]):
            def copy(self) -> object:
                raise AssertionError("virtual copy must not control loader publication")

            def append(self, _value: object) -> None:
                raise AssertionError("private loader roster append must not run")

            def __iter__(self):  # type: ignore[no-untyped-def]
                raise AssertionError("private loader roster scan must not run")

            def __getitem__(self, _index: object) -> object:
                raise AssertionError("private loader token substitution must not run")

        custody = descriptor_custody("loader generation publication")
        hostile = SubstitutingRoster([prior])
        custody.descriptors = hostile
        with mock.patch.object(os, "open", return_value=40), mock.patch.object(
            os,
            "close",
        ) as close:
            self.assertEqual(custody.open("ignored", os.O_RDONLY), 40)
            self.assertIs(type(custody.descriptors), list)
            self.assertEqual(len(custody.descriptors), 2)
            self.assertIs(custody.descriptors[0], prior)
            self.assertIsNot(custody.descriptors[1], prior)
            self.assertEqual(custody.descriptors[1].descriptor, 40)
            self.assertTrue(custody.descriptors[1].published)
            self.assertEqual(hostile, [prior])
            custody.close()
        self.assertEqual(close.call_args_list, [mock.call(40), mock.call(39)])

        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        custody_ast = next(
            node
            for node in ast.parse(loader).body
            if isinstance(node, ast.ClassDef) and node.name == "DescriptorCustody"
        )
        methods = {
            node.name
            for node in custody_ast.body
            if isinstance(node, ast.FunctionDef)
        }
        self.assertFalse(methods & {"_rollback", "_scan", "_fallback"})

    def test_loader_acquisition_generation_boundary_matrix_is_failure_total(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        open_ast = class_method_ast(loader, "DescriptorCustody", "open")
        registration = next(
            node
            for node in ast.walk(open_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "registration"
                for target in node.targets
            )
            and isinstance(node.value, ast.Call)
        )
        first_validation = next(
            node
            for node in ast.walk(open_ast)
            if isinstance(node, ast.If) and node.lineno > registration.lineno
        )
        candidate = next(
            node
            for node in ast.walk(open_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "candidate"
                for target in node.targets
            )
        )
        append = next(
            node
            for node in ast.walk(open_ast)
            if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "append"
        )
        swap = next(
            node
            for node in ast.walk(open_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "descriptors"
                for target in node.targets
            )
        )
        published = next(
            node
            for node in ast.walk(open_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "published"
                for target in node.targets
            )
        )
        returned = next(
            node
            for node in ast.walk(open_ast)
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Name)
        )
        cases = (
            ("loader_after_syscall_before_token", registration.lineno),
            ("loader_after_token_before_validation", first_validation.lineno),
            ("loader_before_candidate_copy", candidate.lineno),
            ("loader_before_candidate_append", append.lineno),
            ("loader_before_roster_swap", swap.lineno),
            ("loader_after_swap_before_published", published.lineno),
            ("loader_after_publication_before_return", returned.lineno),
        )
        registration_type = descriptor_custody.close.__globals__["DescriptorRegistration"]
        for label, line in cases:
            prior = registration_type(39)
            prior.published = True
            custody = descriptor_custody(label)
            custody.descriptors = [prior]
            with self.subTest(boundary=label), mock.patch.object(
                os,
                "open",
                return_value=40,
            ), mock.patch.object(os, "close") as close, self.assertRaisesRegex(
                KeyboardInterrupt,
                label,
            ):
                with interrupt_once_on_line(
                    descriptor_custody.open.__code__,
                    line,
                    label,
                ) as fired:
                    custody.open("ignored", os.O_RDONLY)
            self.assertTrue(fired[0])
            close.assert_called_once_with(40)
            self.assertEqual(custody.descriptors, [prior])

    def test_loader_c_capture_guards_fd_before_python_opcode_resumes(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        capture_code = descriptor_custody._capture_producer_result.__code__
        inside_capture = next(
            instruction.offset
            for instruction in dis.get_instructions(capture_code)
            if instruction.opname == "POP_TOP"
        )
        open_instructions = list(dis.get_instructions(descriptor_custody.open))
        capture_load = next(
            index
            for index, instruction in enumerate(open_instructions)
            if instruction.argval == "_capture_producer_result"
        )
        capture_call = next(
            index
            for index in range(capture_load, len(open_instructions))
            if open_instructions[index].opname.startswith("CALL")
        )
        after_capture_call = open_instructions[capture_call + 1].offset
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        open_ast = class_method_ast(loader, "DescriptorCustody", "open")
        self.assertFalse(
            any(
                isinstance(node, ast.Name) and node.id == "acquired"
                for node in ast.walk(open_ast)
            )
        )
        self.assertNotIn("lambda", ast.get_source_segment(loader, open_ast) or "")

        real_open = os.open
        real_close = os.close
        for label, code, offset in (
            ("loader inside C capture", capture_code, inside_capture),
            (
                "loader after capture helper call",
                descriptor_custody.open.__code__,
                after_capture_call,
            ),
        ):
            opened: list[int] = []

            def observed_open(*args: object, **kwargs: object) -> int:
                descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
                opened.append(descriptor)
                return descriptor

            custody = descriptor_custody(label)
            try:
                with self.subTest(boundary=label), mock.patch.object(
                    os,
                    "open",
                    side_effect=observed_open,
                ), self.assertRaisesRegex(KeyboardInterrupt, label):
                    with interrupt_once_on_opcode(
                        code,
                        offset,
                        label,
                    ) as fired:
                        custody.open("/dev/null", os.O_RDONLY)
                self.assertTrue(fired[0])
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError):
                    os.fstat(opened[0])
                self.assertEqual(custody.descriptors, [])
                self.assertEqual(custody.state, "open")
            finally:
                for descriptor in opened:
                    try:
                        os.fstat(descriptor)
                    except OSError:
                        continue
                    real_close(descriptor)

    def test_loader_pending_acquisition_survives_handler_interruption(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        open_code = descriptor_custody.open.__code__
        open_instructions = list(dis.get_instructions(open_code))
        handler_start = next(
            index
            for index, instruction in enumerate(open_instructions)
            if instruction.opname == "PUSH_EXC_INFO"
        )
        handler_entry = next(
            instruction.offset
            for instruction in open_instructions[handler_start:]
            if instruction.opname == "STORE_FAST"
        )
        real_open = os.open
        real_close = os.close
        opened: list[int] = []

        def observed_open(*args: object, **kwargs: object) -> int:
            descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
            opened.append(descriptor)
            return descriptor

        custody = descriptor_custody("loader pending handler entry")
        custody.state = "closed"
        try:
            with mock.patch.object(
                os,
                "open",
                side_effect=observed_open,
            ), self.assertRaisesRegex(KeyboardInterrupt, "loader handler entry"):
                with interrupt_once_on_opcode(
                    open_code,
                    handler_entry,
                    "loader handler entry",
                ) as fired:
                    custody.open("/dev/null", os.O_RDONLY)
            self.assertTrue(fired[0])
            self.assertEqual(len(opened), 1)
            self.assertIsNotNone(custody.pending_acquisition)
            os.fstat(opened[0])
            custody.close()
            with self.assertRaises(OSError):
                os.fstat(opened[0])
            self.assertIsNone(custody.pending_acquisition)
            self.assertEqual(custody.descriptors, [])
            self.assertEqual(custody.state, "closed")
        finally:
            for descriptor in opened:
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                real_close(descriptor)

    def test_loader_reentrant_close_cannot_consume_active_open(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        open_code = descriptor_custody.open.__code__
        instructions = list(dis.get_instructions(open_code))
        capture_load = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.argval == "_capture_producer_result"
        )
        capture_call = next(
            index
            for index in range(capture_load, len(instructions))
            if instructions[index].opname.startswith("CALL")
        )
        boundaries = (
            ("loader after active capture", instructions[capture_call + 1].offset),
            (
                "loader at active return",
                next(
                    instruction.offset
                    for instruction in instructions
                    if instruction.opname == "RETURN_VALUE"
                ),
            ),
        )
        real_close = os.close
        for label, offset in boundaries:
            custody = descriptor_custody(label)
            observed: list[BaseException] = []
            fired = [False]

            def trace(frame: object, event: str, _argument: object):  # type: ignore[no-untyped-def]
                if getattr(frame, "f_code") is open_code:
                    setattr(frame, "f_trace_opcodes", True)
                    if (
                        not fired[0]
                        and event == "opcode"
                        and getattr(frame, "f_lasti") == offset
                    ):
                        fired[0] = True
                        try:
                            custody.close()
                        except BaseException as error:
                            observed.append(error)
                return trace

            descriptor: int | None = None
            calls: list[int] = []

            def observed_close(value: int) -> None:
                calls.append(value)
                real_close(value)

            previous = sys.gettrace()
            try:
                sys.settrace(trace)
                descriptor = custody.open("/dev/null", os.O_RDONLY)
            finally:
                sys.settrace(previous)
            try:
                self.assertTrue(fired[0])
                self.assertEqual(len(observed), 1)
                self.assertIsInstance(observed[0], SystemExit)
                self.assertIn("acquisition is still active", str(observed[0]))
                assert descriptor is not None
                os.fstat(descriptor)
                with mock.patch.object(
                    os,
                    "close",
                    side_effect=observed_close,
                ):
                    custody.close()
                self.assertEqual(calls, [descriptor])
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            finally:
                if descriptor is not None:
                    try:
                        os.fstat(descriptor)
                    except OSError:
                        pass
                    else:
                        real_close(descriptor)

    def test_loader_restore_and_close_boundary_matrices_persist_first_error(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        restore_ast = class_method_ast(loader, "DescriptorCustody", "_restore_roster")
        restore_assignment = next(
            node
            for node in ast.walk(restore_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "descriptors"
                for target in node.targets
            )
        )
        restore_return = next(
            node
            for node in ast.walk(restore_ast)
            if isinstance(node, ast.Return) and node.lineno > restore_assignment.lineno
        )
        after_restore = min(
            (
                node
                for node in ast.walk(restore_ast)
                if isinstance(node, ast.If)
                and any(
                    isinstance(value, ast.Name) and value.id == "first_error"
                    for value in ast.walk(node.test)
                )
                and restore_assignment.lineno < node.lineno < restore_return.lineno
            ),
            key=lambda node: node.lineno,
        )
        registration_type = descriptor_custody.close.__globals__["DescriptorRegistration"]
        for label, line in (
            ("loader_before_restore_swap", restore_assignment.lineno),
            ("loader_after_restore_swap", after_restore.lineno),
            ("loader_before_restore_return", restore_return.lineno),
        ):
            prior = registration_type(39)
            prior.published = True
            custody = descriptor_custody(label)
            custody.descriptors = [prior]
            custody.state = "closed"
            with self.subTest(boundary=label), mock.patch.object(
                os,
                "open",
                return_value=40,
            ), mock.patch.object(os, "close") as close, self.assertRaisesRegex(
                SystemExit,
                "registration is unavailable",
            ) as raised, interrupt_once_on_line(
                    descriptor_custody._restore_roster.__code__,
                    line,
                    label,
                ) as fired:
                    custody.open("ignored", os.O_RDONLY)
            self.assertTrue(fired[0])
            close.assert_called_once_with(40)
            self.assertEqual(custody.descriptors, [prior])
            self.assertIn(label, "\n".join(raised.exception.__notes__))

        close_ast = class_method_ast(loader, "DescriptorCustody", "_close_once")
        invoke_line = next(
            node.lineno
            for node in ast.walk(close_ast)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_invoke_closer"
        )
        finished_line = next(
            node.lineno
            for node in ast.walk(close_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "close_finished"
                for target in node.targets
            )
            and node.lineno > invoke_line
        )
        for label, line in (
            ("loader_pre_close_before_syscall", invoke_line),
            ("loader_after_close_before_finished", finished_line),
        ):
            custody = descriptor_custody(label)
            with mock.patch.object(os, "open", return_value=40):
                custody.open("ignored", os.O_RDONLY)
            with self.subTest(boundary=label), mock.patch.object(
                os,
                "close",
            ) as close, self.assertRaisesRegex(KeyboardInterrupt, label) as first:
                with interrupt_once_on_line(
                    descriptor_custody._close_once.__code__,
                    line,
                    label,
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            close.assert_called_once_with(40)
            self.assertEqual(custody.descriptors, [])
            self.assertEqual(custody.state, "closed")
            with self.assertRaises(KeyboardInterrupt) as retried:
                custody.close()
            self.assertIs(retried.exception, first.exception)

    def test_loader_hostile_three_descriptor_cleanup_attempts_all(self) -> None:
        descriptor_custody = self._descriptor_custody_type()

        class HostileCleanupError(OSError):
            def __str__(self) -> str:
                raise MemoryError("hostile loader cleanup rendering")

        first = OSError("first loader cleanup failure")
        hostile = HostileCleanupError()
        custody = descriptor_custody("loader three-descriptor cleanup")
        with mock.patch.object(os, "open", side_effect=(40, 41, 42)):
            custody.open("first", os.O_RDONLY)
            custody.open("second", os.O_RDONLY)
            custody.open("third", os.O_RDONLY)
        with mock.patch.object(
            os,
            "close",
            side_effect=(first, hostile, None),
        ) as close, self.assertRaises(OSError) as raised:
            custody.close()
        self.assertEqual(close.call_args_list, [mock.call(42), mock.call(41), mock.call(40)])
        self.assertIs(raised.exception, first)
        self.assertIn(
            "<unprintable HostileCleanupError>",
            "\n".join(first.__notes__),
        )
        self.assertEqual(custody.descriptors, [])
        self.assertEqual(custody.state, "closed")

    def test_loader_close_entry_retries_before_start_but_return_stops_after_start(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        close_once_ast = class_method_ast(loader, "DescriptorCustody", "_close_once")
        entry_line = min(
            node.lineno
            for node in close_once_ast.body
            if isinstance(node, ast.stmt)
        )
        return_line = max(
            node.lineno
            for node in ast.walk(close_once_ast)
            if isinstance(node, ast.Return)
        )
        for label, line, expected_calls in (
            ("loader_close_entry_before_start", entry_line, 2),
            ("loader_close_return_after_start", return_line, 1),
        ):
            custody = descriptor_custody(label)
            with mock.patch.object(os, "open", return_value=40):
                custody.open("ignored", os.O_RDONLY)
            close_once = custody._close_once
            with self.subTest(boundary=label), mock.patch.object(
                custody,
                "_close_once",
                wraps=close_once,
            ) as close_calls, mock.patch.object(
                os,
                "close",
            ) as close, self.assertRaisesRegex(
                KeyboardInterrupt,
                label,
            ) as raised:
                with interrupt_once_on_line(
                    descriptor_custody._close_once.__code__,
                    line,
                    label,
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            self.assertEqual(close_calls.call_count, expected_calls)
            close.assert_called_once_with(40)
            self.assertIn(label, str(raised.exception))
            self.assertEqual(custody.descriptors, [])
            self.assertEqual(custody.state, "closed")

    def test_loader_c_closer_guard_precedes_python_opcode_resumption(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        invoke_code = descriptor_custody._invoke_closer.__code__
        inside_invoke = next(
            instruction.offset
            for instruction in dis.get_instructions(invoke_code)
            if instruction.opname == "POP_TOP"
        )
        close_instructions = list(
            dis.get_instructions(descriptor_custody._close_once)
        )
        invoke_load = next(
            index
            for index, instruction in enumerate(close_instructions)
            if instruction.argval == "_invoke_closer"
        )
        invoke_call = next(
            index
            for index in range(invoke_load, len(close_instructions))
            if close_instructions[index].opname.startswith("CALL")
        )
        after_invoke_call = close_instructions[invoke_call + 1].offset

        real_close = os.close
        for label, code, offset in (
            ("loader inside C closer invocation", invoke_code, inside_invoke),
            (
                "loader after C closer helper call",
                descriptor_custody._close_once.__code__,
                after_invoke_call,
            ),
        ):
            custody = descriptor_custody(label)
            descriptor = custody.open("/dev/null", os.O_RDONLY)
            calls: list[int] = []

            def observed_close(value: int) -> None:
                calls.append(value)
                real_close(value)

            try:
                with self.subTest(boundary=label), mock.patch.object(
                    os,
                    "close",
                    side_effect=observed_close,
                ), self.assertRaisesRegex(KeyboardInterrupt, label):
                    with interrupt_once_on_opcode(
                        code,
                        offset,
                        label,
                    ) as fired:
                        custody.close()
                self.assertTrue(fired[0])
                self.assertEqual(calls, [descriptor])
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                self.assertEqual(custody.descriptors, [])
                self.assertEqual(custody.state, "closed")
            finally:
                try:
                    os.fstat(descriptor)
                except OSError:
                    pass
                else:
                    real_close(descriptor)

    def test_loader_error_return_interruption_preserves_close_failure(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        close_once_ast = class_method_ast(loader, "DescriptorCustody", "_close_once")
        close_line = next(
            node.lineno
            for node in ast.walk(close_once_ast)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_invoke_closer"
        )
        error_return = min(
            (
                node
                for node in ast.walk(close_once_ast)
                if isinstance(node, ast.Return)
                and isinstance(node.value, ast.Attribute)
                and node.value.attr == "close_error"
                and node.lineno > close_line
            ),
            key=lambda node: node.lineno,
        )
        error_persistence = min(
            (
                node
                for node in ast.walk(close_once_ast)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Attribute)
                    and target.attr == "close_error"
                    for target in node.targets
                )
                and node.lineno > close_line
            ),
            key=lambda node: node.lineno,
        )
        for label, line in (
            ("loader_before_cleanup_error_persistence", error_persistence.lineno),
            ("loader_cleanup_error_return_interrupted", error_return.lineno),
        ):
            first = OSError("loader descriptor close failed first")
            custody = descriptor_custody(label)
            with mock.patch.object(os, "open", return_value=40):
                custody.open("ignored", os.O_RDONLY)
            with self.subTest(boundary=label), mock.patch.object(
                os,
                "close",
                side_effect=first,
            ) as close, self.assertRaises(BaseException) as raised:
                with interrupt_once_on_line(
                    descriptor_custody._close_once.__code__,
                    line,
                    label,
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            close.assert_called_once_with(40)
            self.assertIs(raised.exception, first)
            self.assertIn(label, "\n".join(first.__notes__))
            self.assertEqual(custody.descriptors, [])
            self.assertEqual(custody.state, "closed")

    def test_loader_cleanup_activation_bookkeeping_cannot_veto_close(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]

        class FailingActivationRoster(set[int]):
            def add(self, _value: int) -> None:
                raise MemoryError("loader activation roster allocation failed")

        custody = descriptor_custody("loader cleanup activation")
        custody.active_cleanup_tokens = FailingActivationRoster()
        with mock.patch.object(os, "open", return_value=40):
            custody.open("ignored", os.O_RDONLY)
        with mock.patch.object(os, "close") as close:
            custody.close()
        close.assert_called_once_with(40)
        self.assertEqual(custody.descriptors, [])
        self.assertEqual(custody.state, "closed")

        close_once_ast = class_method_ast(loader, "DescriptorCustody", "_close_once")
        self.assertNotIn("active_cleanup_tokens", loader)
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"add", "discard"}
                for node in ast.walk(close_once_ast)
            )
        )
        self.assertNotIn("active_cleanup", loader)
        self.assertTrue(hasattr(descriptor_custody, "_cleanup_is_active"))

        registration_type = descriptor_custody.close.__globals__["DescriptorRegistration"]
        custody = descriptor_custody("loader abandoned cleanup generation")
        with mock.patch.object(os, "open", return_value=41):
            custody.open("ignored", os.O_RDONLY)
        registration = custody.descriptors[0]
        self.assertIsInstance(registration, registration_type)
        registration.close_started = True
        registration.close_finished = False
        registration.close_error = None
        self.assertFalse(custody._cleanup_is_active(registration))
        with mock.patch.object(os, "close") as close, self.assertRaisesRegex(
            SystemExit,
            "invocation is ambiguous",
        ) as raised:
            custody.close()
        close.assert_not_called()
        self.assertIs(registration.close_error, raised.exception)
        self.assertTrue(registration.close_finished)
        self.assertEqual(custody.descriptors, [])
        self.assertEqual(custody.state, "closed")

    def test_loader_open_to_closing_and_final_settlement_are_resumable(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        close_method = class_method_ast(loader, "DescriptorCustody", "close")
        transition = next(
            node
            for node in ast.walk(close_method)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "state"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and node.value.value == "closing"
        )
        after_transition = min(
            node.lineno
            for node in ast.walk(close_method)
            if isinstance(node, ast.stmt) and node.lineno > transition.lineno
        )
        completed = next(
            node
            for node in ast.walk(close_method)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "completed"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and node.value.value is True
        )
        final_settlement = min(
            node.lineno
            for node in ast.walk(close_method)
            if isinstance(node, ast.stmt) and node.lineno > completed.lineno
        )
        for label, line in (
            ("loader_after_open_to_closing", after_transition),
            ("loader_after_completed_before_settlement", final_settlement),
        ):
            custody = descriptor_custody(label)
            with mock.patch.object(os, "open", return_value=40):
                custody.open("ignored", os.O_RDONLY)
            with self.subTest(boundary=label), mock.patch.object(
                os,
                "close",
            ) as close:
                with self.assertRaisesRegex(KeyboardInterrupt, label):
                    with interrupt_once_on_line(
                        descriptor_custody.close.__code__,
                        line,
                        label,
                    ) as fired:
                        custody.close()
                self.assertTrue(fired[0])
                custody.close()
                close.assert_called_once_with(40)
            self.assertEqual(custody.descriptors, [])
            self.assertEqual(custody.state, "closed")

    def test_loader_incomplete_close_rejects_new_generation_until_resume(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        close_ast = class_method_ast(loader, "DescriptorCustody", "close")
        transition = next(
            node
            for node in ast.walk(close_ast)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute) and target.attr == "state"
                for target in node.targets
            )
            and isinstance(node.value, ast.Constant)
            and node.value.value == "closing"
        )
        after_transition = min(
            node.lineno
            for node in ast.walk(close_ast)
            if isinstance(node, ast.stmt) and node.lineno > transition.lineno
        )
        custody = descriptor_custody("loader incomplete close")
        with mock.patch.object(os, "open", return_value=40):
            custody.open("existing", os.O_RDONLY)
        with mock.patch.object(os, "close") as close:
            with self.assertRaisesRegex(KeyboardInterrupt, "loader interrupted"):
                with interrupt_once_on_line(
                    descriptor_custody.close.__code__,
                    after_transition,
                    "loader interrupted",
                ) as fired:
                    custody.close()
            self.assertTrue(fired[0])
            self.assertEqual(custody.state, "closing")
            self.assertEqual(len(custody.descriptors), 1)
            with mock.patch.object(
                os,
                "open",
                return_value=41,
            ), self.assertRaisesRegex(SystemExit, "unavailable"):
                custody.open("new", os.O_RDONLY)
            self.assertEqual(close.call_args_list, [mock.call(41)])
            custody.close()
        self.assertEqual(close.call_args_list, [mock.call(41), mock.call(40)])
        self.assertEqual(custody.state, "closed")

    def test_loader_terminal_roster_errors_are_resumable_at_every_boundary(
        self,
    ) -> None:
        descriptor_custody = self._descriptor_custody_type()
        loader = WRAPPER.read_text(encoding="utf-8").split(
            "read -r -d '' pinned_loader <<'PY' || true\n",
            1,
        )[1].split("\nPY\n", 1)[0]
        close_ast = class_method_ast(loader, "DescriptorCustody", "close")
        publish_ast = class_method_ast(
            loader,
            "DescriptorCustody",
            "_publish_terminal_error",
        )
        terminal_publications = [
            node
            for node in ast.walk(publish_ast)
            if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Tuple)
        ]
        self.assertEqual(len(terminal_publications), 1)
        terminal_publish = terminal_publications[0]
        self.assertEqual(
            [target.attr for target in terminal_publish.targets[0].elts],
            ["close_error", "close_finished"],
        )
        self.assertEqual(terminal_publish.lineno, terminal_publish.end_lineno)
        self.assertIsInstance(terminal_publish.value, ast.Tuple)
        self.assertEqual(
            [
                value.id if isinstance(value, ast.Name) else value.value
                for value in terminal_publish.value.elts
            ],
            ["error", True],
        )
        registration_type = descriptor_custody.close.__globals__["DescriptorRegistration"]
        for error_name, descriptors, expected_calls, error_pattern in (
            ("invalid_error", (-1,), [], "descriptor is invalid"),
            ("alias_error", (41, 41), [mock.call(41)], "roster aliases"),
        ):
            error_publish = next(
                node
                for node in ast.walk(close_ast)
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == error_name
                    for target in node.targets
                )
            )
            publish_call = (
                error_publish.value
                if error_name == "invalid_error"
                else min(
                    (
                        node
                        for node in ast.walk(close_ast)
                        if isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "_publish_terminal_error"
                        and len(node.args) == 2
                        and isinstance(node.args[1], ast.Name)
                        and node.args[1].id == "alias_error"
                        and node.lineno > error_publish.lineno
                    ),
                    key=lambda node: node.lineno,
                )
            )
            self.assertIsInstance(publish_call, ast.Call)
            record_arg = (
                "invalid_error"
                if error_name == "invalid_error"
                else "observed_error"
            )
            record_call = min(
                (
                    node
                    for node in ast.walk(close_ast)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "_record_cleanup_error"
                    and len(node.args) == 1
                    and isinstance(node.args[0], ast.Name)
                    and node.args[0].id == record_arg
                    and node.lineno > publish_call.lineno
                ),
                key=lambda node: node.lineno,
            )
            for boundary, line in (
                ("before_error", error_publish.lineno),
                ("before_terminal_publish", publish_call.lineno),
                ("after_terminal_publish", record_call.lineno),
            ):
                label = f"loader_{error_name}_{boundary}"
                custody = descriptor_custody(label)
                custody.descriptors = [
                    registration_type(descriptor) for descriptor in descriptors
                ]
                registration = custody.descriptors[0]
                with self.subTest(
                    error=error_name,
                    boundary=boundary,
                ), mock.patch.object(os, "close") as close:
                    with self.assertRaisesRegex(KeyboardInterrupt, label):
                        with interrupt_once_on_line(
                            descriptor_custody.close.__code__,
                            line,
                            label,
                        ) as fired:
                            custody.close()
                    self.assertTrue(fired[0])
                    self.assertEqual(custody.state, "closing")
                    if boundary == "after_terminal_publish":
                        self.assertIsInstance(registration.close_error, SystemExit)
                        self.assertFalse(registration.close_started)
                        self.assertTrue(registration.close_finished)
                    else:
                        self.assertIsNone(registration.close_error)
                        self.assertFalse(registration.close_started)
                        self.assertFalse(registration.close_finished)
                    self.assertIsNone(custody.cleanup_error)
                    close.assert_not_called()
                    with self.assertRaisesRegex(
                        SystemExit,
                        error_pattern,
                    ) as raised:
                        custody.close()
                self.assertEqual(close.call_args_list, expected_calls)
                self.assertIsNotNone(custody.cleanup_error)
                self.assertIs(registration.close_error, custody.cleanup_error)
                self.assertFalse(registration.close_started)
                self.assertTrue(registration.close_finished)
                self.assertIs(raised.exception, custody.cleanup_error)
                self.assertEqual(custody.descriptors, [])
                self.assertEqual(custody.state, "closed")

    def test_loader_terminal_error_publication_prefixes_are_resumable(
        self,
    ) -> None:
        descriptor_custody = self._descriptor_custody_type()
        registration_type = descriptor_custody.close.__globals__["DescriptorRegistration"]
        for scenario, descriptor, error_pattern in (
            ("alias_seeded_first", 41, "roster aliases"),
            ("alias_seeded_last", 41, "roster aliases"),
            ("invalid_negative", -1, "descriptor is invalid"),
            ("invalid_boolean", True, "descriptor is invalid"),
            ("invalid_text", "invalid", "descriptor is invalid"),
        ):
            for seeded_error, close_started, close_finished in (
                (False, False, False),
                (True, False, False),
                (False, False, True),
                (False, True, False),
                (False, True, True),
                (True, True, False),
                (True, True, True),
            ):
                if scenario.startswith("alias"):
                    registration = registration_type(41)
                    unique = registration_type(41)
                    descriptors = (
                        [registration, unique]
                        if scenario == "alias_seeded_first"
                        else [unique, registration]
                    )
                else:
                    registration = registration_type(descriptor)
                    descriptors = [registration]
                if seeded_error:
                    registration.close_error = SystemExit(f"seeded {error_pattern}")
                registration.close_started = close_started
                registration.close_finished = close_finished
                custody = descriptor_custody(
                    f"loader {scenario} prefix {seeded_error} "
                    f"{close_started} {close_finished}"
                )
                custody.descriptors = descriptors
                with self.subTest(
                    scenario=scenario,
                    seeded_error=seeded_error,
                    close_started=close_started,
                    close_finished=close_finished,
                ), mock.patch.object(os, "close") as close:
                    with self.assertRaisesRegex(SystemExit, error_pattern) as raised:
                        custody.close()
                if scenario.startswith("alias"):
                    authority_is_seeded = (
                        close_started or scenario == "alias_seeded_last"
                    )
                    seeded_is_terminal = (
                        seeded_error or close_started or close_finished
                    )
                    expected_calls = (
                        []
                        if authority_is_seeded and seeded_is_terminal
                        else [mock.call(41)]
                    )
                else:
                    expected_calls = []
                self.assertEqual(close.call_args_list, expected_calls)
                self.assertIs(raised.exception, custody.cleanup_error)
                self.assertIn(error_pattern, str(custody.cleanup_error))
                registration_was_invoked = (
                    scenario == "alias_seeded_last" and not seeded_is_terminal
                    if scenario.startswith("alias")
                    else False
                )
                self.assertEqual(
                    registration.close_started,
                    close_started or registration_was_invoked,
                )
                self.assertTrue(
                    all(owned.close_finished for owned in descriptors)
                )
                if not scenario.startswith("alias"):
                    self.assertIs(registration.close_error, custody.cleanup_error)
                self.assertEqual(custody.descriptors, [])
                self.assertEqual(custody.state, "closed")

    def test_loader_distinct_tokens_aliasing_one_fd_close_at_most_once(self) -> None:
        descriptor_custody = self._descriptor_custody_type()
        registration_type = descriptor_custody.close.__globals__["DescriptorRegistration"]
        custody = descriptor_custody("loader descriptor aliases")
        custody.descriptors = [registration_type(40), registration_type(40)]
        with mock.patch.object(os, "close") as close, self.assertRaisesRegex(
            SystemExit,
            "aliases one descriptor",
        ):
            custody.close()
        close.assert_called_once_with(40)
        self.assertEqual(custody.descriptors, [])
        self.assertEqual(custody.state, "closed")

        first = registration_type(41)
        started = registration_type(41)
        third = registration_type(41)
        started.close_started = True
        started.close_finished = True
        custody = descriptor_custody("loader started descriptor alias group")
        custody.descriptors = [first, started, third]
        with mock.patch.object(os, "close") as close, self.assertRaisesRegex(
            SystemExit,
            "roster aliases",
        ):
            custody.close()
        close.assert_not_called()
        self.assertTrue(all(item.close_finished for item in (first, started, third)))
        self.assertFalse(first.close_started)
        self.assertTrue(started.close_started)
        self.assertFalse(third.close_started)
        self.assertEqual(custody.descriptors, [])
        self.assertEqual(custody.state, "closed")

    def test_resume_success_cannot_precede_loader_owner_settlement(self) -> None:
        wrapper = WRAPPER.read_text(encoding="utf-8")
        resume = wrapper[
            wrapper.index("def execute_resume_owned")
            : wrapper.index('if mode == "repo":\n    execute_source')
        ]
        self.assertIn(
            "execute_source(source, display_name, control_root_fd, custody)",
            resume,
        )
        reducer = MODULE_PATH.read_text(encoding="utf-8")
        authority_open = reducer[
            reducer.index("    def open(cls, custody: ResourceCustody)")
            : reducer.index(
                "    @property\n    def phase",
                reducer.index("class ControlAuthority"),
            )
        ]
        self.assertLess(
            authority_open.index("held_owner.close()"),
            authority_open.index("return cls(descriptor, control, state)"),
        )
        operation_resume = reducer[
            reducer.index("def operation_resume") : reducer.index("def parser")
        ]
        self.assertIn("control = ControlAuthority.open(control_custody)", operation_resume)
        main = reducer[reducer.index("def main()") : reducer.index('if __name__ == "__main__"')]
        self.assertLess(
            main.index("result = operation_resume"),
            main.index("print(json.dumps(result"),
        )

    def test_verify_only_has_no_output_file_argument(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        verify = source[source.index("  verify-only)") : source.index("  drain)")]
        self.assertIn('invoke_tool repo "${tool}"', verify)
        self.assertNotIn("output", verify.lower())


if __name__ == "__main__":
    unittest.main()
