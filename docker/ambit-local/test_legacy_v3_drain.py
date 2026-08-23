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
) -> MODULE.TaskNamespaceCensus:
    return MODULE.TaskNamespaceCensus(
        frozenset(current),
        frozenset(namespace_fds),
        mounts,
        digest,
        {
            "currentNamespaceCount": len(current),
            "namespaceFdCount": len(namespace_fds),
            "mountNamespaceCount": len(mounts),
            "proofSha256": digest,
        },
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
            source.index("def capture_process")
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
        closed: list[str] = []
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
                security_state=row["securityState"],
            )
            task.close.side_effect = (
                lambda value=f"{row['pid']}/{row['taskId']}": closed.append(value)
            )
            tasks.append(task)
        with mock.patch.object(
            MODULE,
            "require_related_process_cutoff",
            return_value={"related": rows},
        ), mock.patch.object(
            MODULE,
            "capture_task",
            side_effect=tasks,
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE, "reprove_captured_task"
        ), mock.patch.object(
            MODULE, "process_authority", return_value={}
        ), mock.patch.object(
            MODULE, "exact_process_status", return_value="exact"
        ):
            with MODULE.hold_related_process_cutoff(
                {"authority": {}}, allowed_roles=roles
            ):
                self.assertEqual(closed, [])
        self.assertEqual(sorted(closed), ["1/1", "1/3", "2/2"])

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
            security_state=security_state,
        )
        with mock.patch.object(
            MODULE,
            "require_related_process_cutoff",
            side_effect=(original, changed),
        ), mock.patch.object(
            MODULE, "capture_task", return_value=task
        ), mock.patch.object(
            MODULE, "pidfd_exited", return_value=False
        ), mock.patch.object(
            MODULE, "reprove_captured_task"
        ), mock.patch.object(
            MODULE, "process_authority", return_value={}
        ), mock.patch.object(
            MODULE, "exact_process_status", return_value="exact"
        ), self.assertRaisesRegex(MODULE.DrainError, "entering the action cutoff"):
            with MODULE.hold_related_process_cutoff(
                {"authority": {}},
                allowed_roles={"dockerd"},
            ):
                self.fail("a changed task roster reached the action")
        task.close.assert_called_once_with()

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
            security_state=security_state,
        )
        with mock.patch.object(
            MODULE, "require_related_process_cutoff", return_value=proof
        ), mock.patch.object(
            MODULE, "capture_task", return_value=task
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
        ):
            with MODULE.hold_related_process_cutoff(
                {"authority": {}},
                allowed_roles={"dockerd"},
            ):
                pass
        task.close.assert_called_once_with()

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
        ), mock.patch.object(MODULE.os, "close"):
            task = MODULE.capture_task(100, 101)
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual((task.parent_pid, task.start_ticks), (1, 77))
            self.assertEqual(task.security_state, self._root_security())
            task.close()
        pidfd_open.assert_called_once_with(101, MODULE.PIDFD_THREAD)

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
        namespaces = {
            "mountNamespace": {"device": 4, "inode": 1},
            "networkNamespace": {"device": 4, "inode": 2},
            "pidNamespace": {"device": 4, "inode": 3},
            "userNamespace": {"device": 4, "inode": 4},
        }
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
            "namespaces": {},
            "namespaceFds": [],
            "relations": [],
        }
        worker = {
            "pid": 100,
            "taskId": 101,
            "parentPid": 1,
            "startTimeTicks": 11,
            "securityState": root_security,
            "namespaces": {},
            "namespaceFds": [],
            "relations": ["runtimeFdInode"],
        }

        def observation(row: dict[str, object], offset: int) -> object:
            return MODULE.ProcessReferenceObservation(row, 30 + offset, 40 + offset)

        scans = (
            observation(leader, 0),
            observation(worker, 1),
            observation(dict(leader), 2),
            observation(dict(worker), 3),
        )
        with mock.patch.object(
            MODULE, "process_task_coordinates_once", return_value=((100, 100), (100, 101))
        ), mock.patch.object(
            MODULE, "process_reference_scan", side_effect=scans
        ), mock.patch.object(
            MODULE.os, "stat", return_value=mock.Mock(st_ino=1)
        ), mock.patch.object(
            MODULE, "reprove_captured_task"
        ), mock.patch.object(MODULE.os, "close"):
            proof = MODULE._related_process_universe_once(
                processes,
                {"tree": [], "rootIdentity": {"device": 1, "inode": 2}},
                {"unixRecords": []},
                namespace_census(),
                allowed_roles={"dockerd"},
            )
        self.assertEqual(
            [(row["pid"], row["taskId"]) for row in proof["related"]],
            [(100, 100), (100, 101)],
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
            source.index("def task_namespace_census_once")
            : source.index("def stable_task_namespace_census")
        ]
        self.assertIn("process_task_coordinates_once()", namespace_census_source)
        self.assertIn("capture_task", namespace_census_source)
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
        self.assertEqual(collection.count("stable_task_namespace_census()"), 1)
        self.assertGreaterEqual(collection.count("namespace_census="), 4)

    def test_source_covers_empty_argv_maps_namespace_fds_and_pid_reuse(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn('"runtimeMappedPath"', source)
        self.assertIn('"runtimeNamespaceFd"', source)
        self.assertIn('"privateRuntimeNamespace"', source)
        self.assertIn("recorded legacy process PID was reused", source)
        self.assertNotIn("if not raw_arguments:\n                second_parent", source)
        self.assertNotIn("admitted_namespace_tokens", source)
        self.assertNotIn("unclassifiedNamespaceFd", source)
        self.assertNotIn("mount namespace visibility differs across representatives", source)
        self.assertIn('"ambient_current"', source)
        self.assertIn('"queuedScmRightsNamespaceFds"', source)

    def test_namespace_fd_current_owned_and_detached_classification_is_exact(self) -> None:
        ambient = MODULE.NamespaceIdentity("mnt", 4, 100)
        owned = MODULE.NamespaceIdentity("mnt", 4, 101)
        detached = MODULE.NamespaceIdentity("mnt", 4, 102)
        current = frozenset((ambient, owned))
        self.assertEqual(
            MODULE.classify_namespace_fd(
                ambient,
                current=current,
                owned=frozenset((owned,)),
            ),
            "ambient_current",
        )
        self.assertEqual(
            MODULE.classify_namespace_fd(
                owned,
                current=current,
                owned=frozenset((owned,)),
            ),
            "owned",
        )
        self.assertEqual(
            MODULE.classify_namespace_fd(
                detached,
                current=current,
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

    def test_namespace_census_churn_between_passes_rejects(self) -> None:
        stable = namespace_census(digest="1" * 64)
        changed = namespace_census(digest="2" * 64)
        with mock.patch.object(
            MODULE,
            "task_namespace_census_once",
            side_effect=(stable, changed),
        ), self.assertRaisesRegex(MODULE.DrainError, "changed across proof passes"):
            MODULE.stable_task_namespace_census()

    def test_exact_process_status_uses_the_real_exact_vocabulary(self) -> None:
        recorded = captured_process().authority
        with mock.patch.object(MODULE, "process_exists", return_value=True), mock.patch.object(
            MODULE, "capture_process", return_value=captured_process()
        ):
            self.assertEqual(MODULE.exact_process_status(recorded), "exact")

    def test_socket_owner_permission_denial_is_not_treated_as_absence(self) -> None:
        task = mock.Mock(process_fd=10, pidfd=11)
        with mock.patch.object(
            MODULE, "process_task_coordinates_once", return_value=((1, 3),)
        ), mock.patch.object(
            MODULE, "capture_task", return_value=task
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
        with mock.patch.object(
            MODULE, "process_task_coordinates_once", return_value=((100, 101),)
        ), mock.patch.object(
            MODULE, "capture_task", return_value=task
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
            MODULE._verify_runtime_entry_no_follow(
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
            observed=self.symlink_identity(),
            link_target=MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
        )
        with mock.patch.object(
            MODULE.os, "listdir", return_value=("work",)
        ), mock.patch.object(
            MODULE, "_verify_runtime_entry_no_follow", return_value=proof
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
        ) as opened, mock.patch.object(MODULE.os, "fsync"):
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
        proof.close.assert_called_once_with()

    def test_name_swap_blocks_before_unlink_and_absence_is_replay(self) -> None:
        proof = mock.Mock(
            observed=self.symlink_identity(),
            link_target=MODULE.EXPECTED_CONTAINERD_WORK_TARGET,
        )
        with mock.patch.object(
            MODULE.os, "listdir", return_value=("work",)
        ), mock.patch.object(
            MODULE, "_verify_runtime_entry_no_follow", return_value=proof
        ), mock.patch.object(
            MODULE,
            "_reprove_runtime_entry_name",
            side_effect=MODULE.DrainError("name binding differs"),
        ), mock.patch.object(MODULE.os, "unlink") as unlink, self.assertRaisesRegex(
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
        proof.close.assert_called_once_with()

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

    def test_mount_namespace_without_full_root_representative_rejects(self) -> None:
        identity, _full, restricted = self.canonical_and_restricted_views()
        with self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "no proven full-root representative",
        ):
            MODULE.build_mount_namespace_authority(identity, (restricted,))

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
            {("net", 4026531833)},
        )
        with self.assertRaisesRegex(
            MODULE.ManualRecoveryRequired,
            "no live representative",
        ):
            MODULE.require_mounted_namespace_representatives(
                (authority,),
                set(),
            )

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

    def test_duplicate_same_source_ambient_occurrence_is_rejected(self) -> None:
        owned = str(MODULE.TASK_NETNS_TARGET)
        raw = f"21 20 0:4 net:[4026531833] {owned} rw - nsfs nsfs rw\n"
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
        with mock.patch.object(MODULE.Path, "read_text", return_value=raw), mock.patch.object(
            MODULE,
            "stable_global_mount_roster",
            return_value={"occurrences": occurrences},
        ), self.assertRaisesRegex(MODULE.ManualRecoveryRequired, "foreign target"):
            MODULE.netns_baseline()

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
        with mock.patch.object(MODULE.socket, "socket", return_value=fake), mock.patch.object(
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
        ) as rename:
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
        with mock.patch.object(
            MODULE, "recorded_legacy_receipt_bytes", return_value=b"receipt"
        ), mock.patch.object(
            MODULE,
            "_read_regular_at",
            side_effect=lambda *_args, **_kwargs: events.append("read")
            or (31, observed, b"receipt"),
        ), mock.patch.object(
            MODULE, "_require_legacy_receipt"
        ), mock.patch.object(
            MODULE.os,
            "fsync",
            side_effect=lambda _fd: events.append("fsync"),
        ):
            descriptor = MODULE.open_or_publish_prepared_archive(
                {"authority": {"legacyReceipt": {}}},
                20,
            )
        self.assertEqual(descriptor, 31)
        self.assertEqual(events[:2], ["fsync", "read"])

    def test_terminal_archive_response_loss_settles_and_rejects_live_original(self) -> None:
        events: list[str] = []
        observed = mock.Mock()
        values = iter((None, (31, observed, b"archive")))
        with mock.patch.object(
            MODULE, "recorded_evidence_descriptors", return_value=(10, 20)
        ), mock.patch.object(
            MODULE,
            "_read_regular_at",
            side_effect=lambda *_args, **_kwargs: events.append("read")
            or next(values),
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
        with mock.patch.object(
            MODULE, "recorded_evidence_descriptors", return_value=(10, 20)
        ), mock.patch.object(
            MODULE, "_read_regular_at", side_effect=lambda *_args, **_kwargs: next(live_and_archive)
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

    def test_reboot_recovery_is_bound_before_terminal_mutation(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        recovery = source[
            source.index("def recover_terminal_archive_without_control")
            : source.index("def write_projection")
        ]
        self.assertLess(
            recovery.index("state_fd = os.open("),
            recovery.index("read_terminal_projection_without_control(evidence_fd)"),
        )
        self.assertIn('stored_control = projection["control"]', recovery)
        self.assertIn('v5_state["legacyRuntime"] is None', recovery)
        self.assertIn("require_related_process_cutoff(\n            stored_control", recovery)
        self.assertIn("process_cutoff[\"related\"] == []", recovery)
        self.assertNotIn("require_no_boot_recovery_related_processes", recovery)
        self.assertIn("registry_inventory() == authority", recovery)
        self.assertIn("anchors_from_document(recorded_mounts)", recovery)
        last_binding = recovery.rindex("require_recovery_state_binding")
        self.assertLess(last_binding, recovery.index("link_tmpfile_noreplace_at(\n            prepared_fd"))


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
        resume = source[source.index("  resume)") : source.index("  *)")]
        self.assertIn('invoke_tool resume "${control_root}"', resume)
        self.assertIn('invoke_tool repo "${tool}"', resume)

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

    def test_verify_only_has_no_output_file_argument(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        verify = source[source.index("  verify-only)") : source.index("  drain)")]
        self.assertIn('invoke_tool repo "${tool}"', verify)
        self.assertNotIn("output", verify.lower())


if __name__ == "__main__":
    unittest.main()
