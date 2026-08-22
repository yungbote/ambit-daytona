#!/usr/bin/python3
"""Verify and drain one fully evidenced pre-v5 local Daytona runtime.

This is deliberately a remove-only compatibility boundary for the one live
legacy-v3 runtime created on 2026-08-20.  It never starts Docker, adopts old
storage as current authority, changes a cgroup, force-kills a process, or
removes persistent data.  `verify-only` performs no writes.  `drain` and
`resume` require root, the current v5 global lease, a durable legacy-specific
control record, pidfd process custody, and exact mount/socket postconditions.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence


SCHEMA = "ambit.local-daytona-legacy-v3-drain-verification/v1"
CONTROL_SCHEMA = "ambit.local-daytona-legacy-v3-drain-control/v1"
STATE_SCHEMA = "ambit.local-daytona-legacy-v3-drain-state/v1"
PROJECTION_SCHEMA = "ambit.local-daytona-legacy-v3-drain-terminal/v1"
SOURCE_TOMBSTONE_SCHEMA = "ambit.local-daytona-legacy-v3-source-tombstone/v1"
LEGACY_SCHEMA = "ambit.local-daytona-isolated-docker/v3"

EXPECTED_STATE_ROOT = Path("/home/bote/m/.local/ambit-daytona-c16b/state")
EXPECTED_RECEIPT_SHA256 = (
    "c7b6f7f5f77ae5569a918cd33a811aa855b781f3c007df6f9f19bf1d3f458c21"
)
EXPECTED_RUNTIME_ID = "1577287b8182"
EXPECTED_RUNTIME_ROOT = Path(f"/tmp/ambit-c16b-docker-{EXPECTED_RUNTIME_ID}")
EXPECTED_LEGACY_SOURCE = {
    "preRebaseRevision": "a6c90fb4df06a67da8623eff83db14c14ea4f7ed",
    "rebasedEquivalentRevision": "53d821f5536c850b538a5e1ee5427497d18991d4",
    "receiptSourceBinding": "reflog_time_and_live_byte_reconstruction_not_receipt_bound",
    "blobs": {
        "start-isolated-docker.sh": "206260b6a498e6b73ead4f2ca30084efe43e75664cf57aaf83b91f7fa8749338",
        "stop-isolated-docker.sh": "8a1c83d369cb5c1a218c2a1cfcffa2c0d001e0e3e0187bdcc94b765cf54c1203",
        "isolated_process_identity.py": "faf36ab6c8c24b0927b20796ada7046e59077ae445a687f2317b4c3d0b15c377",
        "isolated_runtime_root.py": "5451a4dff9bc6e64018de1f3c1f7edf96205546ba8d4fa00356efd97da217da8",
    },
}

RECEIPT_PATH = EXPECTED_STATE_ROOT / "evidence/outer-docker-receipt.json"
ARCHIVE_RECEIPT_PATH = (
    EXPECTED_STATE_ROOT
    / f"evidence/outer-docker-receipt.legacy-v3-{EXPECTED_RECEIPT_SHA256[:16]}.json"
)
PREPARED_ARCHIVE_PATH = (
    EXPECTED_STATE_ROOT
    / f"evidence/.outer-docker-receipt.legacy-v3-{EXPECTED_RECEIPT_SHA256[:16]}.prepared"
)
PROJECTION_PATH = EXPECTED_STATE_ROOT / "evidence/legacy-v3-drain-terminal.json"
DOCKER_CONFIG = EXPECTED_STATE_ROOT / "config/outer-docker.json"
CONTAINERD_CONFIG = EXPECTED_STATE_ROOT / "config/outer-containerd.toml"
CONTAINERD_PIDFILE = EXPECTED_STATE_ROOT / "config/outer-containerd.pid"
DOCKER_PIDFILE = EXPECTED_RUNTIME_ROOT / "docker.pid"
DOCKER_SOCKET = EXPECTED_RUNTIME_ROOT / "docker.sock"
CONTAINERD_SOCKET = EXPECTED_RUNTIME_ROOT / "containerd.sock"
TASK_NETNS_TARGET = EXPECTED_RUNTIME_ROOT / "docker-exec/netns/default"
TASK_NETNS_RELATIVE = "docker-exec/netns/default"
TASK_NETNS_MARKER_MODE = 0o600
PERSISTENT_ROOTS = (
    EXPECTED_STATE_ROOT / "outer-docker",
    EXPECTED_STATE_ROOT / "outer-containerd",
    EXPECTED_STATE_ROOT / "registry",
)
REGISTRY_STORAGE = EXPECTED_STATE_ROOT / "registry/docker/registry/v2"

GLOBAL_LEASE_PATH = Path("/run/ambit-c16b-docker-global.lock")
CONTROL_ROOT = Path(f"/run/ambit-c16b-legacy-v3-drain-{EXPECTED_RUNTIME_ID}")
CONTROL_PENDING_NAME = f".{CONTROL_ROOT.name}.pending"
CONTROL_NAME = "control.json"
STATE_NAME = "state.json"
SNAPSHOT_NAME = "legacy_v3_drain.py"

EXPECTED_DOCKER_CONFIG_SHA256 = (
    "c1a2663aa4a03db2e27f0e83bb9c78f2f60f4005273bf13c80693b81000695b1"
)
EXPECTED_CONTAINERD_CONFIG_SHA256 = (
    "e6b95e0f690cefb185718ab6fe4dd79839d8833635bb09850f78f7e797c36bff"
)
EXPECTED_CONTAINER_ID = (
    "d3777dd5521ce67fe714ed5bd1fd855d5ee7f2ed3ffa2d0786cbb67a20a07f02"
)
EXPECTED_OVERLAY_TARGET = (
    EXPECTED_STATE_ROOT
    / "outer-docker/overlay2/7cada294f2f87de67b35bcbeab5c66bc59b88ade36d2e8736e92a9b441890ecb/merged"
)
EXPECTED_REGISTRY_MANIFESTS = {
    "ambit/daytona-api": {
        "5301cee2c0d28e946927025e4d18c3f2f2df2c688b2679937e648d9a131928fb"
    },
    "ambit/daytona-proxy": {
        "d0e59627de3814f9db395d81a5f32dac168026cba4779e4188cf88b145af2b4d"
    },
    "ambit/daytona-runner": {
        "d4807a3eb7e8d7cc566ae4c41c89312f6ca4264db8fe7e81759c25c901db81ca"
    },
    "ambit/runtime-pack-core-document": {
        "2f83db61b3a73aba3ffe3532be796f0922661f3a2643fc0142484ffa37861d99",
        "bd39bc5360df9db86839b76b1dde05a97fe70f24671ca1bc1ac5008aa8523ca4",
        "de9da6cbffd22cf21e5eab2b27941e9c3b43646b521a8fbe132e9b15421012b6",
    },
}

EXPECTED_PROCESS_CANDIDATES: dict[str, dict[str, object]] = {
    "containerdWrapperOuter": {
        "pid": 960164,
        "parentPid": 1,
        "startTimeTicks": 80959891,
        "argumentsSha256": "77a7164e53355538b75586d1318d4eefef81e4b64137337435a9af9cd86e7f08",
        "executableName": "sudo",
    },
    "containerdWrapperInner": {
        "pid": 960165,
        "parentPid": 960164,
        "startTimeTicks": 80959891,
        "argumentsSha256": "77a7164e53355538b75586d1318d4eefef81e4b64137337435a9af9cd86e7f08",
        "executableName": "sudo",
    },
    "containerd": {
        "pid": 960166,
        "parentPid": 960165,
        "startTimeTicks": 80959891,
        "argumentsSha256": "7d4abe5345d3526b66e897aad0bd6d3b84f817d103a76529aec0e3edfd3c417f",
        "executable": "/usr/bin/containerd",
    },
    "dockerdWrapperOuter": {
        "pid": 960213,
        "parentPid": 1,
        "startTimeTicks": 80959925,
        "argumentsSha256": "1f282ab869478c3a7b8d1ad0d892bec6baa27e7f85a0a6a97aff5f464ee4e3dd",
        "executableName": "sudo",
    },
    "dockerdWrapperInner": {
        "pid": 960215,
        "parentPid": 960213,
        "startTimeTicks": 80959925,
        "argumentsSha256": "1f282ab869478c3a7b8d1ad0d892bec6baa27e7f85a0a6a97aff5f464ee4e3dd",
        "executableName": "sudo",
    },
    "dockerd": {
        "pid": 960217,
        "parentPid": 960215,
        "startTimeTicks": 80959925,
        "argumentsSha256": "a87b194399f06a9490236a24fb13dbf96131962bf08dada03f58267415335b58",
        "executable": "/usr/bin/dockerd",
    },
    "registryShim": {
        "pid": 964659,
        "parentPid": 1,
        "startTimeTicks": 80963614,
        "argumentsSha256": "a834f2563fa09c5aebc409149a9c88a9c82e39e54d47786cbb223cd981d74414",
        "executable": "/usr/bin/containerd-shim-runc-v2",
    },
    "registryTask": {
        "pid": 964683,
        "parentPid": 964659,
        "startTimeTicks": 80963617,
        "argumentsSha256": "082d432bf472c0fa581000acecffc36a2bd3bc4e02774eb4745eca5c5a86de7f",
        "executableName": "registry",
    },
}

PHASES = (
    "stopping_intent_final",
    "runtime_custody_transferred",
    "docker_api_revoked",
    "dockerd_stop_requested",
    "dockerd_stopped",
    "container_graph_quiesced",
    "containerd_stop_requested",
    "containerd_stopped",
    "mounts_settled",
    "runtime_reducing",
    "runtime_empty",
    "archive_intent_final",
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_NAME_RE = re.compile(r"^ambit-c16b-docker-[0-9a-f]{12}$")
V5_RUNTIME_RE = re.compile(
    r"^ambit-c16b-docker-(?:api-|removing-)?[0-9a-f]{12}$"
)
OPAQUE_MOUNT_ROOT_RE = re.compile(r"^[a-z][a-z0-9_-]*:\[[1-9][0-9]*\]$")
MOUNT_DEVICE_RE = re.compile(r"^[0-9]+:[0-9]+$")
MAX_JSON_BYTES = 2 * 1024 * 1024
CGROUP_PARENT = Path("/sys/fs/cgroup")
CGROUP_NAME_RE = re.compile(r"^ambit-c16b-docker-[0-9a-f]{12}$")
LIBC = ctypes.CDLL(None, use_errno=True)
RENAME_NOREPLACE = 1
AT_EMPTY_PATH = 0x1000
PIDFD_THREAD = os.O_EXCL
NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST = 0x1
NLM_F_MULTI = 0x2
NLM_F_DUMP = 0x300
NLM_F_DUMP_INTR = 0x10
NLMSG_ERROR = 0x2
NLMSG_DONE = 0x3
UDIAG_SHOW_NAME = 0x1
UDIAG_SHOW_PEER = 0x4
UDIAG_SHOW_ICONS = 0x8
UDIAG_SHOW_UID = 0x40
UNIX_DIAG_NAME = 0
UNIX_DIAG_PEER = 2
UNIX_DIAG_ICONS = 3
UNIX_DIAG_UID = 7


class DrainError(RuntimeError):
    """Fail-closed legacy transition error."""


class ManualRecoveryRequired(DrainError):
    """A state the default drain deliberately does not mutate."""


class ProcessUnavailable(DrainError):
    """The exact recorded process lifetime is absent."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DrainError(message)


def manual(condition: bool, message: str) -> None:
    if not condition:
        raise ManualRecoveryRequired(message)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def current_boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[0-9a-f-]{36}", value) is not None, "boot identity is invalid")
    return value


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    assert isinstance(value, dict)
    require(set(value) == expected, f"{label} field roster differs")
    return value


def plain_int(value: object, label: str, *, positive: bool = False) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} is invalid")
    assert isinstance(value, int)
    require(value > 0 if positive else value >= 0, f"{label} is invalid")
    return value


def duplicate_rejector(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DrainError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, label: str) -> object:
    require(0 < len(raw) <= MAX_JSON_BYTES, f"{label} size is invalid")
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=duplicate_rejector,
            parse_constant=lambda value: (_ for _ in ()).throw(
                DrainError(f"{label} contains invalid constant {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DrainError(f"{label} is invalid JSON") from error


def read_regular(path: Path, *, maximum: int = MAX_JSON_BYTES) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        require(stat.S_ISREG(observed.st_mode), f"regular file type differs: {path}")
        require(observed.st_nlink == 1, f"regular file link count differs: {path}")
        require(0 <= observed.st_size <= maximum, f"regular file size differs: {path}")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= maximum, f"regular file is too large: {path}")
        literal = os.stat(path, follow_symlinks=False)
        require(
            (literal.st_dev, literal.st_ino, stat.S_IFMT(literal.st_mode))
            == (observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode)),
            f"regular file binding changed: {path}",
        )
        return b"".join(chunks), observed
    finally:
        os.close(descriptor)


def hash_regular(path: Path, *, maximum: int) -> tuple[str, int, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_nlink == 1
            and 0 <= observed.st_size <= maximum,
            f"hashed file identity differs: {path}",
        )
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            require(size <= maximum, f"hashed file is too large: {path}")
            digest.update(chunk)
        require(size == observed.st_size, f"hashed file length differs: {path}")
        literal = os.stat(path, follow_symlinks=False)
        require(
            (literal.st_dev, literal.st_ino, stat.S_IFMT(literal.st_mode))
            == (observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode)),
            f"hashed file binding changed: {path}",
        )
        return digest.hexdigest(), size, observed
    finally:
        os.close(descriptor)


def exists_nofollow(path: Path) -> bool:
    try:
        os.stat(path, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def identity_document(path: Path, observed: os.stat_result) -> dict[str, object]:
    return {
        "path": str(path),
        "device": observed.st_dev,
        "inode": observed.st_ino,
        "uid": observed.st_uid,
        "gid": observed.st_gid,
        "mode": stat.S_IMODE(observed.st_mode),
        "type": stat.S_IFMT(observed.st_mode),
        "links": observed.st_nlink,
    }


def directory_identity(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_modes: set[int],
) -> dict[str, object]:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(descriptor)
        literal = os.stat(path, follow_symlinks=False)
        require(
            stat.S_ISDIR(observed.st_mode)
            and (observed.st_dev, observed.st_ino)
            == (literal.st_dev, literal.st_ino),
            f"directory identity differs: {path}",
        )
        require(
            (observed.st_uid, observed.st_gid) == (expected_uid, expected_gid)
            and stat.S_IMODE(observed.st_mode) in expected_modes,
            f"directory owner or mode differs: {path}",
        )
        return identity_document(path, observed)
    finally:
        os.close(descriptor)


def regular_identity(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    expected_sha256: str | None = None,
    maximum: int = MAX_JSON_BYTES,
) -> tuple[dict[str, object], bytes]:
    raw, observed = read_regular(path, maximum=maximum)
    require(
        (observed.st_uid, observed.st_gid, stat.S_IMODE(observed.st_mode))
        == (expected_uid, expected_gid, expected_mode),
        f"regular file owner or mode differs: {path}",
    )
    digest = sha256_bytes(raw)
    if expected_sha256 is not None:
        require(digest == expected_sha256, f"regular file digest differs: {path}")
    result = identity_document(path, observed)
    result["sha256"] = digest
    result["size"] = len(raw)
    return result, raw


def validate_legacy_process(value: object, label: str) -> dict[str, object]:
    process = exact_keys(
        value,
        {"pid", "procInode", "startTimeTicks", "executable", "argumentsSha256"},
        label,
    )
    pid = plain_int(process["pid"], f"{label} pid", positive=True)
    proc_inode = plain_int(process["procInode"], f"{label} proc inode", positive=True)
    start_ticks = plain_int(
        process["startTimeTicks"], f"{label} start ticks", positive=True
    )
    require(isinstance(process["executable"], str), f"{label} executable is invalid")
    executable = Path(str(process["executable"]))
    require(executable.is_absolute(), f"{label} executable is invalid")
    require(
        isinstance(process["argumentsSha256"], str)
        and SHA256_RE.fullmatch(str(process["argumentsSha256"])) is not None,
        f"{label} argument digest is invalid",
    )
    return {
        "pid": pid,
        "legacyProcInode": proc_inode,
        "startTimeTicks": start_ticks,
        "executable": str(executable),
        "argumentsSha256": process["argumentsSha256"],
    }


def parse_legacy_receipt(raw: bytes) -> dict[str, object]:
    receipt = exact_keys(
        parse_json_bytes(raw, "legacy v3 receipt"),
        {
            "schema",
            "outcome",
            "observedAt",
            "runtimeRoot",
            "runtimeRootIdentity",
            "socket",
            "dataRoot",
            "execRoot",
            "containerd",
            "network",
            "serverId",
            "serverVersion",
            "dockerPid",
            "dockerProcessIdentity",
            "configSha256",
        },
        "legacy v3 receipt",
    )
    require(receipt["schema"] == LEGACY_SCHEMA, "legacy receipt schema is unsupported")
    require(receipt["outcome"] == "passed", "legacy receipt outcome differs")
    require(
        isinstance(receipt["observedAt"], str)
        and 0 < len(str(receipt["observedAt"])) <= 64,
        "legacy receipt observation is invalid",
    )
    require(receipt["runtimeRoot"] == str(EXPECTED_RUNTIME_ROOT), "legacy runtime path differs")
    runtime = exact_keys(
        receipt["runtimeRootIdentity"],
        {"device", "inode", "uid", "mode"},
        "legacy runtime identity",
    )
    parsed_runtime = {
        "path": str(EXPECTED_RUNTIME_ROOT),
        "device": plain_int(runtime["device"], "legacy runtime device"),
        "inode": plain_int(runtime["inode"], "legacy runtime inode", positive=True),
        "uid": plain_int(runtime["uid"], "legacy runtime owner"),
        "mode": plain_int(runtime["mode"], "legacy runtime mode"),
    }
    require(
        parsed_runtime == {
            "path": str(EXPECTED_RUNTIME_ROOT),
            "device": 44,
            "inode": 12496265,
            "uid": 1000,
            "mode": 0o700,
        },
        "legacy runtime identity differs from the task candidate",
    )
    require(receipt["socket"] == str(DOCKER_SOCKET), "legacy Docker socket differs")
    require(
        receipt["dataRoot"] == str(EXPECTED_STATE_ROOT / "outer-docker")
        and receipt["execRoot"] == str(EXPECTED_RUNTIME_ROOT / "docker-exec"),
        "legacy Docker roots differ",
    )
    containerd = exact_keys(
        receipt["containerd"],
        {"address", "root", "version", "pid", "configSha256", "processIdentity"},
        "legacy containerd receipt",
    )
    require(
        containerd["address"] == str(CONTAINERD_SOCKET)
        and containerd["root"] == str(EXPECTED_STATE_ROOT / "outer-containerd")
        and containerd["pid"] == 960166
        and containerd["configSha256"] == EXPECTED_CONTAINERD_CONFIG_SHA256
        and isinstance(containerd["version"], str),
        "legacy containerd binding differs",
    )
    docker_process = validate_legacy_process(
        receipt["dockerProcessIdentity"], "legacy dockerd process"
    )
    containerd_process = validate_legacy_process(
        containerd["processIdentity"], "legacy containerd process"
    )
    require(
        receipt["dockerPid"] == docker_process["pid"] == 960217,
        "legacy dockerd pid binding differs",
    )
    require(
        containerd["pid"] == containerd_process["pid"],
        "legacy containerd pid binding differs",
    )
    require(
        docker_process["startTimeTicks"] == 80959925
        and docker_process["argumentsSha256"]
        == EXPECTED_PROCESS_CANDIDATES["dockerd"]["argumentsSha256"]
        and docker_process["executable"] == "/usr/bin/dockerd",
        "legacy dockerd stable identity differs",
    )
    require(
        containerd_process["startTimeTicks"] == 80959891
        and containerd_process["argumentsSha256"]
        == EXPECTED_PROCESS_CANDIDATES["containerd"]["argumentsSha256"]
        and containerd_process["executable"] == "/usr/bin/containerd",
        "legacy containerd stable identity differs",
    )
    network = exact_keys(
        receipt["network"],
        {"defaultBridge", "addressPool", "hostFirewallMutation"},
        "legacy network",
    )
    require(
        network
        == {
            "defaultBridge": "disabled",
            "addressPool": "172.30.0.0/16",
            "hostFirewallMutation": False,
        },
        "legacy network binding differs",
    )
    require(
        receipt["configSha256"] == EXPECTED_DOCKER_CONFIG_SHA256,
        "legacy Docker config digest differs",
    )
    require(
        isinstance(receipt["serverId"], str)
        and re.fullmatch(r"[0-9a-f-]{36}", str(receipt["serverId"])) is not None
        and isinstance(receipt["serverVersion"], str),
        "legacy Docker server identity is invalid",
    )
    return {
        "receipt": receipt,
        "runtime": parsed_runtime,
        "dockerd": docker_process,
        "containerd": containerd_process,
    }


def read_at(directory_fd: int, name: str, maximum: int = 2 * 1024 * 1024) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - size))
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            require(size <= maximum, f"process file is too large: {name}")
            chunks.append(chunk)
    finally:
        os.close(descriptor)


def stat_identity(stat_bytes: bytes) -> tuple[int, int]:
    closing = stat_bytes.rfind(b")")
    require(closing > 0, "process stat record is invalid")
    fields = stat_bytes[closing + 2 :].split()
    require(
        len(fields) > 19 and fields[1].isdigit() and fields[19].isdigit(),
        "process stat identity is invalid",
    )
    return int(fields[1]), int(fields[19])


def namespace_identity(process_fd: int, name: str) -> dict[str, int]:
    observed = os.stat(f"ns/{name}", dir_fd=process_fd)
    return {"device": observed.st_dev, "inode": observed.st_ino}


def pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return bool(poller.poll(0))


def process_task_coordinates_once() -> tuple[tuple[int, int], ...]:
    """Enumerate every visible task, including non-leader Linux threads."""
    result: set[tuple[int, int]] = set()
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit():
            continue
        thread_group_id = int(entry)
        task_root = Path("/proc") / entry / "task"
        try:
            task_ids = tuple(os.listdir(task_root))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as error:
            raise ManualRecoveryRequired(
                f"process task roster is unreadable: {thread_group_id}"
            ) from error
        for task in task_ids:
            require(task.isdigit(), f"process task identifier is invalid: {task}")
            result.add((thread_group_id, int(task)))
    return tuple(sorted(result))


@dataclass
class CapturedTask:
    thread_group_id: int
    task_id: int
    pidfd: int
    process_fd: int
    parent_pid: int
    start_ticks: int

    def close(self) -> None:
        os.close(self.process_fd)
        os.close(self.pidfd)


def capture_task(thread_group_id: int, task_id: int) -> CapturedTask | None:
    require(
        thread_group_id > 0 and task_id > 0,
        "process task coordinate is invalid",
    )
    require(hasattr(os, "pidfd_open"), "thread pidfd custody is unavailable")
    try:
        pidfd = os.pidfd_open(task_id, PIDFD_THREAD)
    except OSError as error:
        if error.errno == errno.ESRCH:
            return None
        raise
    process_fd: int | None = None
    keep = False
    try:
        if pidfd_exited(pidfd):
            return None
        task_path = Path("/proc") / str(thread_group_id) / "task" / str(task_id)
        try:
            process_fd = os.open(
                task_path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            observed = os.fstat(process_fd)
            literal = os.stat(task_path, follow_symlinks=False)
            status = read_at(process_fd, "status").decode("ascii", "strict")
            fields = {
                line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in status.splitlines()
                if ":" in line
            }
            parent_pid, start_ticks = stat_identity(read_at(process_fd, "stat"))
        except (FileNotFoundError, ProcessLookupError):
            if pidfd_exited(pidfd):
                return None
            raise ManualRecoveryRequired(
                f"live process task disappeared: {thread_group_id}/{task_id}"
            )
        except PermissionError as error:
            raise ManualRecoveryRequired(
                f"live process task is unreadable: {thread_group_id}/{task_id}"
            ) from error
        require(
            fields.get("Tgid") == str(thread_group_id)
            and fields.get("Pid") == str(task_id)
            and (literal.st_dev, literal.st_ino)
            == (observed.st_dev, observed.st_ino)
            and not pidfd_exited(pidfd),
            f"process task identity changed: {thread_group_id}/{task_id}",
        )
        keep = True
        return CapturedTask(
            thread_group_id,
            task_id,
            pidfd,
            process_fd,
            parent_pid,
            start_ticks,
        )
    finally:
        if process_fd is not None and not keep:
            os.close(process_fd)
        if not keep:
            os.close(pidfd)


@dataclass(frozen=True)
class CapturedProcess:
    authority: dict[str, object]
    observed_proc_inode: int


def capture_process(
    candidate: Mapping[str, object],
    *,
    expected_uid: int = 0,
) -> CapturedProcess:
    pid = plain_int(candidate.get("pid"), "candidate process pid", positive=True)
    require(hasattr(os, "pidfd_open"), "pidfd custody is unavailable")
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError as error:
        if error.errno == errno.ESRCH:
            raise ProcessUnavailable(f"candidate process is absent: {pid}") from error
        raise
    process_fd: int | None = None
    try:
        require(not pidfd_exited(pidfd), f"candidate process exited: {pid}")
        process_fd = os.open(
            Path("/proc") / str(pid),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        process_dir = os.fstat(process_fd)
        first_stat = read_at(process_fd, "stat")
        parent_pid, start_ticks = stat_identity(first_stat)
        mount_namespace = namespace_identity(process_fd, "mnt")
        network_namespace = namespace_identity(process_fd, "net")
        pid_namespace = namespace_identity(process_fd, "pid")
        user_namespace = namespace_identity(process_fd, "user")
        executable_raw = os.readlink("exe", dir_fd=process_fd)
        require(Path(executable_raw).is_absolute(), f"candidate executable path is invalid: {pid}")
        executable_stat = os.stat("exe", dir_fd=process_fd)
        require(
            stat.S_ISREG(executable_stat.st_mode)
            and executable_stat.st_uid == 0
            and executable_stat.st_gid == 0
            and stat.S_IMODE(executable_stat.st_mode) & 0o022 == 0,
            f"candidate executable authority differs: {pid}",
        )
        executable_identity = {
            "device": executable_stat.st_dev,
            "inode": executable_stat.st_ino,
            "uid": executable_stat.st_uid,
            "gid": executable_stat.st_gid,
            "mode": stat.S_IMODE(executable_stat.st_mode),
        }
        raw_arguments = read_at(process_fd, "cmdline")
        require(raw_arguments.endswith(b"\0"), f"candidate argv is invalid: {pid}")
        arguments_sha = sha256_bytes(raw_arguments)
        status = read_at(process_fd, "status").decode("ascii", "strict")
        uid_line = next((line for line in status.splitlines() if line.startswith("Uid:")), "")
        gid_line = next((line for line in status.splitlines() if line.startswith("Gid:")), "")
        uid_values = uid_line.split()[1:]
        gid_values = gid_line.split()[1:]
        require(
            len(uid_values) == 4
            and len(gid_values) == 4
            and all(value.isdigit() for value in (*uid_values, *gid_values))
            and all(int(value) == expected_uid for value in uid_values)
            and all(int(value) == expected_uid for value in gid_values),
            f"candidate process credentials differ: {pid}",
        )
        cgroup_lines = read_at(process_fd, "cgroup").decode("ascii", "strict").splitlines()
        require(
            len(cgroup_lines) == 1 and cgroup_lines[0].startswith("0::/"),
            f"candidate cgroup record differs: {pid}",
        )
        second_stat = read_at(process_fd, "stat")
        require(
            stat_identity(second_stat) == (parent_pid, start_ticks)
            and namespace_identity(process_fd, "mnt") == mount_namespace
            and namespace_identity(process_fd, "net") == network_namespace
            and namespace_identity(process_fd, "pid") == pid_namespace
            and namespace_identity(process_fd, "user") == user_namespace
            and not pidfd_exited(pidfd),
            f"candidate process changed during proof: {pid}",
        )
        expected_parent = candidate.get("parentPid")
        if expected_parent is not None:
            require(parent_pid == expected_parent, f"candidate parent differs: {pid}")
        expected_start = candidate.get("startTimeTicks")
        if expected_start is not None:
            require(start_ticks == expected_start, f"candidate start ticks differ: {pid}")
        expected_arguments = candidate.get("argumentsSha256")
        if expected_arguments is not None:
            require(arguments_sha == expected_arguments, f"candidate argv differs: {pid}")
        expected_executable = candidate.get("executable")
        if expected_executable is not None:
            expected_executable_identity = candidate.get("executableIdentity")
            if expected_executable_identity is None:
                require(
                    Path(executable_raw).resolve(strict=True)
                    == Path(str(expected_executable)).resolve(strict=True),
                    f"candidate executable differs: {pid}",
                )
            else:
                require(
                    executable_raw == expected_executable
                    and executable_identity == expected_executable_identity,
                    f"candidate executable identity differs: {pid}",
                )
        expected_name = candidate.get("executableName")
        if expected_name is not None:
            require(
                Path(executable_raw).name == expected_name,
                f"candidate executable name differs: {pid}",
            )
        return CapturedProcess(
            authority={
                "pid": pid,
                "parentPid": parent_pid,
                "startTimeTicks": start_ticks,
                "executable": executable_raw,
                "executableIdentity": executable_identity,
                "argumentsSha256": arguments_sha,
                "mountNamespace": mount_namespace,
                "networkNamespace": network_namespace,
                "pidNamespace": pid_namespace,
                "userNamespace": user_namespace,
                "cgroup": cgroup_lines[0][3:],
            },
            observed_proc_inode=process_dir.st_ino,
        )
    except FileNotFoundError as error:
        raise ProcessUnavailable(f"candidate process disappeared: {pid}") from error
    finally:
        if process_fd is not None:
            os.close(process_fd)
        os.close(pidfd)


def validate_receipt_process(
    receipt_process: Mapping[str, object],
    captured: CapturedProcess,
) -> dict[str, object]:
    for field in ("pid", "startTimeTicks", "executable", "argumentsSha256"):
        require(
            captured.authority[field] == receipt_process[field],
            f"legacy stable process field differs: {field}",
        )
    return {
        "legacyProcInode": receipt_process["legacyProcInode"],
        "observedProcInode": captured.observed_proc_inode,
        "disposition": "ignored_unstable_procfs_dentry",
    }


def unescape_mount_field(value: str) -> str:
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


@dataclass(frozen=True, order=True)
class MountRecord:
    mount_id: int
    parent_id: int
    device: str
    root: str
    target: str
    filesystem: str


def mount_records(raw: str) -> tuple[MountRecord, ...]:
    result: list[MountRecord] = []
    for line in raw.splitlines():
        fields = line.split()
        require("-" in fields, "mountinfo separator is absent")
        separator = fields.index("-")
        require(separator >= 6 and len(fields) > separator + 2, "mountinfo record is invalid")
        require(
            fields[0].isdigit() and fields[1].isdigit(),
            "mountinfo identity is invalid",
        )
        mount_id = int(fields[0])
        parent_id = int(fields[1])
        device = fields[2]
        root = unescape_mount_field(fields[3])
        target = unescape_mount_field(fields[4])
        filesystem = fields[separator + 1]
        require(MOUNT_DEVICE_RE.fullmatch(device) is not None, "mount device is invalid")
        require(Path(target).is_absolute(), "mount target is not absolute")
        if Path(root).is_absolute():
            canonical_root = os.path.normpath(root)
        else:
            require(
                filesystem == "nsfs" and OPAQUE_MOUNT_ROOT_RE.fullmatch(root) is not None,
                "opaque mount root is invalid",
            )
            canonical_root = root
        result.append(
            MountRecord(
                mount_id,
                parent_id,
                device,
                canonical_root,
                os.path.normpath(target),
                filesystem,
            )
        )
    return tuple(sorted(result))


def path_at_or_below(candidate: str, root: str) -> bool:
    candidate_path = Path(candidate)
    root_path = Path(root)
    return candidate_path == root_path or root_path in candidate_path.parents


def mount_root_at_or_below(candidate: str, root: str) -> bool:
    if Path(candidate).is_absolute() and Path(root).is_absolute():
        return path_at_or_below(candidate, root)
    return candidate == root


def source_anchors(raw: str, root: Path) -> tuple[tuple[str, str], ...]:
    anchors: set[tuple[str, str]] = set()
    for record in mount_records(raw):
        target = Path(record.target)
        if root == target or target in root.parents:
            relative = root.relative_to(target)
            if Path(record.root).is_absolute():
                translated = str(Path(record.root) / relative)
            else:
                require(not relative.parts, "opaque mount root cannot translate descendants")
                translated = record.root
            anchors.add((record.device, os.path.normpath(translated)))
        elif root in target.parents:
            anchors.add((record.device, record.root))
    return tuple(sorted(anchors))


def mount_reference_records(
    raw: str,
    root: Path,
    anchors: tuple[tuple[str, str], ...],
    extra_targets: tuple[str, ...] = (),
) -> tuple[MountRecord, ...]:
    result: list[MountRecord] = []
    for record in mount_records(raw):
        target_reference = path_at_or_below(record.target, str(root))
        source_reference = any(
            record.device == device and mount_root_at_or_below(record.root, source_root)
            for device, source_root in anchors
        )
        if target_reference or source_reference or record.target in extra_targets:
            result.append(record)
    return tuple(sorted(result))


def mount_references(
    raw: str,
    root: Path,
    anchors: tuple[tuple[str, str], ...],
    extra_targets: tuple[str, ...] = (),
) -> tuple[str, ...]:
    return tuple(
        sorted(
            record.target
            for record in mount_reference_records(
                raw, root, anchors, extra_targets
            )
        )
    )


def global_mount_roster_once(
    root: Path,
    anchors: tuple[tuple[str, str], ...] | None = None,
    extra_targets: tuple[str, ...] = (),
) -> tuple[
    tuple[tuple[str, str], ...],
    tuple[tuple[str, tuple[MountRecord, ...]], ...],
]:
    own_raw = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    actual_anchors = source_anchors(own_raw, root) if anchors is None else anchors
    require(actual_anchors, f"mount source anchors are absent: {root}")
    seen: dict[str, tuple[MountRecord, ...]] = {}
    for thread_group_id, task_id in process_task_coordinates_once():
        task = capture_task(thread_group_id, task_id)
        if task is None:
            continue
        try:
            before = namespace_identity(task.process_fd, "mnt")
            raw = read_at(
                task.process_fd,
                "mountinfo",
                maximum=16 * 1024 * 1024,
            ).decode("utf-8", "strict")
            after = namespace_identity(task.process_fd, "mnt")
            require(
                before == after and not pidfd_exited(task.pidfd),
                "mount namespace changed during proof: "
                f"{thread_group_id}/{task_id}",
            )
            namespace = f"{before['device']}:{before['inode']}"
            targets = mount_reference_records(
                raw,
                root,
                actual_anchors,
                extra_targets,
            )
            if namespace in seen:
                manual(
                    seen[namespace] == targets,
                    "mount namespace visibility differs across representatives: "
                    + namespace,
                )
            else:
                seen[namespace] = targets
        finally:
            task.close()
    require(seen, "no process task mount namespace was visible")
    return actual_anchors, tuple(sorted(seen.items()))


def stable_global_mount_roster(
    root: Path,
    anchors: tuple[tuple[str, str], ...] | None = None,
    extra_targets: tuple[str, ...] = (),
) -> dict[str, object]:
    first = global_mount_roster_once(root, anchors, extra_targets)
    second = global_mount_roster_once(root, anchors, extra_targets)
    require(first == second, f"global mount roster changed: {root}")
    actual_anchors, namespaces = second
    occurrences = tuple(
        sorted(
            (namespace, record)
            for namespace, records in namespaces
            for record in records
        )
    )
    return {
        "root": str(root),
        "sourceAnchors": [
            {"device": device, "root": source_root}
            for device, source_root in actual_anchors
        ],
        "occurrences": [
            {
                "mountNamespace": namespace,
                "mountId": record.mount_id,
                "parentId": record.parent_id,
                "device": record.device,
                "root": record.root,
                "target": record.target,
                "filesystem": record.filesystem,
            }
            for namespace, record in occurrences
        ],
    }


def socket_identity(path: Path, *, expected_uid: int, expected_gid: int | None = None) -> dict[str, object]:
    observed = os.stat(path, follow_symlinks=False)
    require(stat.S_ISSOCK(observed.st_mode), f"socket type differs: {path}")
    require(observed.st_uid == expected_uid, f"socket owner differs: {path}")
    if expected_gid is not None:
        require(observed.st_gid == expected_gid, f"socket group differs: {path}")
    return identity_document(path, observed)


def proc_unix_records() -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    raw = Path("/proc/net/unix").read_text(encoding="ascii")
    lines = raw.splitlines()
    require(lines and lines[0].startswith("Num"), "Unix socket table header differs")
    for line in lines[1:]:
        fields = line.split(maxsplit=7)
        require(7 <= len(fields) <= 8, "Unix socket table record is invalid")
        inode = fields[6]
        require(inode.isdigit(), "Unix socket inode is invalid")
        rows.append(
            {
                "reference": fields[0],
                "refCount": fields[1],
                "protocol": fields[2],
                "flags": fields[3],
                "type": fields[4],
                "state": fields[5],
                "inode": int(inode),
                "path": fields[7] if len(fields) == 8 else None,
            }
        )
    return tuple(rows)


def _aligned(value: int) -> int:
    return (value + 3) & ~3


def parse_unix_diag_datagram(
    raw: bytes,
    *,
    expected_sequence: int,
    expected_port_id: int = 0,
) -> tuple[list[dict[str, object]], bool]:
    rows: list[dict[str, object]] = []
    complete = False
    offset = 0
    while offset + 16 <= len(raw):
        length, message_type, flags, sequence, sender = struct.unpack_from(
            "=IHHII", raw, offset
        )
        require(
            16 <= length <= len(raw) - offset,
            "Unix diagnostic netlink message length differs",
        )
        require(
            sequence == expected_sequence,
            "Unix diagnostic netlink sequence differs",
        )
        require(
            sender == expected_port_id,
            "Unix diagnostic response header port differs",
        )
        require(
            flags & NLM_F_DUMP_INTR == 0,
            "Unix diagnostic dump was interrupted",
        )
        require(
            flags & ~(NLM_F_MULTI | NLM_F_DUMP_INTR) == 0,
            "Unix diagnostic response flags differ",
        )
        payload = raw[offset + 16 : offset + length]
        if message_type == NLMSG_DONE:
            if payload:
                require(
                    len(payload) >= 4 and struct.unpack_from("=i", payload)[0] == 0,
                    "Unix diagnostic dump completed with an error",
                )
            complete = True
        elif message_type == NLMSG_ERROR:
            require(len(payload) >= 4, "Unix diagnostic error record is truncated")
            error = struct.unpack_from("=i", payload)[0]
            require(error == 0, f"Unix diagnostic netlink failed: {-error}")
        else:
            require(
                message_type == SOCK_DIAG_BY_FAMILY
                and flags & NLM_F_MULTI
                and len(payload) >= 16,
                "Unix diagnostic record type differs",
            )
            family, socket_type, state, _pad, inode, cookie0, cookie1 = struct.unpack_from(
                "=BBBBIII", payload
            )
            require(family == socket.AF_UNIX, "Unix diagnostic family differs")
            value: dict[str, object] = {
                "inode": inode,
                "type": socket_type,
                "state": state,
                "cookie": [cookie0, cookie1],
                "name": None,
                "peer": None,
                "icons": [],
                "uid": None,
            }
            attribute_offset = 16
            while attribute_offset + 4 <= len(payload):
                attribute_length, attribute_type = struct.unpack_from(
                    "=HH", payload, attribute_offset
                )
                require(
                    4 <= attribute_length <= len(payload) - attribute_offset,
                    "Unix diagnostic attribute length differs",
                )
                body = payload[
                    attribute_offset + 4 : attribute_offset + attribute_length
                ]
                if attribute_type == UNIX_DIAG_NAME:
                    value["name"] = body.rstrip(b"\0").decode("utf-8", "surrogateescape")
                elif attribute_type == UNIX_DIAG_PEER:
                    require(len(body) == 4, "Unix diagnostic peer attribute differs")
                    value["peer"] = struct.unpack("=I", body)[0]
                elif attribute_type == UNIX_DIAG_ICONS:
                    require(len(body) % 4 == 0, "Unix diagnostic icon roster differs")
                    value["icons"] = list(
                        struct.unpack(f"={len(body) // 4}I", body)
                    )
                elif attribute_type == UNIX_DIAG_UID:
                    require(len(body) == 4, "Unix diagnostic uid attribute differs")
                    value["uid"] = struct.unpack("=I", body)[0]
                attribute_offset += _aligned(attribute_length)
            rows.append(value)
        offset += _aligned(length)
    require(offset == len(raw), "Unix diagnostic datagram has trailing bytes")
    return rows, complete


def unix_diag_records_once() -> tuple[dict[str, object], ...]:
    sequence = (os.getpid() ^ int(time.monotonic_ns())) & 0xFFFFFFFF
    request = struct.pack(
        "=IHHII",
        16 + 24,
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        0,
    ) + struct.pack(
        "=BBHIIIII",
        socket.AF_UNIX,
        0,
        0,
        0xFFFFFFFF,
        0,
        UDIAG_SHOW_NAME | UDIAG_SHOW_PEER | UDIAG_SHOW_ICONS | UDIAG_SHOW_UID,
        0xFFFFFFFF,
        0xFFFFFFFF,
    )
    diagnostic = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
    try:
        diagnostic.settimeout(5.0)
        diagnostic.bind((0, 0))
        port_id = int(diagnostic.getsockname()[0])
        require(
            diagnostic.sendto(request, (0, 0)) == len(request),
            "Unix diagnostic request was short",
        )
        rows: list[dict[str, object]] = []
        complete = False
        while not complete:
            try:
                datagram, ancillary, message_flags, sender = diagnostic.recvmsg(
                    1024 * 1024
                )
            except socket.timeout as error:
                raise DrainError("Unix diagnostic netlink timed out") from error
            require(
                isinstance(sender, tuple)
                and len(sender) >= 1
                and sender[0] == 0,
                "Unix diagnostic datagram origin differs",
            )
            require(not ancillary, "Unix diagnostic datagram has ancillary data")
            require(
                message_flags & socket.MSG_TRUNC == 0,
                "Unix diagnostic datagram was truncated",
            )
            parsed, complete = parse_unix_diag_datagram(
                datagram,
                expected_sequence=sequence,
                expected_port_id=port_id,
            )
            rows.extend(parsed)
    finally:
        diagnostic.close()
    require(
        len({int(row["inode"]) for row in rows}) == len(rows),
        "Unix diagnostic socket inode roster is ambiguous",
    )
    return tuple(sorted(rows, key=lambda row: int(row["inode"])))


def stable_unix_diag_records(
    seeds: set[int],
) -> tuple[dict[str, object], ...]:
    first = unix_diag_records_once()
    second = unix_diag_records_once()
    first_related = related_unix_socket_inodes(first, seeds)
    second_related = related_unix_socket_inodes(second, seeds)
    first_projection = tuple(
        row for row in first if int(row["inode"]) in first_related
    )
    second_projection = tuple(
        row for row in second if int(row["inode"]) in second_related
    )
    require(
        first_projection == second_projection,
        "Unix diagnostic peer graph changed across proof passes",
    )
    return second_projection


def related_unix_socket_inodes(
    diagnostic: Sequence[Mapping[str, object]],
    seeds: set[int],
) -> set[int]:
    rows = {int(row["inode"]): row for row in diagnostic}
    adjacency: dict[int, set[int]] = {inode: set() for inode in rows}
    for inode, row in rows.items():
        peer = row["peer"]
        if isinstance(peer, int) and peer > 0:
            adjacency[inode].add(peer)
            adjacency.setdefault(peer, set()).add(inode)
        for icon in row["icons"]:
            adjacency[inode].add(int(icon))
            adjacency.setdefault(int(icon), set()).add(inode)
    related = set(seeds)
    frontier = list(seeds)
    while frontier:
        inode = frontier.pop()
        manual(inode in rows, f"runtime Unix socket is absent from diagnostic graph: {inode}")
        for candidate in adjacency.get(inode, set()):
            if candidate not in related:
                related.add(candidate)
                frontier.append(candidate)
    return related


def socket_inode_owners(inodes: set[int]) -> dict[int, tuple[int, ...]]:
    owners: dict[int, set[int]] = {inode: set() for inode in inodes}
    for thread_group_id, task_id in process_task_coordinates_once():
        task = capture_task(thread_group_id, task_id)
        if task is None:
            continue
        try:
            try:
                fd_root = os.open(
                    "fd",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=task.process_fd,
                )
            except (FileNotFoundError, ProcessLookupError):
                if pidfd_exited(task.pidfd):
                    continue
                raise ManualRecoveryRequired(
                    "live process task FD table disappeared: "
                    f"{thread_group_id}/{task_id}"
                )
            except PermissionError as error:
                raise ManualRecoveryRequired(
                    "process task FD table is unreadable: "
                    f"{thread_group_id}/{task_id}"
                ) from error
            try:
                for name in tuple(os.listdir(fd_root)):
                    try:
                        observed = os.stat(name, dir_fd=fd_root)
                        target = os.readlink(name, dir_fd=fd_root)
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    except PermissionError as error:
                        raise ManualRecoveryRequired(
                            "process task socket FD is unreadable: "
                            f"{thread_group_id}/{task_id}/{name}"
                        ) from error
                    match = re.fullmatch(r"socket:\[([1-9][0-9]*)\]", target)
                    if match is not None and int(match.group(1)) in owners:
                        owners[int(match.group(1))].add(thread_group_id)
                    try:
                        stable = os.stat(name, dir_fd=fd_root)
                    except (FileNotFoundError, ProcessLookupError):
                        if pidfd_exited(task.pidfd):
                            break
                        raise ManualRecoveryRequired(
                            "process task socket FD changed: "
                            f"{thread_group_id}/{task_id}/{name}"
                        )
                    require(
                        (
                            stable.st_dev,
                            stable.st_ino,
                            stat.S_IFMT(stable.st_mode),
                        )
                        == (
                            observed.st_dev,
                            observed.st_ino,
                            stat.S_IFMT(observed.st_mode),
                        ),
                        "process task socket FD changed: "
                        f"{thread_group_id}/{task_id}/{name}",
                    )
            finally:
                os.close(fd_root)
            require(
                not pidfd_exited(task.pidfd),
                f"process task exited during socket ownership proof: {task_id}",
            )
        finally:
            task.close()
    return {inode: tuple(sorted(values)) for inode, values in owners.items()}


def tcp_registry_snapshot(registry_pid: int) -> dict[str, object]:
    matches: list[dict[str, object]] = []
    port_hex = f"{36000:04X}"
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        lines = table.read_text(encoding="ascii").splitlines()
        require(lines and "local_address" in lines[0], "TCP socket table header differs")
        for line in lines[1:]:
            fields = line.split()
            require(len(fields) >= 10, "TCP socket table record is invalid")
            address, port = fields[1].split(":", 1)
            if port != port_hex:
                continue
            inode = int(fields[9])
            matches.append(
                {
                    "table": table.name,
                    "address": address,
                    "port": int(port, 16),
                    "state": fields[3],
                    "inode": inode,
                }
            )
    manual(len(matches) == 1, "legacy registry listener is absent or ambiguous")
    listener = matches[0]
    manual(
        listener["table"] == "tcp"
        and listener["address"] == "0100007F"
        and listener["state"] == "0A",
        "legacy registry listener is not exact IPv4 loopback",
    )
    owners = socket_inode_owners({int(listener["inode"])})
    manual(
        owners[int(listener["inode"])] == (registry_pid,),
        "legacy registry listener ownership differs",
    )
    return {**listener, "owners": list(owners[int(listener["inode"])])}


def require_registry_listener_absent() -> None:
    port_hex = f"{36000:04X}"
    for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
        for line in table.read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 4 and fields[1].split(":", 1)[1] == port_hex:
                raise ManualRecoveryRequired("legacy registry listener remained after dockerd")


def runtime_socket_snapshot(dockerd_pid: int, registry_pid: int = 964683) -> dict[str, object]:
    expected_paths = tuple(
        sorted(
            (
                DOCKER_SOCKET,
                CONTAINERD_SOCKET,
                EXPECTED_RUNTIME_ROOT / "containerd.sock.ttrpc",
                EXPECTED_RUNTIME_ROOT / "docker-exec/metrics.sock",
                EXPECTED_RUNTIME_ROOT / "docker-exec/libnetwork/25fb8cc9e82d.sock",
            )
        )
    )
    manual(
        all(exists_nofollow(path) for path in expected_paths),
        "legacy runtime socket pathname roster differs",
    )
    identities = [socket_identity(path, expected_uid=0) for path in expected_paths]
    unix = proc_unix_records()
    relevant = tuple(
        row
        for row in unix
        if isinstance(row["path"], str)
        and path_at_or_below(str(row["path"]), str(EXPECTED_RUNTIME_ROOT))
    )
    diagnostic = stable_unix_diag_records(
        {int(row["inode"]) for row in relevant}
    )
    related_inodes = related_unix_socket_inodes(
        diagnostic,
        {int(row["inode"]) for row in relevant},
    )
    owners = socket_inode_owners(related_inodes)
    documented: list[dict[str, object]] = []
    for row in relevant:
        value = dict(row)
        value["owners"] = list(owners[int(row["inode"])])
        documented.append(value)
    admitted_owners = {
        int(candidate["pid"]) for candidate in EXPECTED_PROCESS_CANDIDATES.values()
    }
    manual(
        all(
            owners[inode] and set(owners[inode]) <= admitted_owners
            for inode in related_inodes
        ),
        "legacy runtime socket has a foreign or ownerless endpoint",
    )
    docker_rows = [row for row in documented if row["path"] == str(DOCKER_SOCKET)]
    listeners = [
        row
        for row in docker_rows
        if row["flags"] == "00010000" and row["state"] == "01"
    ]
    manual(len(listeners) == 1, "exact Docker API listener is absent or ambiguous")
    manual(len(docker_rows) == 1, "a Docker API client is already connected")
    manual(
        tuple(listeners[0]["owners"]) == (dockerd_pid,),
        "Docker API listener ownership differs",
    )
    diagnostic_by_inode = {
        int(row["inode"]): row for row in diagnostic
    }
    docker_diagnostic = diagnostic_by_inode[int(listeners[0]["inode"])]
    manual(
        docker_diagnostic["peer"] is None
        and docker_diagnostic["icons"] == [],
        "a pathless Docker API peer or pending client is already connected",
    )
    related_diagnostic = [
        {
            **diagnostic_by_inode[inode],
            "owners": list(owners[inode]),
        }
        for inode in sorted(related_inodes)
    ]
    return {
        "pathIdentities": identities,
        "unixRecords": documented,
        "relatedUnixInodes": sorted(related_inodes),
        "unixDiagnostic": related_diagnostic,
        "foreignDockerApiClients": [],
        "registryTcpListener": tcp_registry_snapshot(registry_pid),
    }


def post_revocation_socket_snapshot(control: Mapping[str, object]) -> dict[str, object]:
    authority = control["authority"]
    assert isinstance(authority, dict)
    recorded = authority["sockets"]
    assert isinstance(recorded, dict)
    recorded_rows = [
        row for row in recorded["unixRecords"] if row["path"] == str(DOCKER_SOCKET)
    ]
    require(len(recorded_rows) == 1, "recorded Docker listener is ambiguous")
    listener = recorded_rows[0]
    recorded_diagnostic = next(
        row
        for row in recorded["unixDiagnostic"]
        if row["inode"] == listener["inode"]
    )

    def once() -> dict[str, object]:
        manual(not exists_nofollow(DOCKER_SOCKET), "Docker API pathname reappeared")
        parent_fd, root_fd = runtime_root_descriptors(
            control,
            require_root_owned=True,
        )
        try:
            try:
                os.stat("docker.sock", dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ManualRecoveryRequired("bound Docker API pathname reappeared")
        finally:
            os.close(root_fd)
            os.close(parent_fd)
        rows = [
            row
            for row in proc_unix_records()
            if row["path"] == str(DOCKER_SOCKET)
            or row["inode"] == listener["inode"]
        ]
        owners = socket_inode_owners({int(row["inode"]) for row in rows})
        documented = [
            {**row, "owners": list(owners[int(row["inode"])])} for row in rows
        ]
        manual(
            documented
            == [
                {
                    **{key: listener[key] for key in listener if key != "owners"},
                    "owners": [int(process_authority(control, "dockerd")["pid"])],
                }
            ],
            "Docker API accepted or foreign endpoint survived revocation",
        )
        diagnostic = {
            int(row["inode"]): row
            for row in stable_unix_diag_records({int(listener["inode"])})
        }
        current = diagnostic.get(int(listener["inode"]))
        manual(current is not None, "Docker API listener diagnostic disappeared")
        assert current is not None
        manual(
            current["peer"] is None
            and current["icons"] == []
            and {
                key: current[key]
                for key in ("inode", "type", "state", "cookie", "name", "peer", "icons", "uid")
            }
            == {
                key: recorded_diagnostic[key]
                for key in ("inode", "type", "state", "cookie", "name", "peer", "icons", "uid")
            },
            "Docker API diagnostic peer graph changed after revocation",
        )
        return {
            "pathAbsent": True,
            "listener": documented[0],
            "diagnostic": current,
        }

    first = once()
    second = once()
    require(first == second, "Docker API post-revocation roster changed")
    return second


def process_exists(pid: int) -> bool:
    try:
        os.stat(f"/proc/{pid}")
        return True
    except FileNotFoundError:
        return False


def child_pids(parent_pid: int) -> tuple[int, ...]:
    result: list[int] = []
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit():
            continue
        try:
            raw = Path("/proc") / entry / "stat"
            observed_parent, _ = stat_identity(raw.read_bytes())
        except (FileNotFoundError, ProcessLookupError, PermissionError, DrainError):
            continue
        if observed_parent == parent_pid:
            result.append(int(entry))
    return tuple(result)


def related_shim_pids() -> tuple[int, ...]:
    expected_address = str(CONTAINERD_SOCKET).encode()
    result: list[int] = []
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit():
            continue
        try:
            raw = (Path("/proc") / entry / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        values = raw.rstrip(b"\0").split(b"\0") if raw else []
        if not values:
            continue
        if (
            Path(os.fsdecode(values[0])).name == "containerd-shim-runc-v2"
            and b"-namespace" in values
            and b"ambit-c16b" in values
            and b"-address" in values
            and expected_address in values
        ):
            result.append(int(entry))
    return tuple(result)


def capture_process_graph(parsed_receipt: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    captured: dict[str, CapturedProcess] = {}
    for role, candidate in EXPECTED_PROCESS_CANDIDATES.items():
        captured[role] = capture_process(candidate)
    require(
        related_shim_pids() == (EXPECTED_PROCESS_CANDIDATES["registryShim"]["pid"],),
        "legacy shim roster differs",
    )
    require(
        child_pids(int(EXPECTED_PROCESS_CANDIDATES["registryShim"]["pid"]))
        == (EXPECTED_PROCESS_CANDIDATES["registryTask"]["pid"],),
        "legacy registry task roster differs",
    )
    observations = {
        "containerdProcInode": validate_receipt_process(
            parsed_receipt["containerd"], captured["containerd"]
        ),
        "dockerdProcInode": validate_receipt_process(
            parsed_receipt["dockerd"], captured["dockerd"]
        ),
    }
    shared_cgroups = {
        str(captured[role].authority["cgroup"])
        for role in (
            "containerdWrapperOuter",
            "containerdWrapperInner",
            "containerd",
            "dockerdWrapperOuter",
            "dockerdWrapperInner",
            "dockerd",
            "registryShim",
        )
    }
    require(len(shared_cgroups) == 1, "legacy daemon cgroup observation differs")
    return (
        {
            "processes": {
                role: captured[role].authority for role in sorted(captured)
            },
            "containerId": EXPECTED_CONTAINER_ID,
            "cgroupMutationAuthorized": False,
            "sharedCgroupObservation": next(iter(shared_cgroups)),
        },
        observations,
    )


@dataclass
class ProcessReferenceObservation:
    row: dict[str, object]
    pidfd: int
    process_fd: int

    def close(self) -> None:
        os.close(self.process_fd)
        os.close(self.pidfd)


def _structured_argument_relations(raw: bytes) -> set[str]:
    values = raw.rstrip(b"\0").split(b"\0") if raw else []
    relations: set[str] = set()
    exact_values = {
        str(EXPECTED_RUNTIME_ROOT): "runtimeArgv",
        str(CONTAINERD_SOCKET): "containerdSocketArgv",
        str(DOCKER_CONFIG): "dockerConfigArgv",
        str(CONTAINERD_CONFIG): "containerdConfigArgv",
        EXPECTED_CONTAINER_ID: "containerIdArgv",
        "ambit-c16b": "namespaceArgv",
    }
    for raw_value in values:
        value = os.fsdecode(raw_value)
        candidates = {value}
        if "=" in value:
            candidates.add(value.split("=", 1)[1])
        for prefix in ("unix://", "unix:"):
            candidates.update(
                candidate.removeprefix(prefix)
                for candidate in tuple(candidates)
                if candidate.startswith(prefix)
            )
        for candidate in candidates:
            label = exact_values.get(candidate)
            if label is not None:
                relations.add(label)
            if candidate.startswith("/") and path_at_or_below(
                candidate, str(EXPECTED_RUNTIME_ROOT)
            ):
                relations.add("runtimeArgvPath")
    return relations


def process_reference_scan(
    thread_group_id: int,
    task_id: int | None = None,
    *,
    runtime_inodes: set[tuple[int, int]],
    socket_inodes: set[int],
    private_namespace_tokens: set[str],
    admitted_namespace_tokens: set[str],
) -> ProcessReferenceObservation | None:
    actual_task_id = thread_group_id if task_id is None else task_id
    task = capture_task(thread_group_id, actual_task_id)
    if task is None:
        return None
    keep = False
    try:
        try:
            first_parent = task.parent_pid
            first_start = task.start_ticks
            raw_arguments = read_at(task.process_fd, "cmdline")
            cgroup = read_at(task.process_fd, "cgroup").decode("ascii", "strict")
            relations = _structured_argument_relations(raw_arguments)
            namespaces = {
                name: namespace_identity(task.process_fd, name)
                for name in ("mnt", "net", "pid", "user")
            }
            namespace_tokens = {
                f"{name}:[{identity['inode']}]"
                for name, identity in namespaces.items()
            }
            if namespace_tokens & private_namespace_tokens:
                relations.add("privateRuntimeNamespace")
            for label, name in (("cwd", "cwd"), ("root", "root"), ("exe", "exe")):
                try:
                    target = os.readlink(name, dir_fd=task.process_fd)
                    observed = os.stat(name, dir_fd=task.process_fd)
                except FileNotFoundError:
                    if pidfd_exited(task.pidfd):
                        return None
                    if not raw_arguments:
                        continue
                    raise ManualRecoveryRequired(
                        "live process task edge disappeared: "
                        f"{thread_group_id}/{actual_task_id}/{label}"
                    )
                except PermissionError as error:
                    raise ManualRecoveryRequired(
                        "live process task edge is unreadable: "
                        f"{thread_group_id}/{actual_task_id}/{label}"
                    ) from error
                normalized = target.removesuffix(" (deleted)")
                if path_at_or_below(normalized, str(EXPECTED_RUNTIME_ROOT)):
                    relations.add(label)
                if (observed.st_dev, observed.st_ino) in runtime_inodes:
                    relations.add(f"{label}Inode")
            try:
                fd_directory = os.open(
                    "fd",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=task.process_fd,
                )
            except FileNotFoundError:
                if pidfd_exited(task.pidfd):
                    return None
                if raw_arguments:
                    raise ManualRecoveryRequired(
                        "live process task FD table disappeared: "
                        f"{thread_group_id}/{actual_task_id}"
                    )
                fd_directory = None
            except PermissionError as error:
                raise ManualRecoveryRequired(
                    "live process task FD table is unreadable: "
                    f"{thread_group_id}/{actual_task_id}"
                ) from error
            if fd_directory is not None:
                try:
                    for fd_name in tuple(os.listdir(fd_directory)):
                        try:
                            observed = os.stat(fd_name, dir_fd=fd_directory)
                            target = os.readlink(fd_name, dir_fd=fd_directory)
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                        except PermissionError as error:
                            raise ManualRecoveryRequired(
                                "live process task FD edge is unreadable: "
                                f"{thread_group_id}/{actual_task_id}"
                            ) from error
                        if (observed.st_dev, observed.st_ino) in runtime_inodes:
                            relations.add("runtimeFdInode")
                        normalized = target.removesuffix(" (deleted)")
                        if normalized.startswith("/") and path_at_or_below(
                            normalized, str(EXPECTED_RUNTIME_ROOT)
                        ):
                            relations.add("runtimeFdPath")
                        socket_match = re.fullmatch(
                            r"socket:\[([1-9][0-9]*)\]", target
                        )
                        if (
                            socket_match is not None
                            and int(socket_match.group(1)) in socket_inodes
                        ):
                            relations.add("runtimeSocketFd")
                        if target in private_namespace_tokens:
                            relations.add("runtimeNamespaceFd")
                        if (
                            re.fullmatch(r"(?:mnt|net|pid|user):\[[1-9][0-9]*\]", target)
                            is not None
                            and target not in admitted_namespace_tokens
                        ):
                            relations.add("unclassifiedNamespaceFd")
                        try:
                            stable = os.stat(fd_name, dir_fd=fd_directory)
                        except (FileNotFoundError, ProcessLookupError):
                            if pidfd_exited(task.pidfd):
                                return None
                            raise ManualRecoveryRequired(
                                "live process task FD edge changed: "
                                f"{thread_group_id}/{actual_task_id}"
                            )
                        require(
                            (stable.st_dev, stable.st_ino, stat.S_IFMT(stable.st_mode))
                            == (observed.st_dev, observed.st_ino, stat.S_IFMT(observed.st_mode)),
                            "live process task FD edge changed: "
                            f"{thread_group_id}/{actual_task_id}",
                        )
                finally:
                    os.close(fd_directory)
            try:
                maps = read_at(task.process_fd, "maps", maximum=16 * 1024 * 1024)
            except (FileNotFoundError, ProcessLookupError):
                if pidfd_exited(task.pidfd):
                    return None
                maps = b""
            if str(EXPECTED_RUNTIME_ROOT).encode() in maps:
                relations.add("runtimeMappedPath")
            cgroup_components = {
                component
                for line in cgroup.splitlines()
                for component in line.split("/")
            }
            if EXPECTED_CONTAINER_ID in cgroup_components:
                relations.add("containerCgroup")
            second_parent, second_start = stat_identity(
                read_at(task.process_fd, "stat")
            )
            require(
                (first_parent, first_start) == (second_parent, second_start)
                and not pidfd_exited(task.pidfd),
                "process task reference scan changed: "
                f"{thread_group_id}/{actual_task_id}",
            )
            row = {
                "pid": thread_group_id,
                "taskId": actual_task_id,
                "parentPid": first_parent,
                "startTimeTicks": first_start,
                "namespaces": namespaces,
                "relations": sorted(relations),
            }
            keep = True
            return ProcessReferenceObservation(
                row,
                task.pidfd,
                task.process_fd,
            )
        except (FileNotFoundError, ProcessLookupError):
            if pidfd_exited(task.pidfd):
                return None
            raise
    finally:
        if not keep:
            task.close()


def _related_process_universe_once(
    processes: Mapping[str, Mapping[str, object]],
    runtime: Mapping[str, object],
    sockets: Mapping[str, object],
    *,
    allowed_roles: set[str],
) -> dict[str, object]:
    runtime_inodes = {
        (int(item["device"]), int(item["inode"])) for item in runtime["tree"]
    }
    root = runtime["rootIdentity"]
    runtime_inodes.add((int(root["device"]), int(root["inode"])))
    socket_inodes = {
        int(item["inode"]) for item in sockets["unixRecords"]
    } | {int(inode) for inode in sockets.get("relatedUnixInodes", [])}
    own_namespace_tokens = {
        f"{name}:[{os.stat(f'/proc/self/ns/{name}').st_ino}]"
        for name in ("mnt", "net", "pid", "user")
    }
    recorded_namespace_tokens = {
        f"{name}:[{int(value[field]['inode'])}]"
        for value in processes.values()
        for name, field in (
            ("mnt", "mountNamespace"),
            ("net", "networkNamespace"),
            ("pid", "pidNamespace"),
            ("user", "userNamespace"),
        )
    }
    private_namespace_tokens = recorded_namespace_tokens - own_namespace_tokens
    admitted_namespace_tokens = recorded_namespace_tokens | own_namespace_tokens
    observations: list[ProcessReferenceObservation] = []
    try:
        for thread_group_id, task_id in process_task_coordinates_once():
            observation = process_reference_scan(
                thread_group_id,
                task_id,
                runtime_inodes=runtime_inodes,
                socket_inodes=socket_inodes,
                private_namespace_tokens=private_namespace_tokens,
                admitted_namespace_tokens=admitted_namespace_tokens,
            )
            if observation is not None:
                observations.append(observation)
        rows = {
            (int(value.row["pid"]), int(value.row["taskId"])): value.row
            for value in observations
        }
        require(
            len(rows) == len(observations),
            "process task census contains a duplicate coordinate",
        )
        known_by_tgid = {
            int(value["pid"]): role for role, value in processes.items()
        }
        require(
            len(known_by_tgid) == len(processes),
            "recorded process authority reuses a PID",
        )
        for thread_group_id, role in known_by_tgid.items():
            row = rows.get((thread_group_id, thread_group_id))
            if row is None:
                continue
            recorded = processes[role]
            manual(
                (row["parentPid"], row["startTimeTicks"])
                == (recorded["parentPid"], recorded["startTimeTicks"]),
                f"recorded legacy process PID was reused: {role}",
            )
        related = {
            coordinate
            for coordinate, row in rows.items()
            if row["relations"] or coordinate[0] in known_by_tgid
        }
        unclassified_namespaces = sorted(
            coordinate
            for coordinate, row in rows.items()
            if "unclassifiedNamespaceFd" in row["relations"]
        )
        manual(
            not unclassified_namespaces,
            "an unclassified task-held namespace can hide a mount occurrence: "
            + ",".join(
                f"{thread_group_id}/{task_id}"
                for thread_group_id, task_id in unclassified_namespaces
            ),
        )
        changed = True
        while changed:
            changed = False
            related_groups = {coordinate[0] for coordinate in related}
            for coordinate, row in rows.items():
                same_group = coordinate[0] in related_groups
                descendant = int(row["parentPid"]) in related_groups
                if (same_group or descendant) and coordinate not in related:
                    related.add(coordinate)
                    relation = "threadGroup" if same_group else "descendant"
                    row["relations"] = sorted((*row["relations"], relation))
                    changed = True
        allowed_tgids = {int(processes[role]["pid"]) for role in allowed_roles}
        unknown = sorted(
            coordinate
            for coordinate in related
            if coordinate[0] not in allowed_tgids
        )
        manual(
            not unknown,
            "unrecognized legacy-related task: "
            + ",".join(
                f"{thread_group_id}/{task_id}"
                for thread_group_id, task_id in unknown
            ),
        )
        for role in allowed_roles:
            thread_group_id = int(processes[role]["pid"])
            manual(
                (thread_group_id, thread_group_id) in rows,
                f"recorded legacy process leader is not visible: {role}",
            )
        for observation in observations:
            parent_pid, start_ticks = stat_identity(
                read_at(observation.process_fd, "stat")
            )
            require(
                (parent_pid, start_ticks)
                == (
                    observation.row["parentPid"],
                    observation.row["startTimeTicks"],
                )
                and not pidfd_exited(observation.pidfd),
                "process task changed before census commit: "
                f"{observation.row['pid']}/{observation.row['taskId']}",
            )
        for thread_group_id, task_id in sorted(related):
            repeated = process_reference_scan(
                thread_group_id,
                task_id,
                runtime_inodes=runtime_inodes,
                socket_inodes=socket_inodes,
                private_namespace_tokens=private_namespace_tokens,
                admitted_namespace_tokens=admitted_namespace_tokens,
            )
            manual(
                repeated is not None,
                "related process task disappeared during edge reproof: "
                f"{thread_group_id}/{task_id}",
            )
            assert repeated is not None
            try:
                require(
                    repeated.row == rows[(thread_group_id, task_id)],
                    "related process task edge roster changed before census commit: "
                    f"{thread_group_id}/{task_id}",
                )
            finally:
                repeated.close()
        proof = [rows[coordinate] for coordinate in sorted(related)]
        return {
            "allowedRoles": sorted(allowed_roles),
            "related": proof,
            "proofSha256": sha256_bytes(canonical_json(proof)),
        }
    finally:
        for observation in observations:
            observation.close()


def related_process_universe(
    processes: Mapping[str, Mapping[str, object]],
    runtime: Mapping[str, object],
    sockets: Mapping[str, object],
    *,
    allowed_roles: set[str],
) -> dict[str, object]:
    first = _related_process_universe_once(
        processes,
        runtime,
        sockets,
        allowed_roles=allowed_roles,
    )
    second = _related_process_universe_once(
        processes,
        runtime,
        sockets,
        allowed_roles=allowed_roles,
    )
    require(first == second, "related process universe changed across proof passes")
    return second


def runtime_tree_snapshot() -> dict[str, object]:
    allowed_top_level = {
        "containerd-state",
        "containerd-temp",
        "containerd.sock",
        "containerd.sock.ttrpc",
        "docker-exec",
        "docker.pid",
        "docker.sock",
    }
    root_fd = os.open(
        EXPECTED_RUNTIME_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    rows: list[dict[str, object]] = []

    def scan(directory_fd: int, base: Path) -> None:
        for name in tuple(sorted(os.listdir(directory_fd))):
            path = base / name
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            mode_type = stat.S_IFMT(observed.st_mode)
            manual(
                mode_type
                in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFSOCK, stat.S_IFIFO),
                f"legacy runtime entry type is foreign: {path}",
            )
            manual(
                not stat.S_ISLNK(observed.st_mode),
                f"legacy runtime symlink is forbidden: {path}",
            )
            row = identity_document(path, observed)
            if not stat.S_ISDIR(observed.st_mode):
                row["size"] = observed.st_size
            rows.append(row)
            if stat.S_ISDIR(observed.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                try:
                    bound = os.fstat(child_fd)
                    literal = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    require(
                        (bound.st_dev, bound.st_ino)
                        == (observed.st_dev, observed.st_ino)
                        == (literal.st_dev, literal.st_ino),
                        f"legacy runtime directory changed during snapshot: {path}",
                    )
                    scan(child_fd, path)
                finally:
                    os.close(child_fd)

    try:
        root = os.fstat(root_fd)
        require(
            (root.st_dev, root.st_ino, root.st_uid, root.st_gid, stat.S_IMODE(root.st_mode))
            == (44, 12496265, 1000, 1000, 0o700),
            "legacy runtime root identity differs",
        )
        top_level = tuple(sorted(os.listdir(root_fd)))
        manual(set(top_level) <= allowed_top_level, "legacy runtime root contains a foreign entry")
        scan(root_fd, EXPECTED_RUNTIME_ROOT)
    finally:
        os.close(root_fd)
    return {
        "rootIdentity": identity_document(EXPECTED_RUNTIME_ROOT, root),
        "topLevel": list(top_level),
        "tree": rows,
    }


def registry_inventory() -> dict[str, object]:
    repositories = REGISTRY_STORAGE / "repositories"
    blobs = REGISTRY_STORAGE / "blobs/sha256"
    directory_identity(repositories, expected_uid=0, expected_gid=0, expected_modes={0o755})
    directory_identity(blobs, expected_uid=0, expected_gid=0, expected_modes={0o755})
    revisions: dict[str, set[str]] = {}
    for link in sorted(repositories.glob("**/_manifests/revisions/sha256/*/link")):
        relative = link.relative_to(repositories)
        parts = relative.parts
        marker = parts.index("_manifests")
        repository = "/".join(parts[:marker])
        digest = parts[marker + 3]
        require(SHA256_RE.fullmatch(digest) is not None, "registry revision digest is invalid")
        raw, observed = read_regular(link, maximum=128)
        require(
            observed.st_uid == 0
            and observed.st_gid == 0
            and raw == f"sha256:{digest}".encode(),
            "registry revision link differs",
        )
        revisions.setdefault(repository, set()).add(digest)
    for repository, required in EXPECTED_REGISTRY_MANIFESTS.items():
        manual(required <= revisions.get(repository, set()), f"required registry manifest is absent: {repository}")
    blob_rows: list[dict[str, object]] = []
    for data in sorted(blobs.glob("*/*/data")):
        digest = data.parent.name
        require(SHA256_RE.fullmatch(digest) is not None, "registry blob path is invalid")
        actual, size, observed = hash_regular(data, maximum=2 * 1024**3)
        require(
            observed.st_uid == 0 and observed.st_gid == 0,
            "registry blob owner differs",
        )
        require(actual == digest, f"registry blob digest differs: {digest}")
        blob_rows.append({"digest": digest, "bytes": size})
    require(blob_rows, "registry blob inventory is empty")
    inventory = {
        "revisions": {
            repository: sorted(values) for repository, values in sorted(revisions.items())
        },
        "blobs": blob_rows,
    }
    return {
        "inventorySha256": sha256_bytes(canonical_json(inventory)),
        "blobCount": len(blob_rows),
        "blobBytes": sum(int(row["bytes"]) for row in blob_rows),
        "requiredManifests": {
            repository: sorted(values)
            for repository, values in sorted(EXPECTED_REGISTRY_MANIFESTS.items())
        },
    }


def require_v5_absent(
    *,
    allow_global_lease: bool = False,
    allow_legacy_absent: bool = False,
) -> dict[str, object]:
    foreign: list[str] = []
    for name in os.listdir("/run"):
        if V5_RUNTIME_RE.fullmatch(name) is not None:
            foreign.append(str(Path("/run") / name))
    for name in os.listdir("/home"):
        if name == ".ambit-c16b-runner-storage" or name.startswith(
            ".ambit-c16b-runner-storage-claim"
        ):
            foreign.append(str(Path("/home") / name))
    for name in os.listdir(CGROUP_PARENT):
        if CGROUP_NAME_RE.fullmatch(name) is not None:
            foreign.append(str(CGROUP_PARENT / name))
    if not allow_global_lease and global_runtime_lease_busy():
        foreign.append(str(GLOBAL_LEASE_PATH))
    manual(not foreign, "current v5 authority coexists: " + ",".join(sorted(foreign)))
    legacy = tuple(
        sorted(
            name
            for name in os.listdir("/tmp")
            if RUNTIME_NAME_RE.fullmatch(name) is not None
        )
    )
    expected_rosters = (
        (EXPECTED_RUNTIME_ROOT.name,),
        (),
    ) if allow_legacy_absent else ((EXPECTED_RUNTIME_ROOT.name,),)
    manual(legacy in expected_rosters, "legacy runtime roster differs")
    return {
        "v5Authorities": [],
        "legacyRuntime": str(EXPECTED_RUNTIME_ROOT) if legacy else None,
    }


def global_runtime_lease_busy() -> bool:
    parent_fd = os.open(
        GLOBAL_LEASE_PATH.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    descriptor: int | None = None
    try:
        parent = os.fstat(parent_fd)
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == 0
            and parent.st_gid == 0
            and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
            "global lease parent authority differs",
        )
        try:
            descriptor = os.open(
                GLOBAL_LEASE_PATH.name,
                os.O_RDWR | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            return False
        observed = os.fstat(descriptor)
        literal = os.stat(
            GLOBAL_LEASE_PATH.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o600
            and observed.st_nlink == 1
            and (observed.st_dev, observed.st_ino)
            == (literal.st_dev, literal.st_ino),
            "global lease identity differs",
        )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def pidfile_identity(
    path: Path,
    expected_pid: int,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    identity, raw = regular_identity(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_mode=0o644,
        maximum=64,
    )
    require(raw.decode("ascii", "strict").strip() == str(expected_pid), f"pidfile differs: {path}")
    identity["expectedPid"] = expected_pid
    return identity


def netns_baseline() -> dict[str, object]:
    target = str(TASK_NETNS_TARGET)
    records = mount_records(Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
    matches = [record for record in records if record.target == target]
    require(len(matches) == 1 and matches[0].filesystem == "nsfs", "legacy task netns mount differs")
    source = {"device": matches[0].device, "root": matches[0].root}
    require(
        source == {"device": "0:4", "root": "net:[4026531833]"},
        "legacy task netns source differs",
    )
    source_anchor = ((str(source["device"]), str(source["root"])),)
    ambient_target = "/run/docker/netns/default"
    source_roster = stable_global_mount_roster(
        TASK_NETNS_TARGET,
        source_anchor,
        (target, ambient_target),
    )
    occurrences = list(source_roster["occurrences"])
    require(
        all(
            item["device"] == source["device"]
            and item["root"] == source["root"]
            and item["filesystem"] == "nsfs"
            for item in occurrences
        ),
        "legacy task netns occurrence provenance differs",
    )
    targets = {str(item["target"]) for item in occurrences}
    require(target in targets, "legacy task netns occurrence is absent")
    manual(
        len(occurrences) == 2
        and targets == {target, ambient_target}
        and sum(item["target"] == target for item in occurrences) == 1
        and sum(item["target"] == ambient_target for item in occurrences) == 1
        and len({str(item["mountNamespace"]) for item in occurrences}) == 1,
        "legacy task netns source has a foreign target",
    )
    return {
        "sourceAnchor": source,
        "ownedTarget": target,
        "ambientTargets": [ambient_target],
        "occurrences": occurrences,
    }


def require_mount_targets_within(
    value: Mapping[str, object],
    *,
    allowed_roots: tuple[Path, ...],
    label: str,
) -> None:
    occurrences = value.get("occurrences")
    require(isinstance(occurrences, list), f"{label} mount occurrence roster is invalid")
    foreign = sorted(
        str(item["target"])
        for item in occurrences
        if not any(
            path_at_or_below(str(item["target"]), str(root))
            for root in allowed_roots
        )
    )
    manual(not foreign, f"{label} source has a foreign target: " + ",".join(foreign))


def collect_authority(
    caller_uid: int,
    caller_gid: int,
    *,
    allow_global_lease: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    require((caller_uid, caller_gid) == (1000, 1000), "authenticated legacy caller differs")
    state_identity = directory_identity(
        EXPECTED_STATE_ROOT,
        expected_uid=caller_uid,
        expected_gid=caller_gid,
        expected_modes={0o700},
    )
    evidence_identity = directory_identity(
        EXPECTED_STATE_ROOT / "evidence",
        expected_uid=caller_uid,
        expected_gid=caller_gid,
        expected_modes={0o700},
    )
    config_identity = directory_identity(
        EXPECTED_STATE_ROOT / "config",
        expected_uid=caller_uid,
        expected_gid=caller_gid,
        expected_modes={0o700},
    )
    receipt_identity, receipt_raw = regular_identity(
        RECEIPT_PATH,
        expected_uid=caller_uid,
        expected_gid=caller_gid,
        expected_mode=0o600,
        expected_sha256=EXPECTED_RECEIPT_SHA256,
    )
    manual(
        not exists_nofollow(ARCHIVE_RECEIPT_PATH),
        "legacy receipt archive already exists beside live receipt",
    )
    parsed = parse_legacy_receipt(receipt_raw)
    docker_config, _ = regular_identity(
        DOCKER_CONFIG,
        expected_uid=caller_uid,
        expected_gid=caller_gid,
        expected_mode=0o600,
        expected_sha256=EXPECTED_DOCKER_CONFIG_SHA256,
    )
    containerd_config, _ = regular_identity(
        CONTAINERD_CONFIG,
        expected_uid=caller_uid,
        expected_gid=caller_gid,
        expected_mode=0o600,
        expected_sha256=EXPECTED_CONTAINERD_CONFIG_SHA256,
    )
    runtime_tree = runtime_tree_snapshot()
    docker_pidfile = pidfile_identity(
        DOCKER_PIDFILE, 960217, expected_uid=0, expected_gid=0
    )
    containerd_pidfile = pidfile_identity(
        CONTAINERD_PIDFILE, 960166, expected_uid=0, expected_gid=0
    )
    process_graph, process_observations = capture_process_graph(parsed)
    sockets = runtime_socket_snapshot(960217, 964683)
    processes = process_graph["processes"]
    assert isinstance(processes, dict)
    process_graph["relatedUniverse"] = related_process_universe(
        processes,
        runtime_tree,
        sockets,
        allowed_roles=set(processes),
    )
    runtime_mounts = stable_global_mount_roster(EXPECTED_RUNTIME_ROOT)
    data_mounts = stable_global_mount_roster(EXPECTED_STATE_ROOT / "outer-docker")
    registry_mounts = stable_global_mount_roster(EXPECTED_STATE_ROOT / "registry")
    netns = netns_baseline()
    require_mount_targets_within(
        runtime_mounts,
        allowed_roots=(EXPECTED_RUNTIME_ROOT,),
        label="legacy runtime",
    )
    require_mount_targets_within(
        data_mounts,
        allowed_roots=(EXPECTED_STATE_ROOT / "outer-docker",),
        label="legacy outer Docker",
    )
    require_mount_targets_within(
        registry_mounts,
        allowed_roots=(EXPECTED_STATE_ROOT / "registry", EXPECTED_OVERLAY_TARGET),
        label="legacy registry",
    )
    manual(
        any(item["target"] == str(EXPECTED_OVERLAY_TARGET) for item in data_mounts["occurrences"]),
        "legacy registry overlay mount is absent",
    )
    manual(bool(registry_mounts["occurrences"]), "legacy registry bind mount is absent")
    persistent = {
        str(path): directory_identity(
            path,
            expected_uid=0 if path.name == "outer-docker" else caller_uid,
            expected_gid=0 if path.name == "outer-docker" else caller_gid,
            expected_modes={0o710} if path.name == "outer-docker" else {0o700},
        )
        for path in PERSISTENT_ROOTS
    }
    v5 = require_v5_absent(allow_global_lease=allow_global_lease)
    registry = registry_inventory()
    authority = {
        "bootId": current_boot_id(),
        "stateRootIdentity": state_identity,
        "evidenceRootIdentity": evidence_identity,
        "configRootIdentity": config_identity,
        "legacySource": EXPECTED_LEGACY_SOURCE,
        "legacyReceipt": receipt_identity,
        "legacyReceiptBytes": receipt_raw.decode("utf-8", "strict"),
        "runtime": runtime_tree,
        "configs": {
            "docker": docker_config,
            "containerd": containerd_config,
            "dockerPidfile": docker_pidfile,
            "containerdPidfile": containerd_pidfile,
        },
        "processGraph": process_graph,
        "sockets": sockets,
        "mounts": {
            "runtime": runtime_mounts,
            "outerDocker": data_mounts,
            "registry": registry_mounts,
            "networkNamespace": netns,
        },
        "persistentRoots": persistent,
        "registryInventory": registry,
        "currentV5": v5,
        "mutationPolicy": {
            "cgroup": "forbidden_shared_66_process_observation",
            "forceKill": "forbidden",
            "persistentDataDeletion": "forbidden",
            "automaticShimOrTaskSignal": "forbidden",
            "nonNsfsUnmount": "forbidden",
        },
    }
    observations = {
        "legacyProcInodes": process_observations,
        "processlessMountNamespaces": "not_observable_and_not_claimed",
    }
    return authority, observations


def collect_verification(
    caller_uid: int,
    caller_gid: int,
    *,
    allow_global_lease: bool = False,
) -> dict[str, object]:
    first_authority, first_observations = collect_authority(
        caller_uid, caller_gid, allow_global_lease=allow_global_lease
    )
    second_authority, second_observations = collect_authority(
        caller_uid, caller_gid, allow_global_lease=allow_global_lease
    )
    require(first_authority == second_authority, "legacy authority changed between passes")
    verification_digest = sha256_bytes(canonical_json(second_authority))
    return {
        "schema": SCHEMA,
        "outcome": "verified",
        "mutationAuthorized": False,
        "observedAt": utc_now(),
        "authority": second_authority,
        "observations": second_observations,
        "firstPassObservations": first_observations,
        "blockers": [],
        "verificationSha256": verification_digest,
    }


class RuntimeLease:
    def __init__(self, descriptor: int) -> None:
        self.descriptor = descriptor

    @classmethod
    def acquire(cls) -> "RuntimeLease":
        parent = os.stat(GLOBAL_LEASE_PATH.parent, follow_symlinks=False)
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == 0
            and parent.st_gid == 0
            and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
            "global lease parent authority differs",
        )
        descriptor = os.open(
            GLOBAL_LEASE_PATH,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            observed = os.fstat(descriptor)
            literal = os.stat(GLOBAL_LEASE_PATH, follow_symlinks=False)
            require(
                stat.S_ISREG(observed.st_mode)
                and observed.st_uid == 0
                and observed.st_gid == 0
                and stat.S_IMODE(observed.st_mode) == 0o600
                and observed.st_nlink == 1
                and (observed.st_dev, observed.st_ino)
                == (literal.st_dev, literal.st_ino),
                "global lease identity differs",
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ManualRecoveryRequired("global runtime lifecycle lease is busy") from error
            return cls(descriptor)
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        os.close(self.descriptor)

    def __enter__(self) -> "RuntimeLease":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def atomic_write_at(
    directory_fd: int,
    name: str,
    value: Mapping[str, object],
    *,
    uid: int = 0,
    gid: int = 0,
    mode: int = 0o400,
) -> str:
    require(re.fullmatch(r"[A-Za-z0-9._-]+", name) is not None, "atomic filename is invalid")
    encoded = canonical_json(value)
    require(len(encoded) <= MAX_JSON_BYTES, "atomic document is too large")
    pending = f".{name}.pending"
    try:
        pending_stat = os.stat(pending, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        require(
            stat.S_ISREG(pending_stat.st_mode)
            and pending_stat.st_uid == uid
            and pending_stat.st_gid == gid
            and stat.S_IMODE(pending_stat.st_mode) == mode
            and pending_stat.st_nlink == 1,
            "atomic pending identity differs",
        )
        os.unlink(pending, dir_fd=directory_fd)
        os.fsync(directory_fd)
    descriptor = os.open(
        pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
        dir_fd=directory_fd,
    )
    try:
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fchmod(descriptor, mode)
        os.fchown(descriptor, uid, gid)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(pending, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)
    return sha256_bytes(encoded)


def read_json_at(directory_fd: int, name: str, label: str) -> dict[str, Any] | None:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    try:
        observed = os.fstat(descriptor)
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o400
            and observed.st_nlink == 1
            and observed.st_size <= MAX_JSON_BYTES,
            f"{label} file identity differs",
        )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAX_JSON_BYTES + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= MAX_JSON_BYTES, f"{label} is too large")
            chunks.append(chunk)
        raw = b"".join(chunks)
        require(len(raw) == observed.st_size, f"{label} read length differs")
    finally:
        os.close(descriptor)
    value = parse_json_bytes(raw, label)
    require(isinstance(value, dict), f"{label} is not an object")
    assert isinstance(value, dict)
    return value


def _control_allowed_entries() -> set[str]:
    return {
        SNAPSHOT_NAME,
        f".{SNAPSHOT_NAME}.pending",
        CONTROL_NAME,
        f".{CONTROL_NAME}.pending",
        STATE_NAME,
        f".{STATE_NAME}.pending",
    }


def _validate_control_root_descriptor(parent_fd: int, descriptor: int, name: str) -> None:
    literal = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    observed = os.fstat(descriptor)
    require(
        stat.S_ISDIR(observed.st_mode)
        and observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) == 0o700
        and (observed.st_dev, observed.st_ino) == (literal.st_dev, literal.st_ino),
        "legacy drain control root differs",
    )
    require(
        set(os.listdir(descriptor)) <= _control_allowed_entries(),
        "legacy drain control root contains a foreign entry",
    )


def open_run_parent() -> int:
    parent_fd = os.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent = os.fstat(parent_fd)
        require(
            stat.S_ISDIR(parent.st_mode)
            and parent.st_uid == 0
            and parent.st_gid == 0
            and stat.S_IMODE(parent.st_mode) & 0o022 == 0,
            "legacy drain control parent differs",
        )
        return parent_fd
    except BaseException:
        os.close(parent_fd)
        raise


def open_control_root() -> int:
    parent_fd = open_run_parent()
    try:
        descriptor = os.open(
            CONTROL_ROOT.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        _validate_control_root_descriptor(parent_fd, descriptor, CONTROL_ROOT.name)
        return descriptor
    except BaseException:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    finally:
        os.close(parent_fd)


def snapshot_source(control_fd: int) -> str:
    raw = globals().get("__legacy_pinned_source_bytes__")
    require(
        isinstance(raw, bytes) and 0 < len(raw) <= 4 * 1024 * 1024,
        "legacy drain was not entered through its in-sudo pinned-byte loader",
    )
    assert isinstance(raw, bytes)
    digest = sha256_bytes(raw)
    try:
        existing = read_at(control_fd, SNAPSHOT_NAME, maximum=4 * 1024 * 1024)
    except FileNotFoundError:
        pending = f".{SNAPSHOT_NAME}.pending"
        try:
            pending_stat = os.stat(pending, dir_fd=control_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(
                stat.S_ISREG(pending_stat.st_mode)
                and pending_stat.st_uid == 0
                and pending_stat.st_gid == 0
                and stat.S_IMODE(pending_stat.st_mode) == 0o400
                and pending_stat.st_nlink == 1,
                "legacy drain source pending identity differs",
            )
            os.unlink(pending, dir_fd=control_fd)
            os.fsync(control_fd)
        descriptor = os.open(
            pending,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o400,
            dir_fd=control_fd,
        )
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fchmod(descriptor, 0o400)
            os.fchown(descriptor, 0, 0)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(
            pending,
            SNAPSHOT_NAME,
            src_dir_fd=control_fd,
            dst_dir_fd=control_fd,
        )
        os.fsync(control_fd)
    else:
        require(existing == raw, "legacy drain source snapshot differs")
    return digest


def _reduce_pending_control_capsule(parent_fd: int) -> None:
    try:
        descriptor = os.open(
            CONTROL_PENDING_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except FileNotFoundError:
        return
    try:
        _validate_control_root_descriptor(parent_fd, descriptor, CONTROL_PENDING_NAME)
        for name in tuple(sorted(os.listdir(descriptor))):
            observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            require(
                name in _control_allowed_entries()
                and stat.S_ISREG(observed.st_mode)
                and observed.st_uid == 0
                and observed.st_gid == 0
                and stat.S_IMODE(observed.st_mode) == 0o400
                and observed.st_nlink == 1
                and observed.st_size <= 4 * 1024 * 1024,
                "legacy drain pending capsule entry differs",
            )
            leaf_fd = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=descriptor)
            try:
                bound = os.fstat(leaf_fd)
                require(
                    (bound.st_dev, bound.st_ino)
                    == (observed.st_dev, observed.st_ino),
                    "legacy drain pending capsule entry changed",
                )
                os.unlink(name, dir_fd=descriptor)
                os.fsync(descriptor)
            finally:
                os.close(leaf_fd)
        require(not os.listdir(descriptor), "legacy drain pending capsule did not empty")
        os.rmdir(CONTROL_PENDING_NAME, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(descriptor)


def publish_control_capsule(
    control: Mapping[str, object],
    state: Mapping[str, object],
) -> int:
    parent_fd = open_run_parent()
    descriptor: int | None = None
    published = False
    try:
        try:
            existing = os.open(
                CONTROL_ROOT.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            _validate_control_root_descriptor(parent_fd, existing, CONTROL_ROOT.name)
            return existing
        _reduce_pending_control_capsule(parent_fd)
        os.mkdir(CONTROL_PENDING_NAME, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        descriptor = os.open(
            CONTROL_PENDING_NAME,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        _validate_control_root_descriptor(parent_fd, descriptor, CONTROL_PENDING_NAME)
        source_digest = snapshot_source(descriptor)
        require(
            source_digest == control["sourceSha256"],
            "legacy drain staged source digest differs",
        )
        atomic_write_at(descriptor, CONTROL_NAME, control)
        atomic_write_at(descriptor, STATE_NAME, state)
        require(
            set(os.listdir(descriptor)) == {SNAPSHOT_NAME, CONTROL_NAME, STATE_NAME},
            "legacy drain staged capsule is incomplete",
        )
        os.fsync(descriptor)
        try:
            rename_noreplace_at(
                parent_fd,
                CONTROL_PENDING_NAME,
                parent_fd,
                CONTROL_ROOT.name,
            )
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            os.close(descriptor)
            descriptor = None
            _reduce_pending_control_capsule(parent_fd)
            existing = os.open(
                CONTROL_ROOT.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            _validate_control_root_descriptor(parent_fd, existing, CONTROL_ROOT.name)
            return existing
        os.fsync(parent_fd)
        _validate_control_root_descriptor(parent_fd, descriptor, CONTROL_ROOT.name)
        published = True
        return descriptor
    finally:
        if descriptor is not None and not published:
            os.close(descriptor)
        os.close(parent_fd)


def validate_control(value: object) -> dict[str, Any]:
    control = exact_keys(
        value,
        {
            "schema",
            "observedAt",
            "bootId",
            "stateRoot",
            "caller",
            "verificationSha256",
            "sourceSha256",
            "authority",
        },
        "legacy drain control",
    )
    require(
        control["schema"] == CONTROL_SCHEMA
        and isinstance(control["observedAt"], str)
        and 0 < len(str(control["observedAt"])) <= 128
        and control["bootId"] == current_boot_id()
        and control["stateRoot"] == str(EXPECTED_STATE_ROOT)
        and control["caller"] == {"uid": 1000, "gid": 1000}
        and isinstance(control["verificationSha256"], str)
        and SHA256_RE.fullmatch(str(control["verificationSha256"])) is not None
        and isinstance(control["sourceSha256"], str)
        and SHA256_RE.fullmatch(str(control["sourceSha256"])) is not None
        and isinstance(control["authority"], dict),
        "legacy drain control binding differs",
    )
    require(
        control["verificationSha256"] == sha256_bytes(canonical_json(control["authority"])),
        "legacy drain verification digest differs from its authority",
    )
    return control


def validate_state(value: object, control_digest: str) -> dict[str, Any]:
    state = exact_keys(
        value,
        {
            "schema",
            "observedAt",
            "bootId",
            "stateRoot",
            "controlSha256",
            "phase",
            "netnsMarkerIdentity",
        },
        "legacy drain state",
    )
    require(
        state["schema"] == STATE_SCHEMA
        and isinstance(state["observedAt"], str)
        and 0 < len(str(state["observedAt"])) <= 128
        and state["bootId"] == current_boot_id()
        and state["stateRoot"] == str(EXPECTED_STATE_ROOT)
        and state["controlSha256"] == control_digest
        and state["phase"] in PHASES,
        "legacy drain state binding differs",
    )
    marker = state["netnsMarkerIdentity"]
    marker_required = PHASES.index(str(state["phase"])) >= PHASES.index(
        "mounts_settled"
    )
    if marker_required:
        marker_value = exact_keys(
            marker,
            {"device", "inode", "uid", "gid", "mode", "type", "links", "size"},
            "legacy task netns marker",
        )
        require(
            all(
                isinstance(marker_value[field], int)
                and not isinstance(marker_value[field], bool)
                for field in marker_value
            )
            and marker_value["device"] >= 0
            and marker_value["inode"] > 0
            and marker_value["uid"] == 0
            and marker_value["gid"] == 0
            and marker_value["mode"] == TASK_NETNS_MARKER_MODE
            and marker_value["type"] == stat.S_IFREG
            and marker_value["links"] == 1
            and marker_value["size"] == 0,
            "legacy task netns marker state differs",
        )
    else:
        require(marker is None, "legacy task netns marker was published early")
    return state


class ControlAuthority:
    def __init__(self, descriptor: int, control: dict[str, Any], state: dict[str, Any]) -> None:
        self.descriptor = descriptor
        self.control = control
        self.control_digest = sha256_bytes(canonical_json(control))
        self.state = state

    @classmethod
    def create(
        cls,
        verification: Mapping[str, object],
        *,
        expected_verification_sha256: str,
    ) -> "ControlAuthority":
        require(
            verification["verificationSha256"] == expected_verification_sha256,
            "legacy verification digest differs",
        )
        raw = globals().get("__legacy_pinned_source_bytes__")
        require(
            isinstance(raw, bytes) and 0 < len(raw) <= 4 * 1024 * 1024,
            "legacy drain pinned source bytes are absent",
        )
        assert isinstance(raw, bytes)
        source_digest = sha256_bytes(raw)
        try:
            existing_descriptor = open_control_root()
        except FileNotFoundError:
            existing_descriptor = None
        if existing_descriptor is not None:
            try:
                snapshot = read_at(
                    existing_descriptor,
                    SNAPSHOT_NAME,
                    maximum=4 * 1024 * 1024,
                )
                control_raw = read_json_at(
                    existing_descriptor,
                    CONTROL_NAME,
                    "legacy drain control",
                )
                require(control_raw is not None, "legacy drain control is absent")
                control = validate_control(control_raw)
                require(
                    snapshot == raw
                    and control["sourceSha256"] == source_digest
                    and control["verificationSha256"] == expected_verification_sha256
                    and control["authority"] == verification["authority"],
                    "existing legacy drain control differs",
                )
                control_digest = sha256_bytes(canonical_json(control))
                state_raw = read_json_at(
                    existing_descriptor,
                    STATE_NAME,
                    "legacy drain state",
                )
                require(state_raw is not None, "legacy drain state is absent")
                state = validate_state(state_raw, control_digest)
                return cls(existing_descriptor, control, state)
            except BaseException:
                os.close(existing_descriptor)
                raise
        control_candidate = {
            "schema": CONTROL_SCHEMA,
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(EXPECTED_STATE_ROOT),
            "caller": {"uid": 1000, "gid": 1000},
            "verificationSha256": expected_verification_sha256,
            "sourceSha256": source_digest,
            "authority": verification["authority"],
        }
        control_digest = sha256_bytes(canonical_json(control_candidate))
        state_candidate = {
            "schema": STATE_SCHEMA,
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(EXPECTED_STATE_ROOT),
            "controlSha256": control_digest,
            "phase": "stopping_intent_final",
            "netnsMarkerIdentity": None,
        }
        descriptor = publish_control_capsule(control_candidate, state_candidate)
        try:
            snapshot = read_at(descriptor, SNAPSHOT_NAME, maximum=4 * 1024 * 1024)
            require(snapshot == raw, "legacy drain published source snapshot differs")
            existing_raw = read_json_at(descriptor, CONTROL_NAME, "legacy drain control")
            require(existing_raw is not None, "legacy drain published control is absent")
            control = validate_control(existing_raw)
            require(
                control["verificationSha256"] == expected_verification_sha256
                and control["sourceSha256"] == source_digest
                and control == control_candidate,
                "existing legacy drain control differs",
            )
            control_digest = sha256_bytes(canonical_json(control))
            state_raw = read_json_at(descriptor, STATE_NAME, "legacy drain state")
            require(state_raw is not None, "legacy drain published state is absent")
            state = validate_state(state_raw, control_digest)
            require(state == state_candidate, "existing legacy drain initial state differs")
            return cls(descriptor, control, state)
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def open(cls) -> "ControlAuthority":
        held = globals().get("__legacy_control_root_fd__")
        require(
            isinstance(held, int) and held >= 0,
            "resume did not retain the in-sudo control-root descriptor",
        )
        assert isinstance(held, int)
        descriptor = os.dup(held)
        try:
            snapshot = read_at(descriptor, SNAPSHOT_NAME, maximum=4 * 1024 * 1024)
            control_raw = read_json_at(descriptor, CONTROL_NAME, "legacy drain control")
            require(control_raw is not None, "legacy drain control is absent")
            control = validate_control(control_raw)
            require(
                sha256_bytes(snapshot) == control["sourceSha256"],
                "legacy drain source snapshot digest differs",
            )
            control_digest = sha256_bytes(canonical_json(control))
            state_raw = read_json_at(descriptor, STATE_NAME, "legacy drain state")
            require(state_raw is not None, "legacy drain state is absent")
            state = validate_state(state_raw, control_digest)
            return cls(descriptor, control, state)
        except BaseException:
            os.close(descriptor)
            raise

    def close(self) -> None:
        os.close(self.descriptor)

    def __enter__(self) -> "ControlAuthority":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def phase(self) -> str:
        return str(self.state["phase"])

    def at_least(self, phase: str) -> bool:
        return PHASES.index(self.phase) >= PHASES.index(phase)

    def advance(
        self,
        phase: str,
        *,
        netns_marker_identity: Mapping[str, object] | None = None,
    ) -> None:
        require(phase in PHASES, "legacy drain phase is invalid")
        current_index = PHASES.index(self.phase)
        target_index = PHASES.index(phase)
        require(target_index >= current_index, "legacy drain phase would regress")
        if target_index == current_index:
            return
        require(target_index == current_index + 1, "legacy drain phase would skip")
        marker = self.state["netnsMarkerIdentity"]
        if phase == "mounts_settled":
            require(
                netns_marker_identity is not None,
                "legacy task netns marker identity is absent",
            )
            marker = dict(netns_marker_identity)
        else:
            require(
                netns_marker_identity is None,
                "legacy task netns marker identity was supplied to the wrong phase",
            )
        state = {
            "schema": STATE_SCHEMA,
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(EXPECTED_STATE_ROOT),
            "controlSha256": self.control_digest,
            "phase": phase,
            "netnsMarkerIdentity": marker,
        }
        validate_state(state, self.control_digest)
        atomic_write_at(self.descriptor, STATE_NAME, state)
        self.state = state


def process_authority(control: Mapping[str, object], role: str) -> dict[str, object]:
    authority = control["authority"]
    assert isinstance(authority, dict)
    graph = authority["processGraph"]
    assert isinstance(graph, dict)
    processes = graph["processes"]
    assert isinstance(processes, dict)
    value = processes[role]
    require(isinstance(value, dict), f"recorded process is invalid: {role}")
    return value


def require_related_process_cutoff(
    control: Mapping[str, object],
    *,
    allowed_roles: set[str],
) -> dict[str, object]:
    authority = control["authority"]
    assert isinstance(authority, dict)
    graph = authority["processGraph"]
    assert isinstance(graph, dict)
    processes = graph["processes"]
    runtime = authority["runtime"]
    sockets = authority["sockets"]
    require(
        isinstance(processes, dict)
        and isinstance(runtime, dict)
        and isinstance(sockets, dict),
        "recorded related-process authority is invalid",
    )
    return related_process_universe(
        processes,
        runtime,
        sockets,
        allowed_roles=allowed_roles,
    )


@contextlib.contextmanager
def hold_related_process_cutoff(
    control: Mapping[str, object],
    *,
    allowed_roles: set[str],
    revalidate_after: bool = True,
) -> Iterator[dict[str, object]]:
    proof = require_related_process_cutoff(
        control,
        allowed_roles=allowed_roles,
    )
    held: list[CapturedTask] = []
    try:
        for row in proof["related"]:
            thread_group_id = int(row["pid"])
            task_id = int(row["taskId"])
            task = capture_task(thread_group_id, task_id)
            manual(
                task is not None,
                "recorded legacy task left the action cutoff: "
                f"{thread_group_id}/{task_id}",
            )
            assert task is not None
            held.append(task)
            manual(
                (task.parent_pid, task.start_ticks)
                == (row["parentPid"], row["startTimeTicks"])
                and not pidfd_exited(task.pidfd),
                "recorded legacy task changed at the action cutoff: "
                f"{thread_group_id}/{task_id}",
            )
        committed = require_related_process_cutoff(
            control,
            allowed_roles=allowed_roles,
        )
        require(
            committed == proof,
            "related task universe changed while entering the action cutoff",
        )
        yield proof
        if revalidate_after:
            final = require_related_process_cutoff(
                control,
                allowed_roles=allowed_roles,
            )
            require(
                final == proof,
                "related task universe changed across the action cutoff",
            )
    finally:
        for task in held:
            task.close()


def exact_process_status(recorded: Mapping[str, object]) -> str:
    pid = int(recorded["pid"])
    if not process_exists(pid):
        return "absent"
    try:
        observed = capture_process(recorded)
    except ProcessUnavailable:
        return "absent"
    except DrainError as error:
        raise ManualRecoveryRequired(f"recorded PID has a foreign identity: {pid}") from error
    manual(
        observed.authority == dict(recorded),
        f"recorded PID changed namespace or cgroup identity: {pid}",
    )
    return "exact"


def exact_live_roles(
    control: Mapping[str, object],
    roles: set[str],
) -> set[str]:
    live: set[str] = set()
    for role in sorted(roles):
        status = exact_process_status(process_authority(control, role))
        if status == "exact":
            live.add(role)
        else:
            require(status == "absent", f"legacy process status differs: {role}")
    return live


def signal_exact_process(recorded: Mapping[str, object], timeout_seconds: float = 120.0) -> None:
    pid = int(recorded["pid"])
    if not process_exists(pid):
        return
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError as error:
        if error.errno == errno.ESRCH:
            return
        raise
    try:
        if pidfd_exited(pidfd):
            return
        try:
            observed = capture_process(recorded)
        except ProcessUnavailable:
            return
        require(observed.authority == dict(recorded), "recorded process changed before signal")
        if pidfd_exited(pidfd):
            return
        require(hasattr(signal, "pidfd_send_signal"), "pidfd signaling is unavailable")
        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        require(
            bool(poller.poll(int(timeout_seconds * 1000))),
            f"recorded process did not exit after SIGTERM: {pid}",
        )
    finally:
        os.close(pidfd)


def wait_for_roles_absent(
    control: Mapping[str, object],
    roles: Sequence[str],
    *,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = [
            role
            for role in roles
            if exact_process_status(process_authority(control, role)) == "exact"
        ]
        if not remaining:
            return
        if time.monotonic() >= deadline:
            raise ManualRecoveryRequired(
                "legacy process graph did not quiesce without force: " + ",".join(remaining)
            )
        time.sleep(0.1)


def runtime_root_descriptors(
    control: Mapping[str, object],
    *,
    require_root_owned: bool | None,
) -> tuple[int, int]:
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["runtime"]["rootIdentity"]
    parent_fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_fd: int | None = None
    try:
        root_fd = os.open(
            EXPECTED_RUNTIME_ROOT.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        observed = os.fstat(root_fd)
        literal = os.stat(
            EXPECTED_RUNTIME_ROOT.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        admitted_owners = (
            {(0, 0)}
            if require_root_owned is True
            else {(int(expected["uid"]), int(expected["gid"]))}
            if require_root_owned is False
            else {(int(expected["uid"]), int(expected["gid"])), (0, 0)}
        )
        require(
            stat.S_ISDIR(observed.st_mode)
            and (observed.st_dev, observed.st_ino)
            == (expected["device"], expected["inode"])
            and (literal.st_dev, literal.st_ino)
            == (observed.st_dev, observed.st_ino)
            and (observed.st_uid, observed.st_gid) in admitted_owners
            and stat.S_IMODE(observed.st_mode) == 0o700,
            "legacy runtime root custody differs",
        )
        return parent_fd, root_fd
    except BaseException:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)
        raise


def _recorded_directory_pair(
    control: Mapping[str, object],
    *,
    child_name: str,
    authority_key: str,
) -> tuple[int, int]:
    authority = control["authority"]
    assert isinstance(authority, dict)
    state_expected = authority["stateRootIdentity"]
    child_expected = authority[authority_key]
    assert isinstance(state_expected, dict) and isinstance(child_expected, dict)
    state_fd = os.open(
        EXPECTED_STATE_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    child_fd: int | None = None
    try:
        state_observed = os.fstat(state_fd)
        state_literal = os.stat(EXPECTED_STATE_ROOT, follow_symlinks=False)
        require(
            stat.S_ISDIR(state_observed.st_mode)
            and (state_observed.st_dev, state_observed.st_ino)
            == (state_expected["device"], state_expected["inode"])
            == (state_literal.st_dev, state_literal.st_ino),
            "legacy state root binding differs",
        )
        child_fd = os.open(
            child_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=state_fd,
        )
        child_observed = os.fstat(child_fd)
        child_literal = os.stat(
            child_name,
            dir_fd=state_fd,
            follow_symlinks=False,
        )
        require(
            stat.S_ISDIR(child_observed.st_mode)
            and (child_observed.st_dev, child_observed.st_ino)
            == (child_expected["device"], child_expected["inode"])
            == (child_literal.st_dev, child_literal.st_ino)
            and (child_observed.st_uid, child_observed.st_gid)
            == (child_expected["uid"], child_expected["gid"])
            and stat.S_IMODE(child_observed.st_mode) == child_expected["mode"],
            f"legacy {child_name} directory binding differs",
        )
        return state_fd, child_fd
    except BaseException:
        if child_fd is not None:
            os.close(child_fd)
        os.close(state_fd)
        raise


def recorded_evidence_descriptors(
    control: Mapping[str, object],
) -> tuple[int, int]:
    return _recorded_directory_pair(
        control,
        child_name="evidence",
        authority_key="evidenceRootIdentity",
    )


def recorded_config_descriptors(
    control: Mapping[str, object],
) -> tuple[int, int]:
    return _recorded_directory_pair(
        control,
        child_name="config",
        authority_key="configRootIdentity",
    )


def require_recorded_entry(
    observed: os.stat_result,
    expected: Mapping[str, object],
    *,
    label: str,
) -> None:
    expected_links = int(expected["links"])
    links_match = observed.st_nlink == expected_links or (
        stat.S_ISDIR(observed.st_mode)
        and 2 <= observed.st_nlink <= expected_links
    )
    require(
        (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
            stat.S_IFMT(observed.st_mode),
        )
        == (
            expected["device"],
            expected["inode"],
            expected["uid"],
            expected["gid"],
            expected["mode"],
            expected["type"],
        )
        and links_match
        and (
            "size" not in expected or observed.st_size == expected["size"]
        ),
        f"{label} identity differs",
    )


def transfer_runtime_custody(control: Mapping[str, object]) -> None:
    with hold_related_process_cutoff(
        control,
        allowed_roles=set(EXPECTED_PROCESS_CANDIDATES),
    ):
        _transfer_runtime_custody(control)


def _transfer_runtime_custody(control: Mapping[str, object]) -> None:
    parent_fd, root_fd = runtime_root_descriptors(control, require_root_owned=None)
    try:
        os.fchown(root_fd, 0, 0)
        os.fchmod(root_fd, 0o700)
        os.fsync(root_fd)
        literal = os.stat(
            EXPECTED_RUNTIME_ROOT.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        observed = os.fstat(root_fd)
        require(
            (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o700,
            "legacy runtime root changed during custody transfer",
        )
        os.fsync(parent_fd)
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def remove_bound_socket(control: Mapping[str, object]) -> None:
    with hold_related_process_cutoff(
        control,
        allowed_roles=set(EXPECTED_PROCESS_CANDIDATES),
    ):
        _remove_bound_socket(control)


def _remove_bound_socket(control: Mapping[str, object]) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    sockets = authority["sockets"]
    assert isinstance(sockets, dict)
    expected = next(
        item
        for item in sockets["pathIdentities"]
        if item["path"] == str(DOCKER_SOCKET)
    )
    socket_present = exists_nofollow(DOCKER_SOCKET)
    if socket_present:
        runtime_socket_snapshot(int(process_authority(control, "dockerd")["pid"]))
    parent_fd, root_fd = runtime_root_descriptors(control, require_root_owned=True)
    leaf_fd: int | None = None
    try:
        try:
            leaf_fd = os.open("docker.sock", os.O_PATH | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            leaf_fd = None
        if leaf_fd is None:
            require(not socket_present, "Docker API socket disappeared before revocation")
        else:
            observed = os.fstat(leaf_fd)
            literal = os.stat("docker.sock", dir_fd=root_fd, follow_symlinks=False)
            require(
                stat.S_ISSOCK(observed.st_mode)
                and (observed.st_dev, observed.st_ino, observed.st_uid, observed.st_gid)
                == (
                    expected["device"],
                    expected["inode"],
                    expected["uid"],
                    expected["gid"],
                )
                and (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino),
                "Docker API socket binding differs before revocation",
            )
            os.unlink("docker.sock", dir_fd=root_fd)
            os.fsync(root_fd)
    finally:
        if leaf_fd is not None:
            os.close(leaf_fd)
        os.close(root_fd)
        os.close(parent_fd)
    post_revocation_socket_snapshot(control)


def anchors_from_document(value: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    anchors = value["sourceAnchors"]
    require(isinstance(anchors, list), "mount anchor roster is invalid")
    return tuple((str(item["device"]), str(item["root"])) for item in anchors)


def require_mounts_absent(
    control: Mapping[str, object],
    key: str,
    root: Path,
    *,
    use_recorded_anchors: bool = True,
) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    mounts = authority["mounts"]
    assert isinstance(mounts, dict)
    recorded = mounts[key]
    assert isinstance(recorded, dict)
    observed = stable_global_mount_roster(
        root,
        anchors_from_document(recorded) if use_recorded_anchors else None,
    )
    manual(not observed["occurrences"], f"legacy mount remains: {key}")


def fd_umount(descriptor: int) -> None:
    require(descriptor >= 0, "nsfs mount descriptor is invalid")
    proc_path = f"/proc/self/fd/{descriptor}".encode("ascii")
    function = getattr(LIBC, "umount2", None)
    require(function is not None, "fd-backed umount is unavailable")
    result = function(ctypes.c_char_p(proc_path), ctypes.c_int(0))
    if result != 0:
        observed_errno = ctypes.get_errno()
        raise OSError(observed_errno, os.strerror(observed_errno))


def fd_mount_id(descriptor: int) -> int:
    raw = Path(f"/proc/self/fdinfo/{descriptor}").read_text(
        encoding="ascii"
    )
    values = [
        line.split(":", 1)[1].strip()
        for line in raw.splitlines()
        if line.startswith("mnt_id:")
    ]
    require(
        len(values) == 1 and values[0].isdigit(),
        "held mount descriptor lacks one mount ID",
    )
    return int(values[0])


def _runtime_tree_rows(control: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
    authority = control["authority"]
    assert isinstance(authority, dict)
    runtime = authority["runtime"]
    assert isinstance(runtime, dict)
    return {
        str(Path(str(item["path"])).relative_to(EXPECTED_RUNTIME_ROOT)): item
        for item in runtime["tree"]
    }


def _open_recorded_runtime_directory(
    parent_fd: int,
    name: str,
    expected: Mapping[str, object],
) -> int:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    try:
        observed = os.fstat(descriptor)
        literal = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        require_recorded_entry(observed, expected, label=f"legacy runtime directory {name}")
        require(
            (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino),
            f"legacy runtime directory binding differs: {name}",
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def settle_task_netns(control: Mapping[str, object]) -> dict[str, object]:
    require_related_process_cutoff(control, allowed_roles=set())
    authority = control["authority"]
    assert isinstance(authority, dict)
    netns = authority["mounts"]["networkNamespace"]
    source = netns["sourceAnchor"]
    anchor = ((str(source["device"]), str(source["root"])),)
    observed = stable_global_mount_roster(
        TASK_NETNS_TARGET,
        anchor,
        tuple(sorted((*netns["ambientTargets"], str(netns["ownedTarget"])))),
    )
    recorded_occurrences = list(netns["occurrences"])
    ambient = set(netns["ambientTargets"])
    owned = str(netns["ownedTarget"])
    expected_ambient = [
        item for item in recorded_occurrences if item["target"] in ambient
    ]
    owned_occurrences = [
        item for item in observed["occurrences"] if item["target"] == owned
    ]
    rows = _runtime_tree_rows(control)
    root_parent_fd, root_fd = runtime_root_descriptors(
        control,
        require_root_owned=True,
    )
    exec_fd: int | None = None
    netns_fd: int | None = None
    target_fd: int | None = None
    marker_identity: dict[str, object] | None = None
    try:
        exec_fd = _open_recorded_runtime_directory(
            root_fd,
            "docker-exec",
            rows["docker-exec"],
        )
        netns_fd = _open_recorded_runtime_directory(
            exec_fd,
            "netns",
            rows["docker-exec/netns"],
        )
        target_fd = os.open(
            "default",
            os.O_PATH | os.O_NOFOLLOW,
            dir_fd=netns_fd,
        )
        if owned_occurrences:
            manual(
                observed["occurrences"] == recorded_occurrences
                and len(owned_occurrences) == 1,
                "legacy netns action-time occurrence roster differs",
            )
            mounted = os.fstat(target_fd)
            literal = os.stat("default", dir_fd=netns_fd, follow_symlinks=False)
            require_recorded_entry(
                mounted,
                rows[TASK_NETNS_RELATIVE],
                label="legacy mounted task nsfs",
            )
            require(
                (literal.st_dev, literal.st_ino)
                == (mounted.st_dev, mounted.st_ino),
                "legacy mounted task nsfs binding differs",
            )
            require(
                fd_mount_id(target_fd) == int(owned_occurrences[0]["mountId"]),
                "held task nsfs mount ID differs",
            )
            action_roster = stable_global_mount_roster(
                TASK_NETNS_TARGET,
                anchor,
                tuple(
                    sorted(
                        (*netns["ambientTargets"], str(netns["ownedTarget"]))
                    )
                ),
            )
            manual(
                action_roster["occurrences"] == recorded_occurrences
                and fd_mount_id(target_fd)
                == int(owned_occurrences[0]["mountId"]),
                "legacy netns roster changed before fd-backed unmount",
            )
            fd_umount(target_fd)
            os.close(target_fd)
            target_fd = None
        else:
            manual(
                observed["occurrences"] == expected_ambient,
                "legacy netns absent replay roster differs",
            )
        marker_fd = os.open(
            "default",
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=netns_fd,
        )
        try:
            marker = os.fstat(marker_fd)
            marker_literal = os.stat(
                "default", dir_fd=netns_fd, follow_symlinks=False
            )
            require(
                stat.S_ISREG(marker.st_mode)
                and marker.st_uid == 0
                and marker.st_gid == 0
                and stat.S_IMODE(marker.st_mode) == TASK_NETNS_MARKER_MODE
                and marker.st_nlink == 1
                and marker.st_size == 0
                and (marker_literal.st_dev, marker_literal.st_ino)
                == (marker.st_dev, marker.st_ino),
                "legacy task nsfs did not reveal its exact root-owned empty marker",
            )
            marker_identity = identity_document(TASK_NETNS_TARGET, marker)
            marker_identity.pop("path")
            marker_identity["size"] = marker.st_size
        finally:
            os.close(marker_fd)
        os.fsync(netns_fd)
    finally:
        for descriptor in (target_fd, netns_fd, exec_fd, root_fd, root_parent_fd):
            if descriptor is not None:
                os.close(descriptor)
    final = stable_global_mount_roster(
        TASK_NETNS_TARGET,
        anchor,
        tuple(sorted((*netns["ambientTargets"], str(netns["ownedTarget"])))),
    )
    manual(
        final["occurrences"] == expected_ambient,
        "legacy task netns did not return to its exact ambient roster",
    )
    require(marker_identity is not None, "legacy task netns marker identity is absent")
    return marker_identity


def _require_task_netns_marker(
    observed: os.stat_result,
    expected: Mapping[str, object] | None = None,
) -> None:
    require(
        stat.S_ISREG(observed.st_mode)
        and observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) == TASK_NETNS_MARKER_MODE
        and observed.st_nlink == 1
        and observed.st_size == 0,
        "legacy task netns marker identity differs",
    )
    if expected is not None:
        require(
            (observed.st_dev, observed.st_ino)
            == (expected["device"], expected["inode"]),
            "legacy task netns marker inode differs",
        )


def _scan_runtime_directory(
    directory_fd: int,
    expected_rows: Mapping[str, Mapping[str, object]],
    *,
    prefix: str = "",
    marker_identity: Mapping[str, object],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for name in tuple(sorted(os.listdir(directory_fd))):
        relative = f"{prefix}/{name}" if prefix else name
        manual(
            relative in expected_rows,
            f"legacy runtime preflight found a foreign entry: {relative}",
        )
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if relative == "docker.sock":
            raise ManualRecoveryRequired("legacy Docker API socket reappeared")
        if relative == TASK_NETNS_RELATIVE:
            _require_task_netns_marker(observed, marker_identity)
        else:
            require_recorded_entry(
                observed,
                expected_rows[relative],
                label=f"legacy runtime entry {relative}",
            )
        row = {
            "path": relative,
            "device": observed.st_dev,
            "inode": observed.st_ino,
            "uid": observed.st_uid,
            "gid": observed.st_gid,
            "mode": stat.S_IMODE(observed.st_mode),
            "type": stat.S_IFMT(observed.st_mode),
            "links": observed.st_nlink,
            "size": observed.st_size,
        }
        result.append(row)
        if stat.S_ISDIR(observed.st_mode):
            child_fd = _open_recorded_runtime_directory(
                directory_fd,
                name,
                expected_rows[relative],
            )
            try:
                result.extend(
                    _scan_runtime_directory(
                        child_fd,
                        expected_rows,
                        prefix=relative,
                        marker_identity=marker_identity,
                    )
                )
            finally:
                os.close(child_fd)
    return result


def runtime_reduction_preflight(
    control: Mapping[str, object],
    marker_identity: Mapping[str, object],
) -> dict[str, object]:
    require_related_process_cutoff(control, allowed_roles=set())
    require_mounts_absent(
        control,
        "runtime",
        EXPECTED_RUNTIME_ROOT,
        use_recorded_anchors=False,
    )
    parent_fd, root_fd = runtime_root_descriptors(
        control,
        require_root_owned=True,
    )
    try:
        rows = _runtime_tree_rows(control)
        first = _scan_runtime_directory(
            root_fd,
            rows,
            marker_identity=marker_identity,
        )
        second = _scan_runtime_directory(
            root_fd,
            rows,
            marker_identity=marker_identity,
        )
        require(first == second, "legacy runtime tree changed across preflight passes")
    finally:
        os.close(root_fd)
        os.close(parent_fd)

    authority = control["authority"]
    assert isinstance(authority, dict)
    expected_pidfile = authority["configs"]["containerdPidfile"]
    state_fd, config_fd = recorded_config_descriptors(control)
    try:
        try:
            pidfile_fd = os.open(
                CONTAINERD_PIDFILE.name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=config_fd,
            )
        except FileNotFoundError:
            pidfile = None
        else:
            try:
                observed = os.fstat(pidfile_fd)
                literal = os.stat(
                    CONTAINERD_PIDFILE.name,
                    dir_fd=config_fd,
                    follow_symlinks=False,
                )
                require_recorded_entry(
                    observed,
                    expected_pidfile,
                    label="legacy containerd pidfile",
                )
                raw = b""
                while len(raw) <= 64:
                    chunk = os.read(pidfile_fd, 65 - len(raw))
                    if not chunk:
                        break
                    raw += chunk
                require(
                    raw.decode("ascii", "strict").strip()
                    == str(expected_pidfile["expectedPid"])
                    and sha256_bytes(raw) == expected_pidfile["sha256"]
                    and (literal.st_dev, literal.st_ino)
                    == (observed.st_dev, observed.st_ino),
                    "legacy containerd pidfile bytes or binding differ",
                )
                pidfile = identity_document(CONTAINERD_PIDFILE, observed)
                pidfile["sha256"] = sha256_bytes(raw)
                pidfile["size"] = len(raw)
            finally:
                os.close(pidfile_fd)
    finally:
        os.close(config_fd)
        os.close(state_fd)
    manual(pidfile is not None, "legacy containerd pidfile disappeared")
    return {"runtime": second, "pidfile": pidfile}


def require_containerd_pidfile_exact(control: Mapping[str, object]) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["configs"]["containerdPidfile"]
    state_fd, config_fd = recorded_config_descriptors(control)
    leaf_fd: int | None = None
    try:
        try:
            leaf_fd = os.open(
                CONTAINERD_PIDFILE.name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=config_fd,
            )
        except FileNotFoundError:
            raise ManualRecoveryRequired("legacy containerd pidfile disappeared")
        observed = os.fstat(leaf_fd)
        literal = os.stat(
            CONTAINERD_PIDFILE.name,
            dir_fd=config_fd,
            follow_symlinks=False,
        )
        require_recorded_entry(
            observed,
            expected,
            label="legacy containerd pidfile",
        )
        raw = os.read(leaf_fd, 65)
        require(
            raw.decode("ascii", "strict").strip() == str(expected["expectedPid"])
            and sha256_bytes(raw) == expected["sha256"]
            and (literal.st_dev, literal.st_ino)
            == (observed.st_dev, observed.st_ino),
            "legacy containerd pidfile changed during terminal reproof",
        )
    finally:
        if leaf_fd is not None:
            os.close(leaf_fd)
        os.close(config_fd)
        os.close(state_fd)


def _reduce_runtime_directory(
    directory_fd: int,
    expected_rows: Mapping[str, Mapping[str, object]],
    *,
    prefix: str = "",
    marker_identity: Mapping[str, object],
) -> None:
    for name in tuple(sorted(os.listdir(directory_fd))):
        relative = f"{prefix}/{name}" if prefix else name
        manual(
            relative in expected_rows,
            f"legacy runtime reducer found a foreign entry: {relative}",
        )
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if relative == "docker.sock":
            raise ManualRecoveryRequired("legacy Docker API socket reappeared")
        if relative == TASK_NETNS_RELATIVE:
            _require_task_netns_marker(observed, marker_identity)
        else:
            require_recorded_entry(
                observed,
                expected_rows[relative],
                label=f"legacy runtime entry {relative}",
            )
        if stat.S_ISDIR(observed.st_mode):
            child_fd = _open_recorded_runtime_directory(
                directory_fd,
                name,
                expected_rows[relative],
            )
            try:
                _reduce_runtime_directory(
                    child_fd,
                    expected_rows,
                    prefix=relative,
                    marker_identity=marker_identity,
                )
                require(not os.listdir(child_fd), f"legacy runtime directory remained: {relative}")
                os.fsync(child_fd)
                literal = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                require(
                    (literal.st_dev, literal.st_ino)
                    == (observed.st_dev, observed.st_ino),
                    f"legacy runtime directory changed before removal: {relative}",
                )
                os.rmdir(name, dir_fd=directory_fd)
            finally:
                os.close(child_fd)
        else:
            leaf_fd = os.open(
                name,
                os.O_PATH | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            try:
                bound = os.fstat(leaf_fd)
                require(
                    (bound.st_dev, bound.st_ino) == (observed.st_dev, observed.st_ino),
                    f"legacy runtime leaf changed before removal: {relative}",
                )
                os.unlink(name, dir_fd=directory_fd)
            finally:
                os.close(leaf_fd)
        os.fsync(directory_fd)


def reduce_runtime_tree(
    control: Mapping[str, object],
    marker_identity: Mapping[str, object],
) -> None:
    require_related_process_cutoff(control, allowed_roles=set())
    require_mounts_absent(
        control,
        "runtime",
        EXPECTED_RUNTIME_ROOT,
        use_recorded_anchors=False,
    )
    parent_fd, root_fd = runtime_root_descriptors(
        control,
        require_root_owned=True,
    )
    try:
        _reduce_runtime_directory(
            root_fd,
            _runtime_tree_rows(control),
            marker_identity=marker_identity,
        )
        require(not os.listdir(root_fd), "legacy runtime root did not become empty")
        root = os.fstat(root_fd)
        require(
            root.st_uid == 0
            and root.st_gid == 0
            and stat.S_IMODE(root.st_mode) == 0o700,
            "legacy runtime empty marker custody differs",
        )
        os.fsync(root_fd)
        os.fsync(parent_fd)
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def remove_empty_runtime_root(control: Mapping[str, object]) -> None:
    require_related_process_cutoff(control, allowed_roles=set())
    try:
        parent_fd, root_fd = runtime_root_descriptors(
            control,
            require_root_owned=True,
        )
    except FileNotFoundError:
        parent_fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for _ in range(2):
                try:
                    os.stat(
                        EXPECTED_RUNTIME_ROOT.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    continue
                raise DrainError("legacy runtime root absence is unstable")
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        return
    try:
        require(not os.listdir(root_fd), "legacy runtime empty marker is not empty")
        literal = os.stat(
            EXPECTED_RUNTIME_ROOT.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        observed = os.fstat(root_fd)
        require(
            (literal.st_dev, literal.st_ino) == (observed.st_dev, observed.st_ino)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o700,
            "legacy runtime empty marker binding differs",
        )
        os.rmdir(EXPECTED_RUNTIME_ROOT.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def _read_regular_at(
    directory_fd: int,
    name: str,
    *,
    maximum: int,
    minimum: int = 1,
    flags: int = os.O_RDONLY,
    allowed_links: frozenset[int] = frozenset({1}),
) -> tuple[int, os.stat_result, bytes] | None:
    try:
        descriptor = os.open(
            name,
            flags | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return None
    try:
        observed = os.fstat(descriptor)
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_nlink in allowed_links
            and 0 <= minimum <= observed.st_size <= maximum,
            f"bound regular file identity differs: {name}",
        )
        raw = b""
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        require(
            len(raw) == observed.st_size and len(raw) <= maximum,
            f"bound regular file read differs: {name}",
        )
        literal = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        after = os.fstat(descriptor)
        require(
            (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_uid,
                after.st_gid,
                stat.S_IMODE(after.st_mode),
                after.st_nlink,
            )
            == (
                observed.st_dev,
                observed.st_ino,
                observed.st_size,
                observed.st_uid,
                observed.st_gid,
                stat.S_IMODE(observed.st_mode),
                observed.st_nlink,
            )
            and (literal.st_dev, literal.st_ino)
            == (observed.st_dev, observed.st_ino),
            f"bound regular file changed while reading: {name}",
        )
        return descriptor, observed, raw
    except BaseException:
        os.close(descriptor)
        raise


def settle_linked_publication_replay(directory_fd: int) -> None:
    """Make a response-lost directory link durable before FD-relative reproof."""
    os.fsync(directory_fd)


def rename_noreplace_at(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    function = getattr(LIBC, "renameat2", None)
    require(function is not None, "no-replace rename is unavailable")
    result = function(
        ctypes.c_int(source_directory_fd),
        ctypes.c_char_p(os.fsencode(source_name)),
        ctypes.c_int(destination_directory_fd),
        ctypes.c_char_p(os.fsencode(destination_name)),
        ctypes.c_uint(RENAME_NOREPLACE),
    )
    if result != 0:
        observed_errno = ctypes.get_errno()
        raise OSError(observed_errno, os.strerror(observed_errno))


def _require_legacy_receipt(
    observed: os.stat_result,
    raw: bytes,
    expected: Mapping[str, object],
    *,
    terminal: bool,
) -> None:
    expected_owner = (0, 0, 0o400) if terminal else None
    admitted_live_owners = {
        (int(expected["uid"]), int(expected["gid"]), int(expected["mode"])),
        (0, 0, int(expected["mode"])),
        (0, 0, 0o400),
    }
    owner = (
        observed.st_uid,
        observed.st_gid,
        stat.S_IMODE(observed.st_mode),
    )
    owner_matches = owner == expected_owner if terminal else owner in admitted_live_owners
    require(
        stat.S_ISREG(observed.st_mode)
        and observed.st_nlink in ({1, 2} if terminal else {1})
        and (
            terminal
            or (observed.st_dev, observed.st_ino)
            == (expected["device"], expected["inode"])
        )
        and observed.st_size == expected["size"]
        and sha256_bytes(raw) == EXPECTED_RECEIPT_SHA256
        and owner_matches,
        "legacy receipt terminal identity differs"
        if terminal
        else "legacy receipt live identity differs",
    )


def recorded_legacy_receipt_bytes(control: Mapping[str, object]) -> bytes:
    authority = control["authority"]
    assert isinstance(authority, dict)
    value = authority.get("legacyReceiptBytes")
    require(isinstance(value, str), "recorded legacy receipt bytes are absent")
    raw = value.encode("utf-8")
    expected = authority["legacyReceipt"]
    require(
        len(raw) == expected["size"]
        and sha256_bytes(raw) == EXPECTED_RECEIPT_SHA256,
        "recorded legacy receipt bytes differ",
    )
    return raw


def receipt_tombstone_bytes(control: Mapping[str, object]) -> bytes:
    return receipt_tombstone_bytes_for_control_digest(
        sha256_bytes(canonical_json(control))
    )


def receipt_tombstone_bytes_for_control_digest(control_digest: str) -> bytes:
    require(
        SHA256_RE.fullmatch(control_digest) is not None,
        "legacy tombstone control digest is invalid",
    )
    return canonical_json(
        {
            "schema": SOURCE_TOMBSTONE_SCHEMA,
            "stateRoot": str(EXPECTED_STATE_ROOT),
            "legacyReceiptSha256": EXPECTED_RECEIPT_SHA256,
            "legacyReceiptArchive": str(ARCHIVE_RECEIPT_PATH),
            "controlSha256": control_digest,
        }
    )


def _live_receipt_disposition(
    observed: os.stat_result,
    raw: bytes,
    control: Mapping[str, object],
) -> str:
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["legacyReceipt"]
    original = recorded_legacy_receipt_bytes(control)
    tombstone = receipt_tombstone_bytes(control)
    tombstone_owners = {
        (0, 0, 0o400),
        (int(expected["uid"]), int(expected["gid"]), 0o400),
        (
            int(expected["uid"]),
            int(expected["gid"]),
            int(expected["mode"]),
        ),
    }
    if (
        (observed.st_dev, observed.st_ino)
        == (expected["device"], expected["inode"])
        and (
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        )
        in tombstone_owners
        and observed.st_nlink == 1
        and tombstone.startswith(raw)
    ):
        return "tombstone" if raw == tombstone else "tombstone_prefix"
    try:
        _require_legacy_receipt(observed, raw, expected, terminal=False)
    except DrainError:
        return "foreign"
    return "legacy" if raw == original else "foreign"


def legacy_receipt_state(
    control: Mapping[str, object],
) -> tuple[str, bytes | None]:
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["legacyReceipt"]
    state_fd, evidence_fd = recorded_evidence_descriptors(control)
    live: tuple[int, os.stat_result, bytes] | None = None
    archive: tuple[int, os.stat_result, bytes] | None = None
    try:
        # A linked entry may be visible after response loss but not yet durable.
        # Rebinding this recorded parent, fsyncing it, and only then rereading
        # makes every archived replay complete the publication before advance.
        settle_linked_publication_replay(evidence_fd)
        live = _read_regular_at(
            evidence_fd,
            RECEIPT_PATH.name,
            maximum=MAX_JSON_BYTES,
            minimum=0,
        )
        archive = _read_regular_at(
            evidence_fd,
            ARCHIVE_RECEIPT_PATH.name,
            maximum=MAX_JSON_BYTES,
            allowed_links=frozenset({1, 2}),
        )
        if archive is not None:
            _require_legacy_receipt(archive[1], archive[2], expected, terminal=True)
            if live is not None and sha256_bytes(live[2]) == EXPECTED_RECEIPT_SHA256:
                raise ManualRecoveryRequired("live and archived legacy receipts coexist")
            return "archived", archive[2]
        manual(live is not None, "legacy receipt and archive are both absent")
        assert live is not None
        disposition = _live_receipt_disposition(live[1], live[2], control)
        manual(
            disposition in {"legacy", "tombstone", "tombstone_prefix"},
            "legacy live receipt path contains a foreign entry",
        )
        return disposition, live[2]
    finally:
        for value in (live, archive):
            if value is not None:
                os.close(value[0])
        os.close(evidence_fd)
        os.close(state_fd)


def transfer_receipt_custody(control: Mapping[str, object]) -> None:
    require_related_process_cutoff(control, allowed_roles=set())
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["legacyReceipt"]
    state_fd, evidence_fd = recorded_evidence_descriptors(control)
    value: tuple[int, os.stat_result, bytes] | None = None
    try:
        value = _read_regular_at(
            evidence_fd,
            RECEIPT_PATH.name,
            maximum=MAX_JSON_BYTES,
            minimum=0,
        )
        if value is None:
            state, _ = legacy_receipt_state(control)
            require(state == "archived", "legacy receipt custody source is absent")
            return
        descriptor, observed, raw = value
        disposition = _live_receipt_disposition(observed, raw, control)
        if disposition in {"tombstone", "tombstone_prefix"}:
            return
        manual(disposition == "legacy", "legacy receipt custody path is foreign")
        _require_legacy_receipt(observed, raw, expected, terminal=False)
        if (observed.st_uid, observed.st_gid) != (0, 0):
            os.fchown(descriptor, 0, 0)
            os.fsync(descriptor)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o400:
            os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        literal = os.stat(
            RECEIPT_PATH.name,
            dir_fd=evidence_fd,
            follow_symlinks=False,
        )
        final = os.fstat(descriptor)
        _require_legacy_receipt(final, raw, expected, terminal=True)
        require(
            (literal.st_dev, literal.st_ino) == (final.st_dev, final.st_ino),
            "legacy receipt changed during custody transfer",
        )
        os.fsync(evidence_fd)
    finally:
        if value is not None:
            os.close(value[0])
        os.close(evidence_fd)
        os.close(state_fd)


def _write_all(descriptor: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(descriptor, raw[offset:])
        require(written > 0, "bound file write made no progress")
        offset += written


def _create_root_tmpfile(
    evidence_fd: int,
    raw: bytes,
    *,
    expected_sha256: str,
) -> int:
    require(hasattr(os, "O_TMPFILE"), "unnamed archive publication is unavailable")
    descriptor = os.open(
        ".",
        os.O_TMPFILE | os.O_RDWR,
        0o400,
        dir_fd=evidence_fd,
    )
    try:
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o400)
        _write_all(descriptor, raw)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        observed = os.fstat(descriptor)
        verified = b""
        while len(verified) <= MAX_JSON_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_JSON_BYTES + 1 - len(verified)),
            )
            if not chunk:
                break
            verified += chunk
        require(
            stat.S_ISREG(observed.st_mode)
            and observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o400
            and observed.st_nlink == 0
            and verified == raw
            and sha256_bytes(verified) == expected_sha256,
            "unnamed root publication identity differs",
        )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def link_tmpfile_noreplace_at(
    descriptor: int,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    function = getattr(LIBC, "linkat", None)
    require(function is not None, "unnamed archive link publication is unavailable")
    result = function(
        ctypes.c_int(descriptor),
        ctypes.c_char_p(b""),
        ctypes.c_int(destination_directory_fd),
        ctypes.c_char_p(os.fsencode(destination_name)),
        ctypes.c_int(AT_EMPTY_PATH),
    )
    if result != 0:
        observed_errno = ctypes.get_errno()
        raise OSError(observed_errno, os.strerror(observed_errno))


def open_or_publish_prepared_archive(
    control: Mapping[str, object],
    evidence_fd: int,
) -> int:
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["legacyReceipt"]
    raw = recorded_legacy_receipt_bytes(control)
    # Complete a prior linkat response-loss cutpoint before trusting the name.
    settle_linked_publication_replay(evidence_fd)
    existing = _read_regular_at(
        evidence_fd,
        PREPARED_ARCHIVE_PATH.name,
        maximum=MAX_JSON_BYTES,
    )
    if existing is not None:
        descriptor, observed, prepared = existing
        try:
            _require_legacy_receipt(
                observed,
                prepared,
                expected,
                terminal=True,
            )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    temporary_fd = _create_root_tmpfile(
        evidence_fd,
        raw,
        expected_sha256=EXPECTED_RECEIPT_SHA256,
    )
    try:
        link_tmpfile_noreplace_at(
            temporary_fd,
            evidence_fd,
            PREPARED_ARCHIVE_PATH.name,
        )
        settle_linked_publication_replay(evidence_fd)
        prepared = _read_regular_at(
            evidence_fd,
            PREPARED_ARCHIVE_PATH.name,
            maximum=MAX_JSON_BYTES,
        )
        require(prepared is not None, "prepared legacy archive disappeared")
        try:
            _require_legacy_receipt(
                prepared[1],
                prepared[2],
                expected,
                terminal=True,
            )
            current = os.fstat(temporary_fd)
            require(
                (prepared[1].st_dev, prepared[1].st_ino)
                == (current.st_dev, current.st_ino),
                "prepared legacy archive inode differs",
            )
        finally:
            os.close(prepared[0])
        return temporary_fd
    except BaseException:
        os.close(temporary_fd)
        raise


def _live_path_has_exact_legacy_bytes(evidence_fd: int) -> bool:
    value = _read_regular_at(
        evidence_fd,
        RECEIPT_PATH.name,
        maximum=MAX_JSON_BYTES,
        minimum=0,
    )
    if value is None:
        return False
    try:
        return sha256_bytes(value[2]) == EXPECTED_RECEIPT_SHA256
    finally:
        os.close(value[0])


def complete_receipt_tombstone(
    control: Mapping[str, object],
    evidence_fd: int,
) -> None:
    value = _read_regular_at(
        evidence_fd,
        RECEIPT_PATH.name,
        maximum=MAX_JSON_BYTES,
        minimum=0,
        flags=os.O_RDWR,
    )
    if value is None:
        return
    descriptor, observed, raw = value
    try:
        disposition = _live_receipt_disposition(observed, raw, control)
        if disposition == "foreign":
            manual(
                sha256_bytes(raw) != EXPECTED_RECEIPT_SHA256,
                "foreign live path contains exact legacy receipt bytes",
            )
            return
        manual(
            disposition in {"legacy", "tombstone", "tombstone_prefix"},
            "legacy receipt tombstone source differs",
        )
        tombstone = receipt_tombstone_bytes(control)
        if raw != tombstone:
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            _write_all(descriptor, tombstone)
            os.fsync(descriptor)
        if (os.fstat(descriptor).st_uid, os.fstat(descriptor).st_gid) != (
            int(control["authority"]["legacyReceipt"]["uid"]),
            int(control["authority"]["legacyReceipt"]["gid"]),
        ):
            os.fchown(
                descriptor,
                int(control["authority"]["legacyReceipt"]["uid"]),
                int(control["authority"]["legacyReceipt"]["gid"]),
            )
            os.fsync(descriptor)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != int(
            control["authority"]["legacyReceipt"]["mode"]
        ):
            os.fchmod(
                descriptor,
                int(control["authority"]["legacyReceipt"]["mode"]),
            )
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        final = b""
        while len(final) <= len(tombstone):
            chunk = os.read(descriptor, len(tombstone) + 1 - len(final))
            if not chunk:
                break
            final += chunk
        final_stat = os.fstat(descriptor)
        require(
            final == tombstone
            and (final_stat.st_uid, final_stat.st_gid)
            == (
                int(control["authority"]["legacyReceipt"]["uid"]),
                int(control["authority"]["legacyReceipt"]["gid"]),
            )
            and stat.S_IMODE(final_stat.st_mode)
            == int(control["authority"]["legacyReceipt"]["mode"]),
            "legacy receipt tombstone bytes or cleanup identity differ",
        )
    finally:
        os.close(descriptor)
    manual(
        not _live_path_has_exact_legacy_bytes(evidence_fd),
        "exact legacy receipt bytes reappeared at the live path",
    )


def terminal_projection_value(control: ControlAuthority) -> dict[str, object]:
    require(control.phase == "archive_intent_final", "terminal projection phase differs")
    return {
        "schema": PROJECTION_SCHEMA,
        "outcome": "drained",
        "observedAt": control.state["observedAt"],
        "bootId": control.state["bootId"],
        "stateRoot": str(EXPECTED_STATE_ROOT),
        "legacyReceiptSha256": EXPECTED_RECEIPT_SHA256,
        "legacyReceiptArchive": str(ARCHIVE_RECEIPT_PATH),
        "controlSha256": control.control_digest,
        "sourceSha256": control.control["sourceSha256"],
        "control": control.control,
        "persistentDataPreserved": [str(path) for path in PERSISTENT_ROOTS],
        "legacyRuntimeRemoved": True,
        "cgroupMutationPerformed": False,
        "forceKillPerformed": False,
    }


def read_projection(control: ControlAuthority) -> dict[str, object]:
    expected = terminal_projection_value(control)
    encoded = canonical_json(expected)
    state_fd, evidence_fd = recorded_evidence_descriptors(control.control)
    value: tuple[int, os.stat_result, bytes] | None = None
    try:
        settle_linked_publication_replay(evidence_fd)
        value = _read_regular_at(
            evidence_fd,
            PROJECTION_PATH.name,
            maximum=MAX_JSON_BYTES,
        )
        require(value is not None, "legacy terminal projection is absent")
        observed = value[1]
        require(
            observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o400
            and value[2] == encoded,
            "legacy terminal projection differs",
        )
        return expected
    finally:
        if value is not None:
            os.close(value[0])
        os.close(evidence_fd)
        os.close(state_fd)


def read_terminal_projection_without_control(
    evidence_fd: int,
) -> dict[str, object]:
    settle_linked_publication_replay(evidence_fd)
    stored = _read_regular_at(
        evidence_fd,
        PROJECTION_PATH.name,
        maximum=MAX_JSON_BYTES,
    )
    require(stored is not None, "legacy terminal projection is absent")
    assert stored is not None
    descriptor, identity, raw = stored
    try:
        require(
            identity.st_uid == 0
            and identity.st_gid == 0
            and stat.S_IMODE(identity.st_mode) == 0o400
            and identity.st_nlink == 1,
            "legacy terminal projection identity differs",
        )
    finally:
        os.close(descriptor)
    value = exact_keys(
        parse_json_bytes(raw, "legacy terminal projection"),
        {
            "schema",
            "outcome",
            "observedAt",
            "bootId",
            "stateRoot",
            "legacyReceiptSha256",
            "legacyReceiptArchive",
            "controlSha256",
            "sourceSha256",
            "control",
            "persistentDataPreserved",
            "legacyRuntimeRemoved",
            "cgroupMutationPerformed",
            "forceKillPerformed",
        },
        "legacy terminal projection",
    )
    source = globals().get("__legacy_pinned_source_bytes__")
    stored_control = exact_keys(
        value["control"],
        {
            "schema",
            "observedAt",
            "bootId",
            "stateRoot",
            "caller",
            "verificationSha256",
            "sourceSha256",
            "authority",
        },
        "legacy recovery control",
    )
    require(
        value["schema"] == PROJECTION_SCHEMA
        and value["outcome"] == "drained"
        and isinstance(value["observedAt"], str)
        and 0 < len(value["observedAt"]) <= 128
        and isinstance(value["bootId"], str)
        and re.fullmatch(r"[0-9a-f-]{36}", value["bootId"]) is not None
        and value["stateRoot"] == str(EXPECTED_STATE_ROOT)
        and value["legacyReceiptSha256"] == EXPECTED_RECEIPT_SHA256
        and value["legacyReceiptArchive"] == str(ARCHIVE_RECEIPT_PATH)
        and isinstance(value["controlSha256"], str)
        and SHA256_RE.fullmatch(value["controlSha256"]) is not None
        and stored_control["schema"] == CONTROL_SCHEMA
        and stored_control["bootId"] == value["bootId"]
        and stored_control["stateRoot"] == str(EXPECTED_STATE_ROOT)
        and stored_control["caller"] == {"uid": 1000, "gid": 1000}
        and isinstance(stored_control["authority"], dict)
        and stored_control["verificationSha256"]
        == sha256_bytes(canonical_json(stored_control["authority"]))
        and value["controlSha256"] == sha256_bytes(canonical_json(stored_control))
        and isinstance(source, bytes)
        and value["sourceSha256"]
        == stored_control["sourceSha256"]
        == sha256_bytes(source)
        and value["persistentDataPreserved"]
        == [str(path) for path in PERSISTENT_ROOTS]
        and value["legacyRuntimeRemoved"] is True
        and value["cgroupMutationPerformed"] is False
        and value["forceKillPerformed"] is False,
        "legacy terminal projection recovery binding differs",
    )
    return value


def complete_terminal_tombstone_without_control(
    evidence_fd: int,
    projection: Mapping[str, object],
) -> None:
    value = _read_regular_at(
        evidence_fd,
        RECEIPT_PATH.name,
        maximum=MAX_JSON_BYTES,
        minimum=0,
        flags=os.O_RDWR,
    )
    if value is None:
        return
    descriptor, observed, raw = value
    tombstone = receipt_tombstone_bytes_for_control_digest(
        str(projection["controlSha256"])
    )
    try:
        admitted_owner = (
            observed.st_uid,
            observed.st_gid,
            stat.S_IMODE(observed.st_mode),
        ) in {
            (1000, 1000, 0o600),
            (0, 0, 0o600),
            (0, 0, 0o400),
            (1000, 1000, 0o400),
        }
        manual(
            stat.S_ISREG(observed.st_mode)
            and observed.st_nlink == 1
            and admitted_owner
            and (
                sha256_bytes(raw) == EXPECTED_RECEIPT_SHA256
                or tombstone.startswith(raw)
            ),
            "legacy recovery live receipt is foreign",
        )
        if raw != tombstone:
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            _write_all(descriptor, tombstone)
            os.fsync(descriptor)
        os.fchown(descriptor, 1000, 1000)
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    manual(
        not _live_path_has_exact_legacy_bytes(evidence_fd),
        "exact legacy receipt remained after recovery tombstone",
    )


def require_recovery_state_binding(state_fd: int, evidence_fd: int) -> None:
    state = os.fstat(state_fd)
    evidence = os.fstat(evidence_fd)
    literal_state = os.stat(EXPECTED_STATE_ROOT, follow_symlinks=False)
    literal_evidence = os.stat(
        "evidence",
        dir_fd=state_fd,
        follow_symlinks=False,
    )
    require(
        (literal_state.st_dev, literal_state.st_ino)
        == (state.st_dev, state.st_ino)
        and (literal_evidence.st_dev, literal_evidence.st_ino)
        == (evidence.st_dev, evidence.st_ino),
        "legacy recovery state binding changed",
    )


def recover_terminal_archive_without_control() -> dict[str, object]:
    manual(
        not exists_nofollow(CONTROL_ROOT),
        "legacy control capsule appeared during boot-independent recovery",
    )
    v5_state = require_v5_absent(
        allow_global_lease=True,
        allow_legacy_absent=True,
    )
    manual(
        v5_state["legacyRuntime"] is None
        and not exists_nofollow(EXPECTED_RUNTIME_ROOT),
        "legacy runtime root remains during boot-independent recovery",
    )
    require_registry_listener_absent()
    state_fd = os.open(
        EXPECTED_STATE_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    evidence_fd = os.open(
        "evidence",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=state_fd,
    )
    prepared_fd: int | None = None
    final_fd: int | None = None
    try:
        state = os.fstat(state_fd)
        evidence = os.fstat(evidence_fd)
        require_recovery_state_binding(state_fd, evidence_fd)
        projection = read_terminal_projection_without_control(evidence_fd)
        stored_control = projection["control"]
        assert isinstance(stored_control, dict)
        authority = stored_control["authority"]
        assert isinstance(authority, dict)
        process_cutoff = require_related_process_cutoff(
            stored_control,
            allowed_roles=set(),
        )
        require(
            process_cutoff["related"] == [],
            "legacy boot-independent recovery process cutoff differs",
        )
        expected_state = authority["stateRootIdentity"]
        expected_evidence = authority["evidenceRootIdentity"]
        require(
            (
                state.st_dev,
                state.st_ino,
                state.st_uid,
                state.st_gid,
                stat.S_IMODE(state.st_mode),
            )
            == (
                expected_state["device"],
                expected_state["inode"],
                expected_state["uid"],
                expected_state["gid"],
                expected_state["mode"],
            )
            and (
                evidence.st_dev,
                evidence.st_ino,
                evidence.st_uid,
                evidence.st_gid,
                stat.S_IMODE(evidence.st_mode),
            )
            == (
                expected_evidence["device"],
                expected_evidence["inode"],
                expected_evidence["uid"],
                expected_evidence["gid"],
                expected_evidence["mode"],
            ),
            "legacy recovery state or evidence root differs",
        )
        config_fd = os.open(
            "config",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=state_fd,
        )
        try:
            config = os.fstat(config_fd)
            expected_config = authority["configRootIdentity"]
            require(
                (
                    config.st_dev,
                    config.st_ino,
                    config.st_uid,
                    config.st_gid,
                    stat.S_IMODE(config.st_mode),
                )
                == (
                    expected_config["device"],
                    expected_config["inode"],
                    expected_config["uid"],
                    expected_config["gid"],
                    expected_config["mode"],
                ),
                "legacy recovery config root differs",
            )
            expected_pidfile = authority["configs"]["containerdPidfile"]
            pidfile_value = _read_regular_at(
                config_fd,
                CONTAINERD_PIDFILE.name,
                maximum=64,
            )
            require(pidfile_value is not None, "legacy recovery pidfile is absent")
            assert pidfile_value is not None
            try:
                require_recorded_entry(
                    pidfile_value[1],
                    expected_pidfile,
                    label="legacy recovery containerd pidfile",
                )
                require(
                    pidfile_value[2].decode("ascii", "strict").strip()
                    == str(expected_pidfile["expectedPid"])
                    and sha256_bytes(pidfile_value[2])
                    == expected_pidfile["sha256"],
                    "legacy recovery pidfile bytes differ",
                )
            finally:
                os.close(pidfile_value[0])
        finally:
            os.close(config_fd)
        for path, expected in authority["persistentRoots"].items():
            expected_path = Path(path)
            require(
                expected_path.parent == EXPECTED_STATE_ROOT,
                "legacy recovery persistent root path differs",
            )
            persistent_fd = os.open(
                expected_path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=state_fd,
            )
            try:
                observed = os.fstat(persistent_fd)
                literal = os.stat(
                    expected_path.name,
                    dir_fd=state_fd,
                    follow_symlinks=False,
                )
                require(
                    (
                        observed.st_dev,
                        observed.st_ino,
                        observed.st_uid,
                        observed.st_gid,
                        stat.S_IMODE(observed.st_mode),
                    )
                    == (
                        expected["device"],
                        expected["inode"],
                        expected["uid"],
                        expected["gid"],
                        expected["mode"],
                    )
                    and (literal.st_dev, literal.st_ino)
                    == (observed.st_dev, observed.st_ino),
                    f"legacy recovery persistent root differs: {path}",
                )
            finally:
                os.close(persistent_fd)
        require(
            registry_inventory() == authority["registryInventory"],
            "legacy recovery registry inventory differs",
        )
        for key, root in (
            ("runtime", EXPECTED_RUNTIME_ROOT),
            ("outerDocker", EXPECTED_STATE_ROOT / "outer-docker"),
            ("registry", EXPECTED_STATE_ROOT / "registry"),
        ):
            recorded_mounts = authority["mounts"][key]
            observed_mounts = stable_global_mount_roster(
                root,
                anchors_from_document(recorded_mounts),
            )
            manual(
                not observed_mounts["occurrences"],
                f"legacy recovery mount remains: {key}",
            )
        final = _read_regular_at(
            evidence_fd,
            ARCHIVE_RECEIPT_PATH.name,
            maximum=MAX_JSON_BYTES,
            allowed_links=frozenset({1, 2}),
        )
        if final is not None:
            final_fd, observed, raw = final
            require(
                observed.st_uid == 0
                and observed.st_gid == 0
                and stat.S_IMODE(observed.st_mode) == 0o400
                and observed.st_nlink in (1, 2)
                and sha256_bytes(raw) == EXPECTED_RECEIPT_SHA256,
                "legacy terminal archive recovery identity differs",
            )
            manual(
                not _live_path_has_exact_legacy_bytes(evidence_fd),
                "live and terminal legacy receipt bytes coexist",
            )
            return projection
        prepared = _read_regular_at(
            evidence_fd,
            PREPARED_ARCHIVE_PATH.name,
            maximum=MAX_JSON_BYTES,
        )
        if prepared is None:
            require_recovery_state_binding(state_fd, evidence_fd)
            live = _read_regular_at(
                evidence_fd,
                RECEIPT_PATH.name,
                maximum=MAX_JSON_BYTES,
            )
            manual(
                live is not None
                and sha256_bytes(live[2]) == EXPECTED_RECEIPT_SHA256,
                "prepared archive and exact live receipt are both absent",
            )
            assert live is not None
            try:
                temporary = _create_root_tmpfile(
                    evidence_fd,
                    live[2],
                    expected_sha256=EXPECTED_RECEIPT_SHA256,
                )
                try:
                    link_tmpfile_noreplace_at(
                        temporary,
                        evidence_fd,
                        PREPARED_ARCHIVE_PATH.name,
                    )
                    settle_linked_publication_replay(evidence_fd)
                finally:
                    os.close(temporary)
            finally:
                os.close(live[0])
            prepared = _read_regular_at(
                evidence_fd,
                PREPARED_ARCHIVE_PATH.name,
                maximum=MAX_JSON_BYTES,
            )
        require(prepared is not None, "prepared legacy archive disappeared")
        prepared_fd, prepared_stat, prepared_raw = prepared
        require(
            prepared_stat.st_uid == 0
            and prepared_stat.st_gid == 0
            and stat.S_IMODE(prepared_stat.st_mode) == 0o400
            and prepared_stat.st_nlink == 1
            and sha256_bytes(prepared_raw) == EXPECTED_RECEIPT_SHA256,
            "prepared legacy archive recovery identity differs",
        )
        require_recovery_state_binding(state_fd, evidence_fd)
        complete_terminal_tombstone_without_control(evidence_fd, projection)
        require_recovery_state_binding(state_fd, evidence_fd)
        link_tmpfile_noreplace_at(
            prepared_fd,
            evidence_fd,
            ARCHIVE_RECEIPT_PATH.name,
        )
        settle_linked_publication_replay(evidence_fd)
        final = _read_regular_at(
            evidence_fd,
            ARCHIVE_RECEIPT_PATH.name,
            maximum=MAX_JSON_BYTES,
            allowed_links=frozenset({1, 2}),
        )
        require(final is not None, "terminal legacy archive recovery disappeared")
        final_fd, final_stat, final_raw = final
        require(
            (final_stat.st_dev, final_stat.st_ino)
            == (prepared_stat.st_dev, prepared_stat.st_ino)
            and final_stat.st_uid == 0
            and final_stat.st_gid == 0
            and stat.S_IMODE(final_stat.st_mode) == 0o400
            and final_stat.st_nlink in (1, 2)
            and sha256_bytes(final_raw) == EXPECTED_RECEIPT_SHA256,
            "terminal legacy archive recovery binding differs",
        )
        return projection
    finally:
        if final_fd is not None:
            os.close(final_fd)
        if prepared_fd is not None:
            os.close(prepared_fd)
        os.close(evidence_fd)
        os.close(state_fd)


def write_projection(control: ControlAuthority) -> dict[str, object]:
    value = terminal_projection_value(control)
    encoded = canonical_json(value)
    state_fd, evidence_fd = recorded_evidence_descriptors(control.control)
    temporary_fd: int | None = None
    final_fd: int | None = None
    try:
        # This also completes an already-visible projection link after a crash.
        settle_linked_publication_replay(evidence_fd)
        final = _read_regular_at(
            evidence_fd,
            PROJECTION_PATH.name,
            maximum=MAX_JSON_BYTES,
        )
        if final is not None:
            final_fd, observed, raw = final
            require(
                observed.st_uid == 0
                and observed.st_gid == 0
                and stat.S_IMODE(observed.st_mode) == 0o400
                and raw == encoded,
                "legacy terminal projection differs",
            )
            return value
        temporary_fd = _create_root_tmpfile(
            evidence_fd,
            encoded,
            expected_sha256=sha256_bytes(encoded),
        )
        try:
            link_tmpfile_noreplace_at(
                temporary_fd,
                evidence_fd,
                PROJECTION_PATH.name,
            )
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
        settle_linked_publication_replay(evidence_fd)
        final = _read_regular_at(
            evidence_fd,
            PROJECTION_PATH.name,
            maximum=MAX_JSON_BYTES,
        )
        require(
            final is not None,
            "legacy terminal projection publication disappeared",
        )
        final_fd, observed, raw = final
        require(
            observed.st_uid == 0
            and observed.st_gid == 0
            and stat.S_IMODE(observed.st_mode) == 0o400
            and raw == encoded,
            "legacy terminal projection publication differs",
        )
        return value
    finally:
        if final_fd is not None:
            os.close(final_fd)
        if temporary_fd is not None:
            os.close(temporary_fd)
        os.close(evidence_fd)
        os.close(state_fd)




def archive_receipt(control: ControlAuthority) -> dict[str, object]:
    require(control.phase == "archive_intent_final", "legacy archive intent is absent")
    receipt_state, _ = legacy_receipt_state(control.control)
    if receipt_state == "archived":
        return read_projection(control)
    terminal = write_projection(control)
    require_related_process_cutoff(control.control, allowed_roles=set())
    authority = control.control["authority"]
    assert isinstance(authority, dict)
    expected = authority["legacyReceipt"]
    state_fd, evidence_fd = recorded_evidence_descriptors(control.control)
    temporary_fd: int | None = None
    archived_fd: int | None = None
    try:
        settle_linked_publication_replay(evidence_fd)
        existing = _read_regular_at(
            evidence_fd,
            ARCHIVE_RECEIPT_PATH.name,
            maximum=MAX_JSON_BYTES,
            allowed_links=frozenset({1, 2}),
        )
        if existing is not None:
            try:
                _require_legacy_receipt(
                    existing[1],
                    existing[2],
                    expected,
                    terminal=True,
                )
            finally:
                os.close(existing[0])
            manual(
                not _live_path_has_exact_legacy_bytes(evidence_fd),
                "live and archived legacy receipts coexist",
            )
            return terminal
        temporary_fd = open_or_publish_prepared_archive(
            control.control,
            evidence_fd,
        )
        complete_receipt_tombstone(control.control, evidence_fd)
        manual(
            not _live_path_has_exact_legacy_bytes(evidence_fd),
            "exact legacy receipt remained at the live path",
        )
        try:
            link_tmpfile_noreplace_at(
                temporary_fd,
                evidence_fd,
                ARCHIVE_RECEIPT_PATH.name,
            )
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            raise ManualRecoveryRequired(
                "legacy receipt archive destination appeared without replacement"
            ) from error
        settle_linked_publication_replay(evidence_fd)
        archived = _read_regular_at(
            evidence_fd,
            ARCHIVE_RECEIPT_PATH.name,
            maximum=MAX_JSON_BYTES,
            allowed_links=frozenset({1, 2}),
        )
        require(archived is not None, "legacy receipt archive disappeared")
        archived_fd, archived_stat, archived_raw = archived
        _require_legacy_receipt(
            archived_stat,
            archived_raw,
            expected,
            terminal=True,
        )
        temporary_stat = os.fstat(temporary_fd)
        require(
            (archived_stat.st_dev, archived_stat.st_ino)
            == (temporary_stat.st_dev, temporary_stat.st_ino),
            "legacy receipt archive inode differs from its unnamed source",
        )
        return terminal
    finally:
        if archived_fd is not None:
            os.close(archived_fd)
        if temporary_fd is not None:
            os.close(temporary_fd)
        os.close(evidence_fd)
        os.close(state_fd)




def registry_inventory_matches(control: Mapping[str, object]) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    require(
        registry_inventory() == authority["registryInventory"],
        "registry custody changed during legacy drain",
    )


def require_task_netns_ambient(control: Mapping[str, object]) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    netns = authority["mounts"]["networkNamespace"]
    source = netns["sourceAnchor"]
    anchor = ((str(source["device"]), str(source["root"])),)
    expected = [
        item
        for item in netns["occurrences"]
        if item["target"] in set(netns["ambientTargets"])
    ]
    observed = stable_global_mount_roster(
        TASK_NETNS_TARGET,
        anchor,
        tuple(sorted((*netns["ambientTargets"], str(netns["ownedTarget"])))),
    )
    manual(
        observed["occurrences"] == expected,
        "legacy task netns ambient roster differs",
    )


def require_terminal_reproof(control: Mapping[str, object]) -> None:
    require_related_process_cutoff(control, allowed_roles=set())
    manual(not exists_nofollow(EXPECTED_RUNTIME_ROOT), "legacy runtime root remained")
    require_containerd_pidfile_exact(control)
    for role in EXPECTED_PROCESS_CANDIDATES:
        manual(
            exact_process_status(process_authority(control, role)) == "absent",
            f"legacy process remains: {role}",
        )
    require_mounts_absent(
        control,
        "runtime",
        EXPECTED_RUNTIME_ROOT,
        use_recorded_anchors=False,
    )
    require_mounts_absent(
        control,
        "outerDocker",
        EXPECTED_STATE_ROOT / "outer-docker",
    )
    require_mounts_absent(
        control,
        "registry",
        EXPECTED_STATE_ROOT / "registry",
    )
    require_task_netns_ambient(control)
    require_registry_listener_absent()
    registry_inventory_matches(control)


def run_reducer(control: ControlAuthority) -> dict[str, object]:
    if control.phase == "stopping_intent_final":
        transfer_runtime_custody(control.control)
        control.advance("runtime_custody_transferred")

    if control.phase == "runtime_custody_transferred":
        remove_bound_socket(control.control)
        control.advance("docker_api_revoked")

    if control.phase == "docker_api_revoked":
        post_revocation_socket_snapshot(control.control)
        control.advance("dockerd_stop_requested")

    if control.phase == "dockerd_stop_requested":
        dockerd_status = exact_process_status(
            process_authority(control.control, "dockerd")
        )
        if dockerd_status == "exact":
            post_revocation_socket_snapshot(control.control)
            live_roles = exact_live_roles(
                control.control,
                set(EXPECTED_PROCESS_CANDIDATES),
            )
            with hold_related_process_cutoff(
                control.control,
                allowed_roles=live_roles,
                revalidate_after=False,
            ):
                signal_exact_process(process_authority(control.control, "dockerd"))
        else:
            require(dockerd_status == "absent", "dockerd response-loss state differs")
            manual(not exists_nofollow(DOCKER_SOCKET), "Docker API pathname reappeared")
            require_related_process_cutoff(
                control.control,
                allowed_roles=exact_live_roles(
                    control.control,
                    set(EXPECTED_PROCESS_CANDIDATES) - {"dockerd"},
                ),
            )
        control.advance("dockerd_stopped")

    if control.phase == "dockerd_stopped":
        wait_for_roles_absent(
            control.control,
            (
                "dockerd",
                "dockerdWrapperInner",
                "dockerdWrapperOuter",
                "registryTask",
                "registryShim",
            ),
            timeout_seconds=120.0,
        )
        require_mounts_absent(
            control.control, "outerDocker", EXPECTED_STATE_ROOT / "outer-docker"
        )
        require_mounts_absent(
            control.control, "registry", EXPECTED_STATE_ROOT / "registry"
        )
        require_registry_listener_absent()
        registry_inventory_matches(control.control)
        require_related_process_cutoff(
            control.control,
            allowed_roles={
                "containerdWrapperOuter",
                "containerdWrapperInner",
                "containerd",
            },
        )
        control.advance("container_graph_quiesced")

    if control.phase == "container_graph_quiesced":
        control.advance("containerd_stop_requested")

    if control.phase == "containerd_stop_requested":
        containerd_roles = {
            "containerdWrapperOuter",
            "containerdWrapperInner",
            "containerd",
        }
        containerd_status = exact_process_status(
            process_authority(control.control, "containerd")
        )
        if containerd_status == "exact":
            live_roles = exact_live_roles(control.control, containerd_roles)
            with hold_related_process_cutoff(
                control.control,
                allowed_roles=live_roles,
                revalidate_after=False,
            ):
                signal_exact_process(process_authority(control.control, "containerd"))
        else:
            require(
                containerd_status == "absent",
                "containerd response-loss state differs",
            )
            require_related_process_cutoff(
                control.control,
                allowed_roles=exact_live_roles(
                    control.control,
                    containerd_roles - {"containerd"},
                ),
            )
        control.advance("containerd_stopped")

    if control.phase == "containerd_stopped":
        wait_for_roles_absent(
            control.control,
            (
                "containerd",
                "containerdWrapperInner",
                "containerdWrapperOuter",
            ),
            timeout_seconds=120.0,
        )
        require_related_process_cutoff(control.control, allowed_roles=set())
        marker_identity = settle_task_netns(control.control)
        require_mounts_absent(
            control.control,
            "runtime",
            EXPECTED_RUNTIME_ROOT,
            use_recorded_anchors=False,
        )
        control.advance(
            "mounts_settled",
            netns_marker_identity=marker_identity,
        )

    if control.phase == "mounts_settled":
        control.advance("runtime_reducing")

    if control.phase == "runtime_reducing":
        marker_identity = control.state["netnsMarkerIdentity"]
        require(
            isinstance(marker_identity, dict),
            "legacy task netns marker state is absent",
        )
        runtime_reduction_preflight(control.control, marker_identity)
        reduce_runtime_tree(control.control, marker_identity)
        registry_inventory_matches(control.control)
        control.advance("runtime_empty")

    if control.phase == "runtime_empty":
        remove_empty_runtime_root(control.control)
        require_terminal_reproof(control.control)
        transfer_receipt_custody(control.control)
        control.advance("archive_intent_final")

    require(control.phase == "archive_intent_final", "legacy drain did not reach archive intent")
    require_terminal_reproof(control.control)
    transfer_receipt_custody(control.control)
    return archive_receipt(control)


def require_root(caller_uid: int, caller_gid: int) -> None:
    require(os.geteuid() == 0 and os.getegid() == 0, "legacy transition requires root")
    require((caller_uid, caller_gid) == (1000, 1000), "legacy transition caller differs")
    require(
        os.environ.get("SUDO_UID") == str(caller_uid)
        and os.environ.get("SUDO_GID") == str(caller_gid),
        "authenticated sudo caller differs",
    )


def operation_verify(caller_uid: int, caller_gid: int) -> dict[str, object]:
    require_root(caller_uid, caller_gid)
    return collect_verification(caller_uid, caller_gid)


def operation_drain(
    caller_uid: int,
    caller_gid: int,
    expected_verification_sha256: str,
) -> dict[str, object]:
    require_root(caller_uid, caller_gid)
    require(
        SHA256_RE.fullmatch(expected_verification_sha256) is not None,
        "expected verification digest is invalid",
    )
    with RuntimeLease.acquire():
        verification = collect_verification(
            caller_uid, caller_gid, allow_global_lease=True
        )
        require(
            verification["verificationSha256"] == expected_verification_sha256,
            "legacy verification changed before drain",
        )
        with ControlAuthority.create(
            verification,
            expected_verification_sha256=expected_verification_sha256,
        ) as control:
            return run_reducer(control)


def operation_resume(caller_uid: int, caller_gid: int) -> dict[str, object]:
    require_root(caller_uid, caller_gid)
    with RuntimeLease.acquire():
        held = globals().get("__legacy_control_root_fd__")
        if not isinstance(held, int):
            return recover_terminal_archive_without_control()
        require_v5_absent(allow_global_lease=True, allow_legacy_absent=True)
        with ControlAuthority.open() as control:
            return run_reducer(control)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("operation", choices=("verify-only", "drain", "resume"))
    result.add_argument("state_root", type=Path)
    result.add_argument("caller_uid")
    result.add_argument("caller_gid")
    result.add_argument("expected_verification_sha256", nargs="?")
    return result


def main() -> None:
    os.umask(0o077)
    args = parser().parse_args()
    require(args.state_root == EXPECTED_STATE_ROOT, "legacy drain state root differs")
    require(re.fullmatch(r"[1-9][0-9]*", args.caller_uid) is not None, "caller uid is invalid")
    require(re.fullmatch(r"[0-9]+", args.caller_gid) is not None, "caller gid is invalid")
    caller_uid = int(args.caller_uid)
    caller_gid = int(args.caller_gid)
    if args.operation == "verify-only":
        require(args.expected_verification_sha256 is None, "verify-only takes no digest")
        result = operation_verify(caller_uid, caller_gid)
    elif args.operation == "drain":
        require(
            args.expected_verification_sha256 is not None,
            "drain requires an expected verification digest",
        )
        result = operation_drain(
            caller_uid,
            caller_gid,
            str(args.expected_verification_sha256),
        )
    else:
        require(args.expected_verification_sha256 is None, "resume takes no digest")
        result = operation_resume(caller_uid, caller_gid)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (DrainError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"legacy v3 transition blocked: {error}", file=sys.stderr)
        raise SystemExit(1)
