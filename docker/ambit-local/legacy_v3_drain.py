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
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence


SCHEMA = "ambit.local-daytona-legacy-v3-drain-verification/v1"
CONTROL_SCHEMA = "ambit.local-daytona-legacy-v3-drain-control/v1"
STATE_SCHEMA = "ambit.local-daytona-legacy-v3-drain-state/v1"
PROJECTION_SCHEMA = "ambit.local-daytona-legacy-v3-drain-projection/v1"
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
PROJECTION_PATH = EXPECTED_STATE_ROOT / "evidence/legacy-v3-drain-receipt.json"
DOCKER_CONFIG = EXPECTED_STATE_ROOT / "config/outer-docker.json"
CONTAINERD_CONFIG = EXPECTED_STATE_ROOT / "config/outer-containerd.toml"
CONTAINERD_PIDFILE = EXPECTED_STATE_ROOT / "config/outer-containerd.pid"
DOCKER_PIDFILE = EXPECTED_RUNTIME_ROOT / "docker.pid"
DOCKER_SOCKET = EXPECTED_RUNTIME_ROOT / "docker.sock"
CONTAINERD_SOCKET = EXPECTED_RUNTIME_ROOT / "containerd.sock"
TASK_NETNS_TARGET = EXPECTED_RUNTIME_ROOT / "docker-exec/netns/default"
PERSISTENT_ROOTS = (
    EXPECTED_STATE_ROOT / "outer-docker",
    EXPECTED_STATE_ROOT / "outer-containerd",
    EXPECTED_STATE_ROOT / "registry",
)
REGISTRY_STORAGE = EXPECTED_STATE_ROOT / "registry/docker/registry/v2"

GLOBAL_LEASE_PATH = Path("/run/ambit-c16b-docker-global.lock")
CONTROL_ROOT = Path(f"/run/ambit-c16b-legacy-v3-drain-{EXPECTED_RUNTIME_ID}")
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
    "docker_api_revoked",
    "dockerd_stop_requested",
    "dockerd_stopped",
    "container_graph_quiesced",
    "containerd_stop_requested",
    "containerd_stopped",
    "mounts_settled",
    "runtime_reducing",
    "runtime_removed",
    "receipt_archived",
    "complete",
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RUNTIME_NAME_RE = re.compile(r"^ambit-c16b-docker-[0-9a-f]{12}$")
V5_RUNTIME_RE = re.compile(
    r"^ambit-c16b-docker-(?:api-|removing-)?[0-9a-f]{12}$"
)
OPAQUE_MOUNT_ROOT_RE = re.compile(r"^[a-z][a-z0-9_-]*:\[[1-9][0-9]*\]$")
MOUNT_DEVICE_RE = re.compile(r"^[0-9]+:[0-9]+$")
MAX_JSON_BYTES = 2 * 1024 * 1024


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


def mount_references(
    raw: str,
    root: Path,
    anchors: tuple[tuple[str, str], ...],
) -> tuple[str, ...]:
    result: set[str] = set()
    for record in mount_records(raw):
        target_reference = path_at_or_below(record.target, str(root))
        source_reference = any(
            record.device == device and mount_root_at_or_below(record.root, source_root)
            for device, source_root in anchors
        )
        if target_reference or source_reference:
            result.add(record.target)
    return tuple(sorted(result))


def mount_namespace_key(pid: int) -> str:
    observed = os.stat(f"/proc/{pid}/ns/mnt")
    return f"{observed.st_dev}:{observed.st_ino}"


def global_mount_roster_once(
    root: Path,
    anchors: tuple[tuple[str, str], ...] | None = None,
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, tuple[str, ...]], ...]]:
    own_pid = os.getpid()
    own_raw = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    actual_anchors = source_anchors(own_raw, root) if anchors is None else anchors
    require(actual_anchors, f"mount source anchors are absent: {root}")
    seen: dict[str, tuple[str, ...]] = {
        mount_namespace_key(own_pid): mount_references(own_raw, root, actual_anchors)
    }
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == own_pid:
            continue
        namespace_path = f"/proc/{pid}/ns/mnt"
        try:
            before = os.stat(namespace_path)
            raw = Path(f"/proc/{pid}/mountinfo").read_text(encoding="utf-8")
            after = os.stat(namespace_path)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as error:
            raise ManualRecoveryRequired(f"mount namespace is unreadable: {pid}") from error
        require(
            (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
            f"mount namespace changed during proof: {pid}",
        )
        namespace = f"{before.st_dev}:{before.st_ino}"
        targets = mount_references(raw, root, actual_anchors)
        if namespace in seen:
            manual(
                seen[namespace] == targets,
                f"mount namespace visibility differs across representatives: {namespace}",
            )
        else:
            seen[namespace] = targets
    return actual_anchors, tuple(sorted(seen.items()))


def stable_global_mount_roster(
    root: Path,
    anchors: tuple[tuple[str, str], ...] | None = None,
) -> dict[str, object]:
    first = global_mount_roster_once(root, anchors)
    second = global_mount_roster_once(root, anchors)
    require(first == second, f"global mount roster changed: {root}")
    actual_anchors, namespaces = second
    occurrences = tuple(
        sorted((namespace, target) for namespace, targets in namespaces for target in targets)
    )
    return {
        "root": str(root),
        "sourceAnchors": [
            {"device": device, "root": source_root}
            for device, source_root in actual_anchors
        ],
        "occurrences": [
            {"mountNamespace": namespace, "target": target}
            for namespace, target in occurrences
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


def socket_inode_owners(inodes: set[int]) -> dict[int, tuple[int, ...]]:
    owners: dict[int, set[int]] = {inode: set() for inode in inodes}
    for entry in sorted(os.listdir("/proc")):
        if not entry.isdigit():
            continue
        pid = int(entry)
        fd_root = Path("/proc") / entry / "fd"
        try:
            names = tuple(os.listdir(fd_root))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError as error:
            raise ManualRecoveryRequired(f"process fd table is unreadable: {pid}") from error
        for name in names:
            try:
                target = os.readlink(fd_root / name)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            match = re.fullmatch(r"socket:\[([1-9][0-9]*)\]", target)
            if match is None:
                continue
            inode = int(match.group(1))
            if inode in owners:
                owners[inode].add(pid)
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
    paths = tuple(
        sorted(
            path
            for path in (
                DOCKER_SOCKET,
                CONTAINERD_SOCKET,
                EXPECTED_RUNTIME_ROOT / "containerd.sock.ttrpc",
                EXPECTED_RUNTIME_ROOT / "docker-exec/metrics.sock",
                EXPECTED_RUNTIME_ROOT
                / f"docker-exec/libnetwork/{'25fb8cc9e82d'}.sock",
            )
            if path.exists()
        )
    )
    identities = [socket_identity(path, expected_uid=0) for path in paths]
    unix = proc_unix_records()
    relevant = tuple(
        row
        for row in unix
        if isinstance(row["path"], str)
        and path_at_or_below(str(row["path"]), str(EXPECTED_RUNTIME_ROOT))
    )
    owners = socket_inode_owners({int(row["inode"]) for row in relevant})
    documented: list[dict[str, object]] = []
    for row in relevant:
        value = dict(row)
        value["owners"] = list(owners[int(row["inode"])])
        documented.append(value)
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
    return {
        "pathIdentities": identities,
        "unixRecords": documented,
        "foreignDockerApiClients": [],
        "registryTcpListener": tcp_registry_snapshot(registry_pid),
    }


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
    try:
        root = os.fstat(root_fd)
        require(
            (root.st_dev, root.st_ino, root.st_uid, root.st_gid, stat.S_IMODE(root.st_mode))
            == (44, 12496265, 1000, 1000, 0o700),
            "legacy runtime root identity differs",
        )
        top_level = tuple(sorted(os.listdir(root_fd)))
        manual(set(top_level) <= allowed_top_level, "legacy runtime root contains a foreign entry")
    finally:
        os.close(root_fd)
    rows: list[dict[str, object]] = []
    for directory, names, files in os.walk(EXPECTED_RUNTIME_ROOT, followlinks=False):
        base = Path(directory)
        for name in tuple(sorted((*names, *files))):
            path = base / name
            observed = os.stat(path, follow_symlinks=False)
            mode_type = stat.S_IFMT(observed.st_mode)
            manual(
                mode_type
                in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFSOCK, stat.S_IFIFO),
                f"legacy runtime entry type is foreign: {path}",
            )
            manual(not stat.S_ISLNK(observed.st_mode), f"legacy runtime symlink is forbidden: {path}")
            rows.append(identity_document(path, observed))
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
    if not allow_global_lease and exists_nofollow(GLOBAL_LEASE_PATH):
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
    return identity


def netns_baseline(runtime_mounts: Mapping[str, object]) -> dict[str, object]:
    target = str(TASK_NETNS_TARGET)
    records = mount_records(Path("/proc/self/mountinfo").read_text(encoding="utf-8"))
    matches = [record for record in records if record.target == target]
    require(len(matches) == 1 and matches[0].filesystem == "nsfs", "legacy task netns mount differs")
    source = {"device": matches[0].device, "root": matches[0].root}
    require(
        source == {"device": "0:4", "root": "net:[4026531833]"},
        "legacy task netns source differs",
    )
    occurrences = [
        item
        for item in runtime_mounts["occurrences"]
        if item["target"] == target or item["target"] == "/run/docker/netns/default"
    ]
    targets = {str(item["target"]) for item in occurrences}
    require(target in targets, "legacy task netns occurrence is absent")
    manual(
        targets == {target, "/run/docker/netns/default"},
        "legacy task netns source has a foreign target",
    )
    return {
        "sourceAnchor": source,
        "ownedTarget": target,
        "ambientTargets": ["/run/docker/netns/default"],
        "occurrences": occurrences,
    }


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
    runtime_mounts = stable_global_mount_roster(EXPECTED_RUNTIME_ROOT)
    data_mounts = stable_global_mount_roster(EXPECTED_STATE_ROOT / "outer-docker")
    registry_mounts = stable_global_mount_roster(EXPECTED_STATE_ROOT / "registry")
    netns = netns_baseline(runtime_mounts)
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
        "legacySource": EXPECTED_LEGACY_SOURCE,
        "legacyReceipt": receipt_identity,
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


def open_control_root(*, create: bool) -> int:
    if create:
        try:
            os.mkdir(CONTROL_ROOT, 0o700)
        except FileExistsError:
            pass
    descriptor = os.open(CONTROL_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    observed = os.fstat(descriptor)
    literal = os.stat(CONTROL_ROOT, follow_symlinks=False)
    require(
        stat.S_ISDIR(observed.st_mode)
        and observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) == 0o700
        and (observed.st_dev, observed.st_ino) == (literal.st_dev, literal.st_ino),
        "legacy drain control root differs",
    )
    allowed = {
        SNAPSHOT_NAME,
        f".{SNAPSHOT_NAME}.pending",
        CONTROL_NAME,
        f".{CONTROL_NAME}.pending",
        STATE_NAME,
        f".{STATE_NAME}.pending",
    }
    require(
        set(os.listdir(descriptor)) <= allowed,
        "legacy drain control root contains a foreign entry",
    )
    return descriptor


def snapshot_source(control_fd: int) -> str:
    source_path = Path(__file__).resolve(strict=True)
    raw, source_stat = read_regular(source_path, maximum=4 * 1024 * 1024)
    require(
        source_stat.st_uid in (0, 1000)
        and source_stat.st_gid in (0, 1000)
        and stat.S_IMODE(source_stat.st_mode) & 0o022 == 0,
        "legacy drain source authority differs",
    )
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
        {"schema", "observedAt", "bootId", "stateRoot", "controlSha256", "phase"},
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
        descriptor = open_control_root(create=True)
        try:
            source_digest = snapshot_source(descriptor)
            existing_raw = read_json_at(descriptor, CONTROL_NAME, "legacy drain control")
            if existing_raw is None:
                control = {
                    "schema": CONTROL_SCHEMA,
                    "observedAt": utc_now(),
                    "bootId": current_boot_id(),
                    "stateRoot": str(EXPECTED_STATE_ROOT),
                    "caller": {"uid": 1000, "gid": 1000},
                    "verificationSha256": expected_verification_sha256,
                    "sourceSha256": source_digest,
                    "authority": verification["authority"],
                }
                atomic_write_at(descriptor, CONTROL_NAME, control)
            else:
                control = validate_control(existing_raw)
                require(
                    control["verificationSha256"] == expected_verification_sha256
                    and control["sourceSha256"] == source_digest,
                    "existing legacy drain control differs",
                )
            control_digest = sha256_bytes(canonical_json(control))
            state_raw = read_json_at(descriptor, STATE_NAME, "legacy drain state")
            if state_raw is None:
                state = {
                    "schema": STATE_SCHEMA,
                    "observedAt": utc_now(),
                    "bootId": current_boot_id(),
                    "stateRoot": str(EXPECTED_STATE_ROOT),
                    "controlSha256": control_digest,
                    "phase": "stopping_intent_final",
                }
                atomic_write_at(descriptor, STATE_NAME, state)
            else:
                state = validate_state(state_raw, control_digest)
            return cls(descriptor, control, state)
        except BaseException:
            os.close(descriptor)
            raise

    @classmethod
    def open(cls) -> "ControlAuthority":
        descriptor = open_control_root(create=False)
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

    def advance(self, phase: str) -> None:
        require(phase in PHASES, "legacy drain phase is invalid")
        current_index = PHASES.index(self.phase)
        target_index = PHASES.index(phase)
        require(target_index >= current_index, "legacy drain phase would regress")
        if target_index == current_index:
            return
        require(target_index == current_index + 1, "legacy drain phase would skip")
        state = {
            "schema": STATE_SCHEMA,
            "observedAt": utc_now(),
            "bootId": current_boot_id(),
            "stateRoot": str(EXPECTED_STATE_ROOT),
            "controlSha256": self.control_digest,
            "phase": phase,
        }
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


def exact_process_status(recorded: Mapping[str, object]) -> str:
    pid = int(recorded["pid"])
    if not process_exists(pid):
        return "absent"
    try:
        capture_process(recorded)
    except ProcessUnavailable:
        return "absent"
    except DrainError as error:
        raise ManualRecoveryRequired(f"recorded PID has a foreign identity: {pid}") from error
    return "exact"


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


def remove_bound_socket(control: Mapping[str, object]) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    sockets = authority["sockets"]
    assert isinstance(sockets, dict)
    expected = next(
        item
        for item in sockets["pathIdentities"]
        if item["path"] == str(DOCKER_SOCKET)
    )
    if not exists_nofollow(DOCKER_SOCKET):
        return
    runtime_socket_snapshot(int(process_authority(control, "dockerd")["pid"]))
    root_fd = os.open(EXPECTED_RUNTIME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    leaf_fd: int | None = None
    try:
        try:
            leaf_fd = os.open("docker.sock", os.O_PATH | os.O_NOFOLLOW, dir_fd=root_fd)
        except FileNotFoundError:
            return
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


def trusted_umount() -> Path:
    path = Path("/usr/bin/umount").resolve(strict=True)
    observed = path.stat()
    require(
        stat.S_ISREG(observed.st_mode)
        and observed.st_uid == 0
        and observed.st_gid == 0
        and stat.S_IMODE(observed.st_mode) & 0o022 == 0,
        "umount executable authority differs",
    )
    return path


def settle_task_netns(control: Mapping[str, object]) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    netns = authority["mounts"]["networkNamespace"]
    source = netns["sourceAnchor"]
    anchor = ((str(source["device"]), str(source["root"])),)
    observed = stable_global_mount_roster(TASK_NETNS_TARGET, anchor)
    targets = {item["target"] for item in observed["occurrences"]}
    ambient = set(netns["ambientTargets"])
    owned = str(netns["ownedTarget"])
    if owned in targets:
        manual(targets == ambient | {owned}, "legacy netns source has a foreign target")
        result = subprocess.run(
            [str(trusted_umount()), "--", owned],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"},
        )
        require(result.returncode == 0, "exact legacy task nsfs unmount failed")
    final = stable_global_mount_roster(TASK_NETNS_TARGET, anchor)
    manual(
        {item["target"] for item in final["occurrences"]} == ambient,
        "legacy task netns did not return to ambient targets",
    )


def remove_tree_entry(directory_fd: int, name: str, expected: Mapping[str, object]) -> None:
    observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    require(
        (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            observed.st_gid,
            stat.S_IFMT(observed.st_mode),
        )
        == (
            expected["device"],
            expected["inode"],
            expected["uid"],
            expected["gid"],
            expected["type"],
        ),
        f"legacy runtime entry changed: {name}",
    )
    if stat.S_ISDIR(observed.st_mode):
        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            os.fsync(child_fd)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=directory_fd)
    else:
        require(
            stat.S_ISREG(observed.st_mode)
            or stat.S_ISSOCK(observed.st_mode)
            or stat.S_ISFIFO(observed.st_mode),
            f"legacy runtime leaf type differs: {name}",
        )
        os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def reduce_runtime_tree(control: Mapping[str, object]) -> None:
    if not exists_nofollow(EXPECTED_RUNTIME_ROOT):
        return
    require_mounts_absent(
        control,
        "runtime",
        EXPECTED_RUNTIME_ROOT,
        use_recorded_anchors=False,
    )
    authority = control["authority"]
    assert isinstance(authority, dict)
    runtime = authority["runtime"]
    assert isinstance(runtime, dict)
    expected_rows = {
        str(Path(str(item["path"])).relative_to(EXPECTED_RUNTIME_ROOT)): item
        for item in runtime["tree"]
    }

    def reduce_directory(path: Path, expected_prefix: str = "") -> None:
        directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for name in tuple(sorted(os.listdir(directory_fd))):
                relative = f"{expected_prefix}/{name}" if expected_prefix else name
                manual(relative in expected_rows, f"legacy runtime reducer found a foreign entry: {relative}")
                expected = expected_rows[relative]
                observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(observed.st_mode):
                    reduce_directory(path / name, relative)
                remove_tree_entry(directory_fd, name, expected)
        finally:
            os.close(directory_fd)

    reduce_directory(EXPECTED_RUNTIME_ROOT)
    parent_fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_fd = os.open(EXPECTED_RUNTIME_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        observed = os.fstat(root_fd)
        expected_root = runtime["rootIdentity"]
        require(
            (observed.st_dev, observed.st_ino, observed.st_uid, observed.st_gid)
            == (
                expected_root["device"],
                expected_root["inode"],
                expected_root["uid"],
                expected_root["gid"],
            )
            and not os.listdir(root_fd),
            "legacy runtime root changed before final removal",
        )
        os.rmdir(EXPECTED_RUNTIME_ROOT.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(root_fd)
        os.close(parent_fd)


def unlink_containerd_pidfile(control: Mapping[str, object]) -> None:
    if not exists_nofollow(CONTAINERD_PIDFILE):
        return
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["configs"]["containerdPidfile"]
    parent_fd = os.open(CONTAINERD_PIDFILE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        observed = os.stat(CONTAINERD_PIDFILE.name, dir_fd=parent_fd, follow_symlinks=False)
        require(
            (observed.st_dev, observed.st_ino, observed.st_uid, observed.st_gid)
            == (
                expected["device"],
                expected["inode"],
                expected["uid"],
                expected["gid"],
            ),
            "legacy containerd pidfile changed before removal",
        )
        os.unlink(CONTAINERD_PIDFILE.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def archive_receipt(control: Mapping[str, object]) -> None:
    if exists_nofollow(ARCHIVE_RECEIPT_PATH):
        identity, _ = regular_identity(
            ARCHIVE_RECEIPT_PATH,
            expected_uid=1000,
            expected_gid=1000,
            expected_mode=0o600,
            expected_sha256=EXPECTED_RECEIPT_SHA256,
        )
        require(identity["sha256"] == EXPECTED_RECEIPT_SHA256, "legacy receipt archive differs")
        manual(not exists_nofollow(RECEIPT_PATH), "live and archived legacy receipts coexist")
        return
    manual(exists_nofollow(RECEIPT_PATH), "legacy receipt and archive are both absent")
    authority = control["authority"]
    assert isinstance(authority, dict)
    expected = authority["legacyReceipt"]
    evidence_fd = os.open(
        EXPECTED_STATE_ROOT / "evidence",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        observed = os.stat(RECEIPT_PATH.name, dir_fd=evidence_fd, follow_symlinks=False)
        require(
            (observed.st_dev, observed.st_ino, observed.st_uid, observed.st_gid)
            == (
                expected["device"],
                expected["inode"],
                expected["uid"],
                expected["gid"],
            ),
            "legacy receipt changed before archival",
        )
        os.rename(
            RECEIPT_PATH.name,
            ARCHIVE_RECEIPT_PATH.name,
            src_dir_fd=evidence_fd,
            dst_dir_fd=evidence_fd,
        )
        os.fsync(evidence_fd)
    finally:
        os.close(evidence_fd)


def write_projection(control: ControlAuthority) -> None:
    evidence_fd = os.open(
        EXPECTED_STATE_ROOT / "evidence",
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        atomic_write_at(
            evidence_fd,
            PROJECTION_PATH.name,
            {
                "schema": PROJECTION_SCHEMA,
                "outcome": "drained",
                "observedAt": utc_now(),
                "stateRoot": str(EXPECTED_STATE_ROOT),
                "legacyReceiptSha256": EXPECTED_RECEIPT_SHA256,
                "controlSha256": control.control_digest,
                "persistentDataPreserved": [str(path) for path in PERSISTENT_ROOTS],
                "legacyRuntimeRemoved": True,
                "cgroupMutationPerformed": False,
                "forceKillPerformed": False,
            },
            uid=1000,
            gid=1000,
            mode=0o600,
        )
    finally:
        os.close(evidence_fd)


def registry_inventory_matches(control: Mapping[str, object]) -> None:
    authority = control["authority"]
    assert isinstance(authority, dict)
    require(
        registry_inventory() == authority["registryInventory"],
        "registry custody changed during legacy drain",
    )


def run_reducer(control: ControlAuthority) -> dict[str, object]:
    if control.phase == "complete":
        return {
            "schema": PROJECTION_SCHEMA,
            "outcome": "drained",
            "stateRoot": str(EXPECTED_STATE_ROOT),
            "controlSha256": control.control_digest,
        }

    if control.phase == "stopping_intent_final":
        remove_bound_socket(control.control)
        control.advance("docker_api_revoked")

    if control.phase == "docker_api_revoked":
        control.advance("dockerd_stop_requested")

    if control.phase == "dockerd_stop_requested":
        signal_exact_process(process_authority(control.control, "dockerd"))
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
        control.advance("container_graph_quiesced")

    if control.phase == "container_graph_quiesced":
        control.advance("containerd_stop_requested")

    if control.phase == "containerd_stop_requested":
        signal_exact_process(process_authority(control.control, "containerd"))
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
        settle_task_netns(control.control)
        require_mounts_absent(
            control.control,
            "runtime",
            EXPECTED_RUNTIME_ROOT,
            use_recorded_anchors=False,
        )
        control.advance("mounts_settled")

    if control.phase == "mounts_settled":
        control.advance("runtime_reducing")

    if control.phase == "runtime_reducing":
        reduce_runtime_tree(control.control)
        unlink_containerd_pidfile(control.control)
        registry_inventory_matches(control.control)
        control.advance("runtime_removed")

    if control.phase == "runtime_removed":
        manual(not exists_nofollow(EXPECTED_RUNTIME_ROOT), "legacy runtime root remained")
        for role in EXPECTED_PROCESS_CANDIDATES:
            manual(
                exact_process_status(process_authority(control.control, role)) == "absent",
                f"legacy process remains: {role}",
            )
        registry_inventory_matches(control.control)
        archive_receipt(control.control)
        control.advance("receipt_archived")

    if control.phase == "receipt_archived":
        write_projection(control)
        control.advance("complete")

    require(control.phase == "complete", "legacy drain did not reach completion")
    return {
        "schema": PROJECTION_SCHEMA,
        "outcome": "drained",
        "observedAt": utc_now(),
        "stateRoot": str(EXPECTED_STATE_ROOT),
        "controlSha256": control.control_digest,
        "legacyReceiptArchive": str(ARCHIVE_RECEIPT_PATH),
        "persistentDataPreserved": [str(path) for path in PERSISTENT_ROOTS],
        "cgroupMutationPerformed": False,
        "forceKillPerformed": False,
    }


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
