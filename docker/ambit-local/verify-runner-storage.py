#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "ambit.local-daytona-runner-storage/v3"
CLAIM_DOMAIN = "ambit.local-daytona-runner-storage-claim/v1"
AUTHORITY_ROOT = Path("/home/.ambit-c16b-runner-storage")
TARGET = AUTHORITY_ROOT / "runner-docker"
INNER_RUNNER_DATA_ROOT = TARGET / "inner-runner"
IMAGE = AUTHORITY_ROOT / "runner-docker.xfs"
IMAGE_BYTES = 60 * 1024**3
SANDBOX_BYTES = 20 * 1024**3
MAXIMUM_SANDBOXES = 2
LOOP_DEVICE = re.compile(r"^/dev/loop[0-9]+$")
FILESYSTEM_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class RunnerStorageError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunnerStorageError(message)


def plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def run(args: list[str]) -> str:
    command = (
        args[2:]
        if os.geteuid() == 0 and args[:2] == ["/usr/bin/sudo", "-n"]
        else args
    )
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        cwd="/",
        env={"LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        text=True,
        timeout=120,
    )
    return result.stdout.strip()


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def identity_document(
    path: str,
    device: int,
    inode: int,
    owner_uid: int,
    owner_gid: int,
    mode: int,
) -> dict[str, Any]:
    return {
        "path": path,
        "device": device,
        "inode": inode,
        "ownerUid": owner_uid,
        "ownerGid": owner_gid,
        "mode": f"{mode:04o}",
    }


def validate_storage_identity_observation(value: dict[str, Any]) -> dict[str, Any]:
    expected_keys = {
        "authorityDevice",
        "authorityInode",
        "authorityMode",
        "authorityOwnerGid",
        "authorityOwnerUid",
        "backingFile",
        "backingFilesystemFreeBytes",
        "backingFilesystemTotalBytes",
        "filesystemFreeBytes",
        "filesystemTotalBytes",
        "filesystemType",
        "filesystemUuid",
        "evidenceDevice",
        "evidenceInode",
        "evidenceMode",
        "evidenceOwnerGid",
        "evidenceOwnerUid",
        "evidencePath",
        "imageAllocatedBytes",
        "imageDevice",
        "imageInode",
        "imageLogicalBytes",
        "imageMode",
        "imageOwnerGid",
        "imageOwnerUid",
        "innerRunnerDevice",
        "innerRunnerInode",
        "innerRunnerMode",
        "innerRunnerOwnerGid",
        "innerRunnerOwnerUid",
        "loopDevice",
        "loopDeviceNumber",
        "loopMountTargets",
        "mountNamespaceDevice",
        "mountNamespaceInode",
        "mountOptions",
        "mountTargetDevice",
        "mountTargetInode",
        "mountTargetMode",
        "mountTargetOwnerGid",
        "mountTargetOwnerUid",
        "observerGid",
        "observerUid",
        "stateRoot",
        "stateRootDevice",
        "stateRootInode",
        "stateRootMode",
        "stateRootOwnerGid",
        "stateRootOwnerUid",
        "targetMountTree",
        "xfsFeatures",
    }
    require(set(value) == expected_keys, "runner storage observation shape differs")
    require(isinstance(value["stateRoot"], str), "runner state root is not a string")
    state_root = Path(value["stateRoot"])
    require(state_root.is_absolute(), "runner state root is not absolute")
    require(str(state_root).startswith("/home/"), "runner state root is outside /home")
    require(
        os.path.normpath(str(state_root)) == str(state_root),
        "runner state root is not lexically canonical",
    )
    require(
        plain_int(value["observerUid"])
        and value["observerUid"] > 0
        and plain_int(value["observerGid"])
        and value["observerGid"] >= 0,
        "runner observer identity is invalid",
    )
    require(
        value["stateRootOwnerUid"] == value["observerUid"]
        and value["stateRootOwnerGid"] == value["observerGid"]
        and value["stateRootMode"] == 0o700,
        "runner state-root owner, group, or mode differs",
    )
    device_fields = (
        "stateRootDevice",
        "evidenceDevice",
        "authorityDevice",
        "imageDevice",
        "mountTargetDevice",
        "innerRunnerDevice",
        "mountNamespaceDevice",
    )
    inode_fields = (
        "stateRootInode",
        "evidenceInode",
        "authorityInode",
        "imageInode",
        "mountTargetInode",
        "innerRunnerInode",
        "mountNamespaceInode",
    )
    require(
        all(plain_int(value[field]) and value[field] >= 0 for field in device_fields)
        and all(plain_int(value[field]) and value[field] > 0 for field in inode_fields),
        "runner storage identity coordinate is invalid",
    )
    identity_integer_fields = (
        "stateRootMode",
        "stateRootOwnerUid",
        "stateRootOwnerGid",
        "evidenceMode",
        "evidenceOwnerUid",
        "evidenceOwnerGid",
        "authorityMode",
        "authorityOwnerUid",
        "authorityOwnerGid",
        "imageMode",
        "imageOwnerUid",
        "imageOwnerGid",
        "mountTargetMode",
        "mountTargetOwnerUid",
        "mountTargetOwnerGid",
        "innerRunnerMode",
        "innerRunnerOwnerUid",
        "innerRunnerOwnerGid",
    )
    require(
        all(plain_int(value[field]) and value[field] >= 0 for field in identity_integer_fields),
        "runner storage identity integer is invalid",
    )
    require(
        value["authorityOwnerUid"] == 0
        and value["authorityOwnerGid"] == 0
        and value["authorityMode"] == 0o700,
        "runner authority root ownership or mode differs",
    )
    require(
        value["authorityDevice"] == value["stateRootDevice"],
        "runner authority and user state use different backing filesystems",
    )
    require(
        isinstance(value["evidencePath"], str)
        and value["evidencePath"] == str(state_root / "evidence")
        and value["evidenceOwnerUid"] == value["observerUid"]
        and value["evidenceOwnerGid"] == value["observerGid"]
        and value["evidenceMode"] == 0o700
        and value["evidenceDevice"] == value["stateRootDevice"],
        "runner evidence identity differs",
    )
    require(
        value["imageOwnerUid"] == 0
        and value["imageOwnerGid"] == 0
        and value["imageMode"] == 0o600
        and plain_int(value["imageLogicalBytes"])
        and value["imageLogicalBytes"] == IMAGE_BYTES,
        "runner image ownership, mode, or size differs",
    )
    require(value["imageDevice"] == value["authorityDevice"], "runner image backing differs")
    require(Path(value["backingFile"]) == IMAGE, "runner loop backing differs")
    loop_device = value["loopDevice"]
    require(
        isinstance(loop_device, str) and LOOP_DEVICE.fullmatch(loop_device),
        "runner loop device is invalid",
    )
    loop_number = value["loopDeviceNumber"]
    require(
        isinstance(loop_number, str) and re.fullmatch(r"[0-9]+:[0-9]+", loop_number),
        "runner loop device number is invalid",
    )
    require(value["loopMountTargets"] == [str(TARGET)], "runner loop mount roster differs")
    require(value["targetMountTree"] == [str(TARGET)], "runner target mount tree differs")
    require(
        value["mountTargetOwnerUid"] == 0
        and value["mountTargetOwnerGid"] == 0
        and value["mountTargetMode"] == 0o700,
        "runner mounted target ownership or mode differs",
    )
    require(
        value["innerRunnerOwnerUid"] == 0
        and value["innerRunnerOwnerGid"] == 0
        and value["innerRunnerMode"] == 0o700
        and value["innerRunnerDevice"] == value["mountTargetDevice"],
        "inner runner data-root identity differs",
    )
    target_number = (
        f"{os.major(value['mountTargetDevice'])}:{os.minor(value['mountTargetDevice'])}"
    )
    require(target_number == loop_number, "runner mounted target device differs from loop")
    require(value["filesystemType"] == "xfs", "runner filesystem is not XFS")
    options = value["mountOptions"]
    require(
        isinstance(options, list) and all(isinstance(item, str) for item in options),
        "runner mount options are invalid",
    )
    for option in ("rw", "nodev", "nosuid"):
        require(option in options, f"runner mount option is absent: {option}")
    require("ro" not in options, "runner filesystem is read-only")
    require("pquota" in options or "prjquota" in options, "runner project quota is absent")
    require(
        isinstance(value["filesystemUuid"], str)
        and FILESYSTEM_UUID.fullmatch(value["filesystemUuid"]),
        "runner XFS UUID is invalid",
    )
    features = value["xfsFeatures"]
    require(
        isinstance(features, list) and all(isinstance(item, str) for item in features),
        "runner XFS features are invalid",
    )
    for feature in ("crc=1", "finobt=1", "ftype=1", "projid32bit=1"):
        require(feature in features, f"runner XFS feature is absent: {feature}")
    for free_field, total_field in (
        ("filesystemFreeBytes", "filesystemTotalBytes"),
        ("backingFilesystemFreeBytes", "backingFilesystemTotalBytes"),
    ):
        require(
            plain_int(value[total_field])
            and value[total_field] > 0
            and plain_int(value[free_field])
            and 0 <= value[free_field] <= value[total_field],
            f"runner capacity observation is invalid: {free_field}",
        )
    require(
        plain_int(value["imageAllocatedBytes"])
        and 0 <= value["imageAllocatedBytes"] <= value["backingFilesystemTotalBytes"],
        "runner image allocation observation is invalid",
    )
    state_identity = identity_document(
        str(state_root),
        value["stateRootDevice"],
        value["stateRootInode"],
        value["stateRootOwnerUid"],
        value["stateRootOwnerGid"],
        value["stateRootMode"],
    )
    evidence_identity = identity_document(
        value["evidencePath"],
        value["evidenceDevice"],
        value["evidenceInode"],
        value["evidenceOwnerUid"],
        value["evidenceOwnerGid"],
        value["evidenceMode"],
    )
    caller = {"uid": value["observerUid"], "gid": value["observerGid"]}
    claim_binding = {
        "domain": CLAIM_DOMAIN,
        "authorityRoot": str(AUTHORITY_ROOT),
        "caller": caller,
        "stateRootIdentity": state_identity,
        "evidenceDirectoryIdentity": evidence_identity,
    }
    claim_sha256 = hashlib.sha256(canonical_json_bytes(claim_binding)).hexdigest()
    return {
        "schema": SCHEMA,
        "lifecycleState": "attached",
        "stateRoot": str(state_root),
        "authorityClaimSha256": claim_sha256,
        "caller": caller,
        "stateRootIdentity": state_identity,
        "evidenceDirectoryIdentity": evidence_identity,
        "authorityRoot": {
            "path": str(AUTHORITY_ROOT),
            "device": value["authorityDevice"],
            "inode": value["authorityInode"],
            "ownerUid": 0,
            "ownerGid": 0,
            "mode": "0700",
        },
        "mountTarget": {
            "path": str(TARGET),
            "device": value["mountTargetDevice"],
            "inode": value["mountTargetInode"],
            "ownerUid": value["mountTargetOwnerUid"],
            "ownerGid": value["mountTargetOwnerGid"],
            "mode": "0700",
        },
        "innerRunnerDataRoot": {
            "path": str(INNER_RUNNER_DATA_ROOT),
            "device": value["innerRunnerDevice"],
            "inode": value["innerRunnerInode"],
            "ownerUid": value["innerRunnerOwnerUid"],
            "ownerGid": value["innerRunnerOwnerGid"],
            "mode": "0700",
        },
        "image": {
            "path": str(IMAGE),
            "logicalBytes": IMAGE_BYTES,
            "allocatedBytes": value["imageAllocatedBytes"],
            "device": value["imageDevice"],
            "inode": value["imageInode"],
            "ownerUid": 0,
            "ownerGid": 0,
            "mode": "0600",
        },
        "loop": {
            "device": loop_device,
            "major": int(loop_number.split(":", 1)[0]),
            "minor": int(loop_number.split(":", 1)[1]),
        },
        "filesystem": {
            "type": "xfs",
            "uuid": value["filesystemUuid"],
            "mountOptions": sorted(set(options)),
            "totalBytes": value["filesystemTotalBytes"],
            "freeBytes": value["filesystemFreeBytes"],
            "features": sorted(set(features)),
        },
        "mountNamespace": {
            "device": value["mountNamespaceDevice"],
            "inode": value["mountNamespaceInode"],
        },
        "backingFilesystem": {
            "device": value["authorityDevice"],
            "totalBytes": value["backingFilesystemTotalBytes"],
            "freeBytes": value["backingFilesystemFreeBytes"],
            "allocationDisposition": "sparse_current_headroom_not_preallocated",
            "minimumFreeBytes": IMAGE_BYTES,
        },
        "sandboxDiskPolicy": {
            "perSandboxBytes": SANDBOX_BYTES,
            "maximumSandboxes": MAXIMUM_SANDBOXES,
            "aggregateBytes": SANDBOX_BYTES * MAXIMUM_SANDBOXES,
            "enforcement": "xfs_project_quota_required",
            "backingCapacity": "current_headroom_with_visible_enospc_failure",
        },
    }


def collect_storage_observation(
    state_root: Path,
    *,
    authority_root: Path = AUTHORITY_ROOT,
    observer_uid: int | None = None,
    observer_gid: int | None = None,
    state_root_fd: int | None = None,
    evidence_fd: int | None = None,
    authority_fd: int | None = None,
    image_fd: int | None = None,
) -> dict[str, Any]:
    require(authority_root == AUTHORITY_ROOT, "runner authority root differs")
    require(state_root.is_absolute(), "STATE_ROOT is not absolute")
    require(state_root.resolve(strict=True) == state_root, "STATE_ROOT is not canonical")
    state_path_stat = os.stat(state_root, follow_symlinks=False)
    state_stat = os.fstat(state_root_fd) if state_root_fd is not None else state_path_stat
    require(
        (state_path_stat.st_dev, state_path_stat.st_ino)
        == (state_stat.st_dev, state_stat.st_ino),
        "STATE_ROOT descriptor identity differs",
    )
    evidence_path = state_root / "evidence"
    evidence_path_stat = os.stat(evidence_path, follow_symlinks=False)
    evidence_stat = os.fstat(evidence_fd) if evidence_fd is not None else evidence_path_stat
    require(
        (evidence_path_stat.st_dev, evidence_path_stat.st_ino)
        == (evidence_stat.st_dev, evidence_stat.st_ino),
        "evidence descriptor identity differs",
    )
    authority_path_stat = os.stat(AUTHORITY_ROOT, follow_symlinks=False)
    authority_stat = os.fstat(authority_fd) if authority_fd is not None else authority_path_stat
    require(
        (authority_path_stat.st_dev, authority_path_stat.st_ino)
        == (authority_stat.st_dev, authority_stat.st_ino),
        "authority descriptor identity differs",
    )
    image_path_stat = os.stat(IMAGE, follow_symlinks=False)
    image_stat = os.fstat(image_fd) if image_fd is not None else image_path_stat
    require(
        (image_path_stat.st_dev, image_path_stat.st_ino)
        == (image_stat.st_dev, image_stat.st_ino),
        "image descriptor identity differs",
    )
    target_fd = os.open(TARGET, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    inner_runner_fd: int | None = None
    try:
        target_path_stat = os.stat(TARGET, follow_symlinks=False)
        target_stat = os.fstat(target_fd)
        require(
            (target_path_stat.st_dev, target_path_stat.st_ino)
            == (target_stat.st_dev, target_stat.st_ino),
            "mount-target descriptor identity differs",
        )
        inner_runner_fd = os.open(
            "inner-runner",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=target_fd,
        )
        inner_runner_path_stat = os.stat(INNER_RUNNER_DATA_ROOT, follow_symlinks=False)
        inner_runner_stat = os.fstat(inner_runner_fd)
        require(
            (inner_runner_path_stat.st_dev, inner_runner_path_stat.st_ino)
            == (inner_runner_stat.st_dev, inner_runner_stat.st_ino),
            "inner runner descriptor identity differs",
        )
    finally:
        if inner_runner_fd is not None:
            os.close(inner_runner_fd)
        os.close(target_fd)
    require(stat.S_ISDIR(state_stat.st_mode), "state root is not a directory")
    require(stat.S_ISDIR(evidence_stat.st_mode), "evidence directory is not a directory")
    require(stat.S_ISDIR(authority_stat.st_mode), "authority root is not a directory")
    require(stat.S_ISREG(image_stat.st_mode), "runner image is not regular")
    require(stat.S_ISDIR(target_stat.st_mode), "runner target is not a directory")
    require(stat.S_ISDIR(inner_runner_stat.st_mode), "inner runner data root is not a directory")
    mount_data = json.loads(
        run(["/usr/bin/findmnt", "--json", "--mountpoint", str(TARGET), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
    )
    filesystems = mount_data.get("filesystems")
    require(isinstance(filesystems, list) and len(filesystems) == 1, "runner mount is absent")
    mount = filesystems[0]
    require(isinstance(mount, dict), "runner mount record is invalid")
    loop_device = mount.get("source")
    require(isinstance(loop_device, str), "runner mount source is invalid")
    loop_stat = os.stat(loop_device)
    require(stat.S_ISBLK(loop_stat.st_mode), "runner loop source is not a block device")
    loop_number = f"{os.major(loop_stat.st_rdev)}:{os.minor(loop_stat.st_rdev)}"
    loop_data = json.loads(
        run(["/usr/bin/sudo", "-n", "/usr/bin/losetup", "--json", "--output", "NAME,BACK-FILE", loop_device])
    )
    devices = loop_data.get("loopdevices")
    require(isinstance(devices, list) and len(devices) == 1, "loop identity is absent")
    backing_file = devices[0].get("back-file")
    require(isinstance(backing_file, str), "loop backing is invalid")
    all_mounts = json.loads(run(["/usr/bin/findmnt", "--json", "--list", "-o", "MAJ:MIN,TARGET"]))
    records = all_mounts.get("filesystems")
    require(isinstance(records, list), "mount roster is invalid")
    loop_targets: list[str] = []
    target_tree: list[str] = []
    target_prefix = f"{TARGET}/"
    for record in records:
        require(isinstance(record, dict), "mount roster record is invalid")
        number = record.get("maj:min")
        target = record.get("target")
        require(isinstance(number, str) and isinstance(target, str), "mount record differs")
        if number == loop_number:
            loop_targets.append(target)
        if target == str(TARGET) or target.startswith(target_prefix):
            target_tree.append(target)
    xfs_info = run(["/usr/bin/xfs_info", str(TARGET)])
    features = sorted(set(re.findall(r"(?:crc|finobt|ftype|projid32bit)=[01]", xfs_info)))
    filesystem = os.statvfs(TARGET)
    backing = os.statvfs(AUTHORITY_ROOT)
    namespace_stat = os.stat("/proc/self/ns/mnt")
    return {
        "stateRoot": str(state_root),
        "observerUid": os.getuid() if observer_uid is None else observer_uid,
        "observerGid": os.getgid() if observer_gid is None else observer_gid,
        "stateRootDevice": state_stat.st_dev,
        "stateRootInode": state_stat.st_ino,
        "stateRootMode": stat.S_IMODE(state_stat.st_mode),
        "stateRootOwnerUid": state_stat.st_uid,
        "stateRootOwnerGid": state_stat.st_gid,
        "evidencePath": str(evidence_path),
        "evidenceDevice": evidence_stat.st_dev,
        "evidenceInode": evidence_stat.st_ino,
        "evidenceMode": stat.S_IMODE(evidence_stat.st_mode),
        "evidenceOwnerUid": evidence_stat.st_uid,
        "evidenceOwnerGid": evidence_stat.st_gid,
        "authorityDevice": authority_stat.st_dev,
        "authorityInode": authority_stat.st_ino,
        "authorityMode": stat.S_IMODE(authority_stat.st_mode),
        "authorityOwnerUid": authority_stat.st_uid,
        "authorityOwnerGid": authority_stat.st_gid,
        "imageLogicalBytes": image_stat.st_size,
        "imageAllocatedBytes": image_stat.st_blocks * 512,
        "imageDevice": image_stat.st_dev,
        "imageInode": image_stat.st_ino,
        "imageMode": stat.S_IMODE(image_stat.st_mode),
        "imageOwnerUid": image_stat.st_uid,
        "imageOwnerGid": image_stat.st_gid,
        "mountTargetDevice": target_stat.st_dev,
        "mountTargetInode": target_stat.st_ino,
        "mountTargetMode": stat.S_IMODE(target_stat.st_mode),
        "mountTargetOwnerUid": target_stat.st_uid,
        "mountTargetOwnerGid": target_stat.st_gid,
        "innerRunnerDevice": inner_runner_stat.st_dev,
        "innerRunnerInode": inner_runner_stat.st_ino,
        "innerRunnerMode": stat.S_IMODE(inner_runner_stat.st_mode),
        "innerRunnerOwnerUid": inner_runner_stat.st_uid,
        "innerRunnerOwnerGid": inner_runner_stat.st_gid,
        "loopDevice": loop_device,
        "loopDeviceNumber": loop_number,
        "loopMountTargets": sorted(loop_targets),
        "targetMountTree": sorted(target_tree),
        "backingFile": str(Path(backing_file).resolve(strict=True)),
        "filesystemType": mount.get("fstype"),
        "mountOptions": str(mount.get("options", "")).split(","),
        "filesystemUuid": run(["/usr/bin/sudo", "-n", "/usr/bin/blkid", "-s", "UUID", "-o", "value", loop_device]),
        "xfsFeatures": features,
        "filesystemTotalBytes": filesystem.f_blocks * filesystem.f_frsize,
        "filesystemFreeBytes": filesystem.f_bavail * filesystem.f_frsize,
        "backingFilesystemTotalBytes": backing.f_blocks * backing.f_frsize,
        "backingFilesystemFreeBytes": backing.f_bavail * backing.f_frsize,
        "mountNamespaceDevice": namespace_stat.st_dev,
        "mountNamespaceInode": namespace_stat.st_ino,
    }


def main() -> None:
    if len(sys.argv) != 2:
        raise RunnerStorageError("Usage: verify-runner-storage.py STATE_ROOT")
    receipt = validate_storage_identity_observation(
        collect_storage_observation(Path(sys.argv[1]))
    )
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
