#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA = "ambit.local-daytona-runner-storage/v1"
IMAGE_BYTES = 60 * 1024**3
SANDBOX_BYTES = 20 * 1024**3
MAXIMUM_SANDBOXES = 2
AGGREGATE_SANDBOX_BYTES = SANDBOX_BYTES * MAXIMUM_SANDBOXES
LOOP_DEVICE = re.compile(r"^/dev/loop[0-9]+$")
FILESYSTEM_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class RunnerStorageError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunnerStorageError(message)


def is_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_storage_identity_observation(value: dict[str, Any]) -> dict[str, Any]:
    """Validate owned storage identity without granting host readiness."""
    expected_keys = {
        "backingFile",
        "backingFilesystemFreeBytes",
        "backingFilesystemTotalBytes",
        "capacityDevice",
        "capacityInode",
        "capacityMode",
        "capacityOwnerGid",
        "capacityOwnerUid",
        "filesystemFreeBytes",
        "filesystemTotalBytes",
        "filesystemType",
        "filesystemUuid",
        "imageDevice",
        "imageAllocatedBytes",
        "imageInode",
        "imageLogicalBytes",
        "imageMode",
        "imageOwnerGid",
        "imageOwnerUid",
        "imagePath",
        "loopDevice",
        "loopMountTargets",
        "mountOptions",
        "mountTarget",
        "stateRoot",
        "stateRootDevice",
        "targetMountTree",
        "xfsFeatures",
    }
    require(set(value) == expected_keys, "runner storage observation shape differs")
    state_root = Path(value["stateRoot"])
    expected_target = state_root / "runner-docker"
    expected_image = state_root / "capacity" / "runner-docker.xfs"
    require(state_root.is_absolute(), "runner storage state root is not absolute")
    require(str(state_root).startswith("/home/"), "runner storage state root is outside /home")
    require(Path(value["mountTarget"]) == expected_target, "runner storage mount target differs")
    require(Path(value["imagePath"]) == expected_image, "runner storage image path differs")
    require(Path(value["backingFile"]) == expected_image, "runner storage loop backing differs")
    require(
        isinstance(value["loopDevice"], str) and LOOP_DEVICE.fullmatch(value["loopDevice"]) is not None,
        "runner storage loop device is invalid",
    )
    require(
        value["loopMountTargets"] == [str(expected_target)],
        "runner storage loop device has a missing or additional global mount",
    )
    require(
        value["targetMountTree"] == [str(expected_target)],
        "runner storage target has a missing, nested, or foreign mount",
    )
    require(value["filesystemType"] == "xfs", "runner storage filesystem is not XFS")
    require(
        is_plain_int(value["capacityDevice"])
        and value["capacityDevice"] == value["stateRootDevice"],
        "runner capacity root is on a different backing filesystem",
    )
    require(
        is_plain_int(value["capacityInode"]) and value["capacityInode"] > 0,
        "runner capacity root inode is invalid",
    )
    require(
        is_plain_int(value["capacityOwnerUid"])
        and value["capacityOwnerUid"] == 0
        and is_plain_int(value["capacityOwnerGid"])
        and value["capacityOwnerGid"] == 0
        and is_plain_int(value["capacityMode"])
        and value["capacityMode"] == 0o711,
        "runner capacity root ownership or mode differs",
    )
    options = value["mountOptions"]
    require(
        isinstance(options, list) and all(isinstance(option, str) for option in options),
        "runner storage mount options are invalid",
    )
    require(
        "pquota" in options or "prjquota" in options,
        "runner storage project quotas are not enabled",
    )
    require(
        "rw" in options and "ro" not in options,
        "runner storage filesystem is not writable",
    )
    require("nodev" in options and "nosuid" in options, "runner storage mount hardening differs")
    require(
        is_plain_int(value["imageLogicalBytes"])
        and value["imageLogicalBytes"] == IMAGE_BYTES,
        "runner storage image size differs",
    )
    require(
        is_plain_int(value["imageMode"]) and value["imageMode"] == 0o600,
        "runner storage image mode differs",
    )
    require(
        is_plain_int(value["imageOwnerUid"])
        and value["imageOwnerUid"] == 0
        and is_plain_int(value["imageOwnerGid"])
        and value["imageOwnerGid"] == 0,
        "runner storage image owner or group differs",
    )
    require(
        is_plain_int(value["imageDevice"])
        and value["imageDevice"] >= 0
        and is_plain_int(value["imageInode"])
        and value["imageInode"] > 0,
        "runner storage image identity is invalid",
    )
    require(
        is_plain_int(value["stateRootDevice"])
        and value["imageDevice"] == value["stateRootDevice"],
        "runner storage image is on a different backing filesystem",
    )
    require(
        is_plain_int(value["imageAllocatedBytes"])
        and value["imageAllocatedBytes"] >= 0,
        "runner storage allocated-byte observation is invalid",
    )
    require(
        is_plain_int(value["backingFilesystemTotalBytes"])
        and value["backingFilesystemTotalBytes"] > 0,
        "runner storage backing filesystem total is invalid",
    )
    require(
        value["imageAllocatedBytes"] <= value["backingFilesystemTotalBytes"],
        "runner storage allocated-byte observation exceeds its backing filesystem",
    )
    require(
        is_plain_int(value["backingFilesystemFreeBytes"])
        and 0
        <= value["backingFilesystemFreeBytes"]
        <= value["backingFilesystemTotalBytes"],
        "runner storage backing filesystem free space is invalid",
    )
    require(
        is_plain_int(value["filesystemTotalBytes"])
        and value["filesystemTotalBytes"] > 0,
        "runner storage filesystem total is invalid",
    )
    require(
        is_plain_int(value["filesystemFreeBytes"])
        and 0 <= value["filesystemFreeBytes"] <= value["filesystemTotalBytes"],
        "runner storage filesystem free space is invalid",
    )
    require(
        isinstance(value["filesystemUuid"], str)
        and FILESYSTEM_UUID.fullmatch(value["filesystemUuid"]) is not None,
        "runner storage filesystem UUID is invalid",
    )
    features = value["xfsFeatures"]
    require(
        isinstance(features, list) and all(isinstance(feature, str) for feature in features),
        "runner storage XFS features are invalid",
    )
    for feature in ("crc=1", "finobt=1", "ftype=1", "projid32bit=1"):
        require(feature in features, f"runner storage XFS feature is absent: {feature}")
    return {
        "schema": SCHEMA,
        "outcome": "passed",
        "stateRoot": str(state_root),
        "mountTarget": str(expected_target),
        "image": {
            "path": str(expected_image),
            "logicalBytes": IMAGE_BYTES,
            "allocatedBytes": value["imageAllocatedBytes"],
            "device": value["imageDevice"],
            "inode": value["imageInode"],
            "ownerUid": value["imageOwnerUid"],
            "mode": "0600",
        },
        "filesystem": {
            "type": "xfs",
            "uuid": value["filesystemUuid"],
            "loopDevice": value["loopDevice"],
            "mountOptions": sorted(set(options)),
            "totalBytes": value["filesystemTotalBytes"],
            "freeBytes": value["filesystemFreeBytes"],
            "features": sorted(set(features)),
        },
        "backingFilesystem": {
            "device": value["stateRootDevice"],
            "totalBytes": value["backingFilesystemTotalBytes"],
            "freeBytes": value["backingFilesystemFreeBytes"],
            "allocationDisposition": "sparse_current_headroom_not_preallocated",
            "minimumFreeBytes": IMAGE_BYTES,
        },
        "sandboxDiskPolicy": {
            "perSandboxBytes": SANDBOX_BYTES,
            "maximumSandboxes": MAXIMUM_SANDBOXES,
            "aggregateBytes": AGGREGATE_SANDBOX_BYTES,
            "enforcement": "xfs_project_quota_required",
            "backingCapacity": "current_headroom_with_visible_enospc_failure",
        },
    }


def run(args: list[str]) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def collect_storage_observation(state_root: Path) -> dict[str, Any]:
    require(state_root.is_absolute(), "STATE_ROOT is not absolute")
    require(str(state_root).startswith("/home/"), "STATE_ROOT is outside /home")
    require(state_root.resolve(strict=True) == state_root, "STATE_ROOT is not canonical")
    target = state_root / "runner-docker"
    capacity = state_root / "capacity"
    image = state_root / "capacity" / "runner-docker.xfs"
    target_stat = os.lstat(target)
    capacity_stat = os.lstat(capacity)
    image_stat = os.lstat(image)
    require(stat.S_ISDIR(target_stat.st_mode), "runner storage target is not a directory")
    require(not target.is_symlink(), "runner storage target is a symlink")
    require(stat.S_ISDIR(capacity_stat.st_mode), "runner capacity root is not a directory")
    require(not capacity.is_symlink(), "runner capacity root is a symlink")
    require(stat.S_ISREG(image_stat.st_mode), "runner storage image is not regular")
    require(not image.is_symlink(), "runner storage image is a symlink")

    mount_data = json.loads(
        run(["findmnt", "--json", "--mountpoint", str(target), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
    )
    filesystems = mount_data.get("filesystems")
    require(isinstance(filesystems, list) and len(filesystems) == 1, "runner storage mount is absent")
    mount = filesystems[0]
    require(isinstance(mount, dict), "runner storage mount record is invalid")
    loop_device = mount.get("source")
    require(isinstance(loop_device, str), "runner storage mount source is invalid")
    loop_data = json.loads(
        run(["sudo", "-n", "losetup", "--json", "--output", "NAME,BACK-FILE", loop_device])
    )
    devices = loop_data.get("loopdevices")
    require(isinstance(devices, list) and len(devices) == 1, "runner storage loop identity is absent")
    loop = devices[0]
    require(isinstance(loop, dict), "runner storage loop record is invalid")
    backing_file = loop.get("back-file")
    require(isinstance(backing_file, str), "runner storage backing file is invalid")
    loop_device_stat = os.stat(loop_device)
    require(stat.S_ISBLK(loop_device_stat.st_mode), "runner storage loop device is not a block device")
    loop_device_number = (
        f"{os.major(loop_device_stat.st_rdev)}:{os.minor(loop_device_stat.st_rdev)}"
    )
    loop_mount_data = json.loads(
        run(
            [
                "findmnt",
                "--json",
                "--list",
                "-o",
                "MAJ:MIN,TARGET",
            ]
        )
    )
    loop_mount_filesystems = loop_mount_data.get("filesystems")
    require(
        isinstance(loop_mount_filesystems, list),
        "runner storage global loop mount observation is invalid",
    )
    loop_mount_targets: list[str] = []
    target_mount_tree: list[str] = []
    target_prefix = f"{target}/"
    for loop_mount in loop_mount_filesystems:
        require(
            isinstance(loop_mount, dict)
            and isinstance(loop_mount.get("maj:min"), str)
            and isinstance(loop_mount.get("target"), str),
            "runner storage global loop mount record is invalid",
        )
        if loop_mount["maj:min"] == loop_device_number:
            loop_mount_targets.append(loop_mount["target"])
        if loop_mount["target"] == str(target) or loop_mount["target"].startswith(
            target_prefix
        ):
            target_mount_tree.append(loop_mount["target"])
    filesystem_uuid = run(["sudo", "-n", "blkid", "-s", "UUID", "-o", "value", loop_device])
    xfs_info = run(["xfs_info", str(target)])
    features = sorted(set(re.findall(r"(?:crc|finobt|ftype|projid32bit)=[01]", xfs_info)))
    filesystem = os.statvfs(target)
    backing_filesystem = os.statvfs(state_root)
    state_root_stat = os.stat(state_root)
    return {
        "stateRoot": str(state_root),
        "capacityMode": stat.S_IMODE(capacity_stat.st_mode),
        "capacityOwnerUid": capacity_stat.st_uid,
        "capacityOwnerGid": capacity_stat.st_gid,
        "capacityDevice": capacity_stat.st_dev,
        "capacityInode": capacity_stat.st_ino,
        "mountTarget": mount.get("target"),
        "imagePath": str(image),
        "loopDevice": loop_device,
        "loopMountTargets": sorted(loop_mount_targets),
        "backingFile": str(Path(backing_file).resolve(strict=True)),
        "filesystemType": mount.get("fstype"),
        "mountOptions": str(mount.get("options", "")).split(","),
        "imageLogicalBytes": image_stat.st_size,
        "imageAllocatedBytes": image_stat.st_blocks * 512,
        "imageMode": stat.S_IMODE(image_stat.st_mode),
        "imageOwnerUid": image_stat.st_uid,
        "imageOwnerGid": image_stat.st_gid,
        "imageDevice": image_stat.st_dev,
        "imageInode": image_stat.st_ino,
        "stateRootDevice": state_root_stat.st_dev,
        "targetMountTree": sorted(target_mount_tree),
        "filesystemTotalBytes": filesystem.f_blocks * filesystem.f_frsize,
        "filesystemFreeBytes": filesystem.f_bavail * filesystem.f_frsize,
        "backingFilesystemTotalBytes": backing_filesystem.f_blocks
        * backing_filesystem.f_frsize,
        "backingFilesystemFreeBytes": backing_filesystem.f_bavail
        * backing_filesystem.f_frsize,
        "filesystemUuid": filesystem_uuid,
        "xfsFeatures": features,
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
