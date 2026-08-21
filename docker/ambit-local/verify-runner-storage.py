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
MINIMUM_USABLE_BYTES = 40 * 1024**3
LOOP_DEVICE = re.compile(r"^/dev/loop[0-9]+$")
FILESYSTEM_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


class RunnerStorageError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RunnerStorageError(message)


def validate_storage_observation(value: dict[str, Any]) -> dict[str, Any]:
    expected_keys = {
        "backingFile",
        "backingFilesystemFreeBytes",
        "backingFilesystemTotalBytes",
        "filesystemFreeBytes",
        "filesystemTotalBytes",
        "filesystemType",
        "filesystemUuid",
        "imageDevice",
        "imageAllocatedBytes",
        "imageInode",
        "imageLogicalBytes",
        "imageMode",
        "imageOwnerUid",
        "imagePath",
        "loopDevice",
        "mountOptions",
        "mountTarget",
        "stateRoot",
        "stateRootDevice",
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
    require(value["filesystemType"] == "xfs", "runner storage filesystem is not XFS")
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
    require(value["imageLogicalBytes"] == IMAGE_BYTES, "runner storage image size differs")
    require(value["imageMode"] == 0o600, "runner storage image mode differs")
    require(
        value["imageOwnerUid"] == 0,
        "runner storage image owner differs",
    )
    require(
        isinstance(value["imageDevice"], int)
        and value["imageDevice"] >= 0
        and isinstance(value["imageInode"], int)
        and value["imageInode"] > 0,
        "runner storage image identity is invalid",
    )
    require(
        value["imageDevice"] == value["stateRootDevice"],
        "runner storage image is on a different backing filesystem",
    )
    require(
        isinstance(value["imageAllocatedBytes"], int)
        and 0 <= value["imageAllocatedBytes"] <= IMAGE_BYTES,
        "runner storage allocated-byte observation is invalid",
    )
    require(
        isinstance(value["backingFilesystemTotalBytes"], int)
        and value["backingFilesystemTotalBytes"] >= IMAGE_BYTES,
        "runner storage backing filesystem is too small",
    )
    require(
        isinstance(value["backingFilesystemFreeBytes"], int)
        and value["backingFilesystemFreeBytes"] >= IMAGE_BYTES,
        "runner storage backing filesystem lacks current headroom",
    )
    require(
        isinstance(value["filesystemTotalBytes"], int)
        and value["filesystemTotalBytes"] >= MINIMUM_USABLE_BYTES,
        "runner storage filesystem is below aggregate capacity",
    )
    require(
        isinstance(value["filesystemFreeBytes"], int)
        and value["filesystemFreeBytes"] >= MINIMUM_USABLE_BYTES,
        "runner storage free space is below aggregate capacity",
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
            "perSandboxBytes": 20 * 1024**3,
            "maximumSandboxes": 2,
            "aggregateBytes": 40 * 1024**3,
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
    image = state_root / "capacity" / "runner-docker.xfs"
    target_stat = os.lstat(target)
    image_stat = os.lstat(image)
    require(stat.S_ISDIR(target_stat.st_mode), "runner storage target is not a directory")
    require(not target.is_symlink(), "runner storage target is a symlink")
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
    filesystem_uuid = run(["sudo", "-n", "blkid", "-s", "UUID", "-o", "value", loop_device])
    xfs_info = run(["xfs_info", str(target)])
    features = sorted(set(re.findall(r"(?:crc|finobt|ftype|projid32bit)=[01]", xfs_info)))
    filesystem = os.statvfs(target)
    backing_filesystem = os.statvfs(state_root)
    state_root_stat = os.stat(state_root)
    return {
        "stateRoot": str(state_root),
        "mountTarget": mount.get("target"),
        "imagePath": str(image),
        "loopDevice": loop_device,
        "backingFile": str(Path(backing_file).resolve(strict=True)),
        "filesystemType": mount.get("fstype"),
        "mountOptions": str(mount.get("options", "")).split(","),
        "imageLogicalBytes": image_stat.st_size,
        "imageAllocatedBytes": image_stat.st_blocks * 512,
        "imageMode": stat.S_IMODE(image_stat.st_mode),
        "imageOwnerUid": image_stat.st_uid,
        "imageDevice": image_stat.st_dev,
        "imageInode": image_stat.st_ino,
        "stateRootDevice": state_root_stat.st_dev,
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
    receipt = validate_storage_observation(collect_storage_observation(Path(sys.argv[1])))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
