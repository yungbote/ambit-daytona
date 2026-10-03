#!/usr/bin/env python3
"""Run the native capture test on task-owned XFS/Docker, without host networking.

Invoke under `sudo -n unshare --mount --net --propagation private` and the
machine's heavy gate. Inputs are an existing single-image Docker archive, the
compiled workingcopy test binary, a scratch directory, and an evidence directory.
No images are pulled. This is qualification, not provider installation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time


def namespace(path: str) -> tuple[int, int]:
    stat = os.stat(path)
    return stat.st_dev, stat.st_ino


def require_private_namespaces() -> None:
    for kind in ("net", "mnt"):
        if namespace(f"/proc/self/ns/{kind}") == namespace(f"/proc/1/ns/{kind}"):
            raise RuntimeError(f"native qualification requires a private {kind} namespace")


def image_config(archive_path: Path) -> str:
    # Containerd may report the OCI manifest as Id; legacy Docker reports the
    # config. Derive the config from independent archive bytes before loading.
    with tarfile.open(archive_path) as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
        if len(manifest) != 1:
            raise ValueError("native qualification requires exactly one archived image")
        payload = archive.extractfile(manifest[0]["Config"]).read()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def containerd_command(root: Path, mount: Path) -> list[str]:
    return [
        "containerd", "--config", str(root / "containerd.toml"),
        "--address", str(root / "containerd.sock"),
        "--root", str(mount / "containerd"), "--state", str(root / "containerd-state"),
    ]


def docker_command(root: Path, mount: Path) -> list[str]:
    return [
        "dockerd", "--config-file", str(root / "daemon.json"),
        "--host", "unix://" + str(root / "docker.sock"),
        "--containerd", str(root / "containerd.sock"),
        "--containerd-namespace", root.name,
        "--containerd-plugins-namespace", root.name + "-plugins",
        "--data-root", str(mount / "docker"), "--exec-root", str(root / "exec"),
        "--pidfile", str(root / "dockerd.pid"), "--storage-driver", "overlay2",
        "--bridge", "none", "--iptables=false", "--ip6tables=false",
        "--ip-forward=false", "--ip-masq=false", "--userland-proxy=false",
    ]


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def main(arguments: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("image_archive", "test_binary", "scratch", "evidence"):
        parser.add_argument(argument, type=Path)
    parser.add_argument("--startup-only", action="store_true", help="prove daemon isolation before loading an image")
    args = parser.parse_args(arguments)
    # This guard precedes any scratch creation, mount, daemon or image effect.
    require_private_namespaces()
    image_id = image_config(args.image_archive)
    args.scratch.mkdir(parents=True, exist_ok=True)
    evidence = args.evidence / str(time.time_ns())
    evidence.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="native-capture-", dir=args.scratch))
    mount = root / "xfs"
    mount.mkdir()
    daemon = containerd = None
    mounted = False
    run = subprocess.run
    try:
        image = root / "xfs.img"
        with image.open("wb") as stream:
            stream.truncate(32 * 1024**3)
        run(["mkfs.xfs", "-q", "-f", "-m", "reflink=1", str(image)], check=True)
        run(["mount", "-o", "loop,nosuid,nodev", str(image), str(mount)], check=True)
        mounted = True
        with (evidence / "filesystem.log").open("w") as log:
            run(["xfs_info", str(mount)], stdout=log, stderr=subprocess.STDOUT, check=True)
        (root / "daemon.json").write_text("{}")
        (root / "containerd.toml").write_text(
            'version = 3\ndisabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]\n'
        )
        env = dict(os.environ, DOCKER_HOST="unix://" + str(root / "docker.sock"))
        with (evidence / "containerd.log").open("w") as log:
            containerd = subprocess.Popen(containerd_command(root, mount), stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while not (root / "containerd.sock").exists():
            if containerd.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("private containerd did not become ready")
            time.sleep(0.25)
        with (evidence / "dockerd.log").open("w") as log:
            daemon = subprocess.Popen(docker_command(root, mount), stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 45
        while True:
            probe = run(["docker", "info", "--format", "{{.Driver}}"], env=env, capture_output=True)
            if probe.returncode == 0:
                break
            if daemon.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("private Docker did not become ready")
            time.sleep(0.25)
        isolation = {}
        for kind in ("net", "mnt"):
            own = namespace(f"/proc/self/ns/{kind}")
            for process in (containerd, daemon):
                if namespace(f"/proc/{process.pid}/ns/{kind}") != own:
                    raise RuntimeError(f"qualification daemon escaped private {kind} namespace")
            isolation[kind] = {"self": own, "host": namespace(f"/proc/1/ns/{kind}")}
        (evidence / "isolation.json").write_text(json.dumps({
            "namespaces": isolation, "containerd": containerd.args, "dockerd": daemon.args,
        }, indent=2) + "\n")
        if args.startup_only:
            (evidence / "receipt.json").write_text(json.dumps({"stage": "private-daemon-startup", "exit": 0}, indent=2) + "\n")
            print(str(evidence), flush=True)
            return
        run(["docker", "load", "-i", str(args.image_archive)], env=env, check=True, timeout=900)
        observed = subprocess.check_output(["docker", "image", "inspect", image_id, "--format", "{{.Id}}"], env=env).decode().strip()
        if observed != image_id:
            raise RuntimeError(f"loaded image config differs: {observed} != {image_id}")
        env.update(DAYTONA_FILE_SNAPSHOT_BROWSER_IMAGE=image_id,
                   DAYTONA_FILE_SNAPSHOT_EXPECTED_IMAGE_ID=image_id,
                   DAYTONA_FILE_SNAPSHOT_EVIDENCE_DIR=str(evidence / "proof"))
        command = [str(args.test_binary), "-test.run", "^TestFileSnapshotDockerBrowserAndCustody$", "-test.v", "-test.timeout", "4m"]
        with (evidence / "test.log").open("w") as log:
            run(command, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=250)
        (evidence / "receipt.json").write_text(json.dumps({
            "imageConfigId": observed, "testBinarySha256": hashlib.sha256(args.test_binary.read_bytes()).hexdigest(),
            "command": command, "exit": 0, "filesystem": "xfs", "reflink": True,
        }, indent=2) + "\n")
        print(str(evidence), flush=True)
    finally:
        stop(daemon)
        stop(containerd)
        if mounted:
            run(["umount", str(mount)], check=True)
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
