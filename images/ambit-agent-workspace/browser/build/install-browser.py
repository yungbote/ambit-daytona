#!/usr/bin/env python3
"""Build/install the browser from source and archives named by the image lock.

This runs only during image construction. Cargo's committed lock verifies its
crate graph; source and Chrome archives are independently pinned by SHA-256.
"""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def verify_input(artifact):
    name = artifact["archiveName"]
    if Path(name).name != name:
        raise ValueError("Browser archive must be one input filename")
    source = Path("/inputs") / name
    with source.open("rb") as content:
        actual = hashlib.file_digest(content, "sha256").hexdigest()
    if actual != artifact["sha256"]:
        raise ValueError(f"Browser input checksum mismatch: {name}")
    return source


def main():
    mode, lock_path, base_image = sys.argv[1:]
    lock = json.loads(Path(lock_path).read_text())
    if lock["schema"] != "ambit.workspace-browser-lock/v1":
        raise ValueError("Unknown browser image lock")
    if base_image != lock["baseImage"]:
        raise ValueError("Browser build must retain the exact locked workspace parent")
    helper = lock["inheritedMaterializer"]
    with Path(helper["path"]).open("rb") as binary:
        if hashlib.file_digest(binary, "sha256").hexdigest() != helper["sha256"]:
            raise ValueError("Inherited workspace materializer differs from the locked base")
    root = Path("/opt/ambit/browser")
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ambit-browser-build-") as temporary:
        scratch = Path(temporary)
        if mode == "driver":
            source = lock["agentBrowser"]
            archive = verify_input(source)
            extracted = scratch / "source"
            extracted.mkdir()
            with tarfile.open(archive) as bundle:
                bundle.extractall(extracted, filter="data")
            source_root, = extracted.iterdir()
            manifest = source_root / "cli/Cargo.toml"
            subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path", str(manifest)], check=True)
            (root / "bin").mkdir()
            shutil.copy2(source_root / "cli/target/release/agent-browser", root / "bin/agent-browser")
            license_root = root / "licenses"
            license_root.mkdir()
            shutil.copy2(source_root / "LICENSE", license_root / "agent-browser-LICENSE")
            for license_file in (source_root / "cli/src/native/a11y").glob("LICENSE*"):
                shutil.copy2(license_file, license_root / license_file.name)
            shutil.copy2(source_root / "cli/Cargo.lock", root / "Cargo.lock")
            observed = subprocess.check_output([str(root / "bin/agent-browser"), "--version"], text=True).strip()
            if observed != f"agent-browser {source['version']}":
                raise ValueError(f"Unexpected driver version: {observed}")
        elif mode == "chrome":
            packages = lock["debianPackages"]
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", *[f"{name}={version}" for name, version in packages.items()]], check=True)
            for name, expected in packages.items():
                observed = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", name], text=True)
                if observed != expected:
                    raise ValueError(f"Browser package version mismatch: {name}")
            archive = verify_input(lock["chrome"])
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(scratch)
            chrome_root = scratch / "chrome-linux64"
            shutil.move(str(chrome_root), root / "chrome")
            # ZIP entries do not retain Unix executable modes through zipfile.
            for name in ("chrome", "chrome_crashpad_handler", "chrome_sandbox"):
                (root / "chrome" / name).chmod(0o755)
            observed = subprocess.check_output([str(root / "chrome/chrome"), "--version"], text=True).strip()
            if observed != f"Google Chrome for Testing {lock['chrome']['version']}":
                raise ValueError(f"Unexpected Chrome version: {observed}")
            installed = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], text=True)
            (root / "installed-dpkg.lock").write_text("\n".join(sorted(installed.splitlines())) + "\n")
            shutil.rmtree("/var/lib/apt/lists")
        else:
            raise ValueError("Unknown browser install mode")
    shutil.copy2(lock_path, root / "browser.lock.json")


if __name__ == "__main__":
    main()
