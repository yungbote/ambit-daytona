#!/usr/bin/env python3
"""Build/install the browser from source and archives named by the image lock.

This runs only during image construction. Cargo's committed lock verifies its
crate graph; source and Chrome archives are independently pinned by SHA-256.
"""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

MATERIALIZER_LINEAGE = Path("/opt/ambit/runtime-base/workspace/lineage/materializer")
MATERIALIZER_BUILDER = "docker.io/library/golang@sha256:40dfc169bd5ad8a8617e49c8ead7fe16c6873e79d6937539e9c2e5947b7984ef"


def verify_input(artifact, inputs=Path("/inputs")):
    name = artifact["archiveName"]
    if Path(name).name != name:
        raise ValueError("Browser archive must be one input filename")
    source = inputs / name
    with source.open("rb") as content:
        actual = hashlib.file_digest(content, "sha256").hexdigest()
    if actual != artifact["sha256"]:
        raise ValueError(f"Browser input checksum mismatch: {name}")
    return source


def read_materializer_lock(path, binding):
    content = path.read_bytes()
    if hashlib.sha256(content).hexdigest() != binding["buildLockSha256"]:
        raise ValueError("Materializer build lock differs from the source binding")
    lock = json.loads(content)
    if (
        lock["schema"] != "ambit.atomic-materializer-build-lock/v1"
        or lock["ownership"]["repository"] != binding["repository"]
        or lock["ownership"]["treePath"] != binding["sourcePath"]
        or lock["builderImage"] != MATERIALIZER_BUILDER
        or lock["goVersion"] != "1.25.13"
        or lock["platform"] != "linux/amd64"
        or lock["build"] != {
            "cgoEnabled": False,
            "network": "none_after_module_acquisition",
            "flags": ["-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid="],
        }
    ):
        raise ValueError("Materializer declaration differs from this build recipe")
    return lock


def prepare_materializer_source(binding, destination, inputs=Path("/inputs")):
    """Validate the backend-owned source input before the Go build consumes it."""
    relative = PurePosixPath(binding["sourcePath"])
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("Materializer source must be inside its backend archive")
    archive = verify_input(binding, inputs)
    with tempfile.TemporaryDirectory(prefix="ambit-materializer-source-") as temporary:
        extracted = Path(temporary)
        with tarfile.open(archive) as bundle:
            if any(not (member.isfile() or member.isdir()) for member in bundle.getmembers()):
                raise ValueError("Materializer source archive must contain regular files and directories")
            bundle.extractall(extracted, filter="data")
        source = extracted / relative
        lock = read_materializer_lock(source / "materializer.lock.json", binding)
        for name, expected in lock["sourceSha256"].items():
            if Path(name).name != name or hashlib.sha256((source / name).read_bytes()).hexdigest() != expected:
                raise ValueError("Materializer source differs from its build lock")
        binary_manifest = f"{lock['binary']['sha256']}  /out/ambit-atomic-materialize\n"
        if (source / "binary.sha256").read_text() != binary_manifest:
            raise ValueError("Materializer binary manifest differs from its build lock")
        shutil.copytree(source, destination)


def verify_materializer_install(binding, lineage=MATERIALIZER_LINEAGE):
    lock = read_materializer_lock(lineage / "materializer.lock.json", binding)
    expected = lock["binary"]
    executable = Path(expected["installedPath"])
    metadata = executable.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o555
        or metadata.st_uid != 0
        or metadata.st_size != expected["bytes"]
        or hashlib.sha256(executable.read_bytes()).hexdigest() != expected["sha256"]
    ):
        raise ValueError("Installed materializer differs from its declared source build")


def install_debian_packages(lock, scratch):
    """Resolve the locked packages only against authenticated, frozen indexes.

    APT still owns signature, index and package verification. Temporary APT
    paths leave the inherited workspace's runtime package sources unchanged.
    """
    snapshots = lock["debianSnapshots"]
    packages = lock["debianPackages"]
    if not snapshots or not packages:
        raise ValueError("Browser Debian inputs require snapshots and package versions")
    entries = []
    for source in snapshots:
        if not re.fullmatch(
            r"https://snapshot\.debian\.org/archive/debian(?:-security)?/[0-9]{8}T[0-9]{6}Z/",
            source["snapshot"],
        ) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", source["suite"]):
            raise ValueError("Browser Debian sources must name exact HTTPS snapshots")
        if not re.fullmatch(r"[0-9a-f]{64}", source["inReleaseSha256"]):
            raise ValueError("Browser Debian snapshot requires an InRelease SHA-256")
        entries.append(
            f"Types: deb\nURIs: {source['snapshot']}\nSuites: {source['suite']}\n"
            "Components: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
            # Expiry is intentionally inapplicable to frozen historical bytes;
            # signature verification and the independent byte pin still apply.
            "Check-Valid-Until: no\n"
        )
    scratch.chmod(0o755)  # APT's unprivileged downloader must traverse this path.
    sources = scratch / "browser.sources"
    sources.write_text("\n".join(entries))
    sources.chmod(0o644)
    sourceparts, lists, cache = (scratch / name for name in ("sourceparts", "lists", "cache"))
    for directory in (sourceparts, lists, cache / "archives"):
        directory.mkdir(parents=True)
    apt = [
        "apt-get",
        "-o", f"Dir::Etc::sourcelist={sources}",
        "-o", f"Dir::Etc::sourceparts={sourceparts}",
        "-o", f"Dir::State::lists={lists}",
        "-o", f"Dir::Cache={cache}",
        "-o", "APT::Update::Error-Mode=any",
    ]
    subprocess.run([*apt, "update"], check=True)
    observed = []
    for path in lists.glob("*_InRelease"):
        with path.open("rb") as release:
            observed.append(hashlib.file_digest(release, "sha256").hexdigest())
    if sorted(observed) != sorted(source["inReleaseSha256"] for source in snapshots):
        raise ValueError("Browser Debian InRelease bytes differ from the locked snapshots")
    subprocess.run([
        *apt, "install", "-y", "--no-install-recommends", "--no-remove",
        *[f"{name}={version}" for name, version in packages.items()],
    ], check=True)
    for name, expected in packages.items():
        installed = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", name], text=True)
        if installed != expected:
            raise ValueError(f"Browser package version mismatch: {name}")


def main():
    mode, lock_path, base_image = sys.argv[1:]
    lock = json.loads(Path(lock_path).read_text())
    if lock["schema"] != "ambit.workspace-browser-lock/v1":
        raise ValueError("Unknown browser image lock")
    if base_image != lock["baseImage"]:
        raise ValueError("Browser build must retain the exact locked workspace parent")
    if mode == "materializer-source":
        prepare_materializer_source(lock["materializer"], Path("/materializer-source"))
        return
    if mode == "materializer":
        verify_materializer_install(lock["materializer"])
        return
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
            cargo = json.loads(subprocess.check_output([
                "cargo", "metadata", "--locked", "--format-version", "1",
                "--manifest-path", str(manifest),
            ], text=True))
            notices = []
            for package in cargo["packages"]:
                package_root = Path(package["manifest_path"]).parent
                destination = license_root / "dependencies" / f"{package['name']}@{package['version']}"
                candidates = [path for path in package_root.iterdir() if path.is_file() and path.name.upper().startswith(("LICENSE", "COPYING", "COPYRIGHT", "NOTICE"))]
                if package.get("license_file"):
                    declared = (package_root / package["license_file"]).resolve()
                    if not declared.is_relative_to(package_root.resolve()):
                        raise ValueError("Crate license must remain inside its source package")
                    candidates.append(declared)
                destination.mkdir(parents=True)
                for license_file in set(candidates):
                    shutil.copy2(license_file, destination / license_file.name)
                notices.append({"name": package["name"], "version": package["version"], "license": package.get("license"), "source": package.get("source"), "noticeFiles": sorted({path.name for path in candidates})})
            (license_root / "dependencies.json").write_text(json.dumps(notices, indent=2) + "\n")
            shutil.copy2(source_root / "cli/Cargo.lock", root / "Cargo.lock")
            observed = subprocess.check_output([str(root / "bin/agent-browser"), "--version"], text=True).strip()
            if observed != f"agent-browser {source['version']}":
                raise ValueError(f"Unexpected driver version: {observed}")
        elif mode == "chrome":
            install_debian_packages(lock, scratch)
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
        else:
            raise ValueError("Unknown browser install mode")
    shutil.copy2(lock_path, root / "browser.lock.json")


if __name__ == "__main__":
    main()
