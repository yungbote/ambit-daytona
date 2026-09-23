#!/usr/bin/env python3
"""Build/install the browser from source and archives named by the image lock.

This runs only during image construction. Cargo's committed lock verifies its
crate graph; source and Chrome archives are independently pinned by SHA-256.
"""

import copy
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
TOOLCHAIN_LINEAGE = MATERIALIZER_LINEAGE.parent
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


def toolchain_update(lock, source, lineage=TOOLCHAIN_LINEAGE):
    """An inherited build may change Debian pins, never unrelated toolchains."""
    parent_bytes = (lineage / "toolchains.lock.json").read_bytes()
    source_bytes = source.read_bytes()
    for content, expected in (
        (parent_bytes, lock["toolchains"]["parentLockSha256"]),
        (source_bytes, lock["toolchains"]["sourceLockSha256"]),
    ):
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("Workspace toolchain lock differs from its exact binding")
    parent, target = json.loads(parent_bytes), json.loads(source_bytes)
    before, after = copy.deepcopy(parent), copy.deepcopy(target)
    old_packages = before["debian"].pop("packages")
    new_packages = after["debian"].pop("packages")
    if before != after or not old_packages.keys() <= new_packages.keys():
        raise ValueError("Inherited workspace update may only add or upgrade Debian pins")
    delta = {name: version for name, version in new_packages.items() if old_packages.get(name) != version}
    packages = dict(lock["debianPackages"])
    for name, version in delta.items():
        if name in packages and packages[name] != version:
            raise ValueError(f"Conflicting workspace and browser package pins: {name}")
        packages[name] = version
    return {**lock, "debianPackages": packages}, target


def install_npm(lock, scratch, inputs=Path("/inputs")):
    """Replace the inherited distribution as one verified, offline npm install."""
    archive = verify_input(lock["npm"], inputs)
    node = lock["node"]
    prefix = Path(node["root"]).parent
    npm_root = Path(node["root"]) / "node_modules/npm"
    # The image owner replaces the active bundle, not a second PATH candidate.
    for command in ("npm", "npx"):
        executable = shutil.which(command)
        if not executable or not Path(executable).resolve().is_relative_to(npm_root):
            raise ValueError(f"Inherited {command} does not belong to the declared Node prefix")
    subprocess.run([
        "npm", "install", "--global", "--prefix", str(prefix), "--offline",
        "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(scratch / "npm-cache"),
        str(archive),
    ], check=True)
    descriptor = json.loads((npm_root / "package.json").read_text())
    if descriptor["version"] != node["packages"]["npm"]:
        raise ValueError("Installed npm distribution differs from the lock")
    for command in ("npm", "npx"):
        executable = shutil.which(command)
        if not executable or Path(executable).resolve() != (npm_root / "bin" / f"{command}-cli.js").resolve():
            raise ValueError(f"Installed {command} does not resolve to the replaced npm bundle")
        observed = subprocess.check_output([command, "--version"], text=True).strip()
        if observed != descriptor["version"]:
            raise ValueError(f"Installed {command} version differs from the lock")


def install_playwright(lock, scratch, inputs=Path("/inputs")):
    """Install the pinned client offline; Chrome remains owned by this image."""
    artifact = lock["playwright"]
    archive = verify_input(artifact, inputs)
    node = lock["node"]
    version = node["packages"]["playwright-core"]
    if artifact["version"] != version:
        raise ValueError("Playwright package and library inventory versions differ")
    prefix = Path(node["root"]).parent
    subprocess.run([
        "npm", "install", "--global", "--prefix", str(prefix), "--offline",
        "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(scratch / "npm-cache"),
        str(archive),
    ], check=True)
    package = Path(node["root"]) / "node_modules/playwright-core"
    descriptor = json.loads((package / "package.json").read_text())
    if descriptor.get("name") != "playwright-core" or descriptor.get("version") != version:
        raise ValueError("Installed Playwright differs from the lock")
    for required in ("index.mjs", "index.js", "LICENSE", "NOTICE", "ThirdPartyNotices.txt"):
        if not (package / required).is_file():
            raise ValueError(f"Installed Playwright is missing {required}")


def record_toolchain_update(source, target, lineage=TOOLCHAIN_LINEAGE):
    for name, expected in target["debian"]["packages"].items():
        observed = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", name], text=True)
        if observed != expected:
            raise ValueError(f"Workspace package version mismatch: {name}")
    if source.read_bytes() == (lineage / "toolchains.lock.json").read_bytes():
        # A browser-component update can retain its already qualified parent
        # toolchain verbatim. Preserve that parent's history and observation.
        return
    # Preserve the parent's observation with the parent's exact input lock.
    historical = lineage / "parent-toolchains"
    historical.mkdir()
    for name in ("toolchains.lock.json", "installed-dpkg.lock"):
        shutil.copy2(lineage / name, historical / name)
    shutil.copyfile(source, lineage / "toolchains.lock.json")
    observed = subprocess.check_output(["dpkg-query", "-W", "-f=${binary:Package}=${Version}\n"], text=True)
    (lineage / "installed-dpkg.lock").write_text("\n".join(sorted(observed.splitlines())) + "\n")
    for name in ("toolchains.lock.json", "installed-dpkg.lock"):
        (lineage / name).chmod(0o444)


def prepare_browser_component(root, mode, lock):
    """Replace owned build outputs and retain an exactly pinned Chrome parent."""
    if mode not in ("driver", "chrome"):
        raise ValueError("Unknown browser install mode")
    previous_lock = root / "browser.lock.json"
    previous_bytes = previous_lock.read_bytes() if previous_lock.is_file() else None
    previous = json.loads(previous_bytes) if previous_bytes is not None else None
    reuse_chrome = mode == "chrome" and previous is not None and previous.get("chrome") == lock["chrome"]
    # This is an image build, replacing exactly the browser component's owned
    # files. Reusing an admitted full workspace must not retain stale driver or
    # license files, nor copy its unchanged Chrome distribution into a new layer.
    if mode == "driver" and root.exists():
        shutil.rmtree(root)
    elif mode == "chrome":
        for owned in ("bin", "runtime", "licenses"):
            if (root / owned).exists():
                shutil.rmtree(root / owned)
        (root / "Cargo.lock").unlink(missing_ok=True)
        if not reuse_chrome and (root / "chrome").exists():
            shutil.rmtree(root / "chrome")
    root.mkdir(parents=True, exist_ok=True)
    if mode == "chrome" and previous_bytes is not None:
        (root / "parent-browser.lock.json").write_bytes(previous_bytes)
    return reuse_chrome


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
    reuse_chrome = prepare_browser_component(root, mode, lock)
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
            runtime_root = root / "runtime"
            runtime_root.mkdir()
            shutil.copy2(source_root / "cli/runtime/playwright-runner.mjs", runtime_root / "playwright-runner.mjs")
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
            source_toolchains = Path("/source/toolchains.lock.json")
            debian, target_toolchains = toolchain_update(lock, source_toolchains)
            install_debian_packages(debian, scratch)
            install_npm(lock, scratch)
            install_playwright(lock, scratch)
            record_toolchain_update(source_toolchains, target_toolchains)
            if not reuse_chrome:
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
