#!/usr/bin/env python3
"""Derive installed command descriptors from the workspace's locked inputs.

This is build evidence, not a permission registry or a runtime capability grant.
Only public commands that actually resolve on the workspace PATH are emitted.
"""

import hashlib
from importlib import metadata
import json
from pathlib import Path
import re
import shutil
import subprocess


LINEAGE = Path("/opt/ambit/runtime-base/workspace/lineage")


def main():
    lock_bytes = (LINEAGE / "toolchains.lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    programs = {}

    def add(name, version, path=None, help_args=None):
        selected = shutil.which(name)
        if not selected or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", name):
            return
        if path is not None and Path(selected).resolve() != Path(path).resolve():
            return
        value = {"name": name, "version": version, "helpArgv": [name, *(help_args or ["--help"])]}
        previous = programs.get(name)
        if previous is not None and previous != value:
            raise ValueError(f"Conflicting locked command owners: {name}")
        programs[name] = value

    # The existing conformance checks prove the requirement lock and installed
    # distribution set agree. Console-script metadata supplies real CLI names;
    # a Python import without a console entrypoint is not invented as a command.
    requirement_bytes = (LINEAGE / lock["python"]["requirements"]).read_bytes()
    if hashlib.sha256(requirement_bytes).hexdigest() != lock["python"]["requirementsSha256"]:
        raise ValueError("Workspace Python requirement lock has changed")
    normalize = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    pinned = {normalize(name): version for name, version in re.findall(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)", requirement_bytes.decode(), re.MULTILINE)}
    for distribution in metadata.distributions():
        name = normalize(distribution.metadata["Name"])
        if name not in pinned:
            continue
        if distribution.version != pinned[name]:
            raise ValueError(f"Workspace distribution differs from lock: {name}")
        for entry in distribution.entry_points:
            if entry.group == "console_scripts":
                add(entry.name, distribution.version, Path(lock["python"]["venv"]) / "bin" / entry.name)

    node_root = Path(lock["node"]["root"])
    for package, version in lock["node"]["packages"].items():
        package_root = node_root / "node_modules" / package
        descriptor = json.loads((package_root / "package.json").read_text())
        if descriptor["version"] != version:
            raise ValueError(f"Workspace Node package differs from lock: {package}")
        bins = descriptor.get("bin", {})
        if isinstance(bins, str):
            bins = {package.rsplit("/", 1)[-1]: bins}
        for name, path in bins.items():
            add(name, version, package_root / path)

    # Package ownership provides command versions without guessing from names
    # or promoting every package file to an executable capability.
    for package, version in lock["debian"]["packages"].items():
        installed = subprocess.check_output(["dpkg-query", "-W", "-f=${Version}", package], text=True)
        if installed != version:
            raise ValueError(f"Workspace Debian package differs from lock: {package}")
        paths = subprocess.check_output(["dpkg-query", "-L", package], text=True).splitlines()
        for path_text in paths:
            path = Path(path_text)
            if str(path.parent) in ("/bin", "/usr/bin", "/usr/sbin", "/sbin") and path.is_file():
                add(path.name, version, path)

    for archive in lock["archives"]:
        root = archive.get("installRoot")
        if root:
            for path in (Path(root) / "bin").glob("*"):
                if path.is_file():
                    add(path.name, archive["version"], path)
        elif archive["kind"] == "rustup-init":
            for path in (Path(archive["cargoHome"]) / "bin").glob("*"):
                if path.is_file():
                    if path.name != "rustup":
                        installed = subprocess.run(
                            ["rustup", "which", path.name],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        if installed.returncode != 0:
                            # Rustup creates shims for optional components that
                            # are not installed. A shim is not a usable command.
                            continue
                    add(path.name, archive["version"] if path.name == "rustup" else archive["toolchain"], path)

    # Language entrypoints are supplied by the locked base or the qualified venv.
    add("python3", lock["python"]["interpreterVersion"], Path(lock["python"]["venv"]) / "bin/python3")
    add("node", lock["base"]["invariants"]["node"])
    browser = json.loads(Path("/opt/ambit/browser/browser.lock.json").read_text())
    add("agent-browser", browser["agentBrowser"]["version"], "/usr/local/bin/agent-browser")
    print(json.dumps({"schema": "ambit.workspace-executable-observation/v1", "toolchainLockSha256": hashlib.sha256(lock_bytes).hexdigest(), "executables": sorted(programs.values(), key=lambda value: value["name"])}, indent=2))


if __name__ == "__main__":
    main()
