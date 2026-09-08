#!/usr/bin/env python3
"""Derive installed command and library descriptors from locked workspace inputs.

This is build evidence, not a permission registry or a runtime capability grant.
Commands must resolve on PATH. Libraries retain their actual environment owner.
"""

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


LINEAGE = Path("/opt/ambit/runtime-base/workspace/lineage")
BROWSER_LOCK = Path("/opt/ambit/browser/browser.lock.json")


def add_program(programs, name, version, path=None, help_argv=None, required=False):
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", name
    ):
        if required:
            raise ValueError(f"Invalid locked command name: {name!r}")
        return
    argv = [name, "--help"] if help_argv is None else help_argv
    if not isinstance(version, str) or not version.strip():
        raise ValueError(f"Locked command version is missing: {name}")
    if (
        not isinstance(argv, list)
        or not argv
        or argv[0] != name
        or any(not isinstance(value, str) or "\0" in value for value in argv)
    ):
        raise ValueError(f"Invalid locked command help argv: {name}")
    selected = shutil.which(name)
    if not selected or (
        path is not None and Path(selected).resolve() != Path(path).resolve()
    ):
        if required:
            raise ValueError(
                f"Locked component command is not available on PATH: {name}"
            )
        return
    value = {"name": name, "version": version, "helpArgv": argv}
    previous = programs.get(name)
    if previous is not None and previous != value:
        raise ValueError(f"Conflicting locked command owners: {name}")
    programs[name] = value


def add_libraries(libraries, interpreter, root, packages):
    if not packages:
        return
    if (
        not interpreter
        or not Path(interpreter).is_file()
        or not os.access(interpreter, os.X_OK)
    ):
        raise ValueError(
            f"Locked library environment has no executable interpreter: {root}"
        )
    identity = (str(Path(interpreter).absolute()), str(root.resolve()))
    group = libraries.setdefault(identity, {})
    for name, version in packages.items():
        if name in group and group[name] != version:
            raise ValueError(f"Conflicting locked library owners: {name} in {root}")
        group[name] = version


def collect_python(programs, libraries, python, lock_root):
    # Read the locked environment itself, even when another interpreter runs
    # this collector. Only console entrypoints can supply command descriptors.
    requirement_bytes = (lock_root / python["requirements"]).read_bytes()
    if (
        hashlib.sha256(requirement_bytes).hexdigest()
        != python["requirementsSha256"]
    ):
        raise ValueError("Workspace Python requirement lock has changed")
    venv = (lock_root / python["venv"]).resolve()
    sites = sorted(venv.glob("lib/python*/site-packages"))
    if not sites:
        raise ValueError(f"Locked Python environment has no site-packages: {venv}")
    distributions = metadata.distributions(path=[str(path) for path in sites])

    def normalize(name):
        return re.sub(r"[-_.]+", "-", name).lower()

    pinned = {}
    requirements = re.findall(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?==([^\s;\\]+)",
        requirement_bytes.decode(),
        re.MULTILINE,
    )
    for name, version in requirements:
        name = normalize(name)
        if name in pinned and pinned[name] != version:
            raise ValueError(f"Conflicting Python requirement pins: {name}")
        pinned[name] = version
    installed = {}
    for distribution in distributions:
        name = normalize(distribution.metadata["Name"])
        if name not in pinned:
            continue
        if distribution.version != pinned[name]:
            raise ValueError(f"Workspace distribution differs from lock: {name}")
        installed[name] = distribution.version
        for entry in distribution.entry_points:
            if entry.group == "console_scripts":
                add_program(
                    programs, entry.name, distribution.version,
                    venv / "bin" / entry.name,
                )
        # Wheels may ship native executables as installed scripts without a
        # Python console entry point. RECORD identifies the owning distribution;
        # only executable files in this environment's bin directory qualify.
        for record in distribution.files or ():
            installed_path = Path(distribution.locate_file(record))
            if installed_path.parent.resolve() != (venv / "bin").resolve():
                continue
            if installed_path.is_file() and os.access(installed_path, os.X_OK):
                add_program(
                    programs, installed_path.name, distribution.version,
                    installed_path,
                )
    if missing := pinned.keys() - installed.keys():
        raise ValueError(
            f"Locked Python distributions are not installed: {', '.join(sorted(missing))}"
        )
    add_libraries(libraries, venv / "bin/python3", venv, installed)


def collect_node(programs, libraries, node, lock_root):
    node_root = (lock_root / node["root"]).resolve()
    installed = {}
    for package, version in node["packages"].items():
        package_root = node_root / "node_modules" / package
        descriptor = json.loads((package_root / "package.json").read_text())
        if descriptor["version"] != version:
            raise ValueError(f"Workspace Node package differs from lock: {package}")
        installed[package] = descriptor["version"]
        bins = descriptor.get("bin", {})
        if isinstance(bins, str):
            bins = {package.rsplit("/", 1)[-1]: bins}
        for name, path in bins.items():
            add_program(programs, name, version, package_root / path)
    add_libraries(libraries, shutil.which("node"), node_root, installed)


def collect_debian(programs, packages):
    # Package ownership provides command versions without guessing from names
    # or promoting every package file to an executable capability.
    for package, version in packages.items():
        installed = subprocess.check_output(
            ["dpkg-query", "-W", "-f=${Version}", package], text=True
        )
        if installed != version:
            raise ValueError(f"Workspace Debian package differs from lock: {package}")
        paths = subprocess.check_output(
            ["dpkg-query", "-L", package], text=True
        ).splitlines()
        for path_text in paths:
            path = Path(path_text)
            if (
                str(path.parent) in ("/bin", "/usr/bin", "/usr/sbin", "/sbin")
                and path.is_file()
            ):
                add_program(programs, path.name, version, path)


def collect_executables(component_locks=()):
    lock_bytes = (LINEAGE / "toolchains.lock.json").read_bytes()
    lock = json.loads(lock_bytes)
    programs = {}
    libraries = {}
    collect_python(programs, libraries, lock["python"], LINEAGE)
    collect_node(programs, libraries, lock["node"], LINEAGE)
    collect_debian(programs, lock["debian"]["packages"])
    for archive in lock["archives"]:
        root = archive.get("installRoot")
        if root:
            for path in (Path(root) / "bin").glob("*"):
                if path.is_file():
                    add_program(programs, path.name, archive["version"], path)
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
                    add_program(
                        programs, path.name,
                        archive["version"] if path.name == "rustup" else archive["toolchain"],
                        path,
                    )

    # Language entrypoints are supplied by the locked base or the qualified venv.
    add_program(
        programs, "python3", lock["python"]["interpreterVersion"],
        Path(lock["python"]["venv"]) / "bin/python3",
    )
    add_program(programs, "node", lock["base"]["invariants"]["node"])
    if BROWSER_LOCK.exists():
        browser = json.loads(BROWSER_LOCK.read_text())
        add_program(
            programs, "agent-browser", browser["agentBrowser"]["version"],
            "/usr/local/bin/agent-browser",
        )
    for path in component_locks:
        component = json.loads(path.read_text())
        if "python" in component:
            collect_python(programs, libraries, component["python"], path.parent)
        if "node" in component:
            collect_node(programs, libraries, component["node"], path.parent)
        collect_debian(programs, component.get("debianPackages", {}))
        for executable in component.get("executables", []):
            add_program(
                programs, executable["name"], executable["version"],
                help_argv=executable["helpArgv"], required=True,
            )
    return {
        "schema": "ambit.workspace-executable-observation/v1",
        "toolchainLockSha256": hashlib.sha256(lock_bytes).hexdigest(),
        "executables": sorted(programs.values(), key=lambda value: value["name"]),
        "libraries": [
            {
                "interpreter": interpreter,
                "root": root,
                "packages": [
                    {"name": name, "version": version}
                    for name, version in sorted(packages.items())
                ],
            }
            for (interpreter, root), packages in sorted(libraries.items())
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--component-lock", type=Path, action="append", default=[],
        help="Installed component lock; repeat for additional components",
    )
    options = parser.parse_args(argv)
    print(json.dumps(collect_executables(options.component_lock), indent=2))


if __name__ == "__main__":
    main()
