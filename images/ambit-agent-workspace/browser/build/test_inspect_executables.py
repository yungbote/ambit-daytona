import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "inspect_executables", Path(__file__).with_name("inspect-executables.py")
)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.lineage = self.root / "lineage"
        self.lineage.mkdir()
        python = self.python_environment(
            self.lineage, {"base-library": "1.0"}, {"base-cli": "base-library"}
        )
        python["venv"] = str(self.lineage / "python")
        python["interpreterVersion"] = "Python 3.13.5"
        node = self.node_environment(self.lineage, {"base-node": ("2.0", None)})
        self.executable(self.bin / "node")
        self.lock = {
            "python": python,
            "node": node,
            "debian": {"packages": {}},
            "archives": [],
            "base": {"invariants": {"node": "22.14.0"}},
        }
        (self.lineage / "toolchains.lock.json").write_text(json.dumps(self.lock))
        self.addCleanup(patch.stopall)
        patch.object(inventory, "LINEAGE", self.lineage).start()
        patch.object(inventory, "BROWSER_LOCK", self.root / "absent-browser.json").start()
        patch.dict(os.environ, {"PATH": f"{self.bin}:{self.lineage / 'python/bin'}"}).start()

    def executable(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o755)

    def python_environment(self, root, packages, commands):
        venv = root / "python"
        self.executable(venv / "bin/python3")
        for name, version in packages.items():
            metadata = venv / "lib/python3.13/site-packages" / f"{name}-{version}.dist-info"
            metadata.mkdir(parents=True)
            (metadata / "METADATA").write_text(
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            )
            entries = [command for command, owner in commands.items() if owner == name]
            if entries:
                (metadata / "entry_points.txt").write_text(
                    "[console_scripts]\n" + "".join(f"{entry} = fixture:main\n" for entry in entries)
                )
                for entry in entries:
                    target = venv / "bin" / entry
                    self.executable(target)
                    (self.bin / entry).symlink_to(target)
        requirements = root / "requirements.txt"
        requirements.write_text("".join(f"{name}=={version}\n" for name, version in packages.items()))
        return {
            "venv": "python",
            "requirements": "requirements.txt",
            "requirementsSha256": hashlib.sha256(requirements.read_bytes()).hexdigest(),
        }

    def node_environment(self, root, packages):
        node_root = root / "node"
        for name, (version, command) in packages.items():
            package_root = node_root / "node_modules" / name
            package_root.mkdir(parents=True)
            descriptor = {"name": name, "version": version}
            if command:
                target = package_root / "cli.js"
                self.executable(target)
                descriptor["bin"] = {command: "cli.js"}
                (self.bin / command).symlink_to(target)
            (package_root / "package.json").write_text(json.dumps(descriptor))
        return {"root": "node", "packages": {name: value[0] for name, value in packages.items()}}

    def component(self, root, value):
        root.mkdir(parents=True, exist_ok=True)
        path = root / "component.lock.json"
        path.write_text(json.dumps(value))
        return path

    def test_base_libraries_do_not_become_commands_without_entrypoints(self):
        observed = inventory.collect_executables()
        self.assertEqual(
            [item["name"] for item in observed["executables"]],
            ["base-cli", "node", "python3"],
        )
        packages = {p["name"] for g in observed["libraries"] for p in g["packages"]}
        self.assertEqual(packages, {"base-library", "base-node"})

    def test_component_python_uses_its_own_metadata_and_preserves_cli_symlinks(self):
        root = self.root / "file-tools"
        python = self.python_environment(
            root,
            {"MarkItDown": "0.1.5", "image-library": "3.0"},
            {"markitdown": "MarkItDown"},
        )
        # Extras belong to the requirement syntax, not the installed project name.
        requirements = root / "requirements.txt"
        requirements.write_text("MarkItDown[all]==0.1.5\nimage-library==3.0\n")
        python["requirementsSha256"] = hashlib.sha256(requirements.read_bytes()).hexdigest()
        self.executable(self.bin / "tika")
        path = self.component(root, {
            "python": python,
            "executables": [{"name": "tika", "version": "3.2.3", "helpArgv": ["tika", "--help"]}],
        })
        observed = inventory.collect_executables([path])
        programs = {item["name"]: item for item in observed["executables"]}
        self.assertEqual(programs["markitdown"]["version"], "0.1.5")
        self.assertEqual(programs["tika"]["helpArgv"], ["tika", "--help"])
        self.assertNotIn("image-library", programs)
        group = next(g for g in observed["libraries"] if g["root"] == str(root / "python"))
        self.assertEqual(group["interpreter"], str(root / "python/bin/python3"))
        self.assertEqual(group["packages"], [
            {"name": "image-library", "version": "3.0"},
            {"name": "markitdown", "version": "0.1.5"},
        ])

    def test_multiple_component_locks_and_repeated_environment_are_deterministic(self):
        first = self.component(self.root / "first", {"executables": []})
        root = self.root / "second"
        node = self.node_environment(root, {
            "@scope/renderer": ("1.2", "render-file"),
            "@scope/library": ("4.0", None),
        })
        second = self.component(root, {"node": node})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            inventory.main([
                "--component-lock", str(first),
                "--component-lock", str(second),
                "--component-lock", str(second),
            ])
        observed = json.loads(output.getvalue())
        self.assertEqual(observed, inventory.collect_executables([second, first]))
        self.assertIn("render-file", [item["name"] for item in observed["executables"]])
        self.assertNotIn("@scope/library", [item["name"] for item in observed["executables"]])
        self.assertEqual(len(observed["libraries"]), 3)

    def test_separate_python_environments_retain_different_library_versions(self):
        root = self.root / "component"
        python = self.python_environment(root, {"base-library": "9.0"}, {})
        path = self.component(root, {"python": python})
        observed = inventory.collect_executables([path])
        owners = {
            group["root"]: package["version"]
            for group in observed["libraries"]
            for package in group["packages"]
            if package["name"] == "base-library"
        }
        self.assertEqual(owners, {
            str(self.lineage / "python"): "1.0",
            str(root / "python"): "9.0",
        })

    def test_changed_requirement_bytes_are_rejected(self):
        (self.lineage / "requirements.txt").write_text("base-library==9.0\n")
        with self.assertRaisesRegex(ValueError, "requirement lock has changed"):
            inventory.collect_executables()

    def test_missing_locked_distribution_is_rejected(self):
        metadata = self.lineage / "python/lib/python3.13/site-packages/base-library-1.0.dist-info/METADATA"
        metadata.write_text("Metadata-Version: 2.1\nName: another-library\nVersion: 1.0\n")
        with self.assertRaisesRegex(ValueError, "not installed: base-library"):
            inventory.collect_executables()

    def test_installed_distribution_version_must_match_the_lock(self):
        metadata = self.lineage / "python/lib/python3.13/site-packages/base-library-1.0.dist-info/METADATA"
        metadata.write_text("Metadata-Version: 2.1\nName: base-library\nVersion: 9.0\n")
        with self.assertRaisesRegex(ValueError, "distribution differs from lock"):
            inventory.collect_executables()

    def test_explicit_wrapper_must_resolve_on_path(self):
        path = self.component(self.root / "component", {
            "executables": [{"name": "missing-wrapper", "version": "1", "helpArgv": ["missing-wrapper", "--help"]}],
        })
        with self.assertRaisesRegex(ValueError, "not available on PATH"):
            inventory.collect_executables([path])

    def test_conflicting_command_owners_are_rejected(self):
        path = self.component(self.root / "component", {
            "executables": [{"name": "base-cli", "version": "9", "helpArgv": ["base-cli", "--help"]}],
        })
        with self.assertRaisesRegex(ValueError, "Conflicting locked command owners"):
            inventory.collect_executables([path])

    def test_help_argv_must_address_its_declared_command(self):
        with self.assertRaisesRegex(ValueError, "help argv"):
            inventory.add_program({}, "node", "22", help_argv=["sh", "-c", "node --help"])

    def test_debian_component_uses_installed_package_file_ownership(self):
        programs = {}
        # Valid package commands outside the descriptor name grammar, such as
        # coreutils' `[`, must not invalidate the rest of a component inventory.
        with patch.object(
            inventory.subprocess, "check_output",
            side_effect=["1.0", "/usr/bin/printf\n/usr/bin/[\n"],
        ), patch.object(
            inventory.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}",
        ):
            inventory.collect_debian(programs, {"example-utils": "1.0"})
        self.assertEqual(programs["printf"], {
            "name": "printf", "version": "1.0", "helpArgv": ["printf", "--help"],
        })
        self.assertNotIn("[", programs)


if __name__ == "__main__":
    unittest.main()
