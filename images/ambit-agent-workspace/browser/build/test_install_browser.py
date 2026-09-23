import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "install_browser", Path(__file__).with_name("install-browser.py")
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class MaterializerSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binding = {
            "repository": "https://github.com/yungbote/m-backend",
            "sourcePath": "runtime/agent-workspace-atomic-materializer",
            "archiveName": "atomic-materializer-source.tar.gz",
        }
        self.binary = b"fixture compiled helper"
        self.lock = {
            "schema": "ambit.atomic-materializer-build-lock/v1",
            "ownership": {"repository": self.binding["repository"], "treePath": self.binding["sourcePath"]},
            "builderImage": installer.MATERIALIZER_BUILDER,
            "goVersion": "1.25.13", "platform": "linux/amd64",
            "build": {
                "cgoEnabled": False, "network": "none_after_module_acquisition",
                "flags": ["-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid="],
            },
            "sourceSha256": {"main.go": hashlib.sha256(b"fixture source").hexdigest()},
            "binary": {
                "installedPath": str(self.root / "helper"), "bytes": len(self.binary),
                "sha256": hashlib.sha256(self.binary).hexdigest(),
            },
        }

    def inputs(self, changed=None):
        lock_bytes = json.dumps(self.lock).encode()
        self.binding["buildLockSha256"] = hashlib.sha256(lock_bytes).hexdigest()
        files = {
            "materializer.lock.json": lock_bytes,
            "main.go": b"fixture source",
            "binary.sha256": f"{self.lock['binary']['sha256']}  /out/ambit-atomic-materialize\n".encode(),
        }
        files.update(changed or {})
        archive = self.root / self.binding["archiveName"]
        with tarfile.open(archive, "w:gz") as package:
            for name, content in files.items():
                entry = tarfile.TarInfo(f"{self.binding['sourcePath']}/{name}")
                entry.size = len(content)
                package.addfile(entry, io.BytesIO(content))
        self.binding["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
        return files

    def test_source_input_is_checked_then_copied_without_running_helper_or_tests(self):
        files = self.inputs()
        destination = self.root / "prepared"
        with patch.object(installer.subprocess, "run") as execute:
            installer.prepare_materializer_source(self.binding, destination, self.root)
        self.assertEqual({path.name: path.read_bytes() for path in destination.iterdir()}, files)
        execute.assert_not_called()

    def test_wrong_archive_or_build_lock_is_refused_before_source_is_available(self):
        for field in ("sha256", "buildLockSha256"):
            with self.subTest(field=field):
                self.inputs()
                self.binding[field] = "0" * 64
                destination = self.root / "refused"
                with self.assertRaises(ValueError):
                    installer.prepare_materializer_source(self.binding, destination, self.root)
                self.assertFalse(destination.exists())

    def test_source_and_binary_manifest_must_match_the_backend_lock(self):
        for changes in ({"main.go": b"different source"}, {"binary.sha256": b"another binary\n"}):
            with self.subTest(changes=changes):
                self.inputs(changes)
                destination = self.root / "refused"
                with self.assertRaises(ValueError):
                    installer.prepare_materializer_source(self.binding, destination, self.root)
                self.assertFalse(destination.exists())

    def test_backend_toolchain_and_recipe_changes_require_a_matching_image_recipe(self):
        for field, value in (("goVersion", "1.26.1"), ("builderImage", "golang:latest"), ("platform", "linux/arm64"), ("build", {})):
            with self.subTest(field=field):
                original = self.lock[field]
                self.lock[field] = value
                self.inputs()
                with self.assertRaisesRegex(ValueError, "differs from this build recipe"):
                    installer.prepare_materializer_source(self.binding, self.root / "refused", self.root)
                self.lock[field] = original

    def test_installed_helper_requires_exact_binary_regular_file_and_immutable_root_ownership(self):
        self.inputs()
        lineage = self.root / "lineage"
        lineage.mkdir()
        (lineage / "materializer.lock.json").write_text(json.dumps(self.lock))
        executable = self.root / "helper"
        executable.write_bytes(self.binary)
        valid = {"st_mode": stat.S_IFREG | 0o555, "st_uid": 0, "st_size": len(self.binary)}
        with patch.object(Path, "lstat", return_value=SimpleNamespace(**valid)):
            installer.verify_materializer_install(self.binding, lineage)
        for change in ({"st_mode": stat.S_IFREG | 0o755}, {"st_mode": stat.S_IFLNK | 0o555}, {"st_uid": 1000}, {"st_size": 1}):
            with self.subTest(change=change), patch.object(Path, "lstat", return_value=SimpleNamespace(**{**valid, **change})):
                with self.assertRaisesRegex(ValueError, "differs from its declared source build"):
                    installer.verify_materializer_install(self.binding, lineage)
        executable.write_bytes(b"x" * len(self.binary))
        with patch.object(Path, "lstat", return_value=SimpleNamespace(**valid)):
            with self.assertRaisesRegex(ValueError, "differs from its declared source build"):
                installer.verify_materializer_install(self.binding, lineage)


class DebianInstallationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.releases = [b"signed Debian release", b"signed security release"]
        self.lock = {
            "debianSnapshots": [
                {
                    "snapshot": "https://snapshot.debian.org/archive/debian/20260909T022729Z/",
                    "suite": "trixie",
                    "inReleaseSha256": hashlib.sha256(self.releases[0]).hexdigest(),
                },
                {
                    "snapshot": "https://snapshot.debian.org/archive/debian-security/20260909T031704Z/",
                    "suite": "trixie-security",
                    "inReleaseSha256": hashlib.sha256(self.releases[1]).hexdigest(),
                },
            ],
            "debianPackages": {"libatk1.0-0t64": "2.56.2-1+deb13u1", "libnss3-tools": "2:3.110-1+deb13u4"},
        }

    def apt(self, command, *, check):
        self.assertTrue(check)
        if command[-1] == "update":
            for index, content in enumerate(self.releases):
                (self.root / "lists" / f"snapshot-{index}_InRelease").write_bytes(content)

    def installed_version(self, command, *, text):
        self.assertTrue(text)
        self.assertEqual(command[:3], ["dpkg-query", "-W", "-f=${Version}"])
        return self.lock["debianPackages"][command[3]]

    def test_signed_snapshot_paths_and_exact_versions_are_shared_by_update_and_install(self):
        with patch.object(installer.subprocess, "run", side_effect=self.apt) as run, patch.object(
            installer.subprocess, "check_output", side_effect=self.installed_version
        ):
            installer.install_debian_packages(self.lock, self.root)
        self.assertEqual(run.call_count, 2)
        update, install = [call.args[0] for call in run.call_args_list]
        self.assertEqual(install[:len(update) - 1], update[:-1])
        self.assertEqual(install[len(update) - 1:], [
            "install", "-y", "--no-install-recommends", "--no-remove",
            "libatk1.0-0t64=2.56.2-1+deb13u1", "libnss3-tools=2:3.110-1+deb13u4",
        ])
        self.assertIn(f"Dir::Etc::sourcelist={self.root}/browser.sources", update)
        self.assertIn(f"Dir::Etc::sourceparts={self.root}/sourceparts", update)
        self.assertEqual(list((self.root / "sourceparts").iterdir()), [])
        self.assertIn(f"Dir::State::lists={self.root}/lists", update)
        self.assertIn(f"Dir::Cache={self.root}/cache", update)
        self.assertIn("APT::Update::Error-Mode=any", update)
        sources = (self.root / "browser.sources").read_text()
        self.assertEqual(sources.count("Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"), 2)
        self.assertEqual(sources.count("Check-Valid-Until: no\n"), 2)
        self.assertNotIn("Trusted:", sources)
        self.assertNotIn("Allow-Insecure:", sources)
        self.assertNotIn("deb.debian.org", sources)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / "browser.sources").stat().st_mode & 0o777, 0o644)

    def test_update_failure_prevents_install_even_if_some_indexes_exist(self):
        def incomplete_update(command, *, check):
            self.apt(command, check=check)
            raise subprocess.CalledProcessError(100, command)

        with patch.object(installer.subprocess, "run", side_effect=incomplete_update) as run, patch.object(
            installer.subprocess, "check_output"
        ) as query:
            with self.assertRaises(subprocess.CalledProcessError):
                installer.install_debian_packages(self.lock, self.root)
        self.assertEqual(run.call_count, 1)
        query.assert_not_called()

    def test_missing_extra_or_changed_authenticated_metadata_cannot_reach_install(self):
        for kind in ("missing", "extra", "changed"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                scratch = Path(temporary)

                def update(command, *, check):
                    for index, content in enumerate(self.releases):
                        (scratch / "lists" / f"snapshot-{index}_InRelease").write_bytes(content)
                    first = scratch / "lists/snapshot-0_InRelease"
                    if kind == "missing":
                        first.unlink()
                    elif kind == "extra":
                        (scratch / "lists/unexpected_InRelease").write_bytes(self.releases[0])
                    else:
                        first.write_bytes(b"different signed metadata")

                with patch.object(installer.subprocess, "run", side_effect=update) as run, patch.object(
                    installer.subprocess, "check_output"
                ) as query:
                    with self.assertRaisesRegex(ValueError, "InRelease bytes differ"):
                        installer.install_debian_packages(self.lock, scratch)
                self.assertEqual(run.call_count, 1)
                query.assert_not_called()

    def test_moving_insecure_or_injected_source_is_rejected_before_apt(self):
        for key, value in (
            ("snapshot", "https://deb.debian.org/debian/"),
            ("snapshot", "https://snapshot.debian.org/archive/debian/latest/"),
            ("snapshot", "http://snapshot.debian.org/archive/debian/20260909T022729Z/"),
            ("snapshot", "https://snapshot.debian.org/archive/debian/20260909T022729Z/?moving=1"),
            ("suite", "trixie\nTrusted: yes"),
            ("inReleaseSha256", "not-a-sha256"),
        ):
            with self.subTest(key=key, value=value), patch.object(installer.subprocess, "run") as run:
                lock = copy.deepcopy(self.lock)
                lock["debianSnapshots"][0][key] = value
                with self.assertRaises(ValueError):
                    installer.install_debian_packages(lock, self.root)
                run.assert_not_called()

    def test_empty_source_or_package_roster_is_rejected(self):
        for key in ("debianSnapshots", "debianPackages"):
            with self.subTest(key=key), patch.object(installer.subprocess, "run") as run:
                lock = {**self.lock, key: [] if key == "debianSnapshots" else {}}
                with self.assertRaisesRegex(ValueError, "require snapshots and package versions"):
                    installer.install_debian_packages(lock, self.root)
                run.assert_not_called()

    def test_installed_version_still_must_match_the_lock(self):
        with patch.object(installer.subprocess, "run", side_effect=self.apt), patch.object(
            installer.subprocess, "check_output", return_value="different-version"
        ):
            with self.assertRaisesRegex(ValueError, "Browser package version mismatch: libatk1.0-0t64"):
                installer.install_debian_packages(self.lock, self.root)


class WorkspaceUpdateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lineage = self.root / "lineage"
        self.lineage.mkdir()
        self.parent = {
            "schema": "fixture", "debian": {"suite": "trixie", "packages": {"retained": "1", "updated": "1"}},
            "python": {"version": "retained"}, "node": {"version": "retained"},
        }
        self.target = copy.deepcopy(self.parent)
        self.target["debian"]["packages"].update({"updated": "2", "added": "3"})
        self.source = self.root / "toolchains.lock.json"
        self.lock = {"debianPackages": {"browser": "4"}, "toolchains": {}}
        self.bind()
        (self.lineage / "installed-dpkg.lock").write_text("parent observation\n")

    def bind(self):
        # Deliberately non-canonical whitespace proves publication copies exact bytes.
        self.source.write_text(json.dumps(self.target, indent=4) + "\n")
        (self.lineage / "toolchains.lock.json").write_text(json.dumps(self.parent))
        self.lock["toolchains"] = {
            "sourceLockSha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
            "parentLockSha256": hashlib.sha256((self.lineage / "toolchains.lock.json").read_bytes()).hexdigest(),
        }

    def test_only_changed_and_added_pins_join_the_existing_apt_transaction(self):
        combined, target = installer.toolchain_update(self.lock, self.source, self.lineage)
        self.assertEqual(combined["debianPackages"], {"browser": "4", "updated": "2", "added": "3"})
        self.assertEqual(target, self.target)
        self.assertEqual(self.lock["debianPackages"], {"browser": "4"})

    def test_each_exact_binding_must_match_before_the_update(self):
        for key in ("sourceLockSha256", "parentLockSha256"):
            with self.subTest(key=key):
                self.bind()
                self.lock["toolchains"][key] = "0" * 64
                with self.assertRaisesRegex(ValueError, "exact binding"):
                    installer.toolchain_update(self.lock, self.source, self.lineage)

    def test_unrelated_changes_or_removed_pins_are_not_hidden_by_reconciliation(self):
        for mutation in (
            lambda x: x["python"].update(version="changed"),
            lambda x: x["node"].update(version="changed"),
            lambda x: x["debian"].update(suite="another"),
            lambda x: x["debian"]["packages"].pop("retained"),
        ):
            with self.subTest(mutation=mutation):
                original = copy.deepcopy(self.target)
                mutation(self.target)
                self.bind()
                with self.assertRaisesRegex(ValueError, "only add or upgrade"):
                    installer.toolchain_update(self.lock, self.source, self.lineage)
                self.target = original

    def test_conflicting_component_pin_is_refused(self):
        self.lock["debianPackages"]["updated"] = "different"
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            installer.toolchain_update(self.lock, self.source, self.lineage)

    def test_final_receipt_preserves_parent_and_copies_exact_source_only_after_all_pins_pass(self):
        prior = (self.lineage / "toolchains.lock.json").read_bytes()
        def query(command, *, text):
            if len(command) == 4:
                return self.target["debian"]["packages"][command[-1]]
            return "updated=2\nadded=3\nbrowser=4\nretained=1\n"
        with patch.object(installer.subprocess, "check_output", side_effect=query):
            installer.record_toolchain_update(self.source, self.target, self.lineage)
        self.assertEqual((self.lineage / "toolchains.lock.json").read_bytes(), self.source.read_bytes())
        self.assertEqual((self.lineage / "parent-toolchains/toolchains.lock.json").read_bytes(), prior)
        self.assertEqual((self.lineage / "parent-toolchains/installed-dpkg.lock").read_text(), "parent observation\n")
        self.assertEqual((self.lineage / "installed-dpkg.lock").read_text(), "added=3\nbrowser=4\nretained=1\nupdated=2\n")
        self.assertEqual((self.lineage / "toolchains.lock.json").stat().st_mode & 0o777, 0o444)

    def test_unchanged_pin_drift_does_not_replace_the_active_lock(self):
        prior = (self.lineage / "toolchains.lock.json").read_bytes()
        with patch.object(installer.subprocess, "check_output", return_value="changed"):
            with self.assertRaisesRegex(ValueError, "Workspace package version mismatch: retained"):
                installer.record_toolchain_update(self.source, self.target, self.lineage)
        self.assertEqual((self.lineage / "toolchains.lock.json").read_bytes(), prior)
        self.assertFalse((self.lineage / "parent-toolchains").exists())

    def test_component_only_update_preserves_existing_toolchain_history(self):
        current = self.source.read_bytes()
        (self.lineage / "toolchains.lock.json").write_bytes(current)
        history = self.lineage / "parent-toolchains"
        history.mkdir()
        (history / "prior").write_text("retained history")
        def query(command, *, text):
            return self.target["debian"]["packages"][command[-1]]
        with patch.object(installer.subprocess, "check_output", side_effect=query):
            installer.record_toolchain_update(self.source, self.target, self.lineage)
        self.assertEqual((self.lineage / "toolchains.lock.json").read_bytes(), current)
        self.assertEqual((self.lineage / "installed-dpkg.lock").read_text(), "parent observation\n")
        self.assertEqual((history / "prior").read_text(), "retained history")


class NpmInstallationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prefix = self.root / "node"
        self.package = self.prefix / "lib/node_modules/npm"
        (self.package / "bin").mkdir(parents=True)
        for name in ("npm", "npx"):
            (self.package / f"bin/{name}-cli.js").write_text("fixture")
        (self.package / "package.json").write_text(json.dumps({"version": "10.9.9"}))
        archive = self.root / "npm.tgz"
        archive.write_bytes(b"fixture archive")
        self.lock = {
            "npm": {"archiveName": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()},
            "node": {"root": str(self.prefix / "lib"), "packages": {"npm": "10.9.9"}},
        }

    def which(self, name):
        return str(self.package / f"bin/{name}-cli.js")

    def test_entire_bundle_replaces_existing_prefix_offline_without_scripts(self):
        with patch.object(installer.shutil, "which", side_effect=self.which), patch.object(
            installer.subprocess, "run"
        ) as run, patch.object(installer.subprocess, "check_output", return_value="10.9.9\n"):
            installer.install_npm(self.lock, self.root, self.root)
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["npm", "install", "--global", "--prefix", str(self.prefix)])
        for option in ("--offline", "--ignore-scripts", "--no-audit", "--no-fund"):
            self.assertIn(option, command)
        self.assertEqual(command[-1], str(self.root / "npm.tgz"))

    def test_archive_or_existing_path_mismatch_cannot_install(self):
        for kind in ("archive", "path"):
            with self.subTest(kind=kind), patch.object(installer.subprocess, "run") as run:
                lock = copy.deepcopy(self.lock)
                if kind == "archive":
                    lock["npm"]["sha256"] = "0" * 64
                with patch.object(installer.shutil, "which", return_value="/another/npm"):
                    with self.assertRaises(ValueError):
                        installer.install_npm(lock, self.root, self.root)
                run.assert_not_called()

    def test_installed_entrypoints_and_versions_must_match(self):
        with patch.object(installer.shutil, "which", side_effect=self.which), patch.object(
            installer.subprocess, "run"
        ), patch.object(installer.subprocess, "check_output", return_value="old\n"):
            with self.assertRaisesRegex(ValueError, "version differs"):
                installer.install_npm(self.lock, self.root, self.root)


class PlaywrightInstallationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.prefix = self.root / "node"
        self.package = self.prefix / "lib/node_modules/playwright-core"
        self.package.mkdir(parents=True)
        for name in ("index.mjs", "index.js", "LICENSE", "NOTICE", "ThirdPartyNotices.txt"):
            (self.package / name).write_text("fixture")
        (self.package / "package.json").write_text(json.dumps({"name": "playwright-core", "version": "1.62.1"}))
        archive = self.root / "playwright-core-1.62.1.tgz"
        archive.write_bytes(b"fixture archive")
        self.lock = {
            "playwright": {"archiveName": archive.name, "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "version": "1.62.1"},
            "node": {"root": str(self.prefix / "lib"), "packages": {"npm": "10.9.9", "playwright-core": "1.62.1"}},
        }

    def test_offline_client_install_uses_existing_node_owner_without_browser_download(self):
        with patch.object(installer.subprocess, "run") as run:
            installer.install_playwright(self.lock, self.root, self.root)
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["npm", "install", "--global", "--prefix", str(self.prefix)])
        for option in ("--offline", "--ignore-scripts", "--no-audit", "--no-fund"):
            self.assertIn(option, command)
        self.assertEqual(command[-1], str(self.root / "playwright-core-1.62.1.tgz"))

    def test_changed_archive_or_disagreeing_inventory_refused_before_install(self):
        for field, value in (("sha256", "0" * 64), ("version", "2.0.0")):
            with self.subTest(field=field), patch.object(installer.subprocess, "run") as run:
                changed = copy.deepcopy(self.lock)
                changed["playwright"][field] = value
                with self.assertRaises(ValueError):
                    installer.install_playwright(changed, self.root, self.root)
                run.assert_not_called()

    def test_installed_version_and_required_runtime_and_licenses_verified(self):
        for missing in ("index.mjs", "LICENSE", "NOTICE", "ThirdPartyNotices.txt"):
            with self.subTest(missing=missing), patch.object(installer.subprocess, "run"):
                file = self.package / missing
                original = file.read_text()
                file.unlink()
                with self.assertRaises(ValueError):
                    installer.install_playwright(self.lock, self.root, self.root)
                file.write_text(original)
        (self.package / "package.json").write_text(json.dumps({"name": "playwright-core", "version": "1.61.1"}))
        with patch.object(installer.subprocess, "run"), self.assertRaises(ValueError):
            installer.install_playwright(self.lock, self.root, self.root)


class BrowserComponentUpdateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.root = self.parent / "browser"
        self.root.mkdir()
        self.lock = {"chrome": {"version": "152.0.7977.82", "sha256": "exact-archive"}}
        self.previous = json.dumps(self.lock).encode()
        (self.root / "browser.lock.json").write_bytes(self.previous)
        for directory in ("chrome", "bin", "runtime", "licenses"):
            (self.root / directory).mkdir()
            (self.root / directory / "old-file").write_text(directory)
        (self.root / "Cargo.lock").write_text("old dependency graph")
        (self.parent / "unrelated-toolchain").write_text("preserved")

    def test_exact_chrome_parent_reused_while_obsolete_driver_files_are_pruned(self):
        self.assertTrue(installer.prepare_browser_component(self.root, "chrome", self.lock))
        self.assertEqual((self.root / "chrome/old-file").read_text(), "chrome")
        for removed in ("bin", "runtime", "licenses", "Cargo.lock"):
            self.assertFalse((self.root / removed).exists(), removed)
        self.assertEqual((self.root / "parent-browser.lock.json").read_bytes(), self.previous)
        self.assertEqual((self.parent / "unrelated-toolchain").read_text(), "preserved")

    def test_changed_chrome_is_replaced_and_driver_build_has_no_stale_component_files(self):
        changed = {"chrome": {**self.lock["chrome"], "sha256": "different-archive"}}
        self.assertFalse(installer.prepare_browser_component(self.root, "chrome", changed))
        self.assertFalse((self.root / "chrome").exists())
        self.assertFalse(installer.prepare_browser_component(self.root, "driver", changed))
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual((self.parent / "unrelated-toolchain").read_text(), "preserved")

    def test_unknown_mode_does_not_remove_component(self):
        with self.assertRaises(ValueError):
            installer.prepare_browser_component(self.root, "unknown", self.lock)
        self.assertEqual((self.root / "bin/old-file").read_text(), "bin")


if __name__ == "__main__":
    unittest.main()
