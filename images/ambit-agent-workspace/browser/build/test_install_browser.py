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


if __name__ == "__main__":
    unittest.main()
