import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "install_browser", Path(__file__).with_name("install-browser.py")
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


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
