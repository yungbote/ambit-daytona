"""Execute the source-owned Bash roster gate, including producer failures."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class BrowserBuildContextTests(unittest.TestCase):
    def test_effective_toolchain_lock_comes_from_the_browser_context(self):
        browser = Path(__file__).parents[1]
        dockerfile = (browser / "Dockerfile").read_text()
        mounts = [
            dict(field.split("=", 1) if "=" in field else (field, True)
                 for field in line.strip().split("--mount=", 1)[1].split()[0].split(","))
            for line in dockerfile.splitlines()
            if "--mount=" in line and "target=/source/toolchains.lock.json" in line
        ]
        self.assertEqual(len(mounts), 1)
        mount = mounts[0]
        # The repository context excludes images through .dockerignore. This
        # component already owns its effective lock in the primary context.
        self.assertNotIn("from", mount)
        self.assertEqual(mount["type"], "bind")
        self.assertTrue(mount["ro"])
        source = (browser / mount["source"]).resolve()
        self.assertTrue(source.is_relative_to(browser.resolve()))
        lock = json.loads((browser / "browser.lock.json").read_text())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         lock["toolchains"]["sourceLockSha256"])


class LiveDpkgConformanceTests(unittest.TestCase):
    def run_gate(self, output, status=0, receipt="first=1\nsecond=2\n"):
        source = Path(__file__).parents[2] / "conformance/verify.sh"
        script = source.read_text()
        start = script.index("# A matching source/receipt pair")
        end = script.index("# --- runtime user", start)
        gate = script[start:end]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "installed-dpkg.lock").write_text(receipt)
            query = root / "dpkg-query"
            query.write_text("#!/bin/bash\nprintf '%s' \"$QUERY_OUTPUT\"\nexit \"$QUERY_STATUS\"\n")
            query.chmod(0o755)
            return subprocess.run(
                ["bash", "-c", "set -euo pipefail\nfailures=0\n"
                 "ok() { printf 'ok: %s\\n' \"$*\"; }\n"
                 "fail() { printf 'FAIL: %s\\n' \"$*\"; failures=$((failures + 1)); }\n"
                 + gate + "\n[ \"$failures\" -eq 0 ]\n"],
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                     "LINEAGE": str(root), "QUERY_OUTPUT": output, "QUERY_STATUS": str(status)},
                capture_output=True, text=True, check=False,
            )

    def test_successful_query_is_sorted_and_compared(self):
        result = self.run_gate("second=2\nfirst=1\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok: live dpkg roster equals", result.stdout)

    def test_matching_output_cannot_conceal_an_unsuccessful_query(self):
        result = self.run_gate("first=1\nsecond=2\n", status=42)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: could not read the live dpkg roster", result.stdout)
        self.assertNotIn("ok: live dpkg roster equals", result.stdout)

    def test_successful_query_with_different_packages_fails(self):
        result = self.run_gate("first=1\nsecond=3\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: live dpkg roster drifted", result.stdout)

    def test_query_failure_without_output_fails(self):
        result = self.run_gate("", status=42)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: could not read the live dpkg roster", result.stdout)


class CompositionSourceTests(unittest.TestCase):
    def run_checks(self, composition, selection=None, missing=None, query_status=0):
        script = (Path(__file__).parents[2] / "conformance/verify.sh").read_text()
        # Execute the complete source/receipt/live gate; only its fixed image
        # lineage path is redirected into the test's isolated filesystem.
        header = script[:script.index("# --- runtime user")]
        header = header.replace(
            "LINEAGE=/opt/ambit/runtime-base/workspace/lineage", 'LINEAGE="$TEST_LINEAGE"'
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shared, browser, lineage = [root / name for name in ("locks", "browser", "lineage")]
            for directory in (shared, browser, lineage):
                directory.mkdir()
            base = {"python": {"requirements": "requirements.txt"},
                    "node": {"manifest": "package.json", "lockfile": "package-lock.json"},
                    "debian": {"packages": {"core": "1"}}}
            effective = {**base, "debian": {"packages": {"core": "2", "display": "1"}}}
            for directory, lock, roster in (
                (shared, base, "core=1\n"), (browser, effective, "core=2\ndisplay=1\n")
            ):
                (directory / "toolchains.lock.json").write_text(json.dumps(lock))
                (directory / "installed-dpkg.lock").write_text(roster)
            for name in ("requirements.txt", "package.json", "package-lock.json"):
                (shared / name).write_text("shared fixture\n")
                (lineage / name).write_bytes((shared / name).read_bytes())
            chosen = browser if composition == "browser" else shared
            for name in ("toolchains.lock.json", "installed-dpkg.lock"):
                (lineage / name).write_bytes((chosen / name).read_bytes())
            query = root / "dpkg-query"
            query.write_text("#!/bin/bash\nprintf '%s' \"$QUERY_OUTPUT\"\nexit \"$QUERY_STATUS\"\n")
            query.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                   "SOURCE_LOCKS": str(shared), "TEST_LINEAGE": str(lineage),
                   "QUERY_OUTPUT": (lineage / "installed-dpkg.lock").read_text(),
                   "QUERY_STATUS": str(query_status)}
            # A caller chooses a composition; the image never supplies that choice.
            env.pop("SOURCE_TOOLCHAIN_LOCK", None)
            env.pop("SOURCE_DPKG_ROSTER", None)
            if selection == "browser":
                env.update(SOURCE_TOOLCHAIN_LOCK=str(browser / "toolchains.lock.json"),
                           SOURCE_DPKG_ROSTER=str(browser / "installed-dpkg.lock"))
            if missing in ("SOURCE_TOOLCHAIN_LOCK", "SOURCE_DPKG_ROSTER"):
                env[missing] = str(root / "missing")
            elif missing == "empty":
                env["SOURCE_DPKG_ROSTER"] = ""
            elif missing == "sidecar":
                (shared / "requirements.txt").unlink()
            return subprocess.run(["bash", "-c", header + '\n[ "$failures" -eq 0 ]\n'],
                                  env=env, capture_output=True, text=True, check=False)

    def test_standalone_uses_unchanged_default_source_files(self):
        result = self.run_checks("standalone")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_browser_selects_effective_files_and_keeps_shared_sidecars(self):
        result = self.run_checks("browser", selection="browser")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_neither_composition_accepts_the_other_source_files(self):
        for composition, selection in (("browser", None), ("standalone", "browser")):
            with self.subTest(composition=composition):
                result = self.run_checks(composition, selection=selection)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("image lineage copy differs", result.stdout + result.stderr)
                self.assertIn("installed dpkg roster drifted", result.stdout + result.stderr)

    def test_explicit_missing_empty_and_shared_missing_inputs_cannot_fall_back(self):
        for missing in ("SOURCE_TOOLCHAIN_LOCK", "SOURCE_DPKG_ROSTER", "empty", "sidecar"):
            with self.subTest(missing=missing):
                result = self.run_checks("browser", selection="browser", missing=missing)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("not readable", result.stdout + result.stderr)
                self.assertNotIn("skipping", result.stdout + result.stderr)

    def test_both_compositions_reject_matching_bytes_from_failed_query(self):
        for composition, selection in (("standalone", None), ("browser", "browser")):
            with self.subTest(composition=composition):
                result = self.run_checks(composition, selection=selection, query_status=42)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("could not read the live dpkg roster", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
