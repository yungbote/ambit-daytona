import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("source_inputs", Path(__file__).with_name("source-inputs.py"))
source_inputs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(source_inputs)

HELPER_PATH = "runtime/agent-workspace-atomic-materializer"


def run(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def commit(repo, files, message):
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    run(repo, "add", "-A")
    run(repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", message)
    return run(repo, "rev-parse", "HEAD")


def repository(root, origin):
    root.mkdir()
    run(root, "init", "-q", "-b", "main")
    run(root, "remote", "add", "origin", origin)
    return root


class SourceInputs(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.driver = repository(self.root / "driver", "git@github.com:example/agent-browser.git")
        self.upstream = commit(self.driver, {"cli/Cargo.toml": '[package]\nname = "agent-browser"\nversion = "0.1.0"\n'}, "upstream")
        self.driver_rev = commit(self.driver, {"cli/Cargo.toml": '[package]\nname = "agent-browser"\nversion = "0.2.0"\n',
                                               "cli/src/main.rs": "fn main() {}\n"}, "driver")
        run(self.driver, "update-ref", source_inputs.MAIN, self.driver_rev)
        self.helper = repository(self.root / "helper", "https://github.com/example/backend")
        self.build_lock = '{"schema": "ambit.atomic-materializer-build-lock/v1"}\n'
        self.helper_rev = commit(self.helper, {f"{HELPER_PATH}/materializer.lock.json": self.build_lock,
                                               f"{HELPER_PATH}/main.go": "package main\n", "src/other.ts": "export {}\n"}, "helper")
        run(self.helper, "update-ref", source_inputs.MAIN, self.helper_rev)
        self.lock = self.root / "browser.lock.json"
        self.lock.write_text(json.dumps({
            "schema": "ambit.workspace-browser-lock/v1",
            "agentBrowser": {"repository": "https://github.com/example/agent-browser", "upstreamRepository": "https://github.com/up/agent-browser",
                             "upstreamRevision": self.upstream, "revision": "0" * 40, "sourceTree": "0" * 40, "version": "0.0.0",
                             "archiveName": "agent-browser-source.tar.gz", "sha256": "0" * 64, "features": ["browser-audio"]},
            "chrome": {"version": "1", "sha256": "1" * 64},
            "materializer": {"repository": "https://github.com/example/backend", "revision": "0" * 40, "sourceTree": "0" * 40,
                             "sourcePath": HELPER_PATH, "archiveName": "atomic-materializer-source.tar.gz", "sha256": "0" * 64,
                             "buildLockSha256": "0" * 64},
        }, indent=2) + "\n")

    def invoke(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            source_inputs.main([*argv, "--driver-repo", str(self.driver), "--helper-repo", str(self.helper), "--lock", str(self.lock)])
        return output.getvalue()

    def pin(self, driver=None, helper=None):
        return self.invoke("pin", "--driver", driver or self.driver_rev, "--helper", helper or self.helper_rev)

    def test_pin_derives_every_recorded_field_from_the_two_revisions(self):
        before = json.loads(self.lock.read_text())
        self.pin(driver="main", helper=self.helper_rev[:12])
        lock = json.loads(self.lock.read_text())
        self.assertEqual(lock["chrome"], before["chrome"])
        self.assertEqual(lock["agentBrowser"], {
            **before["agentBrowser"], "revision": self.driver_rev, "sourceTree": run(self.driver, "rev-parse", "HEAD^{tree}"),
            "version": "0.2.0", "archiveName": "agent-browser-source.tar",
            "sha256": hashlib.sha256(subprocess.run(["git", "-C", str(self.driver), "archive", "--format=tar", "--prefix=agent-browser/",
                                                     self.driver_rev], check=True, capture_output=True).stdout).hexdigest()})
        self.assertEqual(lock["materializer"], {
            **before["materializer"], "revision": self.helper_rev, "sourceTree": run(self.helper, "rev-parse", f"HEAD:{HELPER_PATH}"),
            "archiveName": "atomic-materializer-source.tar",
            "sha256": hashlib.sha256(subprocess.run(["git", "-C", str(self.helper), "archive", "--format=tar", self.helper_rev, HELPER_PATH],
                                                    check=True, capture_output=True).stdout).hexdigest(),
            "buildLockSha256": hashlib.sha256(self.build_lock.encode()).hexdigest()})

    def test_export_writes_the_archives_the_installer_reads_with_the_pinned_digests(self):
        self.pin()
        out = self.root / "inputs"
        self.invoke("export", "--out", str(out))
        lock = json.loads(self.lock.read_text())
        for binding in (lock["agentBrowser"], lock["materializer"]):
            self.assertEqual(hashlib.sha256((out / binding["archiveName"]).read_bytes()).hexdigest(), binding["sha256"])
        with tarfile.open(out / "agent-browser-source.tar") as driver:
            self.assertEqual({name.split("/")[0] for name in driver.getnames()}, {"agent-browser"})
            self.assertIn("agent-browser/cli/Cargo.toml", driver.getnames())
        with tarfile.open(out / "atomic-materializer-source.tar") as helper:
            self.assertIn(f"{HELPER_PATH}/materializer.lock.json", helper.getnames())
            self.assertNotIn("src/other.ts", helper.getnames())

    def test_export_refuses_a_lock_whose_digest_is_not_the_revisions_archive(self):
        self.pin()
        lock = json.loads(self.lock.read_text())
        lock["agentBrowser"]["sha256"] = "f" * 64
        self.lock.write_text(json.dumps(lock, indent=2) + "\n")
        with self.assertRaisesRegex(SystemExit, "agent-browser-source.tar at .* is not the archive the lock records"):
            self.invoke("export", "--out", str(self.root / "inputs"))
        self.assertFalse((self.root / "inputs" / "agent-browser-source.tar").exists())

    def test_pin_refuses_a_revision_main_does_not_contain(self):
        branch = commit(self.driver, {"cli/src/lib.rs": "\n"}, "unmerged")
        with self.assertRaisesRegex(SystemExit, f"{branch} is not on https://github.com/example/agent-browser main"):
            self.pin(driver=branch)

    def test_pin_refuses_a_repository_other_than_the_one_the_lock_names(self):
        run(self.helper, "remote", "set-url", "origin", "git@github.com:someone/else.git")
        with self.assertRaisesRegex(SystemExit, "is git@github.com:someone/else.git, not https://github.com/example/backend"):
            self.pin()

    def test_pin_refuses_a_driver_that_does_not_contain_the_recorded_upstream(self):
        run(self.driver, "checkout", "-q", "--orphan", "rewritten")
        rewritten = commit(self.driver, {"cli/Cargo.toml": '[package]\nname = "agent-browser"\nversion = "0.3.0"\n'}, "rewritten")
        run(self.driver, "update-ref", source_inputs.MAIN, rewritten)
        with self.assertRaisesRegex(SystemExit, "the recorded upstream revision .* is not in"):
            self.pin(driver=rewritten)


if __name__ == "__main__":
    unittest.main()
