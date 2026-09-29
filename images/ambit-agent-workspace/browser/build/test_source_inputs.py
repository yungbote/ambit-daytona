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

HELPER_PATHS = ["LICENSE", "libs/computer-use/go.mod", "libs/computer-use/go.sum", "libs/computer-use/cmd/browser-display"]
MATERIALIZER_PATH = "runtime/agent-workspace-atomic-materializer"


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


def repository(root, origin, files):
    root.mkdir()
    run(root, "init", "-q", "-b", "main")
    run(root, "remote", "add", "origin", origin)
    head = commit(root, files, "initial")
    run(root, "update-ref", source_inputs.MAIN, head)
    return root, head


def tar(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", *args], check=True, capture_output=True).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


class SourceInputs(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.driver, self.upstream = repository(self.root / "driver", "git@github.com:example/agent-browser.git",
                                                {"cli/Cargo.toml": '[package]\nname = "agent-browser"\nversion = "0.1.0"\n'})
        self.driver_rev = commit(self.driver, {"cli/Cargo.toml": '[package]\nname = "agent-browser"\nversion = "0.2.0"\n',
                                               "cli/src/main.rs": "fn main() {}\n"}, "driver")
        run(self.driver, "update-ref", source_inputs.MAIN, self.driver_rev)
        self.helper, self.helper_rev = repository(self.root / "helper", "https://github.com/example/daytona", {
            "LICENSE": "license\n", "libs/computer-use/go.mod": "module x\n", "libs/computer-use/go.sum": "",
            "libs/computer-use/cmd/browser-display/main.go": "package main\n", "apps/runner/main.go": "package main\n"})
        self.build_lock = '{"schema": "ambit.atomic-materializer-build-lock/v1"}\n'
        self.backend, self.backend_rev = repository(self.root / "backend", "git@github.com:example/backend.git", {
            f"{MATERIALIZER_PATH}/materializer.lock.json": self.build_lock, f"{MATERIALIZER_PATH}/main.go": "package main\n",
            "src/other.ts": "export {}\n"})
        self.lock = self.root / "browser.lock.json"
        self.lock.write_text(json.dumps({
            "schema": "ambit.workspace-browser-lock/v1",
            "agentBrowser": {"repository": "https://github.com/example/agent-browser", "upstreamRepository": "https://github.com/up/agent-browser",
                             "upstreamRevision": self.upstream, "revision": "", "sourceTree": "", "version": "", "archiveName": "",
                             "sha256": "", "features": ["browser-audio"]},
            "displayHelper": {"repository": "https://github.com/example/daytona", "revision": "", "paths": HELPER_PATHS,
                              "archiveName": "", "sha256": ""},
            "chrome": {"version": "1", "sha256": "1" * 64},
            "materializer": {"repository": "https://github.com/example/backend", "revision": "", "sourceTree": "", "sourcePath": MATERIALIZER_PATH,
                             "archiveName": "", "sha256": "", "buildLockSha256": ""},
        }, indent=2) + "\n")

    def invoke(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            source_inputs.main([*argv, "--lock", str(self.lock)])
        return output.getvalue()

    def pin(self, driver=None, helper=None):
        return self.invoke("pin", "--driver", driver or self.driver_rev, "--driver-repo", str(self.driver),
                           "--helper", helper or self.helper_rev, "--helper-repo", str(self.helper))

    def pin_materializer(self):
        return self.invoke("pin-materializer", "--backend", self.backend_rev, "--backend-repo", str(self.backend))

    def export(self, out):
        return self.invoke("export", "--driver-repo", str(self.driver), "--helper-repo", str(self.helper), "--backend-repo", str(self.backend),
                           "--out", str(out))

    def test_pin_derives_the_driver_and_helper_bindings_from_their_two_revisions(self):
        before = json.loads(self.lock.read_text())
        self.pin(driver="main", helper=self.helper_rev[:12])
        lock = json.loads(self.lock.read_text())
        self.assertEqual({key: lock[key] for key in ("chrome", "materializer")}, {key: before[key] for key in ("chrome", "materializer")})
        self.assertEqual(lock["agentBrowser"], {
            **before["agentBrowser"], "revision": self.driver_rev, "sourceTree": run(self.driver, "rev-parse", "HEAD^{tree}"), "version": "0.2.0",
            "archiveName": "agent-browser-source.tar", "sha256": digest(tar(self.driver, "--prefix=agent-browser/", self.driver_rev))})
        self.assertEqual(lock["displayHelper"], {
            **before["displayHelper"], "revision": self.helper_rev, "archiveName": "browser-display-source.tar",
            "sha256": digest(tar(self.helper, self.helper_rev, *HELPER_PATHS))})

    def test_an_image_is_never_pinned_from_one_revision(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.invoke("pin", "--driver", self.driver_rev, "--driver-repo", str(self.driver))
        self.assertEqual(json.loads(self.lock.read_text())["agentBrowser"]["revision"], "")

    def test_pin_materializer_derives_its_binding_from_the_backend_revision(self):
        self.pin_materializer()
        self.assertEqual(json.loads(self.lock.read_text())["materializer"], {
            "repository": "https://github.com/example/backend", "revision": self.backend_rev,
            "sourceTree": run(self.backend, "rev-parse", f"HEAD:{MATERIALIZER_PATH}"), "sourcePath": MATERIALIZER_PATH,
            "archiveName": "atomic-materializer-source.tar", "sha256": digest(tar(self.backend, self.backend_rev, MATERIALIZER_PATH)),
            "buildLockSha256": digest(self.build_lock.encode())})

    def test_export_writes_the_three_archives_the_installer_reads_with_the_pinned_digests(self):
        self.pin()
        self.pin_materializer()
        out = self.root / "inputs"
        self.export(out)
        lock = json.loads(self.lock.read_text())
        for key in ("agentBrowser", "displayHelper", "materializer"):
            self.assertEqual(digest((out / lock[key]["archiveName"]).read_bytes()), lock[key]["sha256"])
        with tarfile.open(out / "agent-browser-source.tar") as driver:
            self.assertEqual({name.split("/")[0] for name in driver.getnames()}, {"agent-browser"})
        with tarfile.open(out / "browser-display-source.tar") as helper:
            files = {member.name for member in helper.getmembers() if member.isfile()}
            self.assertEqual(files, {"LICENSE", "libs/computer-use/go.mod", "libs/computer-use/go.sum", "libs/computer-use/cmd/browser-display/main.go"})
        with tarfile.open(out / "atomic-materializer-source.tar") as materializer:
            self.assertIn(f"{MATERIALIZER_PATH}/materializer.lock.json", materializer.getnames())
            self.assertNotIn("src/other.ts", materializer.getnames())

    def test_an_archive_does_not_depend_on_the_clones_tar_umask(self):
        self.pin()
        pinned = json.loads(self.lock.read_text())["displayHelper"]["sha256"]
        run(self.helper, "config", "tar.umask", "0022")
        self.pin()
        self.assertEqual(json.loads(self.lock.read_text())["displayHelper"]["sha256"], pinned)

    def test_export_refuses_a_lock_whose_digest_is_not_the_revisions_archive(self):
        self.pin()
        self.pin_materializer()
        lock = json.loads(self.lock.read_text())
        lock["displayHelper"]["sha256"] = "f" * 64
        self.lock.write_text(json.dumps(lock, indent=2) + "\n")
        with self.assertRaisesRegex(SystemExit, "browser-display-source.tar at .* is not the archive the lock records"):
            self.export(self.root / "inputs")
        self.assertFalse((self.root / "inputs").exists())

    def test_pin_refuses_a_revision_main_does_not_contain(self):
        branch = commit(self.helper, {"libs/computer-use/cmd/browser-display/wake.go": "package main\n"}, "unmerged")
        with self.assertRaisesRegex(SystemExit, f"{branch} is not on https://github.com/example/daytona main"):
            self.pin(helper=branch)

    def test_pin_refuses_a_clone_of_another_repository(self):
        run(self.helper, "remote", "set-url", "origin", "git@github.com:someone/else.git")
        with self.assertRaisesRegex(SystemExit, "is git@github.com:someone/else.git, not https://github.com/example/daytona"):
            self.pin()

    def test_pin_refuses_a_driver_that_does_not_contain_the_recorded_upstream(self):
        run(self.driver, "checkout", "-q", "--orphan", "rewritten")
        rewritten = commit(self.driver, {"cli/Cargo.toml": '[package]\nname = "agent-browser"\nversion = "0.3.0"\n'}, "rewritten")
        run(self.driver, "update-ref", source_inputs.MAIN, rewritten)
        with self.assertRaisesRegex(SystemExit, "the recorded upstream revision .* is not in"):
            self.pin(driver=rewritten)


if __name__ == "__main__":
    unittest.main()
