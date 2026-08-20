from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("isolated_runtime_root.py")
SPEC = importlib.util.spec_from_file_location("ambit_isolated_runtime_root", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("could not load isolated runtime root module")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IsolatedRuntimeRootTest(unittest.TestCase):
    def runtime_path(self, parent: Path) -> Path:
        return parent / "ambit-c16b-docker-0123456789ab"

    def test_atomic_create_and_descriptor_reproof(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            path = self.runtime_path(Path(temporary))
            with mock.patch.object(
                MODULE,
                "RUNTIME_ROOT_RE",
                __import__("re").compile(r".*/ambit-c16b-docker-[0-9a-f]{12}$"),
            ):
                identity = MODULE.create_runtime_root(path)
                self.assertEqual(MODULE.verify_runtime_root(path, identity), identity)
                self.assertEqual(set(os.listdir(path)), set(MODULE.CHILD_DIRECTORIES))

    def test_check_to_symlink_substitution_is_rejected_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            parent = Path(temporary)
            path = self.runtime_path(parent)
            target = parent / "outside"
            target.mkdir()
            sentinel = target / "sentinel"
            sentinel.write_text("unchanged")
            path.symlink_to(target, target_is_directory=True)
            with mock.patch.object(
                MODULE,
                "RUNTIME_ROOT_RE",
                __import__("re").compile(r".*/ambit-c16b-docker-[0-9a-f]{12}$"),
            ):
                with self.assertRaises(FileExistsError):
                    MODULE.create_runtime_root(path)
            self.assertEqual(sentinel.read_text(), "unchanged")
            self.assertEqual(list(target.iterdir()), [sentinel])

    def test_post_create_root_and_child_substitution_fail_reproof(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            parent = Path(temporary)
            path = self.runtime_path(parent)
            pattern = __import__("re").compile(r".*/ambit-c16b-docker-[0-9a-f]{12}$")
            with mock.patch.object(MODULE, "RUNTIME_ROOT_RE", pattern):
                identity = MODULE.create_runtime_root(path)
                child = path / MODULE.CHILD_DIRECTORIES[0]
                child.rmdir()
                child.symlink_to(parent, target_is_directory=True)
                with self.assertRaises(MODULE.RuntimeRootError):
                    MODULE.verify_runtime_root(path, identity)

                child.unlink()
                child.mkdir(mode=0o700)
                replacement = parent / "replacement"
                path.rename(replacement)
                path.mkdir(mode=0o700)
                for name in MODULE.CHILD_DIRECTORIES:
                    (path / name).mkdir(mode=0o700)
                with self.assertRaises(MODULE.RuntimeRootError):
                    MODULE.verify_runtime_root(path, identity)

    def test_optional_runtime_socket_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            parent = Path(temporary)
            path = self.runtime_path(parent)
            pattern = __import__("re").compile(r".*/ambit-c16b-docker-[0-9a-f]{12}$")
            with mock.patch.object(MODULE, "RUNTIME_ROOT_RE", pattern):
                identity = MODULE.create_runtime_root(path)
                (path / "containerd.sock.ttrpc").symlink_to(parent, target_is_directory=True)
                with self.assertRaises(MODULE.RuntimeRootError):
                    MODULE.verify_runtime_root(path, identity)


if __name__ == "__main__":
    unittest.main()
