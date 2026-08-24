from __future__ import annotations

import importlib.util
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[3]
    / "runtime-composition/build_union_overlay.py"
)
SPEC = importlib.util.spec_from_file_location("build_union_overlay", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load shared union overlay builder")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
UnionOverlayBuildError = MODULE.UnionOverlayBuildError
build = MODULE.build


class UnionOverlayBuilderTests(unittest.TestCase):
    def test_builds_one_additive_overlay_and_preserves_hardlink_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "core"
            target = root / "target"
            core.mkdir()
            (core / "protected").mkdir()
            (core / "protected/helper").write_bytes(b"helper")
            (core / "common").write_bytes(b"same")
            (core / "core-only").write_bytes(b"retained")
            shutil.copytree(core, target)
            (target / "common").write_bytes(b"changed")
            (target / "new").mkdir()
            (target / "new/first").write_bytes(b"linked")
            os.link(target / "new/first", target / "new/second")

            receipt = build(
                core,
                target,
                root / "result",
                ["/protected/helper"],
                1_787_551_756,
            )

            overlay = root / "result/overlay"
            self.assertEqual(receipt["outcome"], "passed")
            self.assertEqual((overlay / "common").read_bytes(), b"changed")
            self.assertFalse((overlay / "protected/helper").exists())
            self.assertFalse((overlay / "core-only").exists())
            first = (overlay / "new/first").stat()
            second = (overlay / "new/second").stat()
            self.assertEqual((first.st_dev, first.st_ino), (second.st_dev, second.st_ino))
            self.assertEqual(int(first.st_mtime), 1_787_551_756)
            stored = json.loads(
                (root / "result/overlay-build-receipt.json").read_text()
            )
            self.assertEqual(stored["protectedCorePathsOutcome"], "passed")

    def test_rejects_protected_change_special_file_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "core"
            target = root / "target"
            core.mkdir()
            (core / "helper").write_bytes(b"one")
            shutil.copytree(core, target)
            (target / "helper").write_bytes(b"two")
            with self.assertRaisesRegex(UnionOverlayBuildError, "protected"):
                build(
                    core,
                    target,
                    root / "protected-result",
                    ["/helper"],
                    1,
                )

            (target / "helper").write_bytes(b"one")
            os.mkfifo(target / "fifo")
            with self.assertRaisesRegex(UnionOverlayBuildError, "special"):
                build(core, target, root / "special-result", ["/helper"], 1)

            (target / "fifo").unlink()
            (root / "existing").mkdir()
            with self.assertRaisesRegex(UnionOverlayBuildError, "already exists"):
                build(core, target, root / "existing", ["/helper"], 1)

    def test_requires_sorted_unique_absolute_protected_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / "core"
            target = root / "target"
            core.mkdir()
            target.mkdir()
            for values in ([], ["relative"], ["/z", "/a"], ["/a", "/a"]):
                with self.subTest(values=values):
                    with self.assertRaises(UnionOverlayBuildError):
                        build(
                            core,
                            target,
                            root / ("out-" + str(len(values))),
                            values,
                            1,
                        )


if __name__ == "__main__":
    unittest.main()
