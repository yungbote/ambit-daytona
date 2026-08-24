from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pack_bundle import (
    PackBundleError,
    build_manifest,
    verify_manifest,
    write_artifact,
)


class PackBundleTests(unittest.TestCase):
    def test_builds_one_stable_closed_bundle_and_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            inputs = root / "inputs"
            for path in (
                source / "build",
                source / "conformance",
                source / "policy",
                source / "protocol",
                source / "fixture/locks",
                inputs / "python",
            ):
                path.mkdir(parents=True, exist_ok=True)
            (source / "build/install-debian-python-pack.sh").write_text("installer\n")
            (source / "conformance/check.py").write_text("check\n")
            (source / "policy/runtime.json").write_text("{}\n")
            (source / "protocol/command.py").write_text("command\n")
            (source / "pack-set.lock.json").write_text("{}\n")
            (source / "source-contracts.sha256").write_text("source\n")
            (source / "fixture/pack.lock.json").write_text(
                '{"packRevisionRef":"ambit.runtime-pack/fixture@1"}\n'
            )
            (source / "fixture/locks/toolchain.lock.json").write_text(
                '{"packRef":"ambit.runtime-pack/fixture@1",'
                '"baseImage":"registry.test/base@sha256:' + "1" * 64 + '"}\n'
            )
            (inputs / "python/dependency.whl").write_bytes(b"wheel")
            import hashlib

            (source / "fixture/locks/python-wheels.sha256").write_text(
                f"{hashlib.sha256(b'wheel').hexdigest()}  python/dependency.whl\n"
            )
            from pack_bundle import INPUT_MANIFESTS, PACKS

            PACKS["fixture"] = "ambit.runtime-pack/fixture@1"
            INPUT_MANIFESTS["fixture"] = ("python-wheels.sha256",)
            try:
                artifact = root / "fixture.tar"
                write_artifact(source, inputs, "fixture", artifact)
                manifest = build_manifest(source, inputs, "fixture", artifact)
                self.assertEqual(
                    verify_manifest(source, inputs, "fixture", artifact, manifest),
                    manifest,
                )
                second_artifact = root / "fixture-2.tar"
                write_artifact(source, inputs, "fixture", second_artifact)
                self.assertEqual(artifact.read_bytes(), second_artifact.read_bytes())
                (inputs / "python/dependency.whl").write_bytes(b"drift")
                with self.assertRaisesRegex(PackBundleError, "differs"):
                    verify_manifest(source, inputs, "fixture", artifact, manifest)
            finally:
                del PACKS["fixture"]
                del INPUT_MANIFESTS["fixture"]

    def test_rejects_external_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.write_text("x")
            inputs = root / "inputs"
            inputs.mkdir()
            (inputs / "link").symlink_to(target)
            from pack_bundle import _input_paths

            with self.assertRaisesRegex(PackBundleError, "symlink"):
                _input_paths(inputs)


if __name__ == "__main__":
    unittest.main()
