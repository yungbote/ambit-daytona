from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from source_contracts import (
    SourceContractError,
    refresh_source_manifest,
    render_source_manifest,
    verify_source,
)


SOURCE_ROOT = Path(__file__).resolve().parents[1]


class SourceContractTests(unittest.TestCase):
    def test_manifest_renderer_is_stable_and_self_excluding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_text("a\n", encoding="utf-8")
            (root / "z.txt").write_text("z\n", encoding="utf-8")
            (root / "source-contracts.sha256").write_text(
                "stale\n", encoding="utf-8"
            )
            first = render_source_manifest(root)
            refresh_source_manifest(root)
            self.assertEqual((root / "source-contracts.sha256").read_bytes(), first)
            self.assertEqual(render_source_manifest(root), first)
            self.assertEqual(
                [line.split("  ", 1)[1] for line in first.decode().splitlines()],
                ["a.txt", "z.txt"],
            )

    def test_current_source_is_closed_and_exact(self) -> None:
        receipt = verify_source(SOURCE_ROOT)
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(len(receipt["packRefs"]), 4)

    def test_source_manifest_detects_byte_and_roster_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            (root / "README.md").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(SourceContractError, "source digest mismatch"):
                verify_source(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            (root / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(SourceContractError, "roster is not closed"):
                verify_source(root)

    def test_rejects_pack_topology_and_native_office_claim_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            pack_set_path = root / "pack-set.lock.json"
            pack_set = json.loads(pack_set_path.read_text())
            pack_set["facetSpecialistClosures"]["C18_RESEARCH"] = [
                "ambit.runtime-pack/data-research@1"
            ]
            pack_set_path.write_text(json.dumps(pack_set), encoding="utf-8")
            with self.assertRaisesRegex(SourceContractError, "facet-to-pack closure"):
                verify_source(root, verify_hashes=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            toolchain_path = root / "office-authoring/locks/toolchain.lock.json"
            toolchain = json.loads(toolchain_path.read_text())
            toolchain["nativeOfficeFidelity"]["microsoftExcel"] = "supported"
            toolchain_path.write_text(json.dumps(toolchain), encoding="utf-8")
            with self.assertRaisesRegex(SourceContractError, "native Windows/Office"):
                verify_source(root, verify_hashes=False)

    def test_rejects_mutable_image_or_online_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            dockerfile = root / "data-research/Dockerfile"
            dockerfile.write_text(
                dockerfile.read_text().replace(
                    "docker.io/library/python@sha256:d6e0850f13fda0e2305d4c3c1c2f7930fe1042d34ddd958e49bba6ef685d0bb2",
                    "docker.io/library/python:latest",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SourceContractError, "base image is not exact"):
                verify_source(root, verify_hashes=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            dockerfile = root / "pdf-ocr/Dockerfile"
            dockerfile.write_text(
                dockerfile.read_text() + "\nRUN --network=none apt-get install curl\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SourceContractError, "online/bootstrap installer"):
                verify_source(root, verify_hashes=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            dockerfile = root / "office-authoring/Dockerfile"
            dockerfile.write_text(
                dockerfile.read_text().replace(
                    "--mount=type=bind,source=.,target=/source,ro",
                    "COPY . /source/",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SourceContractError, "source-and-input read-only build mounts"
            ):
                verify_source(root, verify_hashes=False)

    def test_rejects_browser_sandbox_disable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            conformance = root / "web-browser/conformance/verify.mjs"
            conformance.write_text(
                conformance.read_text() + "\n// --no-sandbox\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SourceContractError, "disables the browser sandbox"):
                verify_source(root, verify_hashes=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            conformance = root / "web-browser/conformance/verify.mjs"
            conformance.write_text(
                conformance.read_text().replace(
                    "chromiumSandbox: browserName === 'chromium'",
                    "chromiumSandbox: false",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SourceContractError,
                "does not enable the Chromium sandbox",
            ):
                verify_source(root, verify_hashes=False)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            shutil.copytree(SOURCE_ROOT, root)
            toolchain_path = root / "web-browser/locks/toolchain.lock.json"
            toolchain = json.loads(toolchain_path.read_text())
            toolchain["sandbox"]["conformanceSeccompProfile"]["upstreamSha256"] = (
                "sha256:" + "0" * 64
            )
            toolchain_path.write_text(json.dumps(toolchain), encoding="utf-8")
            with self.assertRaisesRegex(
                SourceContractError,
                "web seccomp profile identity",
            ):
                verify_source(root, verify_hashes=False)


if __name__ == "__main__":
    unittest.main()
