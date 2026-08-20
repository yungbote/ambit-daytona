from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("freeze_complete_oci_layout.py")
VERIFIER = Path(__file__).with_name("verify_complete_oci_layout.py")


def encode(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def descriptor(payload: bytes, media_type: str, **extra: Any) -> dict[str, Any]:
    return {
        "mediaType": media_type,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        **extra,
    }


class CompleteOciLayoutTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.base_blobs = self.root / "base-blobs"
        self.candidate_blobs = self.root / "candidate-blobs"
        self.base_blobs.mkdir()
        self.candidate_blobs.mkdir()
        self.layout = self.root / "layout"
        self.receipt = self.root / "receipt.json"
        self.verification = self.root / "verification.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_blob(self, root: Path, payload: bytes) -> None:
        (root / hashlib.sha256(payload).hexdigest()).write_bytes(payload)

    def fixture(self, *, wrong_prefix: bool = False) -> dict[str, Path | str]:
        base_config_payload = encode({"architecture": "amd64", "os": "linux"})
        runtime_config_payload = encode({"architecture": "amd64", "os": "linux", "config": {"User": "daytona"}})
        base_layer = b"base-compressed-layer"
        candidate_layer = b"candidate-compressed-layer"
        wrong_layer = b"wrong-compressed-layer"
        base_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": descriptor(base_config_payload, "application/vnd.oci.image.config.v1+json"),
            "layers": [descriptor(base_layer, "application/vnd.oci.image.layer.v1.tar+gzip")],
        }
        runtime_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": descriptor(runtime_config_payload, "application/vnd.oci.image.config.v1+json"),
            "layers": [
                descriptor(wrong_layer if wrong_prefix else base_layer, "application/vnd.oci.image.layer.v1.tar+gzip"),
                descriptor(candidate_layer, "application/vnd.oci.image.layer.v1.tar+gzip"),
            ],
        }
        empty = b"{}"
        sbom = encode({"predicateType": "https://spdx.dev/Document"})
        provenance = encode({"predicateType": "https://slsa.dev/provenance/v1"})
        attestation_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": descriptor(empty, "application/vnd.oci.empty.v1+json", data=base64.b64encode(empty).decode()),
            "layers": [
                descriptor(
                    sbom,
                    "application/vnd.in-toto+json",
                    annotations={"in-toto.io/predicate-type": "https://spdx.dev/Document"},
                ),
                descriptor(
                    provenance,
                    "application/vnd.in-toto+json",
                    annotations={"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
                ),
            ],
        }
        paths: dict[str, Path | str] = {}
        for name, value in (
            ("base-manifest", base_manifest),
            ("runtime-manifest", runtime_manifest),
            ("attestation-manifest", attestation_manifest),
        ):
            path = self.root / f"{name}.json"
            path.write_bytes(encode(value))
            paths[name] = path
        base_config = self.root / "base-config.json"
        base_config.write_bytes(base_config_payload)
        runtime_config = self.root / "runtime-config.json"
        runtime_config.write_bytes(runtime_config_payload)
        paths["base-config"] = base_config
        paths["runtime-config"] = runtime_config
        base_reference = "registry.example/base@sha256:" + hashlib.sha256(encode(base_manifest)).hexdigest()
        paths["base-reference"] = base_reference
        runtime_descriptor = descriptor(
            encode(runtime_manifest),
            "application/vnd.oci.image.manifest.v1+json",
            platform={"architecture": "amd64", "os": "linux"},
        )
        attestation_descriptor = descriptor(
            encode(attestation_manifest),
            "application/vnd.oci.image.manifest.v1+json",
            platform={"architecture": "unknown", "os": "unknown"},
            annotations={
                "vnd.docker.reference.type": "attestation-manifest",
                "vnd.docker.reference.digest": runtime_descriptor["digest"],
            },
        )
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [runtime_descriptor, attestation_descriptor],
        }
        index_path = self.root / "index.json"
        index_path.write_bytes(encode(index))
        paths["index"] = index_path
        self.write_blob(self.base_blobs, base_layer)
        self.write_blob(self.candidate_blobs, candidate_layer)
        self.write_blob(self.candidate_blobs, sbom)
        self.write_blob(self.candidate_blobs, provenance)
        return paths

    def run_freeze(self, fixture: dict[str, Path | str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--index",
                str(fixture["index"]),
                "--runtime-manifest",
                str(fixture["runtime-manifest"]),
                "--runtime-config",
                str(fixture["runtime-config"]),
                "--attestation-manifest",
                str(fixture["attestation-manifest"]),
                "--base-reference",
                str(fixture["base-reference"]),
                "--base-manifest",
                str(fixture["base-manifest"]),
                "--base-config",
                str(fixture["base-config"]),
                "--base-blobs",
                str(self.base_blobs),
                "--candidate-blobs",
                str(self.candidate_blobs),
                "--output-layout",
                str(self.layout),
                "--output-receipt",
                str(self.receipt),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def run_verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--layout",
                str(self.layout),
                "--receipt",
                str(self.receipt),
                "--output",
                str(self.verification),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_freezes_complete_exact_recursive_layout(self) -> None:
        result = self.run_freeze(self.fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["declaredBase"]["inheritedLayerCount"], 1)
        self.assertEqual(receipt["packOwnedRuntimeLayerCount"], 1)
        self.assertEqual(receipt["blobCount"], 8)
        self.assertEqual(len(list((self.layout / "blobs" / "sha256").iterdir())), 8)
        verification = self.run_verify()
        self.assertEqual(verification.returncode, 0, verification.stderr)
        verified = json.loads(self.verification.read_text())
        self.assertEqual(verified["outcome"], "passed")
        self.assertEqual(verified["blobCount"], 8)

    def test_missing_inherited_compressed_blob_fails(self) -> None:
        fixture = self.fixture()
        for path in self.base_blobs.iterdir():
            path.unlink()
        result = self.run_freeze(fixture)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No such file", result.stderr)

    def test_runtime_base_prefix_mismatch_fails(self) -> None:
        result = self.run_freeze(self.fixture(wrong_prefix=True))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("differs from the declared base", result.stderr)

    def test_post_freeze_blob_mutation_fails_recursive_verification(self) -> None:
        result = self.run_freeze(self.fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        blob = next((self.layout / "blobs" / "sha256").iterdir())
        blob.chmod(0o644)
        blob.write_bytes(blob.read_bytes() + b"tamper")
        verification = self.run_verify()
        self.assertNotEqual(verification.returncode, 0)
        self.assertRegex(verification.stderr, "size mismatch|digest mismatch")

    def test_unreachable_extra_blob_fails_recursive_verification(self) -> None:
        result = self.run_freeze(self.fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.layout / "blobs" / "sha256" / ("f" * 64)).write_bytes(b"extra")
        verification = self.run_verify()
        self.assertNotEqual(verification.returncode, 0)
        self.assertIn("missing or unreachable blobs", verification.stderr)


if __name__ == "__main__":
    unittest.main()
