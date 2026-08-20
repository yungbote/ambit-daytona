from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("publish_certified_runtime.py")
SPEC = importlib.util.spec_from_file_location("ambit_publish_runtime", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("could not load certified runtime publisher")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


class PublishCertifiedRuntimeTest(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, str, str]:
        layout = root / "layout"
        blobs = layout / "blobs" / "sha256"
        blobs.mkdir(parents=True)

        config = b'{"config":{"Env":[]}}'
        layer = b"content"
        config_descriptor = {"digest": digest(config), "mediaType": "application/vnd.oci.image.config.v1+json", "size": len(config)}
        layer_descriptor = {"digest": digest(layer), "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "size": len(layer)}
        platform_body = json.dumps(
            {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config_descriptor, "layers": [layer_descriptor]},
            separators=(",", ":"),
        ).encode()
        platform_descriptor = {"digest": digest(platform_body), "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": len(platform_body), "platform": {"architecture": "amd64", "os": "linux"}}
        attestation_body = json.dumps(
            {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config_descriptor, "layers": [], "subject": platform_descriptor},
            separators=(",", ":"),
        ).encode()
        attestation_descriptor = {"digest": digest(attestation_body), "mediaType": "application/vnd.oci.image.manifest.v1+json", "size": len(attestation_body), "platform": {"architecture": "unknown", "os": "unknown"}}
        index = json.dumps(
            {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [platform_descriptor, attestation_descriptor]},
            separators=(",", ":"),
        ).encode()
        for body in (config, layer, platform_body, attestation_body):
            (blobs / digest(body).removeprefix("sha256:")).write_bytes(body)
        (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}\n')
        (layout / "index.json").write_bytes(index)
        return layout, digest(index), digest(platform_body)

    def test_complete_layout_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout, index_digest, platform_digest = self.fixture(Path(temporary))
            result = MODULE.verify_layout(layout, index_digest, platform_digest)
            self.assertEqual(result.root_index.digest, index_digest)
            self.assertEqual(result.platform_manifest.digest, platform_digest)
            self.assertEqual(len(result.blobs), 4)

    def test_corruption_and_extra_blob_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            layout, index_digest, platform_digest = self.fixture(Path(temporary))
            extra = layout / "blobs" / "sha256" / ("f" * 64)
            extra.write_bytes(b"extra")
            with self.assertRaises(MODULE.PublicationError):
                MODULE.verify_layout(layout, index_digest, platform_digest)
            extra.unlink()
            first = next((layout / "blobs" / "sha256").iterdir())
            first.write_bytes(first.read_bytes() + b"corrupt")
            with self.assertRaises(MODULE.PublicationError):
                MODULE.verify_layout(layout, index_digest, platform_digest)

    def test_registry_origin_and_upload_location_are_loopback_bound(self) -> None:
        with self.assertRaises(MODULE.PublicationError):
            MODULE.LoopbackRegistry("https://registry.example", "ambit/runtime")
        registry = MODULE.LoopbackRegistry("http://127.0.0.1:36000", "ambit/runtime")
        with self.assertRaises(MODULE.PublicationError):
            registry.validated_upload_location("http://evil.example/v2/ambit/runtime/blobs/uploads/1")


if __name__ == "__main__":
    unittest.main()
