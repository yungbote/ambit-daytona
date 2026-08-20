from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SCRIPT = Path(__file__).with_name("fetch_registry_object.py")


class RegistryHandler(BaseHTTPRequestHandler):
    manifest = b'{"mediaType":"application/vnd.oci.image.manifest.v1+json","schemaVersion":2}\n'
    blob = b"exact compressed fixture blob"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if "/manifests/" in self.path:
            payload = self.manifest
            content_type = "application/vnd.oci.image.manifest.v1+json"
        elif "/blobs/" in self.path:
            payload = self.blob
            content_type = "application/octet-stream"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format_string: str, *arguments: object) -> None:
        return


class FetchRegistryObjectTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), RegistryHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.reference = f"127.0.0.1:{self.server.server_port}/fixture/repository"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def run_fetch(
        self,
        *,
        kind: str,
        payload: bytes,
        reference: str | None = None,
        digest: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        output = self.root / f"{kind}.out"
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--reference",
                reference or self.reference,
                "--scheme",
                "http",
                "--kind",
                kind,
                "--digest",
                digest or "sha256:" + hashlib.sha256(payload).hexdigest(),
                "--expected-size",
                str(len(payload)),
                "--output",
                str(output),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_fetches_exact_loopback_manifest_and_blob(self) -> None:
        manifest = self.run_fetch(kind="manifest", payload=RegistryHandler.manifest)
        self.assertEqual(manifest.returncode, 0, manifest.stderr)
        self.assertEqual((self.root / "manifest.out").read_bytes(), RegistryHandler.manifest)
        self.assertEqual(json.loads((self.root / "manifest.out").read_text())["schemaVersion"], 2)
        blob = self.run_fetch(kind="blob", payload=RegistryHandler.blob)
        self.assertEqual(blob.returncode, 0, blob.stderr)
        self.assertEqual((self.root / "blob.out").read_bytes(), RegistryHandler.blob)

    def test_digest_mismatch_fails_without_output(self) -> None:
        result = self.run_fetch(kind="blob", payload=RegistryHandler.blob, digest="sha256:" + "0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest mismatch", result.stderr)
        self.assertFalse((self.root / "blob.out").exists())

    def test_plain_http_non_loopback_reference_is_rejected(self) -> None:
        result = self.run_fetch(
            kind="blob",
            payload=RegistryHandler.blob,
            reference="registry.example/fixture/repository",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("loopback-only", result.stderr)


if __name__ == "__main__":
    unittest.main()
