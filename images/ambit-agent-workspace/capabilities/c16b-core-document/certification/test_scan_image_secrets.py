from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("scan_image_secrets.py")


def tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, payload in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o644
            archive.addfile(member, io.BytesIO(payload))
    return buffer.getvalue()


class ImageSecretScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.image = self.root / "image.tar"
        self.receipt = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_image(self, *, config: dict[str, object], layers: list[dict[str, bytes]]) -> str:
        config_payload = json.dumps(config, sort_keys=True).encode()
        config_sha = hashlib.sha256(config_payload).hexdigest()
        config_name = f"{config_sha}.json"
        layer_names = [f"layer-{index}.tar" for index in range(len(layers))]
        manifest_payload = json.dumps(
            [{"Config": config_name, "RepoTags": [], "Layers": layer_names}], sort_keys=True
        ).encode()
        outer_files = {
            "manifest.json": manifest_payload,
            config_name: config_payload,
            **{name: tar_bytes(files) for name, files in zip(layer_names, layers, strict=True)},
        }
        self.image.write_bytes(tar_bytes(outer_files))
        return config_sha

    def run_scan(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.image), "--output", str(self.receipt)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_clean_archive_passes_and_binds_config(self) -> None:
        config_sha = self.write_image(
            config={"config": {"Env": ["LANG=C.UTF-8"], "Labels": {}}, "history": []},
            layers=[{"usr/bin/example": b"safe runtime bytes"}],
        )
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["input"]["configSha256"], config_sha)
        self.assertEqual(receipt["coverage"]["layers"], 1)

    def test_secret_in_historical_deleted_layer_still_fails(self) -> None:
        self.write_image(
            config={"config": {"Env": ["LANG=C.UTF-8"], "Labels": {}}, "history": []},
            layers=[
                {"workspace/.env": b"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890"},
                {"workspace/.wh..wh..opq": b""},
            ],
        )
        result = self.run_scan()
        self.assertEqual(result.returncode, 2)
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt["outcome"], "failed")
        kinds = {finding["kind"] for finding in receipt["findings"]}
        self.assertIn("sensitive_path", kinds)
        self.assertIn("openai_api_key", kinds)
        self.assertEqual(receipt["coverage"]["layers"], 2)

    def test_secret_environment_and_history_assignment_fail(self) -> None:
        self.write_image(
            config={
                "config": {
                    "Env": ["API_TOKEN=abcdefghijk"],
                    "Labels": {"private_key": "abcdefghijk"},
                },
                "history": [{"created_by": "RUN API_TOKEN=abcdefghijk command"}],
            },
            layers=[{"usr/bin/example": b"safe"}],
        )
        result = self.run_scan()
        self.assertEqual(result.returncode, 2)
        receipt = json.loads(self.receipt.read_text())
        kinds = {finding["kind"] for finding in receipt["findings"]}
        self.assertIn("sensitive_environment", kinds)
        self.assertIn("sensitive_config_key", kinds)
        self.assertIn("sensitive_history_assignment", kinds)


if __name__ == "__main__":
    unittest.main()
