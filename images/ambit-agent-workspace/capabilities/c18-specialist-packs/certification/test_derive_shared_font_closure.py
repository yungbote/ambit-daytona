from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from derive_shared_font_closure import derive


def sha(seed: str) -> str:
    return "sha256:" + seed * 64


class SharedFontClosureTests(unittest.TestCase):
    def test_derives_one_exact_snapshot_compatible_font_union(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            common = {
                "schema": "ambit.c18-debian-binary-closure-lock/v1",
                "platform": "linux/amd64",
                "baseImage": "registry.test/python@" + sha("1"),
                "snapshots": {"debian": {"digest": sha("2")}},
                "signaturePolicy": {"required": True},
                "resolution": {"mode": "offline"},
            }
            source = {
                **common,
                "packRef": "ambit.runtime-pack/source@1",
                "requestedPackages": ["fonts-test=1"],
                "archiveCount": 1,
                "transitiveGraphDigest": sha("3"),
                "archives": [
                    {
                        "package": "fonts-test",
                        "version": "1",
                        "architecture": "all",
                        "localFilename": "fonts-test_1_all.deb",
                        "sha256": sha("4"),
                        "bytes": 1,
                        "signedLocations": [{"repository": "debian", "repositoryPath": "pool/fonts-test.deb"}],
                    }
                ],
                "installedClosure": {"entryCount": 1, "sha256": sha("5")},
            }
            target = {
                **common,
                "packRef": "ambit.runtime-pack/target@1",
                "requestedPackages": ["target=1"],
                "archiveCount": 1,
                "transitiveGraphDigest": sha("6"),
                "archives": [
                    {
                        "package": "target",
                        "version": "1",
                        "architecture": "amd64",
                        "localFilename": "target_1_amd64.deb",
                        "sha256": sha("7"),
                        "bytes": 1,
                        "signedLocations": [{"repository": "debian", "repositoryPath": "pool/target.deb"}],
                    }
                ],
                "installedClosure": {"entryCount": 1, "sha256": sha("8")},
            }
            source_path = root / "source.json"
            target_path = root / "target.json"
            font_set_path = root / "fonts.json"
            installed_path = root / "installed.lock"
            source_path.write_text(json.dumps(source), encoding="utf-8")
            target_path.write_text(json.dumps(target), encoding="utf-8")
            font_set_path.write_text(
                json.dumps({"packages": ["fonts-test=1"]}), encoding="utf-8"
            )
            installed_path.write_text("target=1\n", encoding="utf-8")
            lock, installed, manifest = derive(
                source_path, target_path, font_set_path, installed_path
            )
            self.assertEqual(lock["requestedPackages"], ["fonts-test=1", "target=1"])
            self.assertEqual(lock["archiveCount"], 2)
            self.assertEqual(installed, b"fonts-test=1\ntarget=1\n")
            self.assertIn(b"debian/fonts-test_1_all.deb", manifest)


if __name__ == "__main__":
    unittest.main()
