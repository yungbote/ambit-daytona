from __future__ import annotations

import gzip
import io
import tarfile
import unittest
from pathlib import Path

from build_candidate import (
    CandidateBuildError,
    HELPER_PATH,
    HELPER_SHA256,
    _build_command,
    _inspect_layer,
)


class CandidateBuildTests(unittest.TestCase):
    def test_build_command_is_cold_offline_identity_bound_oci(self) -> None:
        identity = {
            "sourceDateEpoch": 1,
            "revision": "1" * 40,
            "repositoryTree": "2" * 40,
            "subtree": "3" * 40,
            "archiveSha256": "sha256:" + "4" * 64,
            "contextSha256": "sha256:" + "5" * 64,
            "sourceFilesManifestSha256": "sha256:" + "6" * 64,
            "sourceModesManifestSha256": "sha256:" + "7" * 64,
            "identitySha256": "sha256:" + "8" * 64,
        }
        command = _build_command(
            builder="test-builder",
            source_context=Path("/source"),
            source_identity_root=Path("/identity"),
            materializer_inputs=Path("/materializer"),
            source_identity=identity,
            oci_archive=Path("/out/candidate.oci.tar"),
            metadata=Path("/out/metadata.json"),
        )
        self.assertIn("--no-cache", command)
        self.assertIn("--pull=false", command)
        self.assertIn("--provenance=false", command)
        self.assertIn("--sbom=false", command)
        self.assertIn("source_identity=/identity", command)
        self.assertIn("materializer_inputs=/materializer", command)
        self.assertIn(
            "type=oci,dest=/out/candidate.oci.tar,rewrite-timestamp=true", command
        )
        self.assertIn("BUILD_SOURCE_IDENTITY_SHA256=sha256:" + "8" * 64, command)

    def test_layer_scanner_rejects_helper_digest_substitution(self) -> None:
        layer = self._layer([(HELPER_PATH, bytes.fromhex(HELPER_SHA256), 0o555)])
        with self.assertRaisesRegex(CandidateBuildError, "materializer differs"):
            _inspect_layer(layer, 0)

    def test_layer_scanner_rejects_installer_payload(self) -> None:
        layer = self._layer([("usr/bin/apt-get", b"fixture", 0o755)])
        with self.assertRaisesRegex(CandidateBuildError, "installer executable"):
            _inspect_layer(layer, 0)

    def test_layer_scanner_rejects_package_manager_state(self) -> None:
        layer = self._layer([("var/lib/dpkg/status", b"fixture", 0o644)])
        with self.assertRaisesRegex(CandidateBuildError, "package-manager state"):
            _inspect_layer(layer, 0)

    @staticmethod
    def _layer(entries: list[tuple[str, bytes, int]]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:") as archive:
            for name, data, mode in entries:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = mode
                member.uid = 0
                member.gid = 0
                archive.addfile(member, io.BytesIO(data))
        return gzip.compress(buffer.getvalue(), mtime=0)


if __name__ == "__main__":
    unittest.main()
