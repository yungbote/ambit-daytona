from __future__ import annotations

import hashlib
import io
import json
import lzma
import tarfile
import tempfile
import unittest
from pathlib import Path

from debian_lock import DebianLockError, build_lock, verify_lock


class DebianLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.debs = self.root / "debs"
        self.debs.mkdir()
        self.deb = self._build_deb("fixture", "1.2.3", "amd64")
        self.closure = self.root / "installed.lock"
        self.closure.write_text("base-files=13.8\nfixture=1.2.3\n", encoding="utf-8")
        self.indexes = [
            self._index("debian", include=True),
            self._index("debian-security", include=False),
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build_deb(self, package: str, version: str, architecture: str) -> Path:
        control = "\n".join(
            [
                f"Package: {package}",
                f"Version: {version}",
                f"Architecture: {architecture}",
                "Maintainer: Test <test@example.invalid>",
                "Description: exact fixture",
                "",
            ]
        ).encode()
        control_tar = io.BytesIO()
        with tarfile.open(fileobj=control_tar, mode="w:gz") as archive:
            info = tarfile.TarInfo("./control")
            info.size = len(control)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(control))
        data_tar = io.BytesIO()
        with tarfile.open(fileobj=data_tar, mode="w:gz"):
            pass
        output = self.debs / f"{package}_{version}_{architecture}.deb"
        output.write_bytes(
            self._ar(
                [
                    ("debian-binary", b"2.0\n"),
                    ("control.tar.gz", control_tar.getvalue()),
                    ("data.tar.gz", data_tar.getvalue()),
                ]
            )
        )
        return output

    @staticmethod
    def _ar(members: list[tuple[str, bytes]]) -> bytes:
        output = bytearray(b"!<arch>\n")
        for name, payload in members:
            header = (
                f"{name + '/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(payload):<10}`\n"
            ).encode("ascii")
            output.extend(header)
            output.extend(payload)
            if len(payload) % 2:
                output.extend(b"\n")
        return bytes(output)

    def _index(self, repository: str, *, include: bool) -> tuple[Path, str]:
        path = self.root / f"{repository}-Packages.xz"
        content = ""
        if include:
            digest = hashlib.sha256(self.deb.read_bytes()).hexdigest()
            content = "\n".join(
                [
                    "Package: fixture",
                    "Version: 1.2.3",
                    "Architecture: amd64",
                    "Filename: pool/f/fixture.deb",
                    f"Size: {self.deb.stat().st_size}",
                    f"SHA256: {digest}",
                    "",
                    "",
                ]
            )
        with lzma.open(path, "wt", encoding="utf-8") as output:
            output.write(content)
        return path, repository

    def _lock(self) -> dict[str, object]:
        return build_lock(
            self.debs,
            pack_ref="ambit.runtime-pack/test@1",
            requested_packages=["fixture=1.2.3"],
            installed_closure=self.closure,
            package_indexes=self.indexes,
        )

    def test_freezes_and_replays_exact_signed_index_membership(self) -> None:
        lock = self._lock()
        self.assertEqual(lock["archiveCount"], 1)
        self.assertEqual(
            lock["archives"][0]["signedLocations"],
            [{"repository": "debian", "repositoryPath": "pool/f/fixture.deb"}],
        )
        lock_path = self.root / "lock.json"
        lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
        self.assertEqual(
            verify_lock(lock_path, self.debs, self.closure, self.indexes),
            lock,
        )

    def test_rejects_unsigned_substitution_and_missing_direct_package(self) -> None:
        original = self.deb.read_bytes()
        tampered = bytearray(original)
        data_header = tampered.index(b"data.tar.gz/")
        tampered[data_header + 60] ^= 1
        self.deb.write_bytes(tampered)
        with self.assertRaisesRegex(DebianLockError, "signed package index"):
            self._lock()
        self.deb.write_bytes(original)
        with self.assertRaisesRegex(DebianLockError, "requested packages are absent"):
            build_lock(
                self.debs,
                pack_ref="ambit.runtime-pack/test@1",
                requested_packages=["missing=1"],
                installed_closure=self.closure,
                package_indexes=self.indexes,
            )

    def test_rejects_unclosed_directory_and_unsorted_installed_closure(self) -> None:
        (self.debs / "README").write_text("not a package", encoding="utf-8")
        with self.assertRaisesRegex(DebianLockError, "unexpected entries"):
            self._lock()
        (self.debs / "README").unlink()
        self.closure.write_text("fixture=1.2.3\nbase-files=13.8\n", encoding="utf-8")
        with self.assertRaisesRegex(DebianLockError, "sorted"):
            self._lock()

    def test_rejects_duplicate_json_keys(self) -> None:
        lock_path = self.root / "lock.json"
        lock_path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
        with self.assertRaisesRegex(DebianLockError, "duplicate JSON key"):
            verify_lock(lock_path, self.debs, self.closure, self.indexes)

    def test_rejects_mutable_base_image(self) -> None:
        with self.assertRaisesRegex(DebianLockError, "immutable sha256"):
            build_lock(
                self.debs,
                pack_ref="ambit.runtime-pack/test@1",
                requested_packages=["fixture=1.2.3"],
                installed_closure=self.closure,
                package_indexes=self.indexes,
                base_image="docker.io/library/debian:latest",
            )


if __name__ == "__main__":
    unittest.main()
