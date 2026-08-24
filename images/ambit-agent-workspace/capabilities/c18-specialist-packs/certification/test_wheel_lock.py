from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from wheel_lock import WheelLockError, build_lock, verify_lock, write_lock


class WheelLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.wheels = self.root / "wheels"
        self.wheels.mkdir()
        self._wheel("alpha_pkg-1.2.3-py3-none-any.whl", "alpha-pkg", "1.2.3")
        self._wheel("beta-4.5-cp314-abi3-manylinux_2_28_x86_64.whl", "beta", "4.5")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _wheel(self, filename: str, name: str, version: str) -> Path:
        path = self.wheels / filename
        dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                f"{dist_info}/METADATA",
                f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n",
            )
            archive.writestr(f"{name.replace('-', '_')}/__init__.py", "")
        return path

    def _lock(self) -> dict[str, object]:
        return build_lock(
            self.wheels,
            pack_ref="ambit.runtime-pack/test@1",
            python_version="3.14.7",
            platform="linux/amd64",
            direct_requirements=["alpha_pkg"],
        )

    def test_freezes_and_replays_the_exact_closed_wheel_set(self) -> None:
        lock = self._lock()
        self.assertEqual(lock["resolvedDistributionCount"], 2)
        self.assertEqual(lock["directRequirements"], ["alpha-pkg"])
        self.assertEqual(
            [entry["distribution"] for entry in lock["wheels"]],
            ["alpha-pkg", "beta"],
        )
        lock_path = self.root / "wheel.lock.json"
        write_lock(lock_path, lock)
        self.assertEqual(verify_lock(lock_path, self.wheels), lock)

    def test_rejects_extra_non_wheel_input_and_missing_direct_requirement(self) -> None:
        (self.wheels / "source.tar.gz").write_bytes(b"source")
        with self.assertRaisesRegex(WheelLockError, "unexpected entries"):
            self._lock()
        (self.wheels / "source.tar.gz").unlink()
        with self.assertRaisesRegex(WheelLockError, "absent"):
            build_lock(
                self.wheels,
                pack_ref="ambit.runtime-pack/test@1",
                python_version="3.14.7",
                platform="linux/amd64",
                direct_requirements=["missing"],
            )

    def test_rejects_metadata_substitution_and_path_escape(self) -> None:
        target = self.wheels / "alpha_pkg-1.2.3-py3-none-any.whl"
        target.unlink()
        self._wheel(target.name, "other", "1.2.3")
        with self.assertRaisesRegex(WheelLockError, "matching top-level METADATA"):
            self._lock()
        target.unlink()
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr("../escape", "bad")
            archive.writestr(
                "alpha_pkg-1.2.3.dist-info/METADATA",
                "Name: alpha-pkg\nVersion: 1.2.3\n\n",
            )
        with self.assertRaisesRegex(WheelLockError, "unsafe"):
            self._lock()

    def test_ignores_nested_vendored_distribution_metadata(self) -> None:
        target = self.wheels / "alpha_pkg-1.2.3-py3-none-any.whl"
        target.unlink()
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr(
                "alpha_pkg-1.2.3.dist-info/METADATA",
                "Name: alpha-pkg\nVersion: 1.2.3\n\n",
            )
            archive.writestr(
                "alpha_pkg/_vendor/other-9.dist-info/METADATA",
                "Name: other\nVersion: 9\n\n",
            )
        self.assertEqual(self._lock()["resolvedDistributionCount"], 2)

    def test_replay_fails_on_byte_or_lock_tampering(self) -> None:
        lock_path = self.root / "wheel.lock.json"
        write_lock(lock_path, self._lock())
        target = self.wheels / "beta-4.5-cp314-abi3-manylinux_2_28_x86_64.whl"
        target.write_bytes(target.read_bytes() + b"tamper")
        with self.assertRaisesRegex(WheelLockError, "does not reproduce"):
            verify_lock(lock_path, self.wheels)

        target.write_bytes(target.read_bytes()[:-6])
        source = json.loads(lock_path.read_text())
        source["wheels"][0]["sha256"] = "sha256:" + hashlib.sha256(b"other").hexdigest()
        lock_path.write_text(json.dumps(source), encoding="utf-8")
        with self.assertRaisesRegex(WheelLockError, "does not reproduce"):
            verify_lock(lock_path, self.wheels)

    def test_rejects_duplicate_json_keys(self) -> None:
        lock_path = self.root / "wheel.lock.json"
        lock_path.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
        with self.assertRaisesRegex(WheelLockError, "duplicate JSON key"):
            verify_lock(lock_path, self.wheels)


if __name__ == "__main__":
    unittest.main()
