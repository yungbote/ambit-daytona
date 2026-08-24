from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from render_browser_seccomp import BrowserSeccompError, render_profile


SOURCE = Path(__file__).resolve().parents[1] / "policy/playwright-seccomp-v1.62.1.json"


class BrowserSeccompTests(unittest.TestCase):
    def test_derives_one_deny_by_default_rootless_browser_profile(self) -> None:
        rendered = render_profile(SOURCE)
        profile = json.loads(rendered)
        upstream = json.loads(SOURCE.read_text())
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertEqual(
            profile["syscalls"][0]["names"],
            ["chroot", "clone", "setns", "unshare"],
        )
        self.assertEqual(
            set(profile["syscalls"][0]["names"])
            - set(upstream["syscalls"][0]["names"]),
            {"chroot"},
        )
        self.assertEqual(
            profile["syscalls"][0]["args"], upstream["syscalls"][0]["args"]
        )
        self.assertEqual(
            profile["syscalls"][0]["includes"], upstream["syscalls"][0]["includes"]
        )
        self.assertEqual(
            profile["syscalls"][0]["excludes"], upstream["syscalls"][0]["excludes"]
        )
        self.assertEqual(profile["syscalls"][1:], upstream["syscalls"][1:])
        self.assertEqual(
            hashlib.sha256(rendered).hexdigest(),
            "4e893e9d976bf12cfb01912ed62b88079bb23ff9be5ebe3a2a264798908aec42",
        )

    def test_rejects_upstream_byte_or_rule_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            drifted = Path(temporary) / "profile.json"
            drifted.write_bytes(SOURCE.read_bytes() + b"\n")
            with self.assertRaisesRegex(BrowserSeccompError, "digest"):
                render_profile(drifted)


if __name__ == "__main__":
    unittest.main()
