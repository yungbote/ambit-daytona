from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from render_browser_seccomp import (
    RENDER_CONTROL_SYSCALLS,
    ROOTLESS_BROWSER_SYSCALLS,
    BrowserSeccompError,
    render_profile,
)


SOURCE = Path(__file__).resolve().parents[1] / "policy/playwright-seccomp-v1.62.1.json"
RENDERED = Path(__file__).resolve().parents[1] / "policy/specialist-seccomp-v1.json"


class BrowserSeccompTests(unittest.TestCase):
    def test_derives_one_deny_by_default_rootless_browser_profile(self) -> None:
        rendered = render_profile(SOURCE)
        profile = json.loads(rendered)
        upstream = json.loads(SOURCE.read_text())
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")
        self.assertEqual(
            profile["syscalls"][0]["names"],
            list(ROOTLESS_BROWSER_SYSCALLS),
        )
        self.assertEqual(
            set(profile["syscalls"][0]["names"])
            - set(upstream["syscalls"][0]["names"]),
            {"chroot", "clone3"},
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
        common = profile["syscalls"][1]
        upstream_common = upstream["syscalls"][1]
        openat = upstream_common["names"].index("openat")
        self.assertEqual(
            common["names"],
            [
                *upstream_common["names"][: openat + 1],
                *RENDER_CONTROL_SYSCALLS,
                *upstream_common["names"][openat + 1 :],
            ],
        )
        self.assertEqual(
            set(common["names"]) - set(upstream_common["names"]),
            set(RENDER_CONTROL_SYSCALLS),
        )
        self.assertEqual(
            {key: value for key, value in common.items() if key != "names"},
            {key: value for key, value in upstream_common.items() if key != "names"},
        )
        self.assertEqual(profile["syscalls"][2:], upstream["syscalls"][2:])
        self.assertEqual(
            hashlib.sha256(rendered).hexdigest(),
            "9de0b08286e0c0ba068eb8f6bf9e2aa49860327b654b8f0b20bcabc4fdc796f2",
        )
        self.assertEqual(RENDERED.read_bytes(), rendered)

    def test_rejects_upstream_byte_or_rule_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            drifted = Path(temporary) / "profile.json"
            drifted.write_bytes(SOURCE.read_bytes() + b"\n")
            with self.assertRaisesRegex(BrowserSeccompError, "digest"):
                render_profile(drifted)


if __name__ == "__main__":
    unittest.main()
