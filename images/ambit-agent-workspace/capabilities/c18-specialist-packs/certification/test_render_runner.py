from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

from render_command import RenderCommandError  # noqa: E402
from render_runner import _adapter_proofs, _fact_value  # noqa: E402


class RenderRunnerTests(unittest.TestCase):
    def test_normalizes_real_observations_and_assigns_each_artifact_once(self) -> None:
        request = {
            "packRequiredChecks": [
                {"check": "web.accessibility_rules", "label": "Accessibility"},
                {"check": "web.viewport_matrix", "label": "Viewport matrix"},
            ]
        }
        proofs = _adapter_proofs(
            request,
            {
                "web.accessibility_rules": {
                    "check": "web.accessibility_rules",
                    "sourceDigest": "sha256:" + "a" * 64,
                    "violationCount": 0,
                },
                "web.viewport_matrix": {
                    "check": "web.viewport_matrix",
                    "browserVersions": {"chromium": "151.0.7922.34"},
                    "caseCount": 9,
                },
            },
            [
                {
                    "check": "web.viewport_matrix",
                    "mediaType": "image/png",
                    "name": "chromium-mobile.png",
                    "sourcePath": "/tmp/chromium-mobile.png",
                }
            ],
        )
        self.assertEqual(
            proofs["web.accessibility_rules"]["facts"]["source_digest"],
            "sha256:" + "a" * 64,
        )
        self.assertEqual(
            proofs["web.accessibility_rules"]["facts"]["violation_count"],
            "0",
        )
        self.assertEqual(
            proofs["web.viewport_matrix"]["artifacts"][0]["name"],
            "chromium-mobile.png",
        )

    def test_rejects_ambiguous_facts_and_artifact_ownership(self) -> None:
        request = {
            "packRequiredChecks": [
                {"check": "web.viewport_matrix", "label": "Viewport matrix"}
            ]
        }
        with self.assertRaisesRegex(RenderCommandError, "collide"):
            _adapter_proofs(
                request,
                {
                    "web.viewport_matrix": {
                        "check": "web.viewport_matrix",
                        "caseCount": 9,
                        "case_count": 9,
                    }
                },
                [],
            )
        with self.assertRaisesRegex(RenderCommandError, "ownership"):
            _adapter_proofs(
                request,
                {
                    "web.viewport_matrix": {
                        "check": "web.viewport_matrix",
                        "caseCount": 9,
                    }
                },
                [
                    {
                        "check": "web.console_policy",
                        "mediaType": "application/zip",
                        "name": "trace.zip",
                        "sourcePath": "/tmp/trace.zip",
                    }
                ],
            )

    def test_hashes_only_values_that_exceed_the_bounded_fact_lane(self) -> None:
        self.assertEqual(_fact_value("plain exact value"), "plain exact value")
        self.assertRegex(_fact_value({"large": "x" * 1_024}), r"^sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
