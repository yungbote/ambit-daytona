from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

from render_command import RenderCommandError  # noqa: E402
from render_runner import (  # noqa: E402
    _absolute_protocol_path,
    _adapter_proofs,
    _fact_value,
    _require_nonsymlink_chain,
    _semantic_job_roots,
)


class RenderRunnerTests(unittest.TestCase):
    def test_binds_real_job_directories_and_rejects_path_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            job_root = Path(temporary) / "job"
            inputs = job_root / "inputs"
            outputs = job_root / "outputs"
            inputs.mkdir(parents=True)
            outputs.mkdir()
            source = inputs / "source.txt"
            source.write_text("source", encoding="utf-8")
            roots = _semantic_job_roots({"jobRoot": str(job_root)})
            self.assertEqual(
                _absolute_protocol_path("inputs/source.txt", inputs, roots),
                source,
            )
            _require_nonsymlink_chain(
                source,
                inputs,
                final_may_be_absent=False,
            )

            alias = inputs / "alias.txt"
            alias.symlink_to(source)
            with self.assertRaisesRegex(RenderCommandError, "symlink"):
                _require_nonsymlink_chain(
                    alias,
                    inputs,
                    final_may_be_absent=False,
                )
            with self.assertRaisesRegex(RenderCommandError, "escapes"):
                _absolute_protocol_path("outputs/result.json", inputs, roots)

            moved = job_root.with_name("moved")
            job_root.rename(moved)
            (job_root / "inputs").mkdir(parents=True)
            (job_root / "outputs").mkdir()
            with self.assertRaisesRegex(RenderCommandError, "identity changed"):
                _absolute_protocol_path("inputs/source.txt", inputs, roots)

        with tempfile.TemporaryDirectory() as temporary:
            real = Path(temporary) / "real"
            (real / "inputs").mkdir(parents=True)
            (real / "outputs").mkdir()
            alias = Path(temporary) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(RenderCommandError, "alias"):
                _semantic_job_roots({"jobRoot": str(alias)})

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
