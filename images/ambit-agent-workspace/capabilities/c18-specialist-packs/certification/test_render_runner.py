from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

from render_command import RenderCommandError  # noqa: E402
from render_runner import (  # noqa: E402
    _atomic_publish,
    _adapter_proofs,
    _close_semantic_job_roots,
    _fact_value,
    _job_root_from_request_argument,
    _read_exact_regular_file,
    _reprove_semantic_roots,
    _semantic_job_roots,
)


class RenderRunnerTests(unittest.TestCase):
    def test_fd_anchors_control_reads_and_output_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            job_root = Path(temporary) / "job"
            inputs = job_root / "inputs"
            outputs = job_root / "outputs"
            inputs.mkdir(parents=True)
            outputs.mkdir()
            source = inputs / "source.txt"
            source.write_text("source", encoding="utf-8")
            roots = _semantic_job_roots(str(job_root))
            try:
                self.assertEqual(
                    _read_exact_regular_file(
                        roots.inputs_fd,
                        "source.txt",
                        minimum_bytes=1,
                        maximum_bytes=16,
                    ),
                    b"source",
                )
                _atomic_publish("outputs/render/result.json", b"result", roots)
                self.assertEqual(
                    (outputs / "render/result.json").read_bytes(),
                    b"result",
                )
                with self.assertRaisesRegex(RenderCommandError, "already exists"):
                    _atomic_publish("outputs/render/result.json", b"changed", roots)
            finally:
                _close_semantic_job_roots(roots)

    def test_rejects_hardlinked_or_symlinked_control_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            job_root = Path(temporary) / "job"
            inputs = job_root / "inputs"
            (job_root / "outputs").mkdir(parents=True)
            inputs.mkdir()
            request = inputs / "request.json"
            request.write_bytes(b"{}")
            os.link(request, inputs / "request-hardlink.json")
            roots = _semantic_job_roots(str(job_root))
            try:
                with self.assertRaisesRegex(RenderCommandError, "exact bounded"):
                    _read_exact_regular_file(
                        roots.inputs_fd,
                        "request.json",
                        minimum_bytes=1,
                        maximum_bytes=16,
                    )
                request.unlink()
                (inputs / "request-hardlink.json").unlink()
                real = inputs / "real.json"
                real.write_bytes(b"{}")
                (inputs / "request.json").symlink_to(real)
                with self.assertRaises(OSError):
                    _read_exact_regular_file(
                        roots.inputs_fd,
                        "request.json",
                        minimum_bytes=1,
                        maximum_bytes=16,
                    )
            finally:
                _close_semantic_job_roots(roots)

    def test_rejects_rename_then_symlink_ancestor_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            ambit = workspace / ".ambit"
            job_root = (
                ambit
                / "render-jobs"
                / "018f6f56-7b2c-7d20-8a1f-a8022ef17aaa"
            )
            (job_root / "inputs").mkdir(parents=True)
            (job_root / "outputs").mkdir()
            roots = _semantic_job_roots(str(job_root))
            moved = workspace / ".ambit-real"
            ambit.rename(moved)
            ambit.symlink_to(moved, target_is_directory=True)
            try:
                with self.assertRaisesRegex(
                    RenderCommandError,
                    "directory is not real|ancestor identity changed",
                ):
                    _reprove_semantic_roots(roots)
                with self.assertRaises(RenderCommandError):
                    _atomic_publish("outputs/render/result.json", b"blocked", roots)
            finally:
                _close_semantic_job_roots(roots)

    def test_derives_only_policy_admitted_roots_from_exact_argv(self) -> None:
        product = (
            "/workspace/.ambit/render-jobs/"
            "018f6f56-7b2c-7d20-8a1f-a8022ef17aaa/inputs/request.json"
        )
        self.assertEqual(
            _job_root_from_request_argument(product),
            product.removesuffix("/inputs/request.json"),
        )
        self.assertEqual(
            _job_root_from_request_argument("/ambit/inputs/request.json"),
            "/ambit",
        )
        for invalid in (
            "/workspace/.ambit/render-jobs/not-a-job/inputs/request.json",
            "/workspace/.ambit/render-jobs/018f6f56-7b2c-7d20-8a1f-a8022ef17aaa/inputs/../request.json",
            "/tmp/request.json",
        ):
            with self.assertRaises(RenderCommandError):
                _job_root_from_request_argument(invalid)

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
