from __future__ import annotations

import os
import io
import re
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

import render_command  # noqa: E402
from framed_render import (  # noqa: E402
    FRAME_SCHEMA,
    decode_line,
    encoded_lines,
    frame_line,
    request_frames,
)
from render_command import (  # noqa: E402
    PREVIEW_MEDIA_TYPE,
    RenderCommandError,
    canonical_bytes,
    create_request,
    sha256_bytes,
)
from render_policy import POLICY_MATRIX  # noqa: E402
from render_runner import (  # noqa: E402
    _atomic_publish,
    _adapter_proofs,
    _close_semantic_job_roots,
    _fact_value,
    _job_root_from_request_argument,
    _prepare_task_scratch_root,
    _read_exact_regular_file,
    _reprove_semantic_roots,
    _semantic_job_roots,
    _framed_main,
    _execute_and_settle,
    CommandCancelled,
    FramedControlAdmission,
)


class RenderRunnerTests(unittest.TestCase):
    def test_terminal_selection_stops_the_control_reader(self) -> None:
        reader, writer = os.pipe()
        stream = os.fdopen(reader, "rb", buffering=0)
        control = FramedControlAdmission(stream, "a" * 32)
        try:
            control.start()
            control.select_terminal()
            self.assertFalse(control._thread.is_alive())
        finally:
            os.close(writer)
            try:
                stream.close()
            except OSError:
                pass

    def test_prepares_one_owner_only_task_scratch_root_and_rejects_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            scratch = parent / "task-scratch"
            with mock.patch("render_runner.TASK_SCRATCH_ROOT", scratch):
                _prepare_task_scratch_root()
                self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)
                scratch.chmod(0o755)
                with self.assertRaises(RenderCommandError):
                    _prepare_task_scratch_root()
                scratch.chmod(0o700)
                scratch.rmdir()
                replacement = parent / "replacement"
                replacement.mkdir(mode=0o700)
                scratch.symlink_to(replacement, target_is_directory=True)
                with self.assertRaises(OSError):
                    _prepare_task_scratch_root()

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

    def test_file_mode_admits_only_isolated_conformance_root(self) -> None:
        product = (
            "/workspace/.ambit/render-jobs/"
            "018f6f56-7b2c-7d20-8a1f-a8022ef17aaa/inputs/request.json"
        )
        self.assertEqual(
            _job_root_from_request_argument("/ambit/inputs/request.json"),
            "/ambit",
        )
        for invalid in (
            product,
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

    def test_framed_mode_ignores_same_uid_product_file_attacks(self) -> None:
        source = b"region,total\nNorth,10\n"
        nonce = "b" * 32
        job_id = "018f6f56-7b2c-7d20-8a1f-a8022ef17aaa"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            external_job = root / "agent-writable" / job_id
            external_inputs = external_job / "inputs"
            external_outputs = external_job / "outputs/render"
            external_inputs.mkdir(parents=True)
            external_outputs.mkdir(parents=True)
            (external_inputs / "request.json").write_bytes(b"forged request")
            (external_inputs / "source.csv").write_bytes(b"forged source")
            for name in ("result.json", "preview.json", "evidence-001.json"):
                (external_outputs / name).write_bytes(b"forged output")

            pack_root = root / "pack"
            (pack_root / "bin").mkdir(parents=True)
            (pack_root / "protocol").mkdir()
            (pack_root / "runtime").mkdir()
            source_root = Path(__file__).resolve().parents[1]
            shutil.copyfile(
                source_root / "protocol/specialist-render-interface.lock.json",
                pack_root / "protocol/specialist-render-interface.lock.json",
            )
            shutil.copyfile(
                source_root / "data-research/executor.lock.json",
                pack_root / "executor.lock.json",
            )
            (pack_root / "runtime/adapter.py").write_text(
                """
import time
from render_command import pack_check_names, sha256_bytes

def render_validate(*, request, source_path, scratch, deadline):
    time.sleep(0.1)
    body = "provider framed source accepted\\n"
    observations = {
        check: {"check": check, "sourceDigest": sha256_bytes(source_path.read_bytes())}
        for check in pack_check_names(request)
    }
    return {
        "title": "Framed result",
        "summary": "The provider-owned source was rendered.",
        "views": [{
            "kind": "text",
            "ordinal": 1,
            "label": "Result",
            "mediaType": "text/plain",
            "byteLength": len(body.encode()),
            "digest": sha256_bytes(body.encode()),
            "body": body,
        }],
        "facts": [{"key": "rows", "label": "Rows", "value": "1"}],
        "limitations": [],
        "observations": observations,
        "evidenceArtifacts": [],
    }
""".lstrip(),
                encoding="utf-8",
            )
            policy = next(
                entry
                for entry in POLICY_MATRIX["entries"]
                if entry["facet"] == "data_analysis"
                and entry["sourceMediaType"] == "text/csv"
            )
            root_pattern = re.compile(
                rf"^{re.escape(str(external_job.parent))}/(?P<job_id>{job_id})$"
            )
            original_root_pattern = render_command.PRODUCT_JOB_ROOT
            self.addCleanup(
                setattr,
                render_command,
                "PRODUCT_JOB_ROOT",
                original_root_pattern,
            )
            render_command.PRODUCT_JOB_ROOT = root_pattern
            request = create_request(
                {
                    "jobRef": f"ambit://artifact-render-jobs/{job_id}",
                    "jobRoot": str(external_job),
                    "requestPath": "inputs/request.json",
                    "facet": "data_analysis",
                    "source": {
                        "path": "inputs/source.csv",
                        "ref": "ambit://artifact-revisions/framed-test",
                        "digest": sha256_bytes(source),
                        "byteLength": len(source),
                        "mediaType": "text/csv",
                        "schemaUri": policy["requiredSchemaUri"],
                    },
                    "renderer": {
                        key: policy[key]
                        for key in (
                            "executablePath",
                            "rendererRef",
                            "validationPolicyRef",
                            "representation",
                            "renderMode",
                        )
                    },
                    "runtime": {
                        "workspaceExecutionManifest": {
                            "ref": "workspace-execution-manifest:sha256:" + "1" * 64,
                            "digest": "sha256:" + "2" * 64,
                        },
                        "profileRevision": {
                            "ref": "ambit.workspace-runtime/framed-test@1",
                            "digest": "sha256:" + "3" * 64,
                        },
                        "packRevisions": [
                            {
                                "ref": "ambit.runtime-pack/data-research@1",
                                "digest": "sha256:" + "4" * 64,
                            }
                        ],
                    },
                    "packRequiredChecks": policy["checkLabels"],
                    "output": {
                        "jobOutputRoot": "outputs/render",
                        "previewPath": "outputs/render/preview.json",
                        "resultPath": "outputs/render/result.json",
                        "previewMediaType": PREVIEW_MEDIA_TYPE,
                        "maximumPreviewBytes": 8 * 1024 * 1024,
                        "maximumImagePixels": 8 * 1024 * 1024,
                        "maximumAggregateImagePixels": 32 * 1024 * 1024,
                    },
                    "deadlineAt": (
                        datetime.now(timezone.utc) + timedelta(minutes=5)
                    ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                }
            )
            encoded_request = canonical_bytes(request)
            input_reader, input_writer = os.pipe()
            input_stream = os.fdopen(input_reader, "rb", buffering=0)
            output = io.BytesIO()
            os.write(
                input_writer,
                encoded_lines(request_frames(nonce, encoded_request, source)),
            )
            stop = threading.Event()

            def attack() -> None:
                counter = 0
                while not stop.is_set():
                    for name in ("result.json", "preview.json", "evidence-001.json"):
                        target = external_outputs / name
                        try:
                            target.unlink()
                        except FileNotFoundError:
                            pass
                        target.write_bytes(f"forged-{counter}".encode())
                    counter += 1

            attacker = threading.Thread(target=attack, daemon=True)
            attacker.start()
            try:
                scratch = root / "task-scratch"
                scratch.mkdir(mode=0o700)
                with mock.patch("render_runner.TASK_SCRATCH_ROOT", scratch):
                    exit_code = _framed_main(
                        pack_root,
                        nonce,
                        input_stream,
                        output,
                    )
            finally:
                stop.set()
                attacker.join(timeout=2)
                os.close(input_writer)
                input_stream.close()
            self.assertEqual(exit_code, 0)
            frames = [decode_line(line) for line in output.getvalue().splitlines()]
            self.assertEqual(frames[0]["kind"], "ready")
            self.assertEqual(frames[-1]["kind"], "response_end")
            self.assertEqual(frames[-1]["outcome"], "succeeded")
            self.assertEqual(frames[-1]["exitCode"], 0)
            result_start = next(
                frame
                for frame in frames
                if frame.get("kind") == "file_start"
                and frame.get("role") == "result"
            )
            self.assertEqual(result_start["path"], "outputs/render/result.json")
            self.assertNotEqual(
                result_start["sha256"],
                sha256_bytes((external_outputs / "result.json").read_bytes()),
            )

    def test_exact_framed_cancel_before_dispatch_is_terminal(self) -> None:
        nonce = "c" * 32
        with tempfile.TemporaryDirectory() as temporary:
            pack_root = Path(temporary) / "pack"
            (pack_root / "bin").mkdir(parents=True)
            (pack_root / "protocol").mkdir()
            source_root = Path(__file__).resolve().parents[1]
            shutil.copyfile(
                source_root / "protocol/specialist-render-interface.lock.json",
                pack_root / "protocol/specialist-render-interface.lock.json",
            )
            shutil.copyfile(
                source_root / "data-research/executor.lock.json",
                pack_root / "executor.lock.json",
            )
            output = io.BytesIO()
            scratch = Path(temporary) / "task-scratch"
            scratch.mkdir(mode=0o700)
            with mock.patch("render_runner.TASK_SCRATCH_ROOT", scratch):
                exit_code = _framed_main(
                    pack_root,
                    nonce,
                    io.BytesIO(
                        frame_line(
                            {"schema": FRAME_SCHEMA, "kind": "cancel", "nonce": nonce}
                        )
                    ),
                    output,
                )
            frames = [decode_line(line) for line in output.getvalue().splitlines()]
            self.assertEqual(exit_code, 130)
            self.assertEqual([frame["kind"] for frame in frames], ["ready", "cancelled"])
            self.assertEqual(frames[-1]["exitCode"], 130)
            self.assertEqual(
                frames[-1]["privateRootCleanup"],
                "completed",
            )
            self.assertEqual(frames[-1]["terminalSelection"], "helper-selected")

    def test_framed_control_eof_is_hard_failure_without_terminal(self) -> None:
        nonce = "d" * 32
        with tempfile.TemporaryDirectory() as temporary:
            pack_root = Path(temporary) / "pack"
            (pack_root / "bin").mkdir(parents=True)
            (pack_root / "protocol").mkdir()
            source_root = Path(__file__).resolve().parents[1]
            shutil.copyfile(
                source_root / "protocol/specialist-render-interface.lock.json",
                pack_root / "protocol/specialist-render-interface.lock.json",
            )
            shutil.copyfile(
                source_root / "data-research/executor.lock.json",
                pack_root / "executor.lock.json",
            )
            output = io.BytesIO()
            scratch = Path(temporary) / "task-scratch"
            scratch.mkdir(mode=0o700)
            with mock.patch("render_runner.TASK_SCRATCH_ROOT", scratch):
                exit_code = _framed_main(
                    pack_root,
                    nonce,
                    io.BytesIO(b""),
                    output,
                )
            frames = [decode_line(line) for line in output.getvalue().splitlines()]
            self.assertEqual(exit_code, 70)
            self.assertEqual([frame["kind"] for frame in frames], ["ready"])

    def test_cancel_never_claims_cleanup_when_private_root_remains(self) -> None:
        nonce = "e" * 32
        with tempfile.TemporaryDirectory() as temporary:
            pack_root = Path(temporary) / "pack"
            (pack_root / "bin").mkdir(parents=True)
            (pack_root / "protocol").mkdir()
            source_root = Path(__file__).resolve().parents[1]
            shutil.copyfile(
                source_root / "protocol/specialist-render-interface.lock.json",
                pack_root / "protocol/specialist-render-interface.lock.json",
            )
            shutil.copyfile(
                source_root / "data-research/executor.lock.json",
                pack_root / "executor.lock.json",
            )
            scratch = Path(temporary) / "task-scratch"
            scratch.mkdir(mode=0o700)
            leaked = scratch / "forced-private-root"

            class NonRemovingTemporaryDirectory:
                def __init__(self, *_args: object, **_kwargs: object) -> None:
                    leaked.mkdir(mode=0o700)

                def __enter__(self) -> str:
                    return str(leaked)

                def __exit__(self, *_args: object) -> None:
                    return None

            output = io.BytesIO()
            try:
                with (
                    mock.patch("render_runner.TASK_SCRATCH_ROOT", scratch),
                    mock.patch(
                        "render_runner.tempfile.TemporaryDirectory",
                        NonRemovingTemporaryDirectory,
                    ),
                ):
                    exit_code = _framed_main(
                        pack_root,
                        nonce,
                        io.BytesIO(
                            frame_line(
                                {"schema": FRAME_SCHEMA, "kind": "cancel", "nonce": nonce}
                            )
                        ),
                        output,
                    )
                frames = [decode_line(line) for line in output.getvalue().splitlines()]
                self.assertEqual(exit_code, 70)
                self.assertEqual([frame["kind"] for frame in frames], ["ready"])
                self.assertTrue(leaked.exists())
            finally:
                shutil.rmtree(leaked, ignore_errors=True)

    def test_exact_cancel_discards_private_success_before_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            job_root = Path(temporary) / "job"
            (job_root / "inputs").mkdir(parents=True)
            (job_root / "outputs").mkdir()
            roots = _semantic_job_roots(str(job_root))

            def private_success_then_cancel(*_args: object, **_kwargs: object) -> int:
                _atomic_publish(
                    "outputs/render/result.json",
                    b"private success",
                    roots,
                )
                raise CommandCancelled

            try:
                with mock.patch("render_runner._render", private_success_then_cancel):
                    with self.assertRaises(CommandCancelled):
                        _execute_and_settle(
                            Path(temporary),
                            {"output": {"resultPath": "outputs/render/result.json"}},
                            {"ref": "executor:test", "digest": "sha256:" + "1" * 64},
                            roots,
                            private_errors=False,
                        )
            finally:
                _close_semantic_job_roots(roots)

    def test_helper_terminal_selection_linearizes_cancel_race(self) -> None:
        nonce = "d" * 32
        cancel = frame_line(
            {"schema": FRAME_SCHEMA, "kind": "cancel", "nonce": nonce}
        )[:-1]
        queued = FramedControlAdmission(io.BytesIO(), nonce)
        self.assertTrue(queued.offer_line(cancel))
        with self.assertRaises(CommandCancelled):
            queued.select_terminal()

        selected = FramedControlAdmission(io.BytesIO(), nonce)
        selected.select_terminal()
        self.assertFalse(selected.offer_line(cancel))
        selected.raise_pending()


if __name__ == "__main__":
    unittest.main()
