from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT / "protocol"))

from render_command import (  # noqa: E402
    MAXIMUM_OFFICE_SOURCE_BYTES,
    MAXIMUM_PDF_BYTES,
    OFFICE_SOURCE_SUFFIXES,
    RenderCommandError,
    canonical_bytes,
    create_pdf_request,
    create_result,
    parse_request_bytes,
    parse_result_bytes,
    sha256_bytes,
)
from render_policy import require_request_policy  # noqa: E402
from render_runner import _load_executor  # noqa: E402


JOB_ID = "019926c3-9132-8ad4-b05b-51b652ed07c4"
EXECUTOR = json.loads((SOURCE_ROOT / "office-authoring/executor.lock.json").read_text())
EXECUTOR_PIN = {key: EXECUTOR[key] for key in ("ref", "digest")}


def request_body(media_type: str | None = None) -> dict:
    media_type = media_type or next(iter(OFFICE_SOURCE_SUFFIXES))
    return {
        "jobRef": f"ambit://artifact-render-jobs/{JOB_ID}",
        "jobRoot": f"/workspace/.ambit/render-jobs/{JOB_ID}",
        "requestPath": "inputs/request.json",
        "source": {
            "path": "inputs/source" + OFFICE_SOURCE_SUFFIXES[media_type],
            "ref": "ambit://document-sources/sha256/" + "1" * 64,
            "digest": "sha256:" + "1" * 64,
            "byteLength": 10,
            "mediaType": media_type,
            "schemaUri": None,
        },
        "renderer": {
            "executablePath": "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render",
            "rendererRef": "ambit.renderer/office-pdf@1",
            "policyRef": "ambit.render-policy/office-pdf@1",
        },
        "runtime": {
            "workspaceExecutionManifest": {
                "ref": "workspace-execution-manifest:sha256:" + "2" * 64,
                "digest": "sha256:" + "2" * 64,
            },
            "profileRevision": {"ref": "ambit.workspace-runtime/qualification@1", "digest": "sha256:" + "3" * 64},
            "packRevisions": [{"ref": "ambit.runtime-pack/office-authoring@2", "digest": "sha256:" + "4" * 64}],
        },
        "output": {
            "jobOutputRoot": "outputs/render",
            "resultPath": "outputs/render/result.json",
            "pdfPath": "outputs/render/document.pdf",
            "maximumPdfBytes": MAXIMUM_PDF_BYTES,
        },
        "deadlineAt": "2026-09-09T23:59:59.000Z",
    }


class OfficePdfContractTests(unittest.TestCase):
    def test_all_office_kinds_have_one_exact_policy(self) -> None:
        for media_type in OFFICE_SOURCE_SUFFIXES:
            with self.subTest(media_type=media_type):
                request = create_pdf_request(request_body(media_type))
                self.assertEqual(parse_request_bytes(canonical_bytes(request)), request)
                policy = require_request_policy(request)
                self.assertEqual(policy["sourceMediaType"], media_type)
                self.assertEqual(policy["executorPackRevisionRef"], "ambit.runtime-pack/office-authoring@2")

    def test_rejects_unsupported_kinds_and_unbounded_source_or_output(self) -> None:
        for scope, field, value in (
            ("source", "mediaType", "application/pdf"),
            ("source", "byteLength", 0),
            ("source", "byteLength", True),
            ("source", "byteLength", MAXIMUM_OFFICE_SOURCE_BYTES + 1),
            ("output", "maximumPdfBytes", 0),
            ("output", "maximumPdfBytes", MAXIMUM_PDF_BYTES + 1),
        ):
            with self.subTest(scope=scope, field=field, value=value):
                body = request_body()
                body[scope][field] = value
                with self.assertRaises(RenderCommandError):
                    create_pdf_request(body)

    def test_rejects_path_and_job_substitution(self) -> None:
        for scope, field, value in (
            ("source", "path", "inputs/request.json"),
            ("source", "path", "inputs/../source.docx"),
            ("output", "pdfPath", "outputs/other/document.pdf"),
            ("output", "pdfPath", "outputs/render/result.json"),
            ("renderer", "executablePath", "/bin/sh"),
        ):
            with self.subTest(scope=scope, field=field):
                body = request_body()
                body[scope][field] = value
                with self.assertRaises(RenderCommandError):
                    create_pdf_request(body)
        body = request_body()
        body["jobRoot"] = body["jobRoot"][:-1] + "5"
        with self.assertRaises(RenderCommandError):
            create_pdf_request(body)

    def test_an_old_office_pin_does_not_authorize_conversion(self) -> None:
        body = request_body()
        body["runtime"]["packRevisions"][0]["ref"] = "ambit.runtime-pack/office-authoring@1"
        with self.assertRaisesRegex(RenderCommandError, "exact executor pack"):
            require_request_policy(create_pdf_request(body))

    def test_result_binds_request_source_executor_and_output(self) -> None:
        request = create_pdf_request(request_body())
        pdf = b"%PDF-1.7\nqualified\n%%EOF\n"
        result = create_result(request, {
            "execution": {"executorRevision": EXECUTOR_PIN, "startedAt": "2026-09-09T23:00:00.000Z", "completedAt": "2026-09-09T23:00:01.000Z"},
            "outcome": "succeeded",
            "pdf": {"path": request["output"]["pdfPath"], "mediaType": "application/pdf", "byteLength": len(pdf), "digest": sha256_bytes(pdf)},
            "failure": None,
        })
        self.assertEqual(parse_result_bytes(request, canonical_bytes(result)), result)
        for key in ("digest", "byteLength", "mediaType"):
            corrupted = copy.deepcopy(result)
            corrupted["source"][key] = "changed"
            corrupted["digest"] = sha256_bytes(canonical_bytes({k: v for k, v in corrupted.items() if k != "digest"}))
            with self.subTest(key=key), self.assertRaises(RenderCommandError):
                parse_result_bytes(request, canonical_bytes(corrupted))
        changed = copy.deepcopy(result)
        changed["outcome"] = "failed"
        changed["failure"] = {"code": "invalid_office_source", "message": "Invalid Office source."}
        with self.assertRaises(RenderCommandError):
            parse_result_bytes(request, canonical_bytes(changed))

    def test_executor_keeps_the_existing_transport_and_both_operations(self) -> None:
        # Installed packs place the shared protocol beside their executor lock.
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            pack = Path(directory)
            (pack / "protocol").mkdir()
            shutil.copyfile(SOURCE_ROOT / "office-authoring/executor.lock.json", pack / "executor.lock.json")
            shutil.copyfile(SOURCE_ROOT / "protocol/specialist-render-interface.lock.json", pack / "protocol/specialist-render-interface.lock.json")
            self.assertEqual(_load_executor(pack, None, "convert_to_pdf"), EXECUTOR_PIN)
            self.assertEqual(_load_executor(pack, "spreadsheet", "render_validate"), EXECUTOR_PIN)
            with self.assertRaises(RenderCommandError):
                _load_executor(pack, None, "execute_code")


if __name__ == "__main__":
    unittest.main()
