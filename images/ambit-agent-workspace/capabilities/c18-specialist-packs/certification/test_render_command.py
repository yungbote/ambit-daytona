from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

from render_command import (  # noqa: E402
    PREVIEW_MEDIA_TYPE,
    RenderCommandError,
    canonical_bytes,
    create_request,
    create_result,
    parse_request_bytes,
    parse_check_evidence_bytes,
    parse_result_bytes,
)

GOLDENS = json.loads(
    (PROTOCOL_ROOT / "render-command-goldens.v1.json").read_text(encoding="utf-8")
)


def digest(seed: int) -> str:
    return "sha256:" + f"{seed:064x}"


def pin(ref: str, seed: int) -> dict[str, str]:
    return {"ref": ref, "digest": digest(seed)}


class RenderCommandTests(unittest.TestCase):
    def request(self) -> dict[str, object]:
        return json.loads(GOLDENS["request"])

    def test_round_trips_exact_request_and_success_result(self) -> None:
        request = self.request()
        request_bytes = canonical_bytes(request)
        self.assertEqual(parse_request_bytes(request_bytes), request)
        self.assertEqual(
            create_request(
                {
                    key: value
                    for key, value in request.items()
                    if key not in {"contract", "digest", "operation"}
                }
            ),
            request,
        )
        checks = []
        for index, labeled in enumerate(request["packRequiredChecks"], start=1):
            check = labeled["check"]
            evidence = f"evidence-{index}".encode()
            checks.append(
                {
                    "check": check,
                    "outcome": "passed",
                    "evidence": {
                        "path": f"outputs/c18-render/test/evidence/{index:03d}-{check}.json",
                        "mediaType": "application/vnd.ambit.c18-specialist-render-check-evidence+json",
                        "byteLength": len(evidence),
                        "digest": "sha256:" + hashlib.sha256(evidence).hexdigest(),
                    },
                }
            )
        preview = b"preview"
        result = create_result(
            request,
            {
                "outcome": "succeeded",
                "execution": {
                    "executorRevision": pin(
                        "ambit://specialist-render-executors/office-authoring@1",
                        10,
                    ),
                    "startedAt": "2026-08-24T01:00:00.000Z",
                    "completedAt": "2026-08-24T01:00:01.000Z",
                },
                "preview": {
                    "path": request["output"]["previewPath"],
                    "mediaType": PREVIEW_MEDIA_TYPE,
                    "byteLength": len(preview),
                    "bytesDigest": "sha256:" + hashlib.sha256(preview).hexdigest(),
                    "envelopeDigest": digest(11),
                },
                "checks": checks,
                "failure": None,
            },
        )
        self.assertEqual(parse_result_bytes(request, canonical_bytes(result)), result)
        self.assertEqual(
            parse_result_bytes(request, GOLDENS["success"].encode("utf-8")),
            json.loads(GOLDENS["success"]),
        )
        for golden in GOLDENS["evidence"]:
            self.assertEqual(
                parse_check_evidence_bytes(golden["body"].encode("utf-8")),
                json.loads(golden["body"]),
            )

    def test_rejects_unsafe_paths_wrong_pack_and_noncanonical_bytes(self) -> None:
        body = {
            key: value
            for key, value in self.request().items()
            if key not in {"contract", "digest", "operation"}
        }
        body["source"] = {**body["source"], "path": "inputs/../source.xlsx"}
        with self.assertRaisesRegex(RenderCommandError, "path|zone"):
            create_request(body)
        body = {
            key: value
            for key, value in self.request().items()
            if key not in {"contract", "digest", "operation"}
        }
        body["renderer"] = {
            **body["renderer"],
            "executablePath": "/opt/ambit/runtime-pack/pdf-ocr/bin/ambit-specialist-render",
        }
        with self.assertRaisesRegex(RenderCommandError, "owned"):
            create_request(body)
        with self.assertRaisesRegex(RenderCommandError, "exact canonical"):
            parse_request_bytes(b" " + canonical_bytes(self.request()))

    def test_failure_cannot_publish_a_preview_or_unrequested_check(self) -> None:
        request = self.request()
        with self.assertRaises(RenderCommandError):
            create_result(
                request,
                {
                    "outcome": "failed",
                    "execution": {
                        "executorRevision": pin(
                            "ambit://specialist-render-executors/office-authoring@1",
                            10,
                        ),
                        "startedAt": "2026-08-24T01:00:00.000Z",
                        "completedAt": "2026-08-24T01:00:01.000Z",
                    },
                    "preview": {
                        "path": request["output"]["previewPath"],
                        "mediaType": PREVIEW_MEDIA_TYPE,
                        "byteLength": 1,
                        "bytesDigest": digest(12),
                        "envelopeDigest": digest(13),
                    },
                    "checks": [],
                    "failure": {"code": "failed", "message": "Failed."},
                },
            )


if __name__ == "__main__":
    unittest.main()
