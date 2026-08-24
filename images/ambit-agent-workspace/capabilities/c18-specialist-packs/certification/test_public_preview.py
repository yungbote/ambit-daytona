from __future__ import annotations

import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path


PROTOCOL_ROOT = Path(__file__).resolve().parents[1] / "protocol"
sys.path.insert(0, str(PROTOCOL_ROOT))

from public_preview import (  # noqa: E402
    PublicPreviewError,
    create_preview,
    encode_preview,
    parse_preview_bytes,
)


class PublicPreviewTests(unittest.TestCase):
    def test_matches_all_frozen_backend_goldens(self) -> None:
        root = Path(__file__).resolve().parents[1] / "protocol"
        lock = json.loads((root / "public-preview-authority.lock.json").read_text())
        goldens_path = root / lock["goldens"]
        self.assertEqual(
            "sha256:" + hashlib.sha256(goldens_path.read_bytes()).hexdigest(),
            lock["authority"]["goldensSha256"],
        )
        goldens = json.loads(goldens_path.read_text())
        self.assertEqual(len(goldens["goldens"]), 6)
        for golden in goldens["goldens"]:
            encoded = golden["canonicalJson"].encode()
            preview = parse_preview_bytes(encoded)
            self.assertEqual(preview["facet"], golden["facet"])
            self.assertEqual(
                "sha256:" + hashlib.sha256(encoded).hexdigest(),
                golden["bytesDigest"],
            )

    def test_matches_the_backend_data_analysis_golden_byte_for_byte(self) -> None:
        body = b"data analysis preview\n"
        preview = create_preview(
            {
                "facet": "data_analysis",
                "title": "Data analysis preview",
                "summary": "One safe text view for the data analysis specialist artifact.",
                "views": [
                    {
                        "kind": "text",
                        "ordinal": 1,
                        "label": "Preview",
                        "mediaType": "text/plain",
                        "byteLength": len(body),
                        "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
                        "body": body.decode(),
                    }
                ],
                "facts": [{"key": "view_count", "label": "Views", "value": "1"}],
                "validation": [
                    {
                        "check": "safe_preview_encoding",
                        "label": "Safe preview encoding",
                        "status": "passed",
                    }
                ],
                "limitations": [],
            }
        )
        encoded = encode_preview(preview)
        self.assertEqual(
            preview["digest"],
            "sha256:3726121b0514f2ee71aad8111af21d1105858902ca49d55216995719d610fc72",
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(encoded).hexdigest(),
            "sha256:0641558ee3bd102f5ec21001c1267808be700ff899e52dca21a9396c11865863",
        )
        self.assertEqual(parse_preview_bytes(encoded), preview)

    def test_accepts_safe_png_and_rejects_active_or_forged_content(self) -> None:
        png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZFP8AAAAASUVORK5CYII="
        )
        preview = create_preview(
            {
                "facet": "web_application",
                "title": "Web preview",
                "summary": "One safe browser image.",
                "views": [
                    {
                        "kind": "image",
                        "ordinal": 1,
                        "label": "Preview",
                        "altText": "One pixel browser preview.",
                        "mediaType": "image/png",
                        "width": 1,
                        "height": 1,
                        "byteLength": len(png),
                        "digest": "sha256:" + hashlib.sha256(png).hexdigest(),
                        "bodyBase64": base64.b64encode(png).decode(),
                    }
                ],
                "facts": [],
                "validation": [
                    {"check": "web.render", "label": "Web render", "status": "passed"}
                ],
                "limitations": [],
            }
        )
        self.assertEqual(parse_preview_bytes(encode_preview(preview)), preview)
        with self.assertRaises(PublicPreviewError):
            create_preview(
                {
                    **{key: preview[key] for key in ("facet", "facts", "limitations", "summary", "title", "validation")},
                    "views": [{**preview["views"][0], "mediaType": "text/html"}],
                }
            )
        forged = bytearray(encode_preview(preview))
        forged[-2] ^= 1
        with self.assertRaises(PublicPreviewError):
            parse_preview_bytes(bytes(forged))

    def test_requires_sorted_checks_and_keeps_failure_private(self) -> None:
        base = {
            "facet": "pdf",
            "title": "PDF preview",
            "summary": "Safe text preview.",
            "views": [
                {
                    "kind": "text",
                    "ordinal": 1,
                    "label": "Text",
                    "mediaType": "text/plain",
                    "byteLength": 2,
                    "digest": "sha256:" + hashlib.sha256(b"x\n").hexdigest(),
                    "body": "x\n",
                }
            ],
            "facts": [],
            "limitations": [],
        }
        with self.assertRaisesRegex(PublicPreviewError, "sorted"):
            create_preview(
                {
                    **base,
                    "validation": [
                        {"check": "z.check", "label": "Z", "status": "passed"},
                        {"check": "a.check", "label": "A", "status": "passed"},
                    ],
                }
            )
        with self.assertRaisesRegex(PublicPreviewError, "status"):
            create_preview(
                {
                    **base,
                    "validation": [
                        {"check": "pdf.decode", "label": "Decode", "status": "failed"}
                    ],
                }
            )


if __name__ == "__main__":
    unittest.main()
