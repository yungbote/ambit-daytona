from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal

import pikepdf
import pypdf
from PIL import Image, ImageChops, ImageDraw, ImageFont
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas

from common import canonical_json, file_receipts, runtime_guard


PACK_REF = "ambit.runtime-pack/pdf-ocr@1"
SECRET_MARKER = "AMB1T-REDACT-ME-7421"


def create_pdf(
    path: Path,
    *,
    redaction_state: Literal["source", "visual-cover", "removed"],
) -> None:
    document = canvas.Canvas(
        str(path),
        pagesize=LETTER,
        invariant=1,
        pageCompression=1,
        initialFontName="Helvetica",
    )
    document.setTitle("Ambit C18 PDF conformance")
    document.setAuthor("Ambit C18 conformance")
    document.bookmarkPage("summary")
    document.addOutlineEntry("Summary", "summary", level=0)
    document.setFont("Helvetica-Bold", 18)
    document.drawString(72, 720, "PDF validation fixture")
    document.setFont("Helvetica", 12)
    document.drawString(72, 690, "Visible approved content: quarterly statement")
    if redaction_state in {"source", "visual-cover"}:
        document.drawString(72, 660, SECRET_MARKER)
    if redaction_state in {"visual-cover", "removed"}:
        document.setFillColorRGB(0.1, 0.1, 0.1)
        document.rect(72, 650, 220, 22, fill=1, stroke=0)
        document.setFillColorRGB(0, 0, 0)
    if redaction_state == "removed":
        document.drawString(72, 625, "Sensitive content removed, not merely covered")
    document.showPage()
    document.setFont("Helvetica", 12)
    document.drawString(72, 720, "Second page preserves the approved appendix.")
    document.save()


def create_scan(path: Path) -> None:
    image = Image.new("L", (1400, 520), color=255)
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(
        "/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf", 64
    )
    small = ImageFont.truetype(
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf", 42
    )
    draw.text((70, 55), "AMBIT OCR 2026", font=font, fill=0)
    draw.rectangle((70, 180, 1320, 430), outline=0, width=4)
    for x in (470, 870):
        draw.line((x, 180, x, 430), fill=0, width=3)
    for y in (305,):
        draw.line((70, y, 1320, y), fill=0, width=3)
    values = (("Region", "Q1", "Q2"), ("North", "120", "130"))
    for row, values_row in enumerate(values):
        for column, value in enumerate(values_row):
            draw.text((95 + column * 400, 205 + row * 125), value, font=small, fill=0)
    image.save(path, format="PPM")


def generate(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source-with-secret.pdf"
    covered = output / "visual-cover-only.pdf"
    redacted = output / "redacted.pdf"
    edited = output / "metadata-edited.pdf"
    scan = output / "scan.pgm"
    create_pdf(source, redaction_state="source")
    create_pdf(covered, redaction_state="visual-cover")
    create_pdf(redacted, redaction_state="removed")
    create_scan(scan)
    with pikepdf.open(redacted) as document:
        document.docinfo["/Subject"] = "Metadata edit preserves rendered pages"
        document.save(edited, deterministic_id=True, compress_streams=True)
    with pypdf.PdfReader(str(edited)) as reader:
        assert len(reader.pages) == 2
        assert "approved appendix" in (reader.pages[1].extract_text() or "")
    canonical_json(
        output / "fixture-manifest.json",
        {
            "schema": "ambit.c18-pdf-ocr-fixture-manifest/v1",
            "packRef": PACK_REF,
            "expectedOcrText": ["AMBIT OCR 2026", "North", "120", "130"],
            "redactedMarker": SECRET_MARKER,
            "redactionAuthoring": "not-claimed-candidate-validation-only",
            "files": file_receipts(output),
        },
    )


def finalize(output: Path) -> None:
    fixtures = output / "fixtures"
    checks = output / "checks"
    source_text = (checks / "source-with-secret.txt").read_text(encoding="utf-8")
    covered_text = (checks / "visual-cover-only.txt").read_text(encoding="utf-8")
    redacted_text = (checks / "redacted.txt").read_text(encoding="utf-8")
    edited_text = (checks / "metadata-edited.txt").read_text(encoding="utf-8")
    assert SECRET_MARKER in source_text
    assert SECRET_MARKER in covered_text
    assert SECRET_MARKER not in redacted_text
    assert SECRET_MARKER not in edited_text
    assert "Sensitive content removed" in redacted_text
    assert SECRET_MARKER in (checks / "source-with-secret.qdf.pdf").read_bytes().decode(
        "latin-1"
    )
    assert SECRET_MARKER in (checks / "visual-cover-only.qdf.pdf").read_bytes().decode(
        "latin-1"
    )
    assert SECRET_MARKER not in (checks / "redacted.qdf.pdf").read_bytes().decode("latin-1")
    assert SECRET_MARKER.encode() not in (fixtures / "redacted.pdf").read_bytes()
    _assert_deep_marker_absence(fixtures / "redacted.pdf")
    _assert_deep_marker_absence(fixtures / "metadata-edited.pdf")
    ocr_text = (checks / "ocr.txt").read_text(encoding="utf-8")
    for expected in ("AMBIT OCR 2026", "North", "120", "130"):
        assert expected in ocr_text, expected
    ocr_pdf_text = (checks / "ocr-pdf.txt").read_text(encoding="utf-8")
    assert "AMBIT OCR 2026" in ocr_pdf_text

    redacted_page = Image.open(checks / "redacted-1.png").convert("RGB")
    edited_page = Image.open(checks / "metadata-edited-1.png").convert("RGB")
    difference = ImageChops.difference(redacted_page, edited_page)
    assert difference.getbbox() is None
    source_page_two = Image.open(checks / "source-with-secret-2.png").convert("RGB")
    redacted_page_two = Image.open(checks / "redacted-2.png").convert("RGB")
    assert ImageChops.difference(source_page_two, redacted_page_two).getbbox() is None
    with pikepdf.open(checks / "pdfa.pdf") as pdfa:
        metadata = pdfa.open_metadata()
        assert metadata.get("pdfaid:part") == "2"
        assert metadata.get("pdfaid:conformance") == "B"
        output_intents = pdfa.Root.get("/OutputIntents")
        assert output_intents is not None and len(output_intents) == 1
        output_intent = output_intents[0]
        assert output_intent.get("/S") == pikepdf.Name("/GTS_PDFA1")
        assert output_intent.get("/OutputConditionIdentifier") == "sRGB"
        profile = output_intent.get("/DestOutputProfile")
        assert profile is not None and profile.get("/N") == 3
    pdfa_log = (checks / "pdfa.ghostscript.txt").read_text(encoding="utf-8")
    assert "PDF/A processing aborted" not in pdfa_log
    metadata_report = json.loads((checks / "metadata.json").read_text(encoding="utf-8"))
    assert len(metadata_report) == 1
    assert metadata_report[0]["Subject"] == "Metadata edit preserves rendered pages"
    assert SECRET_MARKER not in json.dumps(metadata_report, sort_keys=True)
    assert "does not contain any signatures" in (
        checks / "signature-inspection.txt"
    ).read_text(encoding="utf-8").lower()
    guard = runtime_guard(output / "runtime-guard.tsv")
    assert guard["pack"] == "pdf-ocr"
    pack = json.loads((Path(__file__).resolve().parents[1] / "pack.lock.json").read_text())
    required = pack["conformance"]["requiredChecks"]
    canonical_json(
        output / "conformance-receipt.json",
        {
            "schema": "ambit.runtime-pack-conformance/v3",
            "packRef": PACK_REF,
            "outcome": "passed",
            "fullImage": True,
            "network": "none",
            "runtime": guard,
            "checks": [{"ref": check, "outcome": "passed"} for check in required],
            "files": file_receipts(output),
            "signing": {
                "privateKeyInRuntime": False,
                "effectBoundary": "external-approved-action-only",
            },
            "redactionValidation": {
                "authoring": "not-claimed-candidate-validation-only",
                "sourceDigest": _file_sha256(fixtures / "source-with-secret.pdf"),
                "candidateDigest": _file_sha256(fixtures / "redacted.pdf"),
                "visualCoverNegativeRejected": True,
                "rawBytesScanned": True,
                "decodedObjectStreamsScanned": True,
                "qdfDecodedBytesScanned": True,
                "metadataAndXmpScanned": True,
                "attachmentsAnnotationsFormsAndOutlinesScanned": True,
                "nonTargetPagePixelPreserved": True,
            },
        },
    )


def _file_sha256(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_deep_marker_absence(path: Path) -> None:
    marker = SECRET_MARKER.encode()
    with pikepdf.open(path) as document:
        metadata = document.open_metadata()
        assert SECRET_MARKER not in json.dumps(dict(metadata), sort_keys=True)
        assert SECRET_MARKER not in str(document.docinfo)
        assert SECRET_MARKER not in str(document.Root.get("/AcroForm"))
        assert SECRET_MARKER not in str(document.Root.get("/Names"))
        assert SECRET_MARKER not in str(document.Root.get("/Outlines"))
        for item in document.objects:
            if isinstance(item, pikepdf.Stream):
                try:
                    payload = item.read_bytes()
                except pikepdf.PdfError:
                    payload = item.read_raw_bytes()
                assert marker not in payload
            else:
                assert SECRET_MARKER not in str(item)
    reader = pypdf.PdfReader(str(path))
    assert not reader.get_fields()
    assert not reader.attachments
    assert SECRET_MARKER not in str(reader.outline)
    for page in reader.pages:
        assert SECRET_MARKER not in (page.extract_text() or "")
        assert SECRET_MARKER not in str(page.get("/Annots"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "finalize"))
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            generate(args.output)
        else:
            finalize(args.output)
    except (AssertionError, OSError, ValueError, pikepdf.PdfError) as error:
        print(f"pdf-ocr-conformance: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
