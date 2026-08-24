from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pikepdf
import pypdf
from PIL import Image, ImageChops, ImageDraw, ImageFont
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas

from common import canonical_json, file_receipts, runtime_guard


PACK_REF = "ambit.runtime-pack/pdf-ocr@1"
SECRET_MARKER = "AMB1T-REDACT-ME-7421"


def create_pdf(path: Path, *, include_secret: bool) -> None:
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
    if include_secret:
        document.drawString(72, 660, SECRET_MARKER)
    else:
        document.setFillColorRGB(0.1, 0.1, 0.1)
        document.rect(72, 650, 220, 22, fill=1, stroke=0)
        document.setFillColorRGB(0, 0, 0)
        document.drawString(72, 625, "Sensitive content removed, not merely covered")
    document.showPage()
    document.setFont("Helvetica", 12)
    document.drawString(72, 720, "Second page preserves the approved appendix.")
    document.save()


def create_scan(path: Path) -> None:
    image = Image.new("L", (1400, 520), color=255)
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 64)
    small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 42)
    draw.text((70, 55), "AMB1T OCR 2026", font=font, fill=0)
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
    redacted = output / "redacted.pdf"
    edited = output / "metadata-edited.pdf"
    scan = output / "scan.pgm"
    create_pdf(source, include_secret=True)
    create_pdf(redacted, include_secret=False)
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
            "expectedOcrText": ["AMB1T OCR 2026", "North", "120", "130"],
            "redactedMarker": SECRET_MARKER,
            "files": file_receipts(output),
        },
    )


def finalize(output: Path) -> None:
    fixtures = output / "fixtures"
    checks = output / "checks"
    source_text = (checks / "source-with-secret.txt").read_text(encoding="utf-8")
    redacted_text = (checks / "redacted.txt").read_text(encoding="utf-8")
    edited_text = (checks / "metadata-edited.txt").read_text(encoding="utf-8")
    assert SECRET_MARKER in source_text
    assert SECRET_MARKER not in redacted_text
    assert SECRET_MARKER not in edited_text
    assert "Sensitive content removed" in redacted_text
    ocr_text = (checks / "ocr.txt").read_text(encoding="utf-8")
    for expected in ("AMB1T OCR 2026", "North", "120", "130"):
        assert expected in ocr_text, expected
    ocr_pdf_text = (checks / "ocr-pdf.txt").read_text(encoding="utf-8")
    assert "AMB1T OCR 2026" in ocr_pdf_text

    redacted_page = Image.open(checks / "redacted-1.png").convert("RGB")
    edited_page = Image.open(checks / "metadata-edited-1.png").convert("RGB")
    difference = ImageChops.difference(redacted_page, edited_page)
    assert difference.getbbox() is None
    assert (checks / "pdfa.pdf").read_bytes().startswith(b"%PDF-")
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
        },
    )


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
