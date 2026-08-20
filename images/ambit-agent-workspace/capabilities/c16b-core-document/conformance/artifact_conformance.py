from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import duckdb
import openpyxl
import pikepdf
import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq
from docx import Document
from openpyxl.chart import BarChart, Reference
from openpyxl.styles import Font, PatternFill
from openpyxl.worksheet.table import Table, TableStyleInfo
from PIL import Image
from pptx import Presentation
from pptx.enum.text import PP_ALIGN
from pptx.util import Inches, Pt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


FIXED_TIME = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
FIXED_ZIP_TIME = (2024, 1, 1, 0, 0, 0)


def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "HOME": str(OUTPUT / "home")},
    )


def office_pdf(source: Path, target_dir: Path) -> Path:
    profile = OUTPUT / f"lo-profile-{source.stem}"
    profile.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(parents=True, exist_ok=True)
    run(
        "libreoffice",
        "--headless",
        f"-env:UserInstallation=file://{profile}",
        "--convert-to",
        "pdf",
        "--outdir",
        str(target_dir),
        str(source),
    )
    result = target_dir / f"{source.stem}.pdf"
    assert result.is_file() and result.stat().st_size > 0
    normalize_pdf(result)
    return result


def normalize_pdf(path: Path) -> None:
    normalized = path.with_name(f".{path.name}.normalized")
    with pikepdf.open(path) as document:
        for key in list(document.docinfo.keys()):
            del document.docinfo[key]
        document.save(normalized, deterministic_id=True)
    normalized.replace(path)


def normalize_zip_archive(path: Path) -> None:
    normalized = path.with_name(f".{path.name}.normalized")
    with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(normalized, "w") as target:
        for entry in sorted(source.infolist(), key=lambda item: item.filename):
            info = zipfile.ZipInfo(entry.filename, FIXED_ZIP_TIME)
            info.compress_type = entry.compress_type
            info.comment = entry.comment
            info.create_system = entry.create_system
            info.external_attr = entry.external_attr
            info.flag_bits = entry.flag_bits
            target.writestr(info, source.read(entry.filename), compress_type=entry.compress_type)
    normalized.replace(path)


def validate_pdf(path: Path, expected_text: str | tuple[str, ...], minimum_pages: int = 1) -> None:
    run("qpdf", "--check", str(path))
    with pikepdf.open(path) as document:
        assert len(document.pages) >= minimum_pages
    raster = path.with_suffix("")
    run("pdftoppm", "-f", "1", "-singlefile", "-png", str(path), str(raster))
    image_path = raster.with_suffix(".png")
    with Image.open(image_path) as image:
        assert image.width > 300 and image.height > 300
    extracted = run("pdftotext", str(path), "-").stdout
    expected_values = (expected_text,) if isinstance(expected_text, str) else expected_text
    for value in expected_values:
        assert value in extracted


def build_spreadsheet() -> Path:
    path = OUTPUT / "spreadsheet" / "quarterly-report.xlsx"
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Quarterly Report"
    sheet.append(["Quarter", "Revenue", "Cost", "Margin"])
    for row in [("Q1", 120, 80), ("Q2", 150, 90), ("Q3", 180, 105)]:
        sheet.append([*row, f"=B{sheet.max_row + 1}-C{sheet.max_row + 1}"])
    sheet["A1"].font = Font(bold=True, color="FFFFFF")
    for cell in sheet[1]:
        cell.fill = PatternFill("solid", fgColor="1F4E78")
        cell.font = Font(bold=True, color="FFFFFF")
    table = Table(displayName="QuarterlyRevenue", ref="A1:D4")
    table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2",
        showFirstColumn=False,
        showLastColumn=False,
        showRowStripes=True,
        showColumnStripes=False,
    )
    sheet.add_table(table)
    chart = BarChart()
    chart.title = "Revenue by quarter"
    chart.add_data(Reference(sheet, min_col=2, min_row=1, max_row=4), titles_from_data=True)
    chart.set_categories(Reference(sheet, min_col=1, min_row=2, max_row=4))
    sheet.add_chart(chart, "F2")
    sheet.freeze_panes = "A2"
    workbook.properties.created = FIXED_TIME.replace(tzinfo=None)
    workbook.properties.modified = FIXED_TIME.replace(tzinfo=None)
    workbook.save(path)
    normalize_zip_archive(path)

    reopened = openpyxl.load_workbook(path, data_only=False)
    report = reopened["Quarterly Report"]
    assert report["D2"].value == "=B2-C2"
    assert "QuarterlyRevenue" in report.tables
    assert len(report._charts) == 1
    assert report["A1"].font.bold is True
    assert report.freeze_panes == "A2"
    return path


def build_document() -> Path:
    path = OUTPUT / "document" / "project-brief-v1.docx"
    path.parent.mkdir(parents=True, exist_ok=True)
    document = Document()
    document.add_heading("Ambit Project Brief", level=0)
    document.add_paragraph("A locally certified, content-addressed document workflow.")
    table = document.add_table(rows=1, cols=2)
    table.style = "Light Shading Accent 1"
    table.rows[0].cells[0].text = "Control"
    table.rows[0].cells[1].text = "Result"
    for control, result in [
        ("Non-root runtime", "Passed"),
        ("Offline execution", "Passed"),
        ("Exact pack digest", "Bound"),
    ]:
        cells = table.add_row().cells
        cells[0].text = control
        cells[1].text = result
    document.add_paragraph("Conclusion: artifacts remain editable and inspectable.")
    document.core_properties.created = FIXED_TIME
    document.core_properties.modified = FIXED_TIME
    document.save(path)
    normalize_zip_archive(path)
    reopened = Document(path)
    assert reopened.paragraphs[0].text == "Ambit Project Brief"
    assert reopened.tables[0].cell(1, 1).text == "Passed"
    return path


def revise_document(source: Path) -> Path:
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    revised = OUTPUT / "document" / "project-brief-v2.docx"
    document = Document(source)
    document.add_heading("Verified repair", level=1)
    document.add_paragraph("The editable revision preserves the original structure and adds a reviewed conclusion.")
    document.core_properties.modified = FIXED_TIME
    document.save(revised)
    normalize_zip_archive(revised)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_digest
    reopened = Document(revised)
    assert reopened.tables[0].cell(1, 1).text == "Passed"
    assert reopened.paragraphs[-1].text.endswith("reviewed conclusion.")
    return revised


def build_presentation() -> Path:
    path = OUTPUT / "presentation" / "runtime-overview.pptx"
    path.parent.mkdir(parents=True, exist_ok=True)
    presentation = Presentation()
    presentation.core_properties.created = FIXED_TIME
    presentation.core_properties.modified = FIXED_TIME
    title_slide = presentation.slides.add_slide(presentation.slide_layouts[0])
    title_slide.shapes.title.text = "Certified Runtime Overview"
    title_slide.placeholders[1].text = "Core and document capability evidence"
    detail = presentation.slides.add_slide(presentation.slide_layouts[5])
    detail.shapes.title.text = "Deterministic controls"
    box = detail.shapes.add_textbox(Inches(1), Inches(1.6), Inches(8), Inches(3))
    frame = box.text_frame
    frame.text = "Pinned dependencies"
    for text in ["Non-root execution", "Offline conformance", "Rendered output inspection"]:
        paragraph = frame.add_paragraph()
        paragraph.text = text
        paragraph.font.size = Pt(24)
        paragraph.alignment = PP_ALIGN.LEFT
    presentation.save(path)
    normalize_zip_archive(path)
    reopened = Presentation(path)
    assert len(reopened.slides) == 2
    assert reopened.slides[0].shapes.title.text == "Certified Runtime Overview"
    return path


def build_pdf() -> Path:
    path = OUTPUT / "pdf" / "receipt.pdf"
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = canvas.Canvas(str(path), pagesize=letter, invariant=1)
    writer.setTitle("Ambit Runtime Receipt")
    writer.setFont("Helvetica-Bold", 18)
    writer.drawString(72, 720, "Ambit Runtime Receipt")
    writer.setFont("Helvetica", 11)
    writer.drawString(72, 690, "Document, spreadsheet, presentation, and PDF paths executed locally.")
    writer.showPage()
    writer.save()
    normalize_pdf(path)
    return path


def build_data() -> Path:
    directory = OUTPUT / "data"
    directory.mkdir(parents=True, exist_ok=True)
    parquet = directory / "metrics.parquet"
    table = pa.table({"category": ["a", "b", "c"], "amount": [10, 20, 30]})
    pq.write_table(table, parquet)
    frame = pl.read_parquet(parquet)
    assert frame["amount"].sum() == 60
    result = duckdb.sql(f"SELECT sum(amount) AS total FROM read_parquet('{parquet}')").fetchone()
    assert result == (60,)
    receipt = directory / "analysis.json"
    receipt.write_text(json.dumps({"rows": 3, "sum": 60}, sort_keys=True) + "\n")
    return receipt


def build_research_and_web() -> tuple[Path, Path]:
    research = OUTPUT / "research"
    research.mkdir(parents=True, exist_ok=True)
    markdown = research / "brief.md"
    markdown.write_text(
        "# Grounded runtime brief\n\n"
        "The evidence binds exact local tools and artifacts. [Source A](https://example.invalid/source-a) remains a fixture URI.\n"
    )
    html = research / "brief.html"
    run("pandoc", "--standalone", "--from", "commonmark", "--to", "html5", "-o", str(html), str(markdown))
    assert "Grounded runtime brief" in html.read_text()

    web = OUTPUT / "web"
    web.mkdir(parents=True, exist_ok=True)
    index = web / "index.html"
    index.write_text(
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<link rel='icon' href='data:,'>"
        "<title>Ambit Runtime</title><style>body{font-family:sans-serif;margin:2rem;max-width:60rem}"
        "main{display:grid;gap:1rem}.card{border:1px solid #789;padding:1rem;border-radius:.5rem}"
        "@media(max-width:500px){body{margin:1rem}}</style></head><body>"
        "<main><h1>Ambit runtime conformance</h1><section class='card' aria-labelledby='status'>"
        "<h2 id='status'>Status</h2><p>Local document workflows are ready for inspection.</p>"
        "<button type='button' aria-label='Acknowledge status'>Acknowledge</button>"
        "</section></main></body></html>"
    )
    return html, index


def digest(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": str(path.relative_to(OUTPUT)),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


OUTPUT = Path(sys.argv[1]).resolve()
OUTPUT.mkdir(parents=True, exist_ok=True)
(OUTPUT / "home").mkdir(exist_ok=True)

spreadsheet = build_spreadsheet()
document_v1 = build_document()
presentation = build_presentation()
native_pdf = build_pdf()
data_receipt = build_data()
research_html, web_index = build_research_and_web()

spreadsheet_pdf = office_pdf(spreadsheet, OUTPUT / "spreadsheet" / "rendered")
document_v1_pdf = office_pdf(document_v1, OUTPUT / "document" / "rendered-v1")
validate_pdf(document_v1_pdf, "Ambit Project Brief")
document_v2 = revise_document(document_v1)
document_v2_pdf = office_pdf(document_v2, OUTPUT / "document" / "rendered-v2")
presentation_pdf = office_pdf(presentation, OUTPUT / "presentation" / "rendered")
validate_pdf(
    spreadsheet_pdf,
    ("Quarter Revenue Cost", "40", "60", "75", "Revenue by quarter"),
)
validate_pdf(document_v2_pdf, "Verified repair")
validate_pdf(presentation_pdf, "Certified Runtime Overview", minimum_pages=2)
validate_pdf(native_pdf, "Ambit Runtime Receipt")

artifacts = [
    spreadsheet,
    document_v1,
    document_v2,
    presentation,
    native_pdf,
    data_receipt,
    research_html,
    web_index,
    spreadsheet_pdf,
    document_v1_pdf,
    document_v2_pdf,
    presentation_pdf,
]
(OUTPUT / "artifact-receipt.json").write_text(
    json.dumps(
        {
            "schema": "ambit.runtime-pack-artifact-conformance/v1",
            "artifacts": sorted((digest(path) for path in artifacts), key=lambda item: str(item["path"])),
            "spreadsheet": {
                "formulaText": "preserved",
                "styles": "preserved",
                "chart": "present",
                "table": "present",
                "macroExecution": "disabled",
                "macroPreservation": "not_exercised_no_macro_fixture",
            },
            "document": {
                "workflow": ["create", "render", "inspect", "edit", "render", "validate", "commit-candidate"],
                "originalPreserved": True,
                "revisionCount": 2,
            },
            "data": {"rows": 3, "sum": 60},
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
