from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from docx import Document


FIXED_TIME = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)
FIXED_ZIP_TIME = (2024, 1, 1, 0, 0, 0)
OUTPUT = Path(sys.argv[1]).resolve()


def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "HOME": str(OUTPUT / "home")},
    )


def normalize_zip_archive(path: Path) -> None:
    normalized = path.with_name(f".{path.name}.normalized")
    with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(normalized, "w") as target:
        for entry in sorted(source.infolist(), key=lambda item: item.filename):
            data = source.read(entry.filename)
            if entry.filename == "docProps/core.xml":
                for tag in (b"created", b"modified"):
                    pattern = rb"(<dcterms:" + tag + rb"[^>]*>)[^<]*(</dcterms:" + tag + rb">)"
                    data = re.sub(pattern, rb"\g<1>2024-01-01T00:00:00Z\g<2>", data)
            info = zipfile.ZipInfo(entry.filename, FIXED_ZIP_TIME)
            info.compress_type = entry.compress_type
            info.comment = entry.comment
            info.create_system = entry.create_system
            info.external_attr = entry.external_attr
            info.flag_bits = entry.flag_bits
            target.writestr(info, data, compress_type=entry.compress_type)
    normalized.replace(path)


def normalize_pdf(path: Path) -> None:
    normalized = path.with_name(f".{path.name}.normalized")
    run(
        "qpdf",
        "--remove-info",
        "--remove-metadata",
        "--deterministic-id",
        str(path),
        str(normalized),
    )
    normalized.replace(path)


def inspect_docx(path: Path, expected_last_paragraph: str) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        assert "[Content_Types].xml" in names
        assert "word/document.xml" in names
        assert not any(name.endswith("vbaProject.bin") for name in names)
    reopened = Document(path)
    assert reopened.paragraphs[0].text == "Ambit Project Brief"
    assert reopened.paragraphs[-1].text == expected_last_paragraph
    assert reopened.tables[0].cell(1, 1).text == "Passed"


def create_document() -> Path:
    path = OUTPUT / "document" / "project-brief-v1.docx"
    path.parent.mkdir(parents=True, exist_ok=True)
    document = Document()
    document.add_heading("Ambit Project Brief", level=0)
    document.add_paragraph("A minimal, locally evaluated core document workflow.")
    table = document.add_table(rows=1, cols=2)
    table.style = "Light Shading Accent 1"
    table.rows[0].cells[0].text = "Control"
    table.rows[0].cells[1].text = "Result"
    for control, result in (
        ("Non-root runtime", "Passed"),
        ("Offline execution", "Passed"),
        ("Exact pack digest", "Bound"),
    ):
        cells = table.add_row().cells
        cells[0].text = control
        cells[1].text = result
    conclusion = "Conclusion: the document remains editable and inspectable."
    document.add_paragraph(conclusion)
    document.core_properties.created = FIXED_TIME
    document.core_properties.modified = FIXED_TIME
    document.save(path)
    normalize_zip_archive(path)
    inspect_docx(path, conclusion)
    return path


def revise_document(source: Path) -> Path:
    original_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    revised = OUTPUT / "document" / "project-brief-v2.docx"
    document = Document(source)
    document.add_heading("Verified repair", level=1)
    conclusion = "The second revision preserves the original structure and adds a reviewed conclusion."
    document.add_paragraph(conclusion)
    document.core_properties.modified = FIXED_TIME
    document.save(revised)
    normalize_zip_archive(revised)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_digest
    inspect_docx(revised, conclusion)
    return revised


def render_document(source: Path, revision: str) -> Path:
    profile = OUTPUT / f"lo-profile-{revision}"
    target = OUTPUT / "document" / f"rendered-{revision}"
    profile.mkdir(parents=True, exist_ok=True)
    target.mkdir(parents=True, exist_ok=True)
    run(
        "libreoffice",
        "--headless",
        f"-env:UserInstallation=file://{profile}",
        "--convert-to",
        "pdf:writer_pdf_Export",
        "--outdir",
        str(target),
        str(source),
    )
    pdf = target / f"{source.stem}.pdf"
    assert pdf.is_file() and pdf.stat().st_size > 0
    normalize_pdf(pdf)
    return pdf


def validate_pdf(path: Path, expected_text: tuple[str, ...]) -> Path:
    run("qpdf", "--check", str(path))
    info = run("pdfinfo", str(path)).stdout
    pages = re.search(r"^Pages:\s+(\d+)$", info, flags=re.MULTILINE)
    assert pages and int(pages.group(1)) >= 1
    extracted = " ".join(run("pdftotext", str(path), "-").stdout.split())
    for value in expected_text:
        assert " ".join(value.split()) in extracted
    raster_base = path.with_suffix("")
    run("pdftoppm", "-f", "1", "-singlefile", "-png", str(path), str(raster_base))
    png = raster_base.with_suffix(".png")
    payload = png.read_bytes()
    assert payload[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", payload[16:24])
    assert width > 300 and height > 300
    return png


def digest(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": str(path.relative_to(OUTPUT)),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


OUTPUT.mkdir(parents=True, exist_ok=True)
(OUTPUT / "home").mkdir(exist_ok=True)

document_v1 = create_document()
document_v1_pdf = render_document(document_v1, "v1")
document_v1_png = validate_pdf(document_v1_pdf, ("Ambit Project Brief", "Non-root runtime", "Passed"))
document_v2 = revise_document(document_v1)
document_v2_pdf = render_document(document_v2, "v2")
document_v2_png = validate_pdf(document_v2_pdf, ("Ambit Project Brief", "Verified repair", "reviewed conclusion"))

artifacts = [document_v1, document_v1_pdf, document_v1_png, document_v2, document_v2_pdf, document_v2_png]
(OUTPUT / "artifact-receipt.json").write_text(
    json.dumps(
        {
            "schema": "ambit.runtime-pack-document-conformance/v2",
            "artifacts": sorted((digest(path) for path in artifacts), key=lambda item: str(item["path"])),
            "document": {
                "workflow": ["create", "render", "inspect", "edit", "render", "validate", "commit-candidate"],
                "originalPreserved": True,
                "revisionCount": 2,
                "macroExecution": "disabled",
                "macroPayload": "absent",
            },
            "movedToC18SpecialistPacks": [
                "spreadsheet",
                "presentation",
                "pdf-specialist-and-ocr",
                "data-analysis",
                "research-and-publishing",
                "web-application-browser",
                "media-and-diagrams",
            ],
        },
        indent=2,
        sort_keys=True,
    )
    + "\n"
)
