#!/usr/bin/env python3
"""Exercise installed tools as a non-root user with networking disabled."""
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from docx import Document
import pymupdf
from PIL import Image, ImageDraw


def run(argv, *, cwd, env=None, timeout=60):
    started = time.monotonic()
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=timeout, check=False)
    if result.returncode:
        raise AssertionError({"argv": argv, "exit": result.returncode,
                              "stderr": result.stderr[-4000:]})
    return result.stdout, time.monotonic() - started


results = []
with tempfile.TemporaryDirectory(prefix="ambit-file-tools-") as name:
    directory = Path(name)
    assert os.getuid() != 0, "Exercise the actual non-root workspace user"
    assert importlib.metadata.version("mammoth") == "1.12.1"
    private_python = "/opt/ambit/file-tools/python/bin/python"
    version, _ = run([private_python, "-c", "import importlib.metadata as m; print(m.version('markitdown')); print(m.version('mammoth'))"], cwd=directory)
    assert version.splitlines() == ["0.1.7", "1.11.0"]
    results.append({"check": "isolated Python dependencies", "passed": True})

    doc = Document()
    doc.add_heading("Workspace quantity check", 0)
    doc.add_paragraph("The source material remains unchanged.")
    table = doc.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "Material"
    table.rows[0].cells[1].text = "Quantity"
    row = table.add_row()
    row.cells[0].text = "Copper"
    row.cells[1].text = "18.75"
    source = directory / "source document.docx"
    doc.save(source)
    markdown, elapsed = run(["markitdown", source.name], cwd=directory)
    assert all(value in markdown for value in ["Workspace quantity check", "Copper", "18.75"])
    results.append({"check": "MarkItDown structure", "seconds": elapsed, "passed": True})

    # Detection comes from content; this is not an application extension router.
    opaque = directory / "opaque.upload"
    opaque.write_bytes(source.read_bytes())
    text, elapsed = run(["tika", "--text", opaque.name], cwd=directory)
    assert all(value in text for value in ["Workspace quantity check", "Copper", "18.75"])
    results.append({"check": "Tika content detection and relative path", "seconds": elapsed, "passed": True})

    image = Image.new("RGB", (1800, 1200), "white")
    ImageDraw.Draw(image).text((100, 100), "RASTER EVIDENCE 427", fill="black", font_size=60)
    image_path = directory / "image.png"
    image.save(image_path)
    pdf = pymupdf.open()
    page = pdf.new_page(width=900, height=600)
    page.insert_image(page.rect, filename=str(image_path))
    pdf_path = directory / "image-only.pdf"
    pdf.save(pdf_path)
    pdf.close()
    traps = directory / "traps"
    traps.mkdir()
    trap = traps / "tesseract"
    marker = directory / "unexpected-ocr"
    trap.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$OCR_PROBE_MARKER\"\nexit 73\n")
    trap.chmod(0o755)
    environment = {**os.environ, "PATH": str(traps) + ":" + os.environ["PATH"],
                   "OCR_PROBE_MARKER": str(marker)}
    text, elapsed = run(["tika", "--text", pdf_path.name], cwd=directory,
                        env=environment, timeout=30)
    assert "RASTER EVIDENCE" not in text
    assert not marker.exists(), "Default Tika extraction unexpectedly invoked OCR"
    results.append({"check": "image-only input does not trigger hidden OCR", "seconds": elapsed, "passed": True})

    version, _ = run(["vips", "--version"], cwd=directory)
    assert "8.16.1" in version
    run(["vips", "crop", str(image_path), "region.png", "80", "80", "1000", "200"], cwd=directory)
    with Image.open(directory / "region.png") as region:
        assert region.size == (1000, 200)
        assert region.tobytes() == image.crop((80, 80, 1080, 280)).tobytes()
    results.append({"check": "exact image region", "passed": True})

print(json.dumps({"checks": results, "passed": len(results)}, indent=2))
