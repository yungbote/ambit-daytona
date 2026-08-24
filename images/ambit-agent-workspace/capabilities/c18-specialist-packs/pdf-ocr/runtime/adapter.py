from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pikepdf
import pypdf
from PIL import Image

from process_control import ProcessDeadlineExceeded, ProcessFailure, run_bounded
from render_command import pack_check_names
from render_runner import AdapterFailure


PACK_ROOT = Path("/opt/ambit/runtime-pack/pdf-ocr")
PATH = f"{PACK_ROOT}/python/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PDF = "application/pdf"
IMAGE_MEDIA_TYPES = {
    "image/jpeg",
    "image/png",
    "image/tiff",
    "image/x-portable-graymap",
}
MAXIMUM_PDF_OBJECTS = 2_000_000
FORBIDDEN_PDF_NAMES = {
    "/AA",
    "/EmbeddedFiles",
    "/JavaScript",
    "/JS",
    "/Launch",
    "/RichMedia",
    "/SubmitForm",
    "/XFA",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _environment(scratch: Path) -> dict[str, str]:
    values = {
        "HOME": scratch / "home",
        "XDG_CACHE_HOME": scratch / "cache",
        "XDG_CONFIG_HOME": scratch / "config",
        "XDG_RUNTIME_DIR": scratch / "run",
    }
    for directory in values.values():
        directory.mkdir(mode=0o700)
    return {
        **{key: str(value) for key, value in values.items()},
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": PATH,
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }


def _run(
    argv: list[str],
    *,
    scratch: Path,
    deadline: float,
    environment: dict[str, str],
    check: bool = True,
) -> tuple[int, bytes, bytes]:
    try:
        result = run_bounded(
            argv,
            deadline=deadline,
            cwd=scratch,
            environment=environment,
            check=check,
        )
        return result.returncode, result.stdout, result.stderr
    except ProcessDeadlineExceeded as error:
        raise AdapterFailure(
            "pdf_deadline_exceeded",
            "The PDF validator exceeded its exact deadline.",
            outcome="blocked",
        ) from error
    except ProcessFailure as error:
        raise AdapterFailure(
            "pdf_native_tool_failed",
            "An offline PDF validation tool rejected the artifact.",
            observations={
                "tool": Path(error.result.argv[0]).name,
                "exitCode": error.result.returncode,
                "stderrSha256": "sha256:" + hashlib.sha256(error.result.stderr).hexdigest(),
            },
        ) from error


def _pdf_structure(path: Path, scratch: Path, deadline: float, environment: dict[str, str]) -> dict[str, Any]:
    qdf = scratch / "decoded.qdf.pdf"
    _run(
        ["qpdf", "--check", str(path)],
        scratch=scratch,
        deadline=deadline,
        environment=environment,
    )
    _run(
        ["qpdf", "--qdf", "--object-streams=disable", str(path), str(qdf)],
        scratch=scratch,
        deadline=deadline,
        environment=environment,
    )
    reader = pypdf.PdfReader(str(path), strict=True)
    if reader.is_encrypted or not reader.pages:
        raise AdapterFailure(
            "pdf_encrypted_or_empty",
            "The PDF is encrypted or contains no pages.",
            check="pdf.page_render_complete",
        )
    if len(reader.pages) > 256:
        raise AdapterFailure(
            "pdf_page_limit",
            "The PDF exceeds the admitted 256-page validation bound.",
            check="pdf.page_render_complete",
            observations={"pageCount": len(reader.pages)},
        )
    if reader.attachments:
        raise AdapterFailure(
            "pdf_attachment_forbidden",
            "The PDF contains embedded attachments that are not admitted for preview.",
            check="pdf.metadata_policy",
        )
    fields = reader.get_fields()
    with pikepdf.open(path) as document:
        object_count = len(document.objects)
        if object_count > MAXIMUM_PDF_OBJECTS:
            raise AdapterFailure("pdf_object_limit", "The PDF object roster exceeds its safe bound.")
        root_text = str(document.Root)
        forbidden = sorted(name for name in FORBIDDEN_PDF_NAMES if name in root_text)
        if forbidden:
            raise AdapterFailure(
                "pdf_active_content_forbidden",
                "The PDF contains active or embedded content that is not admitted for preview.",
                check="pdf.metadata_policy",
                observations={"forbiddenNames": forbidden},
            )
        metadata = document.open_metadata()
        pdfa_part = metadata.get("pdfaid:part")
        pdfa_conformance = metadata.get("pdfaid:conformance")
        output_intents = document.Root.get("/OutputIntents")
        tagged = document.Root.get("/StructTreeRoot") is not None
        stream_bytes = 0
        for item in document.objects:
            if isinstance(item, pikepdf.Stream):
                try:
                    stream_bytes += len(item.read_bytes())
                except pikepdf.PdfError:
                    stream_bytes += len(item.read_raw_bytes())
    signature_status, signature_stdout, signature_stderr = _run(
        ["pdfsig", str(path)],
        scratch=scratch,
        deadline=deadline,
        environment=environment,
        check=False,
    )
    signature_text = (signature_stdout + signature_stderr).decode("utf-8", errors="replace")
    if signature_status not in {0, 2}:
        raise AdapterFailure(
            "pdf_signature_inspection_failed",
            "Poppler could not inspect PDF signatures.",
            check="pdf.pdfa_and_signature_inspection",
        )
    return {
        "pageCount": len(reader.pages),
        "objectCount": object_count,
        "decodedStreamBytes": stream_bytes,
        "tagged": tagged,
        "formFieldCount": 0 if not fields else len(fields),
        "outlineEntryCount": len(reader.outline),
        "attachmentCount": 0,
        "pdfaPart": None if pdfa_part is None else str(pdfa_part),
        "pdfaConformance": None if pdfa_conformance is None else str(pdfa_conformance),
        "outputIntentCount": 0 if output_intents is None else len(output_intents),
        "signatureInspectionExitCode": signature_status,
        "signatureCount": 0 if "does not contain any signatures" in signature_text.lower() else 1,
        "qdfDigest": _sha256(qdf),
    }


def _render_pdf_pages(
    path: Path,
    scratch: Path,
    deadline: float,
    environment: dict[str, str],
) -> tuple[list[Path], str, Path]:
    pages_root = scratch / "pages"
    pages_root.mkdir()
    prefix = pages_root / "page"
    _run(
        ["pdftoppm", "-png", "-r", "96", str(path), str(prefix)],
        scratch=scratch,
        deadline=deadline,
        environment=environment,
    )
    pages = sorted(pages_root.glob("page-*.png"))
    if not pages:
        raise AdapterFailure(
            "pdf_page_render_missing",
            "The PDF renderer produced no page images.",
            check="pdf.page_render_complete",
        )
    text_path = scratch / "native-text.txt"
    _run(
        ["pdftotext", "-layout", str(path), str(text_path)],
        scratch=scratch,
        deadline=deadline,
        environment=environment,
    )
    return pages, text_path.read_text(encoding="utf-8", errors="strict"), text_path


def _ocr_images(
    pages: list[Path],
    scratch: Path,
    deadline: float,
    environment: dict[str, str],
) -> tuple[str, list[dict[str, Any]]]:
    texts: list[str] = []
    receipts: list[dict[str, Any]] = []
    for index, page in enumerate(pages, start=1):
        output = scratch / f"ocr-{index}"
        _run(
            ["tesseract", str(page), str(output), "--psm", "6"],
            scratch=scratch,
            deadline=deadline,
            environment=environment,
        )
        text_path = output.with_suffix(".txt")
        text = text_path.read_text(encoding="utf-8", errors="strict")
        texts.append(text)
        receipts.append(
            {
                "page": index,
                "imageDigest": _sha256(page),
                "textDigest": _sha256(text_path),
                "textBytes": len(text.encode()),
            }
        )
    return "\n".join(texts), receipts


def _image_source(
    path: Path,
    media_type: str,
    scratch: Path,
) -> tuple[list[Path], dict[str, Any]]:
    with Image.open(path) as image:
        image.verify()
    with Image.open(path) as image:
        width, height = image.size
        frames = getattr(image, "n_frames", 1)
        if width <= 0 or height <= 0 or width * height > 128 * 1024 * 1024 or frames > 256:
            raise AdapterFailure(
                "image_resource_limit",
                "The scanned image exceeds its safe geometry or frame bound.",
                check="pdf.image_decode_complete",
            )
        normalized = scratch / "scan.png"
        image.seek(0)
        image.convert("RGB").save(normalized, format="PNG", optimize=False)
    return [normalized], {
        "sourceMediaType": media_type,
        "width": width,
        "height": height,
        "frameCount": frames,
        "normalizedDigest": _sha256(normalized),
    }


def _views(
    pages: list[Path],
    text: str,
    request: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    views: list[dict[str, Any]] = []
    limitations: list[dict[str, str]] = []
    pixels = 0
    payload_bytes = 0
    for page in pages:
        payload = page.read_bytes()
        with Image.open(page) as image:
            width, height = image.size
        page_pixels = width * height
        if (
            width > 4_096
            or height > 4_096
            or page_pixels > request["output"]["maximumImagePixels"]
            or pixels + page_pixels > request["output"]["maximumAggregateImagePixels"]
            or len(payload) > 512 * 1024
            or payload_bytes + len(payload) > 3 * 1024 * 1024
        ):
            limitations.append(
                {
                    "code": "preview_page_roster_truncated",
                    "severity": "warning",
                    "message": "Additional pages remain in private evidence because the public preview reached its safe image bound.",
                }
            )
            break
        pixels += page_pixels
        payload_bytes += len(payload)
        views.append(
            {
                "kind": "image",
                "ordinal": len(views) + 1,
                "label": f"Page {len(views) + 1}",
                "altText": f"Rendered PDF or scan page {len(views) + 1} of {len(pages)}.",
                "mediaType": "image/png",
                "width": width,
                "height": height,
                "byteLength": len(payload),
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "bodyBase64": base64.b64encode(payload).decode(),
            }
        )
    normalized = text.replace("\r", "")
    encoded = normalized.encode("utf-8")
    if encoded:
        if len(encoded) > 1024 * 1024:
            encoded = encoded[: 1024 * 1024]
            while True:
                try:
                    normalized = encoded.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    encoded = encoded[:-1]
            limitations.append(
                {
                    "code": "preview_text_truncated",
                    "severity": "warning",
                    "message": "The public text view is truncated; complete extraction remains in private evidence.",
                }
            )
        views.append(
            {
                "kind": "text",
                "ordinal": len(views) + 1,
                "label": "Extracted text",
                "mediaType": "text/plain",
                "byteLength": len(encoded),
                "digest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
                "body": normalized,
            }
        )
    if not views:
        payload = b"No extractable text or bounded page image is available for public preview.\n"
        views.append(
            {
                "kind": "text",
                "ordinal": 1,
                "label": "Preview status",
                "mediaType": "text/plain",
                "byteLength": len(payload),
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "body": payload.decode(),
            }
        )
    return views, sorted(limitations, key=lambda item: item["code"])


def render_validate(
    *,
    request: dict[str, Any],
    source_path: Path,
    scratch: Path,
    deadline: float,
) -> dict[str, Any]:
    media_type = request["source"]["mediaType"]
    environment = _environment(scratch)
    if media_type == PDF:
        structure = _pdf_structure(source_path, scratch, deadline, environment)
        pages, native_text, text_path = _render_pdf_pages(
            source_path, scratch, deadline, environment
        )
        ocr_text, ocr_receipts = _ocr_images(
            pages, scratch, deadline, environment
        )
        text = native_text if native_text.strip() else ocr_text
        structure["nativeTextBytes"] = len(native_text.encode())
        structure["ocr"] = ocr_receipts
        requested_checks = pack_check_names(request)
        if "pdf.accessibility_structure" in requested_checks and not structure["tagged"]:
            raise AdapterFailure(
                "pdf_accessibility_structure_missing",
                "The PDF has no tagged accessibility structure.",
                check="pdf.accessibility_structure",
                observations={"tagged": False},
            )
    elif media_type in IMAGE_MEDIA_TYPES:
        pages, structure = _image_source(source_path, media_type, scratch)
        text, ocr_receipts = _ocr_images(pages, scratch, deadline, environment)
        structure["ocr"] = ocr_receipts
        text_path = scratch / "ocr-text.txt"
        text_path.write_text(text, encoding="utf-8")
        text_path.chmod(0o400)
    else:
        raise AdapterFailure("unsupported_pdf_source", "The PDF/OCR source format is unsupported.")

    common = {
        "sourceDigest": _sha256(source_path),
        "sourceBytes": source_path.stat().st_size,
        **structure,
    }
    structure_path = scratch / "pdf-structure.json"
    structure_path.write_text(
        json.dumps(common, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    structure_path.chmod(0o400)
    observations: dict[str, dict[str, Any]] = {}
    for check in pack_check_names(request):
        observations[check] = {"check": check, **common}
    views, limitations = _views(pages, text, request)
    facts = [
        {"key": "page_count", "label": "Pages", "value": str(len(pages))},
        {"key": "source_bytes", "label": "Source bytes", "value": str(source_path.stat().st_size)},
        {"key": "text_bytes", "label": "Extracted text bytes", "value": str(len(text.encode()))},
    ]
    return {
        "title": "PDF preview",
        "summary": "Offline structural, metadata, page-render, signature, and OCR inspection of the exact source bytes.",
        "views": views,
        "facts": facts,
        "limitations": limitations,
        "observations": observations,
        "evidenceArtifacts": [
            {
                "check": "pdf.page_render_complete",
                "mediaType": "application/json",
                "name": "pdf-structure.json",
                "sourcePath": str(structure_path),
            },
            {
                "check": "pdf.text_extraction_binding"
                if media_type == PDF
                else "pdf.ocr_text_binding",
                "mediaType": "text/plain",
                "name": "extracted-text.txt",
                "sourcePath": str(text_path),
            },
        ],
    }
