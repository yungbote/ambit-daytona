from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from typing import Any


CONTRACT = "ambit.c18-specialist-artifact-preview/v1"
MEDIA_TYPE = "application/vnd.ambit.c18-specialist-artifact-preview+json"
SCHEMA_VERSION = 1
FACETS = frozenset(
    {
        "data_analysis",
        "pdf",
        "presentation",
        "research",
        "spreadsheet",
        "web_application",
    }
)
MAXIMUM_PREVIEW_BYTES = 16 * 1024 * 1024
MAXIMUM_TEXT_VIEW_BYTES = 1024 * 1024
MAXIMUM_IMAGE_VIEW_BYTES = 512 * 1024
MAXIMUM_AGGREGATE_VIEW_BYTES = 4 * 1024 * 1024
MAXIMUM_IMAGE_DIMENSION = 4_096
MAXIMUM_IMAGE_PIXELS = 8 * 1024 * 1024
MAXIMUM_AGGREGATE_IMAGE_PIXELS = 32 * 1024 * 1024
MAXIMUM_VIEWS = 128
MAXIMUM_FACTS = 128
MAXIMUM_VALIDATIONS = 256
MAXIMUM_LIMITATIONS = 128
TOKEN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
PLAIN_TEXT_CONTROL = re.compile(
    "[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\ud800-\udfff]"
)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class PublicPreviewError(ValueError):
    """The C18 public preview does not match the cross-runtime byte contract."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise PublicPreviewError("preview is not strict canonical JSON") from error


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact_record(value: object, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PublicPreviewError(f"{name} fields are invalid")
    return value


def _utf16_length(value: str) -> int:
    return len(value.encode("utf-16-le", errors="strict")) // 2


def _descriptive(value: object, name: str, max_chars: int, max_bytes: int) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise PublicPreviewError(f"{name} is not exact printable text")
    if (
        _utf16_length(value) > max_chars
        or len(value.encode("utf-8")) > max_bytes
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value)
    ):
        raise PublicPreviewError(f"{name} exceeds its canonical text boundary")
    return value


def _token(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or not TOKEN.fullmatch(value):
        raise PublicPreviewError(f"{name} is not a canonical token")
    return value


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PublicPreviewError(f"{name} is outside its integer bound")
    return value


def _sha256(value: object, name: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise PublicPreviewError(f"{name} is not an exact SHA-256")
    return value


def _sorted_unique(values: list[str], name: str) -> None:
    if values != sorted(set(values)):
        raise PublicPreviewError(f"{name} is not sorted and unique")


def _plain_text(value: object, name: str) -> tuple[str, bytes]:
    if (
        not isinstance(value, str)
        or not value
        or _utf16_length(value) > MAXIMUM_TEXT_VIEW_BYTES
        or unicodedata.normalize("NFC", value) != value
        or "\r" in value
        or PLAIN_TEXT_CONTROL.search(value)
    ):
        raise PublicPreviewError(f"{name} is not canonical plain text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PublicPreviewError(f"{name} is not well-formed Unicode") from error
    if len(encoded) > MAXIMUM_TEXT_VIEW_BYTES:
        raise PublicPreviewError(f"{name} exceeds its byte bound")
    return value, encoded


def _canonical_base64(value: object, name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise PublicPreviewError(f"{name} is not base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise PublicPreviewError(f"{name} is not canonical base64") from error
    if not decoded or len(decoded) > MAXIMUM_IMAGE_VIEW_BYTES or base64.b64encode(decoded).decode() != value:
        raise PublicPreviewError(f"{name} is not canonical bounded base64")
    return decoded


def _validate_view(value: object, ordinal: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PublicPreviewError("preview view is not an object")
    kind = value.get("kind")
    if kind == "text":
        record = _exact_record(
            value,
            {"body", "byteLength", "digest", "kind", "label", "mediaType", "ordinal"},
            "text view",
        )
        if record["mediaType"] != "text/plain":
            raise PublicPreviewError("text view media type is invalid")
        body, payload = _plain_text(record["body"], "text view body")
        result: dict[str, Any] = {
            "kind": "text",
            "ordinal": _integer(record["ordinal"], "text view ordinal", 1, MAXIMUM_VIEWS),
            "label": _descriptive(record["label"], "text view label", 256, 1_024),
            "mediaType": "text/plain",
            "byteLength": _integer(record["byteLength"], "text view bytes", 1, MAXIMUM_TEXT_VIEW_BYTES),
            "digest": _sha256(record["digest"], "text view digest"),
            "body": body,
        }
    elif kind == "image":
        record = _exact_record(
            value,
            {
                "altText",
                "bodyBase64",
                "byteLength",
                "digest",
                "height",
                "kind",
                "label",
                "mediaType",
                "ordinal",
                "width",
            },
            "image view",
        )
        media_type = record["mediaType"]
        if media_type != "image/png":
            raise PublicPreviewError("image view media type is invalid")
        payload = _canonical_base64(record["bodyBase64"], "image view body")
        if (
            len(payload) < 24
            or not payload.startswith(PNG_SIGNATURE)
            or int.from_bytes(payload[8:12], "big") != 13
            or payload[12:16] != b"IHDR"
        ):
            raise PublicPreviewError("image view does not contain PNG bytes")
        actual_width = int.from_bytes(payload[16:20], "big")
        actual_height = int.from_bytes(payload[20:24], "big")
        width = _integer(record["width"], "image view width", 1, MAXIMUM_IMAGE_DIMENSION)
        height = _integer(record["height"], "image view height", 1, MAXIMUM_IMAGE_DIMENSION)
        if actual_width != width or actual_height != height or width * height > MAXIMUM_IMAGE_PIXELS:
            raise PublicPreviewError("image view dimensions are forged or exceed their bound")
        result = {
            "kind": "image",
            "ordinal": _integer(record["ordinal"], "image view ordinal", 1, MAXIMUM_VIEWS),
            "label": _descriptive(record["label"], "image view label", 256, 1_024),
            "altText": _descriptive(record["altText"], "image view alt text", 2_048, 8_192),
            "mediaType": media_type,
            "width": width,
            "height": height,
            "byteLength": _integer(record["byteLength"], "image view bytes", 1, MAXIMUM_IMAGE_VIEW_BYTES),
            "digest": _sha256(record["digest"], "image view digest"),
            "bodyBase64": base64.b64encode(payload).decode(),
        }
    else:
        raise PublicPreviewError("preview view kind is invalid")
    if result["ordinal"] != ordinal:
        raise PublicPreviewError("preview view ordinals are not contiguous")
    if result["byteLength"] != len(payload) or result["digest"] != _digest_bytes(payload):
        raise PublicPreviewError("preview view byte identity is forged")
    return result


def _validate_body(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {"facet", "facts", "limitations", "summary", "title", "validation", "views"},
        "preview body",
    )
    facet = record["facet"]
    if facet not in FACETS:
        raise PublicPreviewError("preview facet is invalid")
    raw_views = record["views"]
    if not isinstance(raw_views, list) or not 1 <= len(raw_views) <= MAXIMUM_VIEWS:
        raise PublicPreviewError("preview view roster is invalid")
    views = [_validate_view(value, index + 1) for index, value in enumerate(raw_views)]
    if sum(view["byteLength"] for view in views) > MAXIMUM_AGGREGATE_VIEW_BYTES:
        raise PublicPreviewError("decoded preview views exceed their total byte bound")
    aggregate_pixels = sum(
        view["width"] * view["height"] for view in views if view["kind"] == "image"
    )
    if aggregate_pixels > MAXIMUM_AGGREGATE_IMAGE_PIXELS:
        raise PublicPreviewError("decoded preview images exceed their aggregate pixel bound")

    raw_facts = record["facts"]
    if not isinstance(raw_facts, list) or len(raw_facts) > MAXIMUM_FACTS:
        raise PublicPreviewError("preview fact roster is invalid")
    facts = []
    for value in raw_facts:
        item = _exact_record(value, {"key", "label", "value"}, "preview fact")
        facts.append(
            {
                "key": _token(item["key"], "preview fact key"),
                "label": _descriptive(item["label"], "preview fact label", 256, 1_024),
                "value": _descriptive(item["value"], "preview fact value", 1_024, 4_096),
            }
        )
    _sorted_unique([item["key"] for item in facts], "preview facts")

    raw_validation = record["validation"]
    if not isinstance(raw_validation, list) or not 1 <= len(raw_validation) <= MAXIMUM_VALIDATIONS:
        raise PublicPreviewError("preview validation roster is invalid")
    validation = []
    for value in raw_validation:
        item = _exact_record(value, {"check", "label", "status"}, "preview validation")
        if item["status"] != "passed":
            raise PublicPreviewError("preview validation status is invalid")
        validation.append(
            {
                "check": _token(item["check"], "preview validation check"),
                "label": _descriptive(item["label"], "preview validation label", 512, 2_048),
                "status": item["status"],
            }
        )
    _sorted_unique([item["check"] for item in validation], "preview validation")

    raw_limitations = record["limitations"]
    if not isinstance(raw_limitations, list) or len(raw_limitations) > MAXIMUM_LIMITATIONS:
        raise PublicPreviewError("preview limitation roster is invalid")
    limitations = []
    for value in raw_limitations:
        item = _exact_record(value, {"code", "message", "severity"}, "preview limitation")
        if item["severity"] not in {"info", "warning"}:
            raise PublicPreviewError("preview limitation severity is invalid")
        limitations.append(
            {
                "code": _token(item["code"], "preview limitation code"),
                "severity": item["severity"],
                "message": _descriptive(item["message"], "preview limitation message", 2_048, 8_192),
            }
        )
    _sorted_unique([item["code"] for item in limitations], "preview limitations")
    return {
        "facet": facet,
        "title": _descriptive(record["title"], "preview title", 256, 1_024),
        "summary": _descriptive(record["summary"], "preview summary", 4_096, 16_384),
        "views": views,
        "facts": facts,
        "validation": validation,
        "limitations": limitations,
    }


def create_preview(value: object) -> dict[str, Any]:
    body = {
        "contract": CONTRACT,
        "schemaVersion": SCHEMA_VERSION,
        **_validate_body(value),
    }
    preview = {**body, "digest": _digest_bytes(_canonical_bytes(body))}
    encoded = _canonical_bytes(preview)
    if len(encoded) > MAXIMUM_PREVIEW_BYTES:
        raise PublicPreviewError("sealed preview exceeds its byte bound")
    return preview


def validate_preview(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {
            "contract",
            "digest",
            "facet",
            "facts",
            "limitations",
            "schemaVersion",
            "summary",
            "title",
            "validation",
            "views",
        },
        "preview",
    )
    if record["contract"] != CONTRACT or record["schemaVersion"] != SCHEMA_VERSION:
        raise PublicPreviewError("preview contract identity is invalid")
    expected = create_preview(
        {key: record[key] for key in ("facet", "facts", "limitations", "summary", "title", "validation", "views")}
    )
    if record != expected:
        raise PublicPreviewError("preview is noncanonical or has a forged digest")
    return expected


def encode_preview(value: object) -> bytes:
    return _canonical_bytes(validate_preview(value))


def parse_preview_bytes(value: bytes) -> dict[str, Any]:
    if not isinstance(value, bytes) or not 1 <= len(value) <= MAXIMUM_PREVIEW_BYTES:
        raise PublicPreviewError("preview bytes are empty or exceed their bound")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise PublicPreviewError(f"duplicate JSON key {key!r}")
            result[key] = child
        return result

    try:
        source = json.loads(value.decode("utf-8", errors="strict"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicPreviewError("preview bytes are not canonical UTF-8 JSON") from error
    preview = validate_preview(source)
    if value != _canonical_bytes(preview):
        raise PublicPreviewError("preview bytes are not the exact canonical encoding")
    return preview
