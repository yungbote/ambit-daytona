from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from public_preview import MEDIA_TYPE as PREVIEW_MEDIA_TYPE


REQUEST_CONTRACT = "ambit.c18-specialist-render-command-request/v2"
RESULT_CONTRACT = "ambit.c18-specialist-render-command-result/v2"
PDF_REQUEST_CONTRACT = "ambit.c18-specialist-render-command-request/v3"
PDF_RESULT_CONTRACT = "ambit.c18-specialist-render-command-result/v3"
PDF_OPERATION = "convert_to_pdf"
PDF_MEDIA_TYPE = "application/pdf"
OFFICE_EXECUTABLE = "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render"
OFFICE_SOURCE_SUFFIXES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
}
OFFICE_MEDIA_TYPES = frozenset(OFFICE_SOURCE_SUFFIXES)
MAXIMUM_OFFICE_SOURCE_BYTES = 64 * 1024 * 1024
MAXIMUM_PDF_BYTES = 256 * 1024 * 1024
EVIDENCE_CONTRACT = "ambit.c18-specialist-render-check-evidence/v1"
EVIDENCE_MEDIA_TYPE = "application/vnd.ambit.c18-specialist-render-check-evidence+json"
MAXIMUM_COMMAND_BYTES = 2 * 1024 * 1024
MAXIMUM_EVIDENCE_BYTES = 1024 * 1024
MAXIMUM_EVIDENCE_ARTIFACT_BYTES = 512 * 1024 * 1024
MAXIMUM_SOURCE_BYTES = 512 * 1024 * 1024
MAXIMUM_CHECKS = 256
MAXIMUM_PACKS = 32
TOKEN = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
MEDIA_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*$"
)
SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")
PRODUCT_JOB_ROOT = re.compile(
    r"^/workspace/\.ambit/render-jobs/(?P<job_id>"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
PRODUCT_JOB_REF = re.compile(
    r"^ambit://artifact-render-jobs/(?P<job_id>"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})$"
)
CONFORMANCE_JOB_REF = re.compile(
    r"^ambit://artifact-render-jobs/conformance-"
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$"
)
CONFORMANCE_PROFILE_REF = "ambit.workspace-runtime/c18-specialist-conformance@1"
ISO_INSTANT = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
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
PACK_EXECUTABLES = {
    "data_analysis": "/opt/ambit/runtime-pack/data-research/bin/ambit-specialist-render",
    "pdf": "/opt/ambit/runtime-pack/pdf-ocr/bin/ambit-specialist-render",
    "presentation": "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render",
    "research": "/opt/ambit/runtime-pack/data-research/bin/ambit-specialist-render",
    "spreadsheet": "/opt/ambit/runtime-pack/office-authoring/bin/ambit-specialist-render",
    "web_application": "/opt/ambit/runtime-pack/web-browser/bin/ambit-specialist-render",
}


class RenderCommandError(ValueError):
    """A command request/result does not match the exact host/runtime protocol."""


def canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise RenderCommandError("value is not strict canonical JSON") from error


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact_record(value: object, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RenderCommandError(f"{name} fields are invalid")
    return value


def _token(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or not TOKEN.fullmatch(value):
        raise RenderCommandError(f"{name} is not a canonical token")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise RenderCommandError(f"{name} is not an exact SHA-256")
    return value


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RenderCommandError(f"{name} exceeds its integer bound")
    return value


def _printable(value: object, name: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value)
    ):
        raise RenderCommandError(f"{name} is not exact bounded printable text")
    return value


def _operational_ref(value: object, name: str) -> str:
    ref = _printable(value, name, 512)
    if ":" not in ref and "@" not in ref:
        raise RenderCommandError(f"{name} is not an operational reference")
    return ref


def _media_type(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or not MEDIA_TYPE.fullmatch(value):
        raise RenderCommandError(f"{name} is not a canonical media type")
    return value


def _safe_path(value: object, zone: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > 128
        or value.startswith("/")
    ):
        raise RenderCommandError(f"{name} is not a relative path")
    if "\\" in value or ":" in value or "//" in value:
        raise RenderCommandError(f"{name} contains an unsafe separator")
    parts = PurePosixPath(value).parts
    if (
        not parts
        or parts[0] != zone
        or len(parts) == 1
        or any(
            part in {"", ".", ".."}
            or part.endswith(".sock")
            or not SAFE_SEGMENT.fullmatch(part)
            for part in parts
        )
    ):
        raise RenderCommandError(f"{name} escapes the {zone} semantic zone")
    return value


def _is_beneath(path: str, root: str) -> bool:
    return path.startswith(root + "/") and len(path) > len(root) + 1


def _job_root(value: object) -> str:
    if value == "/ambit":
        return value
    if not isinstance(value, str) or not PRODUCT_JOB_ROOT.fullmatch(value):
        raise RenderCommandError("request job root is not policy-admitted")
    return value


def _require_job_root_authority(
    job_root: str,
    job_ref: str,
    profile_ref: str,
) -> None:
    if job_root == "/ambit":
        if (
            CONFORMANCE_JOB_REF.fullmatch(job_ref) is None
            or profile_ref != CONFORMANCE_PROFILE_REF
        ):
            raise RenderCommandError(
                "the /ambit semantic root is reserved for exact conformance authority"
            )
        return
    root_match = PRODUCT_JOB_ROOT.fullmatch(job_root)
    ref_match = PRODUCT_JOB_REF.fullmatch(job_ref)
    if (
        root_match is None
        or ref_match is None
        or root_match.group("job_id") != ref_match.group("job_id")
        or profile_ref == CONFORMANCE_PROFILE_REF
    ):
        raise RenderCommandError(
            "product semantic root does not bind the exact artifact render job"
        )


def _iso_instant(value: object, name: str) -> str:
    if not isinstance(value, str) or not ISO_INSTANT.fullmatch(value):
        raise RenderCommandError(f"{name} is not a canonical millisecond UTC instant")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RenderCommandError(f"{name} is not a real instant") from error
    if parsed.tzinfo != timezone.utc:
        raise RenderCommandError(f"{name} is not UTC")
    return value


def instant_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _pinned(value: object, name: str) -> dict[str, str]:
    record = _exact_record(value, {"digest", "ref"}, name)
    return {
        "ref": _operational_ref(record["ref"], f"{name} ref"),
        "digest": _digest(record["digest"], f"{name} digest"),
    }


def _checks(value: object, name: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > MAXIMUM_CHECKS or (not value and not allow_empty):
        raise RenderCommandError(f"{name} roster is invalid")
    checks = [_token(item, f"{name} item") for item in value]
    if checks != sorted(set(checks)):
        raise RenderCommandError(f"{name} is not sorted and unique")
    return checks


def _labeled_checks(value: object, name: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAXIMUM_CHECKS:
        raise RenderCommandError(f"{name} roster is invalid")
    checks = []
    for item in value:
        record = _exact_record(item, {"check", "label"}, f"{name} item")
        checks.append(
            {
                "check": _token(record["check"], f"{name} check"),
                "label": _printable(record["label"], f"{name} label", 512),
            }
        )
    names = [item["check"] for item in checks]
    if names != sorted(set(names)):
        raise RenderCommandError(f"{name} is not sorted and unique")
    return checks


def pack_check_names(request: dict[str, Any]) -> list[str]:
    if request.get("operation") == PDF_OPERATION:
        return []
    return [item["check"] for item in request["packRequiredChecks"]]


def _seal(contract: str, body: dict[str, Any]) -> dict[str, Any]:
    unsealed = {"contract": contract, **body}
    sealed = {**unsealed, "digest": sha256_bytes(canonical_bytes(unsealed))}
    if len(canonical_bytes(sealed)) > MAXIMUM_COMMAND_BYTES:
        raise RenderCommandError("sealed command exceeds its byte bound")
    return sealed


def _parse_source(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {"byteLength", "digest", "mediaType", "path", "ref", "schemaUri"},
        "request source",
    )
    return {
        "path": _safe_path(record["path"], "inputs", "request source path"),
        "ref": _operational_ref(record["ref"], "request source ref"),
        "digest": _digest(record["digest"], "request source digest"),
        "byteLength": _integer(
            record["byteLength"], "request source bytes", 1, MAXIMUM_SOURCE_BYTES
        ),
        "mediaType": _media_type(record["mediaType"], "request source media type"),
        "schemaUri": (
            None
            if record["schemaUri"] is None
            else _operational_ref(record["schemaUri"], "request source schema URI")
        ),
    }


def _parse_renderer(value: object, facet: str) -> dict[str, str]:
    record = _exact_record(
        value,
        {
            "executablePath",
            "rendererRef",
            "validationPolicyRef",
            "representation",
            "renderMode",
        },
        "request renderer",
    )
    executable = _printable(record["executablePath"], "request executable", 1_024)
    if executable != PACK_EXECUTABLES[facet]:
        raise RenderCommandError("request executable is not owned by the selected facet pack")
    return {
        "executablePath": executable,
        "rendererRef": _operational_ref(record["rendererRef"], "request renderer ref"),
        "validationPolicyRef": _operational_ref(
            record["validationPolicyRef"], "request validation policy ref"
        ),
        "representation": _token(record["representation"], "request representation"),
        "renderMode": _token(record["renderMode"], "request render mode"),
    }


def _parse_runtime(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {"packRevisions", "profileRevision", "workspaceExecutionManifest"},
        "request runtime",
    )
    raw_packs = record["packRevisions"]
    if not isinstance(raw_packs, list) or not 1 <= len(raw_packs) <= MAXIMUM_PACKS:
        raise RenderCommandError("request pack roster is invalid")
    packs = [_pinned(item, "request pack revision") for item in raw_packs]
    if [item["ref"] for item in packs] != sorted({item["ref"] for item in packs}):
        raise RenderCommandError("request pack revisions are not sorted and unique")
    return {
        "workspaceExecutionManifest": _pinned(
            record["workspaceExecutionManifest"], "request workspace execution manifest"
        ),
        "profileRevision": _pinned(record["profileRevision"], "request profile revision"),
        "packRevisions": packs,
    }


def _parse_output(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {
            "jobOutputRoot",
            "maximumAggregateImagePixels",
            "maximumImagePixels",
            "maximumPreviewBytes",
            "previewMediaType",
            "previewPath",
            "resultPath",
        },
        "request output",
    )
    if record["previewMediaType"] != PREVIEW_MEDIA_TYPE:
        raise RenderCommandError("request preview media type is invalid")
    preview_path = _safe_path(record["previewPath"], "outputs", "preview path")
    result_path = _safe_path(record["resultPath"], "outputs", "result path")
    job_output_root = _safe_path(
        record["jobOutputRoot"], "outputs", "job output root"
    )
    if preview_path == result_path:
        raise RenderCommandError("preview and result paths overlap")
    output_prefix = job_output_root + "/"
    if not preview_path.startswith(output_prefix) or not result_path.startswith(
        output_prefix
    ):
        raise RenderCommandError("output files escape the exact job output root")
    return {
        "jobOutputRoot": job_output_root,
        "previewPath": preview_path,
        "resultPath": result_path,
        "previewMediaType": PREVIEW_MEDIA_TYPE,
        "maximumPreviewBytes": _integer(
            record["maximumPreviewBytes"], "maximum preview bytes", 1, 8 * 1024 * 1024
        ),
        "maximumImagePixels": _integer(
            record["maximumImagePixels"], "maximum image pixels", 1, 8 * 1024 * 1024
        ),
        "maximumAggregateImagePixels": _integer(
            record["maximumAggregateImagePixels"],
            "maximum aggregate image pixels",
            1,
            32 * 1024 * 1024,
        ),
    }


def create_pdf_request(value: object) -> dict[str, Any]:
    """A bounded document read shares operation custody, without authoring policy."""
    record = _exact_record(
        value,
        {
            "deadlineAt", "jobRef", "jobRoot", "output", "requestPath",
            "renderer", "runtime", "source",
        },
        "PDF conversion request body",
    )
    source = _parse_source(record["source"])
    if (
        source["mediaType"] not in OFFICE_MEDIA_TYPES
        or source["byteLength"] > MAXIMUM_OFFICE_SOURCE_BYTES
    ):
        raise RenderCommandError("PDF conversion source type or size is unsupported")
    renderer = _exact_record(
        record["renderer"], {"executablePath", "rendererRef", "policyRef"},
        "PDF conversion renderer",
    )
    if renderer["executablePath"] != OFFICE_EXECUTABLE:
        raise RenderCommandError("PDF conversion executable is not owned by the Office pack")
    renderer = {
        "executablePath": OFFICE_EXECUTABLE,
        "rendererRef": _operational_ref(renderer["rendererRef"], "PDF renderer ref"),
        "policyRef": _operational_ref(renderer["policyRef"], "PDF policy ref"),
    }
    output = _exact_record(
        record["output"],
        {"jobOutputRoot", "resultPath", "pdfPath", "maximumPdfBytes"},
        "PDF conversion output",
    )
    output = {
        "jobOutputRoot": _safe_path(output["jobOutputRoot"], "outputs", "job output root"),
        "resultPath": _safe_path(output["resultPath"], "outputs", "result path"),
        "pdfPath": _safe_path(output["pdfPath"], "outputs", "PDF path"),
        "maximumPdfBytes": _integer(
            output["maximumPdfBytes"], "maximum PDF bytes", 1, MAXIMUM_PDF_BYTES
        ),
    }
    if (
        output["resultPath"] == output["pdfPath"]
        or any(
            not _is_beneath(output[key], output["jobOutputRoot"])
            for key in ("resultPath", "pdfPath")
        )
    ):
        raise RenderCommandError("PDF output paths overlap or escape their job root")
    request_path = _safe_path(record["requestPath"], "inputs", "request path")
    if source["path"] == request_path:
        raise RenderCommandError("request and source paths overlap")
    job_ref = _operational_ref(record["jobRef"], "request job ref")
    job_root = _job_root(record["jobRoot"])
    runtime = _parse_runtime(record["runtime"])
    _require_job_root_authority(job_root, job_ref, runtime["profileRevision"]["ref"])
    return _seal(
        PDF_REQUEST_CONTRACT,
        {
            "operation": PDF_OPERATION,
            "jobRef": job_ref,
            "jobRoot": job_root,
            "requestPath": request_path,
            "source": source,
            "renderer": renderer,
            "runtime": runtime,
            "output": output,
            "deadlineAt": _iso_instant(record["deadlineAt"], "request deadline"),
        },
    )


def _parse_pdf_request(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {
            "contract", "digest", "operation", "deadlineAt", "jobRef", "jobRoot",
            "output", "requestPath", "renderer", "runtime", "source",
        },
        "PDF conversion request",
    )
    if record["operation"] != PDF_OPERATION:
        raise RenderCommandError("PDF conversion operation is invalid")
    parsed = create_pdf_request(
        {key: child for key, child in record.items() if key not in {"contract", "digest", "operation"}}
    )
    if record != parsed:
        raise RenderCommandError("PDF conversion request is noncanonical or forged")
    return parsed


def create_request(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {
            "deadlineAt",
            "facet",
            "jobRef",
            "jobRoot",
            "output",
            "packRequiredChecks",
            "requestPath",
            "renderer",
            "runtime",
            "source",
        },
        "request body",
    )
    facet = _token(record["facet"], "request facet")
    if facet not in FACETS:
        raise RenderCommandError("request facet is invalid")
    source = _parse_source(record["source"])
    output = _parse_output(record["output"])
    request_path = _safe_path(
        record["requestPath"], "inputs", "render request path"
    )
    if source["path"] in {
        request_path,
        output["previewPath"],
        output["resultPath"],
    }:
        raise RenderCommandError("request, source, and output paths overlap")
    job_ref = _operational_ref(record["jobRef"], "request job ref")
    job_root = _job_root(record["jobRoot"])
    runtime = _parse_runtime(record["runtime"])
    _require_job_root_authority(
        job_root,
        job_ref,
        runtime["profileRevision"]["ref"],
    )
    return _seal(
        REQUEST_CONTRACT,
        {
            "operation": "render_validate",
            "jobRef": job_ref,
            "jobRoot": job_root,
            "requestPath": request_path,
            "facet": facet,
            "source": source,
            "renderer": _parse_renderer(record["renderer"], facet),
            "runtime": runtime,
            "packRequiredChecks": _labeled_checks(
                record["packRequiredChecks"], "request pack checks"
            ),
            "output": output,
            "deadlineAt": _iso_instant(record["deadlineAt"], "request deadline"),
        },
    )


def parse_request(value: object) -> dict[str, Any]:
    if isinstance(value, dict) and value.get("contract") == PDF_REQUEST_CONTRACT:
        return _parse_pdf_request(value)
    record = _exact_record(
        value,
        {
            "contract",
            "deadlineAt",
            "digest",
            "facet",
            "jobRef",
            "jobRoot",
            "operation",
            "output",
            "packRequiredChecks",
            "requestPath",
            "renderer",
            "runtime",
            "source",
        },
        "request",
    )
    if record["contract"] != REQUEST_CONTRACT or record["operation"] != "render_validate":
        raise RenderCommandError("request contract identity is invalid")
    parsed = create_request(
        {
            key: record[key]
            for key in (
                "deadlineAt",
                "facet",
                "jobRef",
                "jobRoot",
                "output",
                "packRequiredChecks",
                "requestPath",
                "renderer",
                "runtime",
                "source",
            )
        }
    )
    if record != parsed:
        raise RenderCommandError("request is noncanonical or has a forged digest")
    return parsed


def parse_request_bytes(value: bytes) -> dict[str, Any]:
    return _parse_exact_bytes(value, parse_request)


def _parse_evidence(value: object) -> dict[str, Any]:
    record = _exact_record(value, {"byteLength", "digest", "mediaType", "path"}, "check evidence")
    return {
        "path": _safe_path(record["path"], "outputs", "check evidence path"),
        "mediaType": _media_type(record["mediaType"], "check evidence media type"),
        "byteLength": _integer(
            record["byteLength"],
            "check evidence bytes",
            1,
            MAXIMUM_EVIDENCE_ARTIFACT_BYTES,
        ),
        "digest": _digest(record["digest"], "check evidence digest"),
    }


def _parse_result_checks(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > MAXIMUM_CHECKS:
        raise RenderCommandError("result check roster is invalid")
    checks = []
    for item in value:
        record = _exact_record(item, {"check", "evidence", "outcome"}, "result check")
        if record["outcome"] not in {"blocked", "failed", "passed"}:
            raise RenderCommandError("result check outcome is invalid")
        checks.append(
            {
                "check": _token(record["check"], "result check name"),
                "outcome": record["outcome"],
                "evidence": (
                    None if record["evidence"] is None else _parse_evidence(record["evidence"])
                ),
            }
        )
    if [item["check"] for item in checks] != sorted({item["check"] for item in checks}):
        raise RenderCommandError("result checks are not sorted and unique")
    return checks


def _parse_execution(value: object) -> dict[str, Any]:
    record = _exact_record(
        value, {"completedAt", "executorRevision", "startedAt"}, "result execution"
    )
    started_at = _iso_instant(record["startedAt"], "execution start")
    completed_at = _iso_instant(record["completedAt"], "execution completion")
    if completed_at < started_at:
        raise RenderCommandError("execution completion precedes start")
    return {
        "executorRevision": _pinned(record["executorRevision"], "executor revision"),
        "startedAt": started_at,
        "completedAt": completed_at,
    }


def _parse_failure(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    record = _exact_record(value, {"code", "message"}, "result failure")
    return {
        "code": _token(record["code"], "failure code"),
        "message": _printable(record["message"], "failure message", 2_048),
    }


def _create_pdf_result(request: dict[str, Any], value: object) -> dict[str, Any]:
    record = _exact_record(
        value, {"execution", "failure", "outcome", "pdf"}, "PDF conversion result body"
    )
    outcome = record["outcome"]
    if outcome not in {"cancelled", "failed", "succeeded"}:
        raise RenderCommandError("PDF conversion outcome is invalid")
    failure = _parse_failure(record["failure"])
    pdf = None if record["pdf"] is None else _parse_evidence(record["pdf"])
    if outcome == "succeeded":
        if (
            failure is not None
            or pdf is None
            or pdf["mediaType"] != PDF_MEDIA_TYPE
            or pdf["path"] != request["output"]["pdfPath"]
            or pdf["byteLength"] > request["output"]["maximumPdfBytes"]
        ):
            raise RenderCommandError("successful PDF result has no exact bounded PDF")
    elif pdf is not None or failure is None:
        raise RenderCommandError("non-success PDF result must not publish PDF bytes")
    return _seal(
        PDF_RESULT_CONTRACT,
        {
            "operation": PDF_OPERATION,
            "request": {key: request[key] for key in ("jobRef", "jobRoot", "digest")},
            "source": {key: request["source"][key] for key in ("mediaType", "digest", "byteLength")},
            "outcome": outcome,
            "execution": _parse_execution(record["execution"]),
            "pdf": pdf,
            "failure": failure,
        },
    )


def create_result(request_value: object, value: object) -> dict[str, Any]:
    request = parse_request(request_value)
    if request["operation"] == PDF_OPERATION:
        return _create_pdf_result(request, value)
    record = _exact_record(
        value,
        {"checks", "execution", "failure", "outcome", "preview"},
        "result body",
    )
    outcome = record["outcome"]
    if outcome not in {"cancelled", "failed", "succeeded"}:
        raise RenderCommandError("result outcome is invalid")
    execution = _parse_execution(record["execution"])
    checks = _parse_result_checks(record["checks"])
    preview = None
    if record["preview"] is not None:
        preview_record = _exact_record(
            record["preview"],
            {"byteLength", "bytesDigest", "envelopeDigest", "mediaType", "path"},
            "result preview",
        )
        if preview_record["mediaType"] != PREVIEW_MEDIA_TYPE:
            raise RenderCommandError("result preview media type is invalid")
        preview = {
            "path": _safe_path(preview_record["path"], "outputs", "result preview path"),
            "mediaType": PREVIEW_MEDIA_TYPE,
            "byteLength": _integer(
                preview_record["byteLength"], "result preview bytes", 1, 16 * 1024 * 1024
            ),
            "bytesDigest": _digest(preview_record["bytesDigest"], "result preview byte digest"),
            "envelopeDigest": _digest(
                preview_record["envelopeDigest"], "result preview envelope digest"
            ),
        }
    failure = _parse_failure(record["failure"])
    requested_checks = pack_check_names(request)
    if outcome == "succeeded":
        if (
            preview is None
            or failure is not None
            or preview["path"] != request["output"]["previewPath"]
            or preview["byteLength"] > request["output"]["maximumPreviewBytes"]
            or [item["check"] for item in checks] != requested_checks
            or any(item["outcome"] != "passed" or item["evidence"] is None for item in checks)
        ):
            raise RenderCommandError("successful result does not exactly pass the requested pack checks")
    elif preview is not None or failure is None or any(
        item["check"] not in requested_checks for item in checks
    ):
        raise RenderCommandError("non-success result relation is invalid")
    paths = [item["evidence"]["path"] for item in checks if item["evidence"] is not None]
    if (
        len(paths) != len(set(paths))
        or any(not _is_beneath(path, request["output"]["jobOutputRoot"]) for path in paths)
        or request["source"]["path"] in paths
        or request["output"]["previewPath"] in paths
        or request["output"]["resultPath"] in paths
    ):
        raise RenderCommandError("check evidence paths overlap another command artifact")
    return _seal(
        RESULT_CONTRACT,
        {
            "request": {
                "jobRef": request["jobRef"],
                "jobRoot": request["jobRoot"],
                "digest": request["digest"],
            },
            "outcome": outcome,
            "execution": execution,
            "preview": preview,
            "checks": checks,
            "failure": failure,
        },
    )


def parse_result(request_value: object, value: object) -> dict[str, Any]:
    request = parse_request(request_value)
    if request["operation"] == PDF_OPERATION:
        record = _exact_record(
            value,
            {"contract", "digest", "operation", "request", "source", "execution", "outcome", "pdf", "failure"},
            "PDF conversion result",
        )
        parsed = _create_pdf_result(
            request, {key: record[key] for key in ("execution", "outcome", "pdf", "failure")}
        )
        if record != parsed:
            raise RenderCommandError("PDF result identity is noncanonical or forged")
        return parsed
    record = _exact_record(
        value,
        {"checks", "contract", "digest", "execution", "failure", "outcome", "preview", "request"},
        "result",
    )
    if record["contract"] != RESULT_CONTRACT:
        raise RenderCommandError("result contract identity is invalid")
    identity = _exact_record(
        record["request"], {"digest", "jobRef", "jobRoot"}, "result request identity"
    )
    if identity != {
        "jobRef": request["jobRef"],
        "jobRoot": request["jobRoot"],
        "digest": request["digest"],
    }:
        raise RenderCommandError("result request identity differs")
    parsed = create_result(
        request,
        {key: record[key] for key in ("checks", "execution", "failure", "outcome", "preview")},
    )
    if record != parsed:
        raise RenderCommandError("result is noncanonical or has a forged digest")
    return parsed


def parse_result_bytes(request_value: object, value: bytes) -> dict[str, Any]:
    return _parse_exact_bytes(value, lambda source: parse_result(request_value, source))


def create_check_evidence(
    request: dict[str, Any],
    executor_revision: dict[str, str],
    check: str,
    outcome: str,
    facts: list[dict[str, str]],
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    if outcome not in {"failed", "passed"}:
        raise RenderCommandError("evidence outcome is invalid")
    fact_keys: list[str] = []
    normalized_facts: list[dict[str, str]] = []
    for fact in facts:
        record = _exact_record(fact, {"key", "value"}, "evidence fact")
        key = _token(record["key"], "evidence fact key")
        value = _printable(record["value"], "evidence fact value", 256)
        fact_keys.append(key)
        normalized_facts.append({"key": key, "value": value})
    if fact_keys != sorted(set(fact_keys)) or len(fact_keys) > 128:
        raise RenderCommandError("evidence facts are not sorted, unique, and bounded")
    normalized_artifacts = [_parse_evidence(item) for item in artifacts]
    artifact_paths = [item["path"] for item in normalized_artifacts]
    if (
        artifact_paths != sorted(set(artifact_paths))
        or len(artifact_paths) > 64
        or (
            "output" in request
            and any(
                not _is_beneath(path, request["output"]["jobOutputRoot"])
                for path in artifact_paths
            )
        )
    ):
        raise RenderCommandError("evidence artifacts are not sorted, unique, and bounded")
    body = {
        "contract": EVIDENCE_CONTRACT,
        "request": {
            "jobRef": request["jobRef"],
            "digest": request["digest"],
            "sourceDigest": request["source"]["digest"],
        },
        "executorRevision": _pinned(executor_revision, "evidence executor revision"),
        "check": _token(check, "evidence check"),
        "outcome": outcome,
        "facts": normalized_facts,
        "artifacts": normalized_artifacts,
    }
    evidence = {**body, "digest": sha256_bytes(canonical_bytes(body))}
    if len(canonical_bytes(evidence)) > MAXIMUM_EVIDENCE_BYTES:
        raise RenderCommandError("check evidence exceeds one MiB")
    return evidence


def parse_check_evidence(value: object) -> dict[str, Any]:
    record = _exact_record(
        value,
        {
            "artifacts",
            "check",
            "contract",
            "digest",
            "executorRevision",
            "facts",
            "outcome",
            "request",
        },
        "check evidence",
    )
    if record["contract"] != EVIDENCE_CONTRACT:
        raise RenderCommandError("check evidence contract identity is invalid")
    request = _exact_record(
        record["request"],
        {"digest", "jobRef", "sourceDigest"},
        "check evidence request",
    )
    normalized_request = {
        "jobRef": _operational_ref(request["jobRef"], "evidence job ref"),
        "digest": _digest(request["digest"], "evidence request digest"),
        "sourceDigest": _digest(
            request["sourceDigest"], "evidence source digest"
        ),
    }
    executor = _pinned(record["executorRevision"], "evidence executor revision")
    check = _token(record["check"], "evidence check")
    outcome = record["outcome"]
    if outcome not in {"failed", "passed"}:
        raise RenderCommandError("evidence outcome is invalid")
    evidence = create_check_evidence(
        {
            "jobRef": normalized_request["jobRef"],
            "digest": normalized_request["digest"],
            "source": {"digest": normalized_request["sourceDigest"]},
        },
        executor,
        check,
        outcome,
        record["facts"],
        record["artifacts"],
    )
    if evidence != record:
        raise RenderCommandError("check evidence is noncanonical or forged")
    return evidence


def parse_check_evidence_bytes(value: bytes) -> dict[str, Any]:
    return _parse_exact_bytes(value, parse_check_evidence)


def _parse_exact_bytes(value: bytes, parser: Any) -> dict[str, Any]:
    if not isinstance(value, bytes) or not 1 <= len(value) <= MAXIMUM_COMMAND_BYTES:
        raise RenderCommandError("command bytes are empty or exceed their bound")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise RenderCommandError(f"duplicate JSON key {key!r}")
            result[key] = child
        return result

    try:
        source = json.loads(value.decode("utf-8", errors="strict"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RenderCommandError("command bytes are not canonical UTF-8 JSON") from error
    parsed = parser(source)
    if value != canonical_bytes(parsed):
        raise RenderCommandError("command bytes are not the exact canonical encoding")
    return parsed
