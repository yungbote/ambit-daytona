from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from render_command import PDF_OPERATION, RenderCommandError, canonical_bytes


SCHEMA = "ambit.c18-specialist-render-runtime-policy-matrix/v1"
POLICY_PATH = Path(__file__).with_name("render-policy-matrix.v1.json")


def _load(
    path: Path = POLICY_PATH,
    *,
    schema: str = SCHEMA,
    fields: set[str] | None = None,
    identity_fields: tuple[str, ...] = ("facet", "sourceMediaType"),
) -> dict[str, Any]:
    payload = path.read_bytes()

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RenderCommandError("runtime policy matrix has duplicate JSON keys")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RenderCommandError("runtime policy matrix is not canonical JSON") from error
    if payload != canonical_bytes(value) + b"\n":
        raise RenderCommandError("runtime policy matrix bytes are noncanonical")
    if not isinstance(value, dict) or set(value) != {"entries", "schema"}:
        raise RenderCommandError("runtime policy matrix fields are invalid")
    if value["schema"] != schema or not isinstance(value["entries"], list):
        raise RenderCommandError("runtime policy matrix identity is invalid")
    entry_fields = fields if fields is not None else {
        "checkLabels", "executablePath", "executorPackRevisionRef", "facet",
        "packChecks", "renderMode", "rendererRef", "representation",
        "requiredSchemaUri", "sourceMediaType", "validationPolicyRef",
    }
    identities: list[tuple[str, ...]] = []
    for entry in value["entries"]:
        if not isinstance(entry, dict) or set(entry) != entry_fields:
            raise RenderCommandError("runtime policy matrix entry fields are invalid")
        identities.append(tuple(entry[field] for field in identity_fields))
    if identities != sorted(set(identities)):
        raise RenderCommandError("runtime policy matrix entries are not canonical")
    return value


POLICY_MATRIX = _load()
PDF_POLICY_MATRIX = _load(
    Path(__file__).with_name("render-policy-matrix.office-pdf.v3.json"),
    schema="ambit.c18-specialist-render-runtime-policy-matrix/v3",
    fields={
        "operation", "sourceMediaType", "executablePath", "rendererRef",
        "policyRef", "executorPackRevisionRef",
    },
    identity_fields=("operation", "sourceMediaType"),
)


def require_request_policy(request: dict[str, Any]) -> dict[str, Any]:
    if request["operation"] == PDF_OPERATION:
        matches = [
            entry for entry in PDF_POLICY_MATRIX["entries"]
            if entry["operation"] == PDF_OPERATION
            and entry["sourceMediaType"] == request["source"]["mediaType"]
        ]
        if len(matches) != 1:
            raise RenderCommandError("request has no exact PDF conversion policy")
        policy = matches[0]
        if request["renderer"] != {
            key: policy[key] for key in ("executablePath", "rendererRef", "policyRef")
        }:
            raise RenderCommandError("PDF renderer differs from runtime policy")
        if policy["executorPackRevisionRef"] not in {
            entry["ref"] for entry in request["runtime"]["packRevisions"]
        }:
            raise RenderCommandError("PDF runtime omits the exact executor pack")
        return policy
    matches = [
        entry
        for entry in POLICY_MATRIX["entries"]
        if entry["facet"] == request["facet"]
        and entry["sourceMediaType"] == request["source"]["mediaType"]
    ]
    if len(matches) != 1:
        raise RenderCommandError("request has no exact runtime policy entry")
    policy = matches[0]
    if request["renderer"] != {
        "executablePath": policy["executablePath"],
        "rendererRef": policy["rendererRef"],
        "validationPolicyRef": policy["validationPolicyRef"],
        "representation": policy["representation"],
        "renderMode": policy["renderMode"],
    }:
        raise RenderCommandError("request renderer differs from runtime policy")
    if request["packRequiredChecks"] != policy["checkLabels"]:
        raise RenderCommandError("request checks differ from runtime policy")
    required_schema = policy["requiredSchemaUri"]
    if required_schema is not None and request["source"]["schemaUri"] != required_schema:
        raise RenderCommandError("request schema differs from runtime policy")
    pack_refs = [entry["ref"] for entry in request["runtime"]["packRevisions"]]
    if policy["executorPackRevisionRef"] not in pack_refs:
        raise RenderCommandError("request runtime omits the exact executor pack")
    return policy
