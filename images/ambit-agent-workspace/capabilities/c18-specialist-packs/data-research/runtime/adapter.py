from __future__ import annotations

import hashlib
import json
import math
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pandas as pd
import pyarrow.parquet as pq

from process_control import ProcessDeadlineExceeded, ProcessFailure, run_bounded
from render_command import pack_check_names
from render_runner import AdapterFailure


PACK_ROOT = Path("/opt/ambit/runtime-pack/data-research")
PATH = f"{PACK_ROOT}/python/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAXIMUM_TEXT_INPUT_BYTES = 64 * 1024 * 1024
MAXIMUM_ROWS = 5_000_000
MAXIMUM_COLUMNS = 10_000
MAXIMUM_JSON_NODES = 2_000_000
MAXIMUM_JSON_DEPTH = 64
LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class _HtmlStructure(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.headings = 0
        self.links: list[str] = []
        self.scripts = 0
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings += 1
        if tag == "script":
            self.scripts += 1
        if tag == "a":
            for key, value in attrs:
                if key == "href" and value:
                    self.links.append(value)

    def handle_data(self, data: str) -> None:
        value = " ".join(data.split())
        if value:
            self.text.append(value)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _environment(scratch: Path) -> dict[str, str]:
    values = {
        "HOME": scratch / "home",
        "MPLCONFIGDIR": scratch / "matplotlib",
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
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TZ": "UTC",
    }


def _run(
    argv: list[str],
    *,
    scratch: Path,
    deadline: float,
    environment: dict[str, str],
) -> None:
    try:
        run_bounded(
            argv,
            deadline=deadline,
            cwd=scratch,
            environment=environment,
        )
    except ProcessDeadlineExceeded as error:
        raise AdapterFailure(
            "data_deadline_exceeded",
            "The data or research validator exceeded its exact deadline.",
            outcome="blocked",
        ) from error
    except ProcessFailure as error:
        raise AdapterFailure(
            "data_native_tool_failed",
            "An offline data or publishing tool rejected the artifact.",
            observations={
                "tool": Path(error.result.argv[0]).name,
                "exitCode": error.result.returncode,
                "stderrSha256": "sha256:" + hashlib.sha256(error.result.stderr).hexdigest(),
            },
        ) from error


def _json(path: Path) -> Any:
    if path.stat().st_size > MAXIMUM_TEXT_INPUT_BYTES:
        raise AdapterFailure("json_input_limit", "The JSON source exceeds its safe byte bound.")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AdapterFailure("duplicate_json_key", "The JSON source contains duplicate keys.")
            result[key] = value
        return result

    value = json.loads(path.read_text(encoding="utf-8", errors="strict"), object_pairs_hook=reject_duplicates)
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAXIMUM_JSON_NODES or depth > MAXIMUM_JSON_DEPTH:
            raise AdapterFailure("json_structure_limit", "The JSON source exceeds its structural bound.")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise AdapterFailure("json_number_invalid", "The JSON source contains a non-finite number.")
    return value


def _frame(path: Path, media_type: str) -> tuple[pd.DataFrame, dict[str, Any]]:
    if media_type in {"text/csv", "text/tab-separated-values"}:
        if path.stat().st_size > MAXIMUM_TEXT_INPUT_BYTES:
            raise AdapterFailure("table_input_limit", "The delimited source exceeds its safe byte bound.")
        frame = pd.read_csv(
            path,
            sep="\t" if media_type == "text/tab-separated-values" else ",",
            encoding="utf-8",
            keep_default_na=False,
        )
        source = "delimited"
    elif media_type == "application/json":
        value = _json(path)
        rows = value if isinstance(value, list) else value.get("rows") if isinstance(value, dict) else None
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise AdapterFailure(
                "json_table_shape_invalid",
                "The JSON data source must be a record array or contain one exact rows array.",
                check="data_analysis.schema_and_value_structure",
            )
        frame = pd.DataFrame.from_records(rows)
        source = "json-records"
    elif media_type == "application/vnd.apache.parquet":
        parquet = pq.ParquetFile(path)
        metadata = parquet.metadata
        if metadata.num_rows > MAXIMUM_ROWS or metadata.num_columns > MAXIMUM_COLUMNS:
            raise AdapterFailure(
                "parquet_structure_limit",
                "The Parquet source exceeds its admitted row or column bound.",
                check="data_analysis.schema_and_value_structure",
                observations={"rows": metadata.num_rows, "columns": metadata.num_columns},
            )
        frame = parquet.read().to_pandas()
        source = "parquet"
    else:
        raise AdapterFailure("unsupported_data_source", "The data source format is unsupported.")
    if len(frame) > MAXIMUM_ROWS or len(frame.columns) > MAXIMUM_COLUMNS or len(frame.columns) == 0:
        raise AdapterFailure(
            "table_structure_limit",
            "The decoded table exceeds its admitted shape or has no columns.",
            check="data_analysis.schema_and_value_structure",
        )
    return frame, {
        "decoder": source,
        "rowCount": len(frame),
        "columnCount": len(frame.columns),
        "columns": [str(value) for value in frame.columns],
        "dtypes": {str(key): str(value) for key, value in frame.dtypes.items()},
        "nullCount": int(frame.isna().sum().sum()),
    }


def _canonical_data_artifact(value: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {
        "assertions",
        "dataset",
        "environment",
        "lineage",
        "report",
        "reproduction",
        "schema",
    } or value["schema"] != "ambit.data-analysis-artifact/v1":
        raise AdapterFailure(
            "data_artifact_schema_invalid",
            "The canonical data-analysis artifact does not match its exact schema.",
            check="data_analysis.schema_and_output_integrity",
        )
    dataset = value["dataset"]
    environment = value["environment"]
    lineage = value["lineage"]
    reproduction = value["reproduction"]
    assertions = value["assertions"]
    report = value["report"]
    if (
        not isinstance(dataset, dict)
        or not isinstance(dataset.get("digest"), str)
        or not isinstance(environment, dict)
        or not isinstance(environment.get("seed"), int)
        or environment.get("timezone") != "UTC"
        or not isinstance(environment.get("packages"), list)
        or not isinstance(lineage, dict)
        or not isinstance(lineage.get("sources"), list)
        or not isinstance(lineage.get("transforms"), list)
        or not isinstance(reproduction, dict)
        or reproduction.get("matches") is not True
        or not isinstance(assertions, list)
        or any(not isinstance(item, dict) or item.get("passed") is not True for item in assertions)
        or not isinstance(report, dict)
        or not isinstance(report.get("title"), str)
        or not isinstance(report.get("summary"), str)
    ):
        raise AdapterFailure(
            "data_artifact_invariant_invalid",
            "The canonical data-analysis lineage, environment, assertion, or reproduction record is incomplete.",
        )
    return f"{report['title']}\n\n{report['summary']}\n", {
        "datasetDigest": dataset["digest"],
        "sourceCount": len(lineage["sources"]),
        "transformCount": len(lineage["transforms"]),
        "seed": environment["seed"],
        "packageCount": len(environment["packages"]),
        "assertionCount": len(assertions),
        "reproductionMatches": True,
    }


def _research_artifact(value: Any, canonical: bool) -> tuple[str, dict[str, Any]]:
    if not isinstance(value, dict):
        raise AdapterFailure("research_structure_invalid", "The research source is not an object.")
    required = {"claims", "citations", "sources"}
    if not required.issubset(value) or any(not isinstance(value[key], list) for key in required):
        raise AdapterFailure(
            "research_structure_invalid",
            "The research source lacks exact claim, citation, or source arrays.",
            check="research.source_bundle_structure",
        )
    sources = {item.get("id"): item for item in value["sources"] if isinstance(item, dict)}
    citations = {item.get("id"): item for item in value["citations"] if isinstance(item, dict)}
    if len(sources) != len(value["sources"]) or len(citations) != len(value["citations"]):
        raise AdapterFailure("research_identity_invalid", "Research source or citation IDs are absent or duplicated.")
    for citation in citations.values():
        if citation.get("sourceId") not in sources or not isinstance(citation.get("targetDigest"), str):
            raise AdapterFailure(
                "citation_target_invalid",
                "A citation does not resolve to an exact source target.",
                check="research.citation_targets_resolve",
            )
    for claim in value["claims"]:
        if not isinstance(claim, dict) or not isinstance(claim.get("citationIds"), list) or any(
            citation not in citations for citation in claim["citationIds"]
        ):
            raise AdapterFailure(
                "claim_citation_linkage_invalid",
                "A research claim does not link to exact admitted citation IDs.",
                check="research.claim_citation_linkage",
            )
    if canonical:
        if value.get("schema") != "ambit.research-artifact/v1" or not isinstance(value.get("provenance"), dict):
            raise AdapterFailure(
                "research_canonical_schema_invalid",
                "The canonical research artifact lacks its provenance schema.",
                check="research.provenance_complete",
            )
        if any(
            not isinstance(source.get("authorizationReceipt"), dict)
            or not isinstance(source["authorizationReceipt"].get("digest"), str)
            for source in sources.values()
        ):
            raise AdapterFailure(
                "research_authorization_receipt_missing",
                "A canonical research source lacks an authorization receipt binding.",
                check="research.source_authorization_bound",
            )
    lines = ["Research artifact"]
    for claim in value["claims"][:1000]:
        lines.append(f"- {claim.get('text', claim.get('id', 'Claim'))}")
    return "\n".join(lines) + "\n", {
        "claimCount": len(value["claims"]),
        "citationCount": len(citations),
        "sourceCount": len(sources),
        "canonical": canonical,
    }


def _plain_research(
    path: Path,
    media_type: str,
    scratch: Path,
    deadline: float,
    environment: dict[str, str],
) -> tuple[str, dict[str, Any]]:
    if path.stat().st_size > MAXIMUM_TEXT_INPUT_BYTES:
        raise AdapterFailure("research_text_limit", "The research document exceeds its safe byte bound.")
    text = path.read_text(encoding="utf-8", errors="strict")
    if media_type == "text/html":
        parser = _HtmlStructure()
        parser.feed(text)
        if parser.scripts:
            raise AdapterFailure(
                "research_active_html_forbidden",
                "Active script content is not admitted in a research document preview.",
                check="research.link_structure_valid",
            )
        if parser.headings == 0:
            raise AdapterFailure(
                "research_heading_missing",
                "The research document has no heading structure.",
                check="research.accessibility_structure",
            )
        plain = "\n".join(parser.text) + "\n"
        links = parser.links
        headings = parser.headings
    else:
        headings = sum(1 for line in text.splitlines() if re.match(r"^#{1,6}\s+\S", line))
        if headings == 0:
            raise AdapterFailure(
                "research_heading_missing",
                "The research document has no Markdown heading structure.",
                check="research.accessibility_structure",
            )
        links = LINK.findall(text)
        output = scratch / "research.txt"
        _run(
            ["pandoc", "--from=gfm", "--to=plain", str(path), "-o", str(output)],
            scratch=scratch,
            deadline=deadline,
            environment=environment,
        )
        plain = output.read_text(encoding="utf-8", errors="strict")
    if any(not link or any(character.isspace() for character in link) for link in links):
        raise AdapterFailure(
            "research_link_invalid",
            "The research document contains a malformed link target.",
            check="research.link_structure_valid",
        )
    return plain, {"headingCount": headings, "linkCount": len(links), "scriptCount": 0}


def _text_view(text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    normalized = text.replace("\r", "")
    payload = normalized.encode("utf-8")
    limitations: list[dict[str, str]] = []
    if len(payload) > 4 * 1024 * 1024:
        payload = payload[: 4 * 1024 * 1024]
        while True:
            try:
                normalized = payload.decode("utf-8")
                break
            except UnicodeDecodeError:
                payload = payload[:-1]
        limitations.append(
            {
                "code": "preview_text_truncated",
                "severity": "warning",
                "message": "The public text preview is truncated; complete decoded structure remains in private evidence.",
            }
        )
    if not payload:
        payload = b"No displayable text rows.\n"
        normalized = payload.decode()
    return [
        {
            "kind": "text",
            "ordinal": 1,
            "label": "Preview",
            "mediaType": "text/plain",
            "byteLength": len(payload),
            "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "body": normalized,
        }
    ], limitations


def render_validate(
    *,
    request: dict[str, Any],
    source_path: Path,
    scratch: Path,
    deadline: float,
) -> dict[str, Any]:
    media_type = request["source"]["mediaType"]
    environment = _environment(scratch)
    if request["facet"] == "data_analysis":
        if media_type == "application/vnd.ambit.data-analysis+json":
            text, structure = _canonical_data_artifact(_json(source_path))
            canonical = True
        else:
            frame, structure = _frame(source_path, media_type)
            text = frame.head(100).to_csv(index=False, lineterminator="\n")
            canonical = False
        title = "Data analysis preview"
        summary = "Exact decoded schema, bounded table projection, and reproducibility structure for the data artifact."
    elif request["facet"] == "research":
        if media_type in {"application/json", "application/vnd.ambit.research+json"}:
            canonical = media_type == "application/vnd.ambit.research+json"
            text, structure = _research_artifact(_json(source_path), canonical)
        elif media_type in {"text/html", "text/markdown"}:
            text, structure = _plain_research(
                source_path, media_type, scratch, deadline, environment
            )
        else:
            raise AdapterFailure("unsupported_research_source", "The research source format is unsupported.")
        title = "Research preview"
        summary = "Deterministic source, citation-linkage, provenance-structure, and safe document inspection."
    else:
        raise AdapterFailure("facet_not_owned", "The data-research pack does not own this facet.")

    observations: dict[str, dict[str, Any]] = {}
    common = {
        "sourceDigest": _sha256(source_path),
        "sourceBytes": source_path.stat().st_size,
        **structure,
    }
    for check in pack_check_names(request):
        observations[check] = {"check": check, **common}
    structure_path = scratch / "specialist-structure.json"
    structure_path.write_text(
        json.dumps(common, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    structure_path.chmod(0o400)
    text_path = scratch / "specialist-preview.txt"
    text_path.write_text(text, encoding="utf-8")
    text_path.chmod(0o400)
    views, limitations = _text_view(text)
    if request["facet"] == "data_analysis":
        facts = [
            {"key": "column_count", "label": "Columns", "value": str(structure.get("columnCount", "n/a"))},
            {"key": "row_count", "label": "Rows", "value": str(structure.get("rowCount", "n/a"))},
            {"key": "source_bytes", "label": "Source bytes", "value": str(source_path.stat().st_size)},
        ]
    else:
        facts = [
            {"key": "citation_count", "label": "Citations", "value": str(structure.get("citationCount", "n/a"))},
            {"key": "source_bytes", "label": "Source bytes", "value": str(source_path.stat().st_size)},
            {"key": "source_count", "label": "Sources", "value": str(structure.get("sourceCount", "n/a"))},
        ]
    evidence_check = (
        "data_analysis.table_preview_complete"
        if request["facet"] == "data_analysis"
        else next(
            candidate
            for candidate in (
                "research.document_render_complete",
                "research.source_bundle_structure",
                "research.accessibility_structure",
            )
            if candidate in observations
        )
    )
    return {
        "title": title,
        "summary": summary,
        "views": views,
        "facts": facts,
        "limitations": limitations,
        "observations": observations,
        "evidenceArtifacts": [
            {
                "check": evidence_check,
                "mediaType": "application/json",
                "name": "specialist-structure.json",
                "sourcePath": str(structure_path),
            },
            {
                "check": evidence_check,
                "mediaType": "text/plain",
                "name": "specialist-preview.txt",
                "sourcePath": str(text_path),
            },
        ],
    }
