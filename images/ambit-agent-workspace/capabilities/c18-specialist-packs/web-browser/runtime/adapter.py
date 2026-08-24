from __future__ import annotations

import base64
import hashlib
import json
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from process_control import ProcessDeadlineExceeded, ProcessFailure, run_bounded
from render_command import pack_check_names
from render_runner import AdapterFailure


PACK_ROOT = Path("/opt/ambit/runtime-pack/web-browser")
PATH = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAXIMUM_ARCHIVE_ENTRIES = 20_000
MAXIMUM_ARCHIVE_ENTRY_BYTES = 64 * 1024 * 1024
MAXIMUM_ARCHIVE_TOTAL_BYTES = 512 * 1024 * 1024
MAXIMUM_JSON_BUNDLE_BYTES = 64 * 1024 * 1024


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
        "NODE_PATH": str(PACK_ROOT / "node_modules"),
        "PATH": PATH,
        "PLAYWRIGHT_BROWSERS_PATH": "/ms-playwright",
        "TZ": "UTC",
    }


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} or "\\" in part for part in path.parts)
    ):
        raise AdapterFailure("web_path_unsafe", "The web bundle contains an unsafe path.")
    return path


def _extract_zip(source: Path, bundle: Path) -> dict[str, Any]:
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries if not entry.is_dir()]
        if (
            len(entries) > MAXIMUM_ARCHIVE_ENTRIES
            or len(names) != len(set(names))
            or sum(entry.file_size for entry in entries) > MAXIMUM_ARCHIVE_TOTAL_BYTES
        ):
            raise AdapterFailure(
                "web_archive_limit",
                "The web bundle archive exceeds its entry or expanded-byte bound.",
                check="web.archive_containment",
            )
        for entry in entries:
            relative = _safe_relative(entry.filename.rstrip("/"))
            if stat.S_ISLNK(entry.external_attr >> 16) or entry.file_size > MAXIMUM_ARCHIVE_ENTRY_BYTES:
                raise AdapterFailure(
                    "web_archive_entry_unsafe",
                    "The web bundle contains a symlink or oversized entry.",
                    check="web.archive_containment",
                )
            target = bundle.joinpath(*relative.parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                continue
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with archive.open(entry) as input_file, target.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file, 1024 * 1024)
            target.chmod(0o400)
    if not (bundle / "index.html").is_file():
        raise AdapterFailure(
            "web_entrypoint_missing",
            "The web bundle has no root index.html entrypoint.",
            check="web.build_entrypoint_declared",
        )
    return {
        "entryCount": len(names),
        "expandedBytes": sum((bundle / name).stat().st_size for name in names),
    }


def _extract_json(source: Path, bundle: Path) -> dict[str, Any]:
    if source.stat().st_size > MAXIMUM_JSON_BUNDLE_BYTES:
        raise AdapterFailure("web_json_limit", "The web bundle manifest exceeds its byte bound.")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AdapterFailure("web_json_duplicate", "The web bundle manifest has duplicate keys.")
            result[key] = value
        return result

    value = json.loads(source.read_text(encoding="utf-8", errors="strict"), object_pairs_hook=reject_duplicates)
    if (
        not isinstance(value, dict)
        or set(value) != {"buildLock", "entrypoint", "files", "schema"}
        or value["schema"] != "ambit.web-application-bundle/v1"
        or value["entrypoint"] != "index.html"
        or not isinstance(value["files"], list)
        or not isinstance(value["buildLock"], dict)
    ):
        raise AdapterFailure(
            "web_bundle_schema_invalid",
            "The canonical web bundle does not match its exact manifest schema.",
            check="web.build_lock_output_binding",
        )
    seen: set[str] = set()
    total = 0
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"bodyBase64", "digest", "mediaType", "path"}:
            raise AdapterFailure("web_file_manifest_invalid", "A web bundle file descriptor is invalid.")
        relative = _safe_relative(item["path"])
        if item["path"] in seen:
            raise AdapterFailure("web_file_duplicate", "The web bundle repeats a file path.")
        seen.add(item["path"])
        try:
            payload = base64.b64decode(item["bodyBase64"], validate=True)
        except ValueError as error:
            raise AdapterFailure("web_file_base64_invalid", "A web bundle file is not canonical base64.") from error
        if base64.b64encode(payload).decode() != item["bodyBase64"]:
            raise AdapterFailure("web_file_base64_invalid", "A web bundle file is not canonical base64.")
        total += len(payload)
        if total > MAXIMUM_ARCHIVE_TOTAL_BYTES or len(payload) > MAXIMUM_ARCHIVE_ENTRY_BYTES:
            raise AdapterFailure("web_file_limit", "A web bundle file exceeds its byte bound.")
        if "sha256:" + hashlib.sha256(payload).hexdigest() != item["digest"]:
            raise AdapterFailure("web_file_digest_invalid", "A web bundle file digest is forged.")
        target = bundle.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(payload)
        target.chmod(0o400)
    if "index.html" not in seen:
        raise AdapterFailure("web_entrypoint_missing", "The web bundle has no root index.html entrypoint.")
    return {
        "entryCount": len(seen),
        "expandedBytes": total,
        "buildLockDigest": "sha256:"
        + hashlib.sha256(
            json.dumps(value["buildLock"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _materialize(source: Path, media_type: str, bundle: Path) -> dict[str, Any]:
    bundle.mkdir(mode=0o700)
    if media_type == "text/html":
        payload = source.read_bytes()
        if len(payload) > MAXIMUM_ARCHIVE_ENTRY_BYTES:
            raise AdapterFailure("web_html_limit", "The HTML source exceeds its safe byte bound.")
        payload.decode("utf-8", errors="strict")
        target = bundle / "index.html"
        target.write_bytes(payload)
        target.chmod(0o400)
        return {"entryCount": 1, "expandedBytes": len(payload)}
    if media_type in {"application/zip", "application/vnd.ambit.web-application+zip"}:
        return _extract_zip(source, bundle)
    if media_type == "application/vnd.ambit.web-application+json":
        return _extract_json(source, bundle)
    raise AdapterFailure("unsupported_web_source", "The web application source format is unsupported.")


def _run_browser(
    bundle: Path,
    evidence: Path,
    scratch: Path,
    deadline: float,
    environment: dict[str, str],
) -> dict[str, Any]:
    result = scratch / "browser-result.json"
    try:
        run_bounded(
            [
                "node",
                str(PACK_ROOT / "runtime/render.mjs"),
                str(bundle),
                str(evidence),
                str(result),
            ],
            deadline=deadline,
            cwd=scratch,
            environment=environment,
        )
    except ProcessDeadlineExceeded as error:
        raise AdapterFailure(
            "web_deadline_exceeded",
            "The browser validation matrix exceeded its exact deadline.",
            outcome="blocked",
        ) from error
    except ProcessFailure as error:
        raise AdapterFailure(
            "web_browser_validation_failed",
            "A browser, accessibility, console, network, or responsive check failed.",
            observations={
                "exitCode": error.result.returncode,
                "stderrSha256": "sha256:" + hashlib.sha256(error.result.stderr).hexdigest(),
            },
        ) from error
    return json.loads(result.read_text(encoding="utf-8"))


def _views(cases: list[dict[str, Any]], request: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    views: list[dict[str, Any]] = []
    limitations: list[dict[str, str]] = []
    pixels = 0
    payload_bytes = 0
    for case in cases:
        screenshot = Path(case["screenshotPath"])
        payload = screenshot.read_bytes()
        if (
            len(payload) < 24
            or payload[:8] != b"\x89PNG\r\n\x1a\n"
            or int.from_bytes(payload[8:12], "big") != 13
            or payload[12:16] != b"IHDR"
        ):
            raise AdapterFailure("web_screenshot_invalid", "A browser screenshot is not a canonical PNG.")
        width = int.from_bytes(payload[16:20], "big")
        height = int.from_bytes(payload[20:24], "big")
        case_pixels = width * height
        if (
            width > 4_096
            or height > 4_096
            or case_pixels > request["output"]["maximumImagePixels"]
            or pixels + case_pixels > request["output"]["maximumAggregateImagePixels"]
            or len(payload) > 512 * 1024
            or payload_bytes + len(payload) > 3 * 1024 * 1024
        ):
            limitations.append(
                {
                    "code": "preview_browser_matrix_truncated",
                    "severity": "warning",
                    "message": "Additional browser cases remain in private evidence because the public preview reached its image bound.",
                }
            )
            break
        pixels += case_pixels
        payload_bytes += len(payload)
        views.append(
            {
                "kind": "image",
                "ordinal": len(views) + 1,
                "label": f"{case['browser']} {case['viewport']['name']}",
                "altText": f"Web application in {case['browser']} at the {case['viewport']['name']} viewport.",
                "mediaType": "image/png",
                "width": width,
                "height": height,
                "byteLength": len(payload),
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "bodyBase64": base64.b64encode(payload).decode(),
            }
        )
    summary = (
        f"Validated {len(cases)} browser and viewport cases with no accessibility, "
        "console, external-network, or horizontal-overflow failures.\n"
    ).encode()
    views.append(
        {
            "kind": "text",
            "ordinal": len(views) + 1,
            "label": "Browser validation summary",
            "mediaType": "text/plain",
            "byteLength": len(summary),
            "digest": "sha256:" + hashlib.sha256(summary).hexdigest(),
            "body": summary.decode(),
        }
    )
    return views, limitations


def render_validate(
    *,
    request: dict[str, Any],
    source_path: Path,
    scratch: Path,
    deadline: float,
) -> dict[str, Any]:
    if request["facet"] != "web_application":
        raise AdapterFailure("facet_not_owned", "The web-browser pack does not own this facet.")
    environment = _environment(scratch)
    bundle = scratch / "bundle"
    materialization = _materialize(source_path, request["source"]["mediaType"], bundle)
    evidence = scratch / "browser-evidence"
    evidence.mkdir(mode=0o700)
    browser = _run_browser(bundle, evidence, scratch, deadline, environment)
    cases = browser.get("cases")
    requested_checks = pack_check_names(request)
    if not isinstance(cases, list) or len(cases) != 9:
        raise AdapterFailure(
            "web_browser_matrix_incomplete",
            "The browser validation matrix is incomplete.",
            check=(
                "web.viewport_matrix"
                if "web.viewport_matrix" in requested_checks
                else requested_checks[0]
            ),
        )
    common = {
        "sourceDigest": _sha256(source_path),
        "sourceBytes": source_path.stat().st_size,
        "browserCaseCount": len(cases),
        "browserVersions": {
            case["browser"]: case["browserVersion"] for case in cases
        },
        "consoleErrorCount": sum(case["consoleErrorCount"] for case in cases),
        "externalRequestAttemptCount": sum(
            case["blockedExternalRequestCount"] for case in cases
        ),
        "accessibilityViolationCount": sum(
            case["accessibilityViolationCount"] for case in cases
        ),
        "horizontalOverflowPixels": sum(
            case["horizontalOverflowPixels"] for case in cases
        ),
        **materialization,
    }
    observations: dict[str, dict[str, Any]] = {}
    for check in requested_checks:
        observations[check] = {"check": check, **common}
    views, limitations = _views(cases, request)
    screenshot_check = next(
        candidate
        for candidate in (
            "web.viewport_matrix",
            "web.static_document_render_complete",
            "web.static_asset_integrity",
        )
        if candidate in observations
    )
    accessibility_check = (
        "web.accessibility_rules"
        if "web.accessibility_rules" in observations
        else screenshot_check
    )
    trace_check = (
        "web.console_policy" if "web.console_policy" in observations else screenshot_check
    )
    evidence_artifacts = []
    for case in cases:
        stem = f"{case['browser']}-{case['viewport']['name']}"
        evidence_artifacts.extend(
            [
                {
                    "check": screenshot_check,
                    "mediaType": "image/png",
                    "name": f"{stem}-viewport.png",
                    "sourcePath": case["screenshotPath"],
                },
                {
                    "check": accessibility_check,
                    "mediaType": "text/plain",
                    "name": f"{stem}-aria.txt",
                    "sourcePath": case["ariaPath"],
                },
                {
                    "check": trace_check,
                    "mediaType": "application/zip",
                    "name": f"{stem}-trace.zip",
                    "sourcePath": case["tracePath"],
                },
            ]
        )
    return {
        "title": "Web application preview",
        "summary": "Sandboxed Chromium, Firefox, and WebKit validation across mobile, tablet, and desktop viewports.",
        "views": views,
        "facts": [
            {"key": "browser_count", "label": "Browsers", "value": "3"},
            {"key": "case_count", "label": "Browser cases", "value": str(len(cases))},
            {"key": "source_bytes", "label": "Source bytes", "value": str(source_path.stat().st_size)},
        ],
        "limitations": limitations,
        "observations": observations,
        "evidenceArtifacts": evidence_artifacts,
    }
