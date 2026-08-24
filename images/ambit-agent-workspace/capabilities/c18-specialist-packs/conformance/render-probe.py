from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


PACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACK_ROOT / "protocol"))

from public_preview import parse_preview_bytes  # noqa: E402
from render_command import (  # noqa: E402
    CONFORMANCE_PROFILE_REF,
    PREVIEW_MEDIA_TYPE,
    canonical_bytes,
    create_request,
    parse_check_evidence_bytes,
    parse_result_bytes,
    sha256_bytes,
)
from render_policy import POLICY_MATRIX  # noqa: E402


CONFORMANCE_ROOT = Path("/ambit")


def semantic_job_identity(slug: str) -> tuple[Path, str, str]:
    return (
        CONFORMANCE_ROOT,
        f"ambit://artifact-render-jobs/conformance-{slug}",
        CONFORMANCE_PROFILE_REF,
    )


def require_real_directory(
    path: Path,
    *,
    create_beneath: Path | None = None,
) -> None:
    if not path.is_absolute():
        raise ValueError("render probe directory is not absolute")
    if create_beneath is not None:
        try:
            path.relative_to(create_beneath)
        except ValueError as error:
            raise ValueError("render probe directory escapes its creation anchor") from error
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            if create_beneath is None or current == create_beneath:
                raise ValueError("render probe directory anchor is absent")
            try:
                current.relative_to(create_beneath)
            except ValueError as error:
                raise ValueError(
                    "render probe attempted to create outside its job root"
                ) from error
            os.mkdir(current, mode=0o700)
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("render probe job root contains an alias")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def exact_policy(facet: str, media_type: str) -> dict[str, object]:
    values = [
        value
        for value in POLICY_MATRIX["entries"]
        if value["facet"] == facet and value["sourceMediaType"] == media_type
    ]
    if len(values) != 1:
        raise ValueError("render probe has no exact policy")
    return values[0]


def pin(ref: str, digest: str) -> dict[str, str]:
    return {"ref": ref, "digest": digest}


def probe(args: argparse.Namespace) -> dict[str, object]:
    source = args.source.resolve(strict=True)
    policy = exact_policy(args.facet, args.media_type)
    slug = args.name
    job_root, job_ref, profile_ref = semantic_job_identity(slug)
    require_real_directory(job_root)
    input_root = job_root / "inputs" / "c18-render-probe" / slug
    output_root = job_root / "outputs" / "c18-render-probe" / slug
    require_real_directory(input_root, create_beneath=job_root)
    require_real_directory(output_root.parent, create_beneath=job_root)
    admitted_source = input_root / f"source{source.suffix}"
    with source.open("rb") as reader, admitted_source.open("xb") as writer:
        shutil.copyfileobj(reader, writer, 1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
    admitted_source.chmod(0o400)
    source_relative = admitted_source.relative_to(job_root).as_posix()
    job_output_root = output_root.relative_to(job_root).as_posix()
    request_relative = (input_root / "request.json").relative_to(
        job_root
    ).as_posix()
    pack_ref = str(policy["executorPackRevisionRef"])
    pack_lock = PACK_ROOT / "pack.lock.json"
    request = create_request(
        {
            "jobRef": job_ref,
            "jobRoot": str(job_root),
            "requestPath": request_relative,
            "facet": args.facet,
            "source": {
                "path": source_relative,
                "ref": f"ambit://artifact-revisions/conformance-{slug}",
                "digest": sha256_file(admitted_source),
                "byteLength": admitted_source.stat().st_size,
                "mediaType": args.media_type,
                "schemaUri": policy["requiredSchemaUri"],
            },
            "renderer": {
                key: policy[key]
                for key in (
                    "executablePath",
                    "rendererRef",
                    "validationPolicyRef",
                    "representation",
                    "renderMode",
                )
            },
            "runtime": {
                "workspaceExecutionManifest": pin(
                    "workspace-execution-manifest:sha256:" + "1" * 64,
                    "sha256:" + "2" * 64,
                ),
                "profileRevision": pin(
                    profile_ref,
                    "sha256:" + "3" * 64,
                ),
                "packRevisions": [pin(pack_ref, sha256_file(pack_lock))],
            },
            "packRequiredChecks": policy["checkLabels"],
            "output": {
                "jobOutputRoot": job_output_root,
                "previewPath": f"{job_output_root}/preview.json",
                "resultPath": f"{job_output_root}/result.json",
                "previewMediaType": PREVIEW_MEDIA_TYPE,
                "maximumPreviewBytes": 8 * 1024 * 1024,
                "maximumImagePixels": 8 * 1024 * 1024,
                "maximumAggregateImagePixels": 32 * 1024 * 1024,
            },
            "deadlineAt": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }
    )
    request_path = input_root / "request.json"
    request_path.write_bytes(canonical_bytes(request))
    request_path.chmod(0o400)
    completed = subprocess.run(
        [
            str(policy["executablePath"]),
            "--request",
            str(request_path),
            "--result",
            str(job_root / request["output"]["resultPath"]),
        ],
        stdin=subprocess.DEVNULL,
        check=False,
    )
    result_path = job_root / request["output"]["resultPath"]
    if completed.returncode != 0 or not result_path.is_file():
        raise RuntimeError(f"specialist render probe failed with {completed.returncode}")
    result = parse_result_bytes(request, result_path.read_bytes())
    if result["outcome"] != "succeeded" or result["preview"] is None:
        raise RuntimeError("specialist render probe did not succeed")
    preview_path = job_root / result["preview"]["path"]
    preview_bytes = preview_path.read_bytes()
    if sha256_bytes(preview_bytes) != result["preview"]["bytesDigest"]:
        raise RuntimeError("specialist render preview bytes differ")
    preview = parse_preview_bytes(preview_bytes)
    evidence_digests: list[str] = []
    artifact_paths: set[str] = set()
    for check in result["checks"]:
        descriptor = check["evidence"]
        if descriptor is None:
            raise RuntimeError("successful specialist check has no evidence")
        evidence_path = job_root / descriptor["path"]
        evidence_bytes = evidence_path.read_bytes()
        if (
            len(evidence_bytes) != descriptor["byteLength"]
            or sha256_bytes(evidence_bytes) != descriptor["digest"]
        ):
            raise RuntimeError("specialist check evidence bytes differ")
        evidence = parse_check_evidence_bytes(evidence_bytes)
        if evidence["check"] != check["check"]:
            raise RuntimeError("specialist check evidence identity differs")
        evidence_digests.append(evidence["digest"])
        for artifact in evidence["artifacts"]:
            if artifact["path"] in artifact_paths:
                raise RuntimeError("specialist evidence artifact path is duplicated")
            artifact_paths.add(artifact["path"])
            artifact_path = job_root / artifact["path"]
            if (
                artifact_path.stat().st_size != artifact["byteLength"]
                or sha256_file(artifact_path) != artifact["digest"]
            ):
                raise RuntimeError("specialist evidence artifact bytes differ")
    return {
        "schema": "ambit.c18-specialist-render-runtime-probe/v2",
        "name": slug,
        "jobRef": job_ref,
        "jobRoot": str(job_root),
        "facet": args.facet,
        "mediaType": args.media_type,
        "requestDigest": request["digest"],
        "resultDigest": result["digest"],
        "previewDigest": preview["digest"],
        "evidenceDigests": evidence_digests,
        "artifactPaths": sorted(artifact_paths),
        "outcome": "passed",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--facet", required=True)
    parser.add_argument("--media-type", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = probe(args)
        args.receipt.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"render-probe: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
