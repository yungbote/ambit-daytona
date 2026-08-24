from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any

from freeze_source_identity import SOURCE_PATH, freeze, verify_context


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HELPER_PATH = "opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize"
HELPER_SHA256 = "8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5"


class CandidateBuildError(RuntimeError):
    """The exact source did not produce one reproducible closed OCI candidate."""


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def build(
    repo: Path,
    revision: str,
    materializer_inputs: Path,
    builder: str,
    output: Path,
) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    materializer_inputs = materializer_inputs.resolve(strict=True)
    _verify_materializer_inputs(materializer_inputs)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_identity = freeze(repo, revision, output / "source-identity")
    source_context_root = output / "source-context"
    source_context_root.mkdir(mode=0o700)
    archive = (output / "source-identity/daytona-source.tar").read_bytes()
    _extract_tar(archive, source_context_root)
    source_context = source_context_root / SOURCE_PATH
    _normalize_modes(source_context, output / "source-identity/source-modes.tsv")
    verify_context(
        source_context,
        output / "source-identity",
        str(source_identity["identitySha256"]),
    )

    build_records = []
    for ordinal in (1, 2):
        oci_archive = output / f"build-{ordinal}.oci.tar"
        metadata = output / f"build-{ordinal}.metadata.json"
        command = _build_command(
            builder=builder,
            source_context=source_context,
            source_identity_root=output / "source-identity",
            materializer_inputs=materializer_inputs,
            source_identity=source_identity,
            oci_archive=oci_archive,
            metadata=metadata,
        )
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        _write(output / f"build-{ordinal}.stdout", process.stdout)
        _write(output / f"build-{ordinal}.stderr", process.stderr)
        if process.returncode != 0:
            raise CandidateBuildError(f"cold build {ordinal} failed")
        if not oci_archive.is_file() or not metadata.is_file():
            raise CandidateBuildError(f"cold build {ordinal} omitted output")
        layout = output / f"build-{ordinal}"
        layout.mkdir(mode=0o700)
        _extract_tar(oci_archive.read_bytes(), layout)
        verification = _verify_layout(layout)
        build_records.append(
            {
                "ordinal": ordinal,
                "argv": command,
                "exitCode": process.returncode,
                "stdoutSha256": sha256(process.stdout),
                "stderrSha256": sha256(process.stderr),
                "metadataSha256": sha256(metadata.read_bytes()),
                "ociArchiveSha256": sha256(oci_archive.read_bytes()),
                "ociArchiveBytes": oci_archive.stat().st_size,
                "layout": verification,
            }
        )

    first_archive = (output / "build-1.oci.tar").read_bytes()
    second_archive = (output / "build-2.oci.tar").read_bytes()
    if first_archive != second_archive:
        raise CandidateBuildError("cold builds produced different OCI archives")
    if build_records[0]["layout"] != build_records[1]["layout"]:
        raise CandidateBuildError("cold builds produced different OCI graphs")

    receipt = {
        "schema": "ambit.runtime-core-base-build-receipt/v1",
        "source": source_identity,
        "materializerInputs": {
            "path": os.fspath(materializer_inputs),
            "sourceArchiveSha256": "sha256:af8db17dc5d7b2266444efc4911661659fdaf23035b7dde0172f29d9e55374ca",
            "binarySha256": f"sha256:{HELPER_SHA256}",
        },
        "builder": builder,
        "builds": build_records,
        "byteIdenticalCompleteOciArchives": True,
        "outcome": "passed",
    }
    rendered = canonical_json(receipt)
    _write(output / "build-receipt.json", rendered)
    return {**receipt, "receiptSha256": sha256(rendered)}


def _build_command(
    *,
    builder: str,
    source_context: Path,
    source_identity_root: Path,
    materializer_inputs: Path,
    source_identity: dict[str, object],
    oci_archive: Path,
    metadata: Path,
) -> list[str]:
    values = {
        "SOURCE_DATE_EPOCH": source_identity["sourceDateEpoch"],
        "BUILD_SOURCE_REVISION": source_identity["revision"],
        "BUILD_SOURCE_TREE": source_identity["repositoryTree"],
        "BUILD_SOURCE_SUBTREE": source_identity["subtree"],
        "BUILD_SOURCE_ARCHIVE_SHA256": source_identity["archiveSha256"],
        "BUILD_SOURCE_CONTEXT_SHA256": source_identity["contextSha256"],
        "BUILD_SOURCE_FILES_SHA256": source_identity["sourceFilesManifestSha256"],
        "BUILD_SOURCE_MODES_SHA256": source_identity["sourceModesManifestSha256"],
        "BUILD_SOURCE_IDENTITY_SHA256": source_identity["identitySha256"],
    }
    command = [
        "docker",
        "buildx",
        "build",
        "--builder",
        builder,
        "--progress=plain",
        "--platform",
        "linux/amd64",
        "--pull=false",
        "--no-cache",
        "--provenance=false",
        "--sbom=false",
        "--build-context",
        f"materializer_inputs={materializer_inputs}",
        "--build-context",
        f"source_identity={source_identity_root}",
    ]
    for name, value in values.items():
        command.extend(["--build-arg", f"{name}={value}"])
    command.extend(
        [
            "--target",
            "core_base",
            "--metadata-file",
            os.fspath(metadata),
            "--output",
            f"type=oci,dest={oci_archive},rewrite-timestamp=true",
            os.fspath(source_context),
        ]
    )
    return command


def _verify_materializer_inputs(root: Path) -> None:
    expected = {
        "ambit-atomic-materialize": (2568340, HELPER_SHA256),
        "backend-atomic-materializer-source.tar": (
            184320,
            "af8db17dc5d7b2266444efc4911661659fdaf23035b7dde0172f29d9e55374ca",
        ),
    }
    actual = sorted(path.name for path in root.iterdir())
    if actual != sorted(expected):
        raise CandidateBuildError("materializer input roster is not exact")
    for name, (size, digest) in expected.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise CandidateBuildError(f"materializer input is unsafe: {name}")
        data = path.read_bytes()
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise CandidateBuildError(f"materializer input differs: {name}")


def _verify_layout(layout: Path) -> dict[str, object]:
    index_bytes = (layout / "index.json").read_bytes()
    index = json.loads(index_bytes)
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise CandidateBuildError("OCI index does not select exactly one manifest")
    descriptor = manifests[0]
    manifest_bytes = _blob(layout, descriptor)
    manifest = json.loads(manifest_bytes)
    if manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise CandidateBuildError("OCI platform manifest media type is invalid")
    config_descriptor = manifest.get("config")
    layers = manifest.get("layers")
    if not isinstance(config_descriptor, dict) or not isinstance(layers, list) or not layers:
        raise CandidateBuildError("OCI platform manifest closure is invalid")
    config_bytes = _blob(layout, config_descriptor)
    config = json.loads(config_bytes)
    layer_records = []
    path_rows: list[str] = []
    helper_count = 0
    for ordinal, layer in enumerate(layers):
        layer_bytes = _blob(layout, layer)
        records, found_helper = _inspect_layer(layer_bytes, ordinal)
        path_rows.extend(records)
        helper_count += found_helper
        layer_records.append(
            {
                "digest": layer["digest"],
                "size": layer["size"],
                "mediaType": layer["mediaType"],
            }
        )
    if helper_count != 1:
        raise CandidateBuildError("OCI layers do not contain exactly one materializer")
    labels = ((config.get("config") or {}).get("Labels") or {})
    if labels.get("io.ambit.runtime-pack") != "ambit.runtime-pack/core@1":
        raise CandidateBuildError("OCI config does not identify core@1")
    if (config.get("config") or {}).get("User") != "1000:1000":
        raise CandidateBuildError("OCI config runtime user is invalid")
    return {
        "indexDocumentSha256": sha256(index_bytes),
        "platformManifestDigest": descriptor["digest"],
        "platformManifestBytes": len(manifest_bytes),
        "configDigest": config_descriptor["digest"],
        "configBytes": len(config_bytes),
        "layers": layer_records,
        "layerPathManifestSha256": sha256("".join(sorted(path_rows)).encode()),
        "blobCount": len(list((layout / "blobs/sha256").iterdir())),
    }


def _blob(layout: Path, descriptor: Any) -> bytes:
    if not isinstance(descriptor, dict):
        raise CandidateBuildError("OCI descriptor is invalid")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise CandidateBuildError("OCI descriptor digest is invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise CandidateBuildError("OCI descriptor size is invalid")
    path = layout / "blobs/sha256" / digest.removeprefix("sha256:")
    data = path.read_bytes()
    if len(data) != size or sha256(data) != digest:
        raise CandidateBuildError("OCI descriptor bytes differ")
    return data


def _inspect_layer(layer: bytes, ordinal: int) -> tuple[list[str], int]:
    try:
        uncompressed = gzip.decompress(layer)
    except OSError as error:
        raise CandidateBuildError("OCI layer is not deterministic gzip") from error
    rows: list[str] = []
    helper_count = 0
    with tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name.removeprefix("./"))
            if path.is_absolute() or ".." in path.parts:
                raise CandidateBuildError("OCI layer path is unsafe")
            normalized = path.as_posix()
            if member.isdev() or member.isfifo():
                raise CandidateBuildError("OCI layer contains a device or fifo")
            if normalized.startswith(("etc/apt/", "etc/dpkg/", "usr/lib/apt/", "usr/lib/dpkg/", "var/lib/apt/", "var/lib/dpkg/")):
                raise CandidateBuildError("OCI layer retains package-manager state")
            basename = path.name
            if member.mode & 0o111 and basename.startswith(("apt", "dpkg", "pip", "npm", "npx")):
                raise CandidateBuildError("OCI layer retains installer executable payload")
            digest = "-"
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise CandidateBuildError("OCI layer file bytes are absent")
                data = stream.read()
                digest = hashlib.sha256(data).hexdigest()
                if normalized == HELPER_PATH:
                    if digest != HELPER_SHA256 or member.mode & 0o777 != 0o555:
                        raise CandidateBuildError("OCI layer materializer differs")
                    helper_count += 1
            rows.append(
                f"{ordinal}\t{member.type!r}\t{member.mode & 0o777:o}\t{member.uid}\t{member.gid}\t{digest}\t{normalized}\n"
            )
    return rows, helper_count


def _extract_tar(value: bytes, output: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(value), mode="r:") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise CandidateBuildError("archive path is unsafe")
            if not (member.isdir() or member.isfile()):
                raise CandidateBuildError("archive contains a non-regular member")
        archive.extractall(output, filter="data")


def _normalize_modes(source: Path, manifest: Path) -> None:
    for row in manifest.read_text(encoding="utf-8").splitlines():
        mode, relative = row.split("\t", 1)
        (source / relative.removeprefix("./")).chmod(int(mode, 8))


def _write(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--materializer-inputs", required=True, type=Path)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                build(
                    args.repo,
                    args.revision,
                    args.materializer_inputs,
                    args.builder,
                    args.output,
                ),
                indent=2,
                sort_keys=True,
            )
        )
    except (OSError, CandidateBuildError, json.JSONDecodeError) as error:
        print(f"core-candidate-build: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
