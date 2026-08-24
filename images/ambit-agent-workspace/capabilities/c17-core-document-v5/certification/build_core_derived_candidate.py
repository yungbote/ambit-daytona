from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_PATH = "images/ambit-agent-workspace/capabilities/c17-core-document-v5"


class CoreDerivedBuildError(RuntimeError):
    """The frozen source did not produce one reproducible core-derived OCI."""


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def build(
    *,
    source_identity: Path,
    public_inputs: Path,
    materializer_inputs: Path,
    core_layout: Path,
    composition_source: Path,
    builder: str,
    output: Path,
) -> dict[str, object]:
    source_identity = source_identity.resolve(strict=True)
    public_inputs = public_inputs.resolve(strict=True)
    materializer_inputs = materializer_inputs.resolve(strict=True)
    core_layout = core_layout.resolve(strict=True)
    composition_source = composition_source.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise CoreDerivedBuildError("candidate output already exists")
    identity = _source_identity(source_identity)
    source_context = output / "source-context"
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    _extract_source_context(
        source_identity / "daytona-source.tar",
        source_identity / "source-files.sha256",
        source_identity / "source-modes.tsv",
        source_context,
    )
    package_root = source_context / SOURCE_PATH
    union_lock = _json(
        package_root / "locks/union-overlay-builder-input.lock.json"
    )
    core = union_lock.get("coreParent")
    if not isinstance(core, dict):
        raise CoreDerivedBuildError("core parent lock is absent")
    core_manifest = _digest(core.get("platformManifestDigest"), "core manifest")
    core_source_date_epoch = core.get("sourceDateEpoch")
    if (
        not isinstance(core_source_date_epoch, int)
        or isinstance(core_source_date_epoch, bool)
        or core_source_date_epoch <= 0
    ):
        raise CoreDerivedBuildError("core source epoch is invalid")
    _verify_external_composition_inputs(union_lock, composition_source)

    records: list[dict[str, object]] = []
    for ordinal in (1, 2):
        archive = output / f"build-{ordinal}.oci.tar"
        metadata = output / f"build-{ordinal}.metadata.json"
        command = _build_command(
            builder=builder,
            package_root=package_root,
            source_identity=source_identity,
            public_inputs=public_inputs,
            materializer_inputs=materializer_inputs,
            core_layout=core_layout,
            core_manifest=core_manifest,
            core_source_date_epoch=core_source_date_epoch,
            composition_source=composition_source,
            identity=identity,
            archive=archive,
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
            raise CoreDerivedBuildError(f"cold build {ordinal} failed")
        if not archive.is_file() or not metadata.is_file():
            raise CoreDerivedBuildError(f"cold build {ordinal} omitted output")
        archive_bytes = archive.read_bytes()
        records.append(
            {
                "ordinal": ordinal,
                "argv": command,
                "exitCode": process.returncode,
                "stdoutSha256": sha256(process.stdout),
                "stderrSha256": sha256(process.stderr),
                "metadataSha256": sha256(metadata.read_bytes()),
                "ociArchiveSha256": sha256(archive_bytes),
                "ociArchiveBytes": len(archive_bytes),
                "layout": _verify_oci_archive(
                    archive_bytes,
                    core,
                    identity,
                ),
            }
        )
    first = (output / "build-1.oci.tar").read_bytes()
    second = (output / "build-2.oci.tar").read_bytes()
    if first != second or records[0]["layout"] != records[1]["layout"]:
        raise CoreDerivedBuildError("cold builds are not byte-identical")

    receipt = {
        "schema": "ambit.runtime-core-derived-document-build-receipt/v1",
        "source": identity,
        "builder": builder,
        "coreParent": {
            "platformManifestDigest": core_manifest,
            "configDigest": core.get("configDigest"),
            "sourceIdentitySha256": core.get("sourceIdentitySha256"),
            "orderedLayers": core.get("orderedLayers"),
        },
        "builds": records,
        "byteIdenticalCompleteOciArchives": True,
        "outcome": "passed",
    }
    rendered = canonical_json(receipt)
    _write(output / "build-receipt.json", rendered)
    return {**receipt, "receiptSha256": sha256(rendered)}


def _build_command(
    *,
    builder: str,
    package_root: Path,
    source_identity: Path,
    public_inputs: Path,
    materializer_inputs: Path,
    core_layout: Path,
    core_manifest: str,
    core_source_date_epoch: int,
    composition_source: Path,
    identity: dict[str, Any],
    archive: Path,
    metadata: Path,
) -> list[str]:
    values = {
        "SOURCE_DATE_EPOCH": core_source_date_epoch,
        "BUILD_SOURCE_DATE_EPOCH": identity["sourceDateEpoch"],
        "BUILD_SOURCE_REVISION": identity["revision"],
        "BUILD_SOURCE_TREE": identity["repositoryTree"],
        "BUILD_SOURCE_SUBTREE": identity["subtree"],
        "BUILD_SOURCE_ARCHIVE_SHA256": identity["archiveSha256"],
        "BUILD_SOURCE_CONTEXT_SHA256": identity["contextSha256"],
        "BUILD_SOURCE_FILES_SHA256": identity["sourceFilesManifestSha256"],
        "BUILD_SOURCE_MODES_SHA256": identity["sourceModesManifestSha256"],
        "BUILD_SOURCE_IDENTITY_SHA256": identity["identitySha256"],
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
        f"public_inputs={public_inputs}",
        "--build-context",
        f"materializer_inputs={materializer_inputs}",
        "--build-context",
        f"source_identity={source_identity}",
        "--build-context",
        f"core_parent=oci-layout://{core_layout}@{core_manifest}",
        "--build-context",
        f"composition_source={composition_source}",
    ]
    for name, value in values.items():
        command.extend(["--build-arg", f"{name}={value}"])
    command.extend(
        [
            "--target",
            "core_document_v5",
            "--metadata-file",
            os.fspath(metadata),
            "--output",
            f"type=oci,dest={archive},rewrite-timestamp=true",
            os.fspath(package_root),
        ]
    )
    return command


def _source_identity(root: Path) -> dict[str, Any]:
    expected = {
        "daytona-source.tar",
        "source-files.sha256",
        "source-identity.json",
        "source-modes.tsv",
    }
    if {path.name for path in root.iterdir()} != expected or any(
        path.is_symlink() or not path.is_file() for path in root.iterdir()
    ):
        raise CoreDerivedBuildError("source identity context is not exact")
    identity_bytes = (root / "source-identity.json").read_bytes()
    identity = json.loads(identity_bytes)
    if (
        not isinstance(identity, dict)
        or canonical_json(identity) != identity_bytes
        or identity.get("path") != SOURCE_PATH
    ):
        raise CoreDerivedBuildError("source identity is invalid")
    for field in (
        "archiveSha256",
        "contextSha256",
        "sourceFilesManifestSha256",
        "sourceModesManifestSha256",
    ):
        _digest(identity.get(field), f"source {field}")
    archive = (root / "daytona-source.tar").read_bytes()
    files = (root / "source-files.sha256").read_bytes()
    modes = (root / "source-modes.tsv").read_bytes()
    if (
        identity["archiveSha256"] != sha256(archive)
        or identity["sourceFilesManifestSha256"] != sha256(files)
        or identity["sourceModesManifestSha256"] != sha256(modes)
        or identity["contextSha256"] != sha256(files + modes)
    ):
        raise CoreDerivedBuildError("source identity bytes differ")
    for field in ("revision", "repositoryTree", "subtree"):
        if not isinstance(identity.get(field), str) or not re.fullmatch(
            r"[0-9a-f]{40}", identity[field]
        ):
            raise CoreDerivedBuildError(f"source {field} is invalid")
    if not isinstance(identity.get("sourceDateEpoch"), int) or identity[
        "sourceDateEpoch"
    ] <= 0:
        raise CoreDerivedBuildError("source epoch is invalid")
    identity["identitySha256"] = sha256(identity_bytes)
    return identity


def _extract_source_context(
    archive_path: Path,
    files_path: Path,
    modes_path: Path,
    output: Path,
) -> None:
    output.mkdir(mode=0o700)
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise CoreDerivedBuildError("source archive path is unsafe")
            if not (member.isdir() or member.isfile()):
                raise CoreDerivedBuildError("source archive member is unsafe")
        archive.extractall(output, filter="data")
    for row in modes_path.read_text(encoding="utf-8").splitlines():
        mode, relative = row.split("\t", 1)
        (output / SOURCE_PATH / relative.removeprefix("./")).chmod(int(mode, 8))
    expected: list[str] = []
    for row in files_path.read_text(encoding="utf-8").splitlines():
        digest, relative = row.split("  ", 1)
        candidate = output / SOURCE_PATH / relative.removeprefix("./")
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or hashlib.sha256(candidate.read_bytes()).hexdigest() != digest
        ):
            raise CoreDerivedBuildError(f"source context differs: {relative}")
        expected.append(relative)
    actual = sorted(
        "./" + path.relative_to(output / SOURCE_PATH).as_posix()
        for path in (output / SOURCE_PATH).rglob("*")
        if path.is_file()
    )
    if sorted(expected) != actual:
        raise CoreDerivedBuildError("source context file roster differs")


def _verify_external_composition_inputs(
    lock: dict[str, Any],
    composition_source: Path,
) -> None:
    for field in ("builder", "coreContract"):
        pin = lock.get(field)
        if not isinstance(pin, dict):
            raise CoreDerivedBuildError(f"composition {field} pin is absent")
        path = pin.get("path")
        digest = pin.get("sha256")
        if not isinstance(path, str) or not path.startswith(
            "images/ambit-agent-workspace/"
        ):
            raise CoreDerivedBuildError(f"composition {field} path is invalid")
        relative = path.removeprefix("images/ambit-agent-workspace/")
        candidate = composition_source / relative
        if (
            candidate.is_symlink()
            or not candidate.is_file()
            or sha256(candidate.read_bytes()) != digest
        ):
            raise CoreDerivedBuildError(f"composition {field} differs")


def _verify_oci_archive(
    archive_bytes: bytes,
    core: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, object]:
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name.removeprefix("./"))
            if path.is_absolute() or ".." in path.parts:
                raise CoreDerivedBuildError("OCI archive path is unsafe")
            if member.isdir():
                continue
            if not member.isfile() or path.as_posix() in files:
                raise CoreDerivedBuildError("OCI archive roster is invalid")
            stream = archive.extractfile(member)
            if stream is None:
                raise CoreDerivedBuildError("OCI archive bytes are absent")
            files[path.as_posix()] = stream.read()
    if files.get("oci-layout") != b'{"imageLayoutVersion":"1.0.0"}':
        raise CoreDerivedBuildError("OCI layout marker is invalid")
    index = _json_bytes(files.get("index.json"), "OCI index")
    manifests = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise CoreDerivedBuildError("OCI index is ambiguous")
    manifest_descriptor = manifests[0]
    manifest_bytes = _blob(files, manifest_descriptor)
    manifest = _json_bytes(manifest_bytes, "OCI manifest")
    config_descriptor = manifest.get("config")
    layers = manifest.get("layers")
    if not isinstance(config_descriptor, dict) or not isinstance(layers, list):
        raise CoreDerivedBuildError("OCI manifest closure is invalid")
    config_bytes = _blob(files, config_descriptor)
    config = _json_bytes(config_bytes, "OCI config")
    for layer in layers:
        _blob(files, layer)
    expected_core = core.get("orderedLayers")
    if not isinstance(expected_core, list) or layers[: len(expected_core)] != expected_core:
        raise CoreDerivedBuildError("final image does not preserve core layer prefix")
    suffix = layers[len(expected_core) :]
    if len(suffix) != 1:
        raise CoreDerivedBuildError("final image does not contain one closed overlay layer")
    image_config = config.get("config") if isinstance(config, dict) else None
    labels = image_config.get("Labels") if isinstance(image_config, dict) else None
    if (
        not isinstance(labels, dict)
        or image_config.get("User") != "1000:1000"
        or labels.get("io.ambit.runtime-pack")
        != "ambit.runtime-pack/core-document@5"
        or labels.get("io.ambit.core-parent-platform-manifest")
        != core.get("platformManifestDigest")
        or labels.get("io.ambit.source-identity-sha256")
        != identity["identitySha256"]
        or labels.get("org.opencontainers.image.revision") != identity["revision"]
    ):
        raise CoreDerivedBuildError("final OCI config lineage is invalid")
    expected_paths = {"index.json", "oci-layout"}
    expected_paths.update(
        "blobs/sha256/" + digest.removeprefix("sha256:")
        for digest in [
            manifest_descriptor["digest"],
            config_descriptor["digest"],
            *(layer["digest"] for layer in layers),
        ]
    )
    if set(files) != expected_paths:
        raise CoreDerivedBuildError("OCI archive has omitted or extra blobs")
    return {
        "indexDocumentSha256": sha256(files["index.json"]),
        "platformManifestDigest": manifest_descriptor["digest"],
        "configDigest": config_descriptor["digest"],
        "orderedLayers": layers,
        "coreLayerPrefixCount": len(expected_core),
        "overlayLayerCount": 1,
        "blobCount": len(expected_paths) - 2,
    }


def _blob(files: dict[str, bytes], descriptor: Any) -> bytes:
    if not isinstance(descriptor, dict):
        raise CoreDerivedBuildError("OCI descriptor is invalid")
    digest = _digest(descriptor.get("digest"), "OCI descriptor")
    size = descriptor.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise CoreDerivedBuildError("OCI descriptor size is invalid")
    value = files.get("blobs/sha256/" + digest.removeprefix("sha256:"))
    if value is None or len(value) != size or sha256(value) != digest:
        raise CoreDerivedBuildError("OCI descriptor bytes differ")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise CoreDerivedBuildError(f"{label} digest is invalid")
    return value


def _json(path: Path) -> dict[str, Any]:
    return _json_bytes(path.read_bytes(), path.name)


def _json_bytes(value: bytes | None, label: str) -> dict[str, Any]:
    if value is None:
        raise CoreDerivedBuildError(f"{label} is absent")
    parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise CoreDerivedBuildError(f"{label} is invalid")
    return parsed


def _write(path: Path, value: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-identity", required=True, type=Path)
    parser.add_argument("--public-inputs", required=True, type=Path)
    parser.add_argument("--materializer-inputs", required=True, type=Path)
    parser.add_argument("--core-layout", required=True, type=Path)
    parser.add_argument("--composition-source", required=True, type=Path)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(
            json.dumps(
                build(
                    source_identity=args.source_identity,
                    public_inputs=args.public_inputs,
                    materializer_inputs=args.materializer_inputs,
                    core_layout=args.core_layout,
                    composition_source=args.composition_source,
                    builder=args.builder,
                    output=args.output,
                ),
                indent=2,
                sort_keys=True,
            )
        )
    except (OSError, CoreDerivedBuildError, json.JSONDecodeError) as error:
        print(f"core-derived-build: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
