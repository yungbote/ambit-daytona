from __future__ import annotations

import argparse
import hashlib
import json
import stat
from pathlib import Path
from typing import Any


OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    require(isinstance(value, dict), f"expected JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def descriptor_identity(descriptor: dict[str, Any]) -> tuple[str, int, str]:
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    media_type = descriptor.get("mediaType")
    require(isinstance(digest, str) and digest.startswith("sha256:") and len(digest) == 71, "descriptor digest is invalid")
    require(isinstance(size, int) and not isinstance(size, bool) and size >= 0, "descriptor size is invalid")
    require(isinstance(media_type, str) and media_type, "descriptor media type is invalid")
    return digest, size, media_type


def verify_descriptor_blob(root: Path, descriptor: dict[str, Any]) -> Path:
    digest, size, _ = descriptor_identity(descriptor)
    path = root / "blobs" / "sha256" / digest.removeprefix("sha256:")
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), f"OCI blob is not a regular file: {digest}")
    require(metadata.st_size == size, f"OCI blob size mismatch: {digest}")
    require(f"sha256:{sha256(path)}" == digest, f"OCI blob digest mismatch: {digest}")
    return path


parser = argparse.ArgumentParser()
parser.add_argument("--layout", required=True, type=Path)
parser.add_argument("--receipt", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()

layout = args.layout.resolve(strict=True)
require(layout.is_dir() and not layout.is_symlink(), "OCI layout root is invalid")
layout_file = layout / "oci-layout"
index_path = layout / "index.json"
require(layout_file.read_bytes() == b'{"imageLayoutVersion":"1.0.0"}\n', "OCI layout version file is invalid")
index = load(index_path)
receipt = load(args.receipt)
require(
    receipt.get("schema") == "ambit.runtime-pack-complete-oci-layout/v1" and receipt.get("outcome") == "passed",
    "complete OCI layout receipt is invalid",
)
require(index.get("schemaVersion") == 2 and index.get("mediaType") == OCI_INDEX, "OCI root index is invalid")
require(
    receipt.get("rootIndex")
    == {"digest": f"sha256:{sha256(index_path)}", "bytes": index_path.stat().st_size, "mediaType": OCI_INDEX},
    "OCI root index differs from its freeze receipt",
)

manifests = index.get("manifests")
require(isinstance(manifests, list) and len(manifests) == 2, "OCI root index descriptor roster is invalid")
reachable: dict[str, tuple[int, str]] = {}
for manifest_descriptor in manifests:
    require(isinstance(manifest_descriptor, dict), "OCI manifest descriptor is invalid")
    manifest_digest, manifest_size, manifest_media_type = descriptor_identity(manifest_descriptor)
    require(manifest_media_type == OCI_MANIFEST, "OCI subject is not an image manifest")
    manifest_path = verify_descriptor_blob(layout, manifest_descriptor)
    reachable[manifest_digest] = (manifest_size, manifest_media_type)
    manifest = load(manifest_path)
    require(
        manifest.get("schemaVersion") == 2 and manifest.get("mediaType") == OCI_MANIFEST,
        "reachable OCI manifest is invalid",
    )
    config = manifest.get("config")
    layers = manifest.get("layers")
    require(isinstance(config, dict), "reachable OCI config descriptor is invalid")
    require(isinstance(layers, list), "reachable OCI layer roster is invalid")
    for descriptor in [config, *layers]:
        require(isinstance(descriptor, dict), "reachable OCI object descriptor is invalid")
        digest, size, media_type = descriptor_identity(descriptor)
        verify_descriptor_blob(layout, descriptor)
        previous = reachable.get(digest)
        require(previous is None or previous == (size, media_type), "same OCI digest has conflicting descriptors")
        reachable[digest] = (size, media_type)

actual_blob_names = {path.name for path in (layout / "blobs" / "sha256").iterdir()}
require(actual_blob_names == {digest.removeprefix("sha256:") for digest in reachable}, "OCI layout has missing or unreachable blobs")
receipt_objects = receipt.get("objects")
require(isinstance(receipt_objects, list), "OCI freeze receipt object roster is invalid")
receipt_identities = {
    (item.get("digest"), item.get("size"), item.get("mediaType"))
    for item in receipt_objects
    if isinstance(item, dict)
}
reachable_identities = {(digest, size, media_type) for digest, (size, media_type) in reachable.items()}
require(receipt_identities == reachable_identities, "OCI reachable graph differs from freeze receipt")
require(receipt.get("blobCount") == len(reachable), "OCI freeze receipt blob count differs")

file_manifest = []
for path in sorted(item for item in layout.rglob("*") if item.is_file()):
    relative = path.relative_to(layout).as_posix()
    file_manifest.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256(path)})
tree_payload = json.dumps(file_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
verification = {
    "schema": "ambit.runtime-pack-complete-oci-layout-verification/v1",
    "outcome": "passed",
    "rootIndexDigest": f"sha256:{sha256(index_path)}",
    "runtimeManifestDigest": receipt.get("runtimeManifestDigest"),
    "attestationManifestDigest": receipt.get("attestationManifestDigest"),
    "blobCount": len(reachable),
    "blobBytes": sum(size for size, _ in reachable.values()),
    "fileCount": len(file_manifest),
    "layoutTreeSha256": hashlib.sha256(tree_payload).hexdigest(),
    "files": file_manifest,
}
args.output.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n")
