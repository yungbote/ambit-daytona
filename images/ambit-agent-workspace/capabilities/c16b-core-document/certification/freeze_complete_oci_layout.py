from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import stat
from collections import Counter
from pathlib import Path
from typing import Any


OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_EMPTY = "application/vnd.oci.empty.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"
IN_TOTO = "application/vnd.in-toto+json"


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
    require(
        isinstance(digest, str)
        and digest.startswith("sha256:")
        and len(digest) == 71
        and all(character in "0123456789abcdef" for character in digest[7:]),
        "OCI descriptor digest is invalid",
    )
    require(isinstance(size, int) and not isinstance(size, bool) and size >= 0, "OCI descriptor size is invalid")
    require(isinstance(media_type, str) and media_type, "OCI descriptor media type is invalid")
    return digest, size, media_type


def verify_file(path: Path, descriptor: dict[str, Any], description: str) -> None:
    digest, size, _ = descriptor_identity(descriptor)
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), f"{description} is not a regular file")
    require(metadata.st_size == size, f"{description} size mismatch")
    require(f"sha256:{sha256(path)}" == digest, f"{description} digest mismatch")


def blob_path(root: Path, digest: str) -> Path:
    return root / digest.removeprefix("sha256:")


def write_blob(layout: Path, descriptor: dict[str, Any], source: Path | bytes, origin: str) -> dict[str, Any]:
    digest, size, media_type = descriptor_identity(descriptor)
    destination = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
    if isinstance(source, bytes):
        require(len(source) == size, f"{origin} inline object size mismatch")
        require(f"sha256:{hashlib.sha256(source).hexdigest()}" == digest, f"{origin} inline object digest mismatch")
        destination.write_bytes(source)
    else:
        verify_file(source, descriptor, origin)
        shutil.copyfile(source, destination)
    os.chmod(destination, 0o444)
    verify_file(destination, descriptor, f"frozen {origin}")
    return {"digest": digest, "size": size, "mediaType": media_type, "origin": origin}


parser = argparse.ArgumentParser()
parser.add_argument("--index", required=True, type=Path)
parser.add_argument("--runtime-manifest", required=True, type=Path)
parser.add_argument("--runtime-config", required=True, type=Path)
parser.add_argument("--attestation-manifest", required=True, type=Path)
parser.add_argument("--base-reference", required=True)
parser.add_argument("--base-manifest", required=True, type=Path)
parser.add_argument("--base-config", required=True, type=Path)
parser.add_argument("--base-blobs", required=True, type=Path)
parser.add_argument("--candidate-blobs", required=True, type=Path)
parser.add_argument("--output-layout", required=True, type=Path)
parser.add_argument("--output-receipt", required=True, type=Path)
args = parser.parse_args()

layout = args.output_layout
require(not layout.exists(), "output OCI layout must not already exist")
layout.mkdir(parents=True)
(layout / "blobs" / "sha256").mkdir(parents=True)

index = load(args.index)
runtime_manifest = load(args.runtime_manifest)
attestation_manifest = load(args.attestation_manifest)
base_manifest = load(args.base_manifest)
runtime_config = load(args.runtime_config)
base_config = load(args.base_config)

require(index.get("schemaVersion") == 2 and index.get("mediaType") == OCI_INDEX, "root OCI index is invalid")
index_descriptors = index.get("manifests")
require(isinstance(index_descriptors, list) and len(index_descriptors) == 2, "root index roster is not exact")
runtime_descriptors = [
    descriptor
    for descriptor in index_descriptors
    if isinstance(descriptor, dict) and descriptor.get("platform") == {"architecture": "amd64", "os": "linux"}
]
attestation_descriptors = [
    descriptor
    for descriptor in index_descriptors
    if isinstance(descriptor, dict)
    and descriptor.get("annotations", {}).get("vnd.docker.reference.type") == "attestation-manifest"
]
require(len(runtime_descriptors) == 1 and len(attestation_descriptors) == 1, "root index subjects are ambiguous")
runtime_descriptor = runtime_descriptors[0]
attestation_descriptor = attestation_descriptors[0]
require(descriptor_identity(runtime_descriptor)[2] == OCI_MANIFEST, "runtime descriptor media type is invalid")
require(descriptor_identity(attestation_descriptor)[2] == OCI_MANIFEST, "attestation descriptor media type is invalid")
verify_file(args.runtime_manifest, runtime_descriptor, "runtime manifest")
verify_file(args.attestation_manifest, attestation_descriptor, "attestation manifest")
require(
    attestation_descriptor.get("annotations", {}).get("vnd.docker.reference.digest")
    == runtime_descriptor.get("digest"),
    "attestation descriptor does not bind the runtime manifest",
)

require(runtime_manifest.get("schemaVersion") == 2 and runtime_manifest.get("mediaType") == OCI_MANIFEST, "runtime manifest is invalid")
runtime_config_descriptor = runtime_manifest.get("config")
runtime_layers = runtime_manifest.get("layers")
require(isinstance(runtime_config_descriptor, dict), "runtime config descriptor is invalid")
require(descriptor_identity(runtime_config_descriptor)[2] == OCI_CONFIG, "runtime config media type is invalid")
require(isinstance(runtime_layers, list) and runtime_layers, "runtime layer roster is empty")
require(all(isinstance(layer, dict) for layer in runtime_layers), "runtime layer descriptor is invalid")
require(all(descriptor_identity(layer)[2] == OCI_LAYER for layer in runtime_layers), "runtime layer media type is invalid")
verify_file(args.runtime_config, runtime_config_descriptor, "runtime config")
require(runtime_config.get("architecture") == "amd64" and runtime_config.get("os") == "linux", "runtime config platform is invalid")

base_digest = args.base_reference.rsplit("@", 1)[-1]
require(base_digest.startswith("sha256:") and f"sha256:{sha256(args.base_manifest)}" == base_digest, "declared base manifest digest mismatch")
require(base_manifest.get("schemaVersion") == 2 and base_manifest.get("mediaType") == OCI_MANIFEST, "declared base manifest is invalid")
base_config_descriptor = base_manifest.get("config")
base_layers = base_manifest.get("layers")
require(isinstance(base_config_descriptor, dict), "base config descriptor is invalid")
require(isinstance(base_layers, list) and base_layers, "base layer roster is empty")
require(descriptor_identity(base_config_descriptor)[2] == OCI_CONFIG, "base config media type is invalid")
require(
    all(isinstance(layer, dict) and descriptor_identity(layer)[2] == OCI_LAYER for layer in base_layers),
    "base layer media type is invalid",
)
verify_file(args.base_config, base_config_descriptor, "declared base config")
require(base_config.get("architecture") == "amd64" and base_config.get("os") == "linux", "declared base platform is invalid")
require(len(runtime_layers) > len(base_layers), "runtime must add at least one pack-owned layer")
for index_value, base_layer in enumerate(base_layers):
    require(isinstance(base_layer, dict), "base layer descriptor is invalid")
    require(
        runtime_layers[index_value] == base_layer,
        f"runtime inherited layer {index_value} differs from the declared base",
    )

require(
    attestation_manifest.get("schemaVersion") == 2
    and attestation_manifest.get("mediaType") == OCI_MANIFEST,
    "attestation manifest is invalid",
)
attestation_config_descriptor = attestation_manifest.get("config")
attestation_layers = attestation_manifest.get("layers")
require(isinstance(attestation_config_descriptor, dict), "attestation config descriptor is invalid")
require(descriptor_identity(attestation_config_descriptor)[2] == OCI_EMPTY, "attestation config is not OCI empty")
require(isinstance(attestation_layers, list) and len(attestation_layers) == 2, "attestation layer roster is not exact")
require(
    Counter(
        layer.get("annotations", {}).get("in-toto.io/predicate-type")
        for layer in attestation_layers
        if isinstance(layer, dict)
    )
    == Counter({"https://spdx.dev/Document": 1, "https://slsa.dev/provenance/v1": 1}),
    "attestation predicate roster is not exact",
)
require(all(descriptor_identity(layer)[2] == IN_TOTO for layer in attestation_layers), "attestation layer media type is invalid")

objects: list[dict[str, Any]] = []
objects.append(write_blob(layout, runtime_descriptor, args.runtime_manifest, "candidate-runtime-manifest"))
objects.append(write_blob(layout, attestation_descriptor, args.attestation_manifest, "candidate-attestation-manifest"))
objects.append(write_blob(layout, runtime_config_descriptor, args.runtime_config, "candidate-runtime-config"))

for layer in base_layers:
    digest, _, _ = descriptor_identity(layer)
    objects.append(write_blob(layout, layer, blob_path(args.base_blobs, digest), "declared-base-layer"))
for layer in runtime_layers[len(base_layers) :]:
    digest, _, _ = descriptor_identity(layer)
    objects.append(write_blob(layout, layer, blob_path(args.candidate_blobs, digest), "candidate-runtime-layer"))

inline_data = attestation_config_descriptor.get("data")
require(isinstance(inline_data, str), "attestation empty config must be inline")
objects.append(
    write_blob(
        layout,
        attestation_config_descriptor,
        base64.b64decode(inline_data, validate=True),
        "inline-attestation-config",
    )
)
for layer in attestation_layers:
    digest, _, _ = descriptor_identity(layer)
    objects.append(write_blob(layout, layer, blob_path(args.candidate_blobs, digest), "candidate-attestation-layer"))

expected_digests = {descriptor["digest"] for descriptor in objects}
require(len(expected_digests) == len(objects), "OCI object graph contains duplicate content descriptors")
actual_blob_names = {path.name for path in (layout / "blobs" / "sha256").iterdir()}
require(actual_blob_names == {digest.removeprefix("sha256:") for digest in expected_digests}, "frozen OCI blob roster differs")

shutil.copyfile(args.index, layout / "index.json")
os.chmod(layout / "index.json", 0o444)
oci_layout_payload = b'{"imageLayoutVersion":"1.0.0"}\n'
(layout / "oci-layout").write_bytes(oci_layout_payload)
os.chmod(layout / "oci-layout", 0o444)
require(f"sha256:{sha256(layout / 'index.json')}" == f"sha256:{sha256(args.index)}", "root index copy mismatch")

source_counts = Counter(str(item["origin"]) for item in objects)
receipt = {
    "schema": "ambit.runtime-pack-complete-oci-layout/v1",
    "outcome": "passed",
    "rootIndex": {
        "digest": f"sha256:{sha256(layout / 'index.json')}",
        "bytes": (layout / "index.json").stat().st_size,
        "mediaType": OCI_INDEX,
    },
    "ociLayout": {
        "sha256": hashlib.sha256(oci_layout_payload).hexdigest(),
        "bytes": len(oci_layout_payload),
        "imageLayoutVersion": "1.0.0",
    },
    "runtimeManifestDigest": runtime_descriptor["digest"],
    "attestationManifestDigest": attestation_descriptor["digest"],
    "declaredBase": {
        "reference": args.base_reference,
        "manifestDigest": base_digest,
        "configDigest": base_config_descriptor["digest"],
        "inheritedLayerCount": len(base_layers),
    },
    "packOwnedRuntimeLayerCount": len(runtime_layers) - len(base_layers),
    "blobCount": len(objects),
    "blobBytes": sum(int(item["size"]) for item in objects),
    "sourceCounts": dict(sorted(source_counts.items())),
    "objects": sorted(objects, key=lambda item: str(item["digest"])),
}
args.output_receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
