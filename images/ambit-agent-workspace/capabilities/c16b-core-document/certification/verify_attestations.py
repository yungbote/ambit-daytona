from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
from typing import Any


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SENSITIVE_ENV_RE = re.compile(r"(?:api[_-]?key|password|private[_-]?key|secret|token)", re.IGNORECASE)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_descriptor(
    descriptor: dict[str, Any],
    *,
    digest: str,
    size: int,
    media_type: str,
    description: str,
) -> None:
    require(descriptor.get("digest") == digest, f"{description} digest mismatch")
    require(descriptor.get("size") == size, f"{description} size mismatch")
    require(descriptor.get("mediaType") == media_type, f"{description} media type mismatch")


parser = argparse.ArgumentParser()
parser.add_argument("evidence_dir", type=Path)
parser.add_argument("--index", required=True)
parser.add_argument("--manifest", required=True)
parser.add_argument("--config", required=True)
parser.add_argument("--attestation-manifest", required=True)
parser.add_argument("--sbom-layer", required=True)
parser.add_argument("--provenance-layer", required=True)
parser.add_argument("--expected-labels", required=True, type=Path)
parser.add_argument("--expected-build-args", required=True, type=Path)
parser.add_argument("--expected-materials", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()

root = args.evidence_dir.resolve()
index_path = root / "index.json"
manifest_path = root / "runtime-manifest.json"
config_path = root / "config.json"
attestation_manifest_path = root / "attestation-manifest.json"
sbom_path = root / "sbom.intoto.json"
provenance_path = root / "provenance.intoto.json"

expected = {
    "index": args.index.removeprefix("sha256:"),
    "manifest": args.manifest.removeprefix("sha256:"),
    "config": args.config.removeprefix("sha256:"),
    "attestationManifest": args.attestation_manifest.removeprefix("sha256:"),
    "sbomLayer": args.sbom_layer.removeprefix("sha256:"),
    "provenanceLayer": args.provenance_layer.removeprefix("sha256:"),
}
require(
    all(re.fullmatch(r"[0-9a-f]{64}", value) for value in expected.values()),
    "expected OCI digest is invalid",
)
actual = {
    "index": sha256(index_path),
    "manifest": sha256(manifest_path),
    "config": sha256(config_path),
    "attestationManifest": sha256(attestation_manifest_path),
    "sbomLayer": sha256(sbom_path),
    "provenanceLayer": sha256(provenance_path),
}
require(actual == expected, f"raw OCI or attestation digest mismatch: {actual!r}")

index = load(index_path)
manifest = load(manifest_path)
config = load(config_path)
attestation_manifest = load(attestation_manifest_path)
sbom = load(sbom_path)
provenance = load(provenance_path)
expected_labels = load(args.expected_labels)
expected_build_args = load(args.expected_build_args)
expected_materials_value = json.loads(args.expected_materials.read_text())
require(isinstance(expected_materials_value, list), "expected materials must be a JSON list")
expected_materials: list[tuple[str, str]] = []
for index_value, value in enumerate(expected_materials_value):
    require(isinstance(value, dict), f"expected material {index_value} is invalid")
    require(set(value) == {"uri", "digest"}, f"expected material {index_value} keys are invalid")
    require(
        isinstance(value["uri"], str)
        and value["uri"].startswith("pkg:docker/")
        and isinstance(value["digest"], str)
        and DIGEST_RE.fullmatch(value["digest"]),
        f"expected material {index_value} identity is invalid",
    )
    expected_materials.append((value["uri"], value["digest"]))
require(expected_materials, "expected material inventory is empty")

require(index.get("schemaVersion") == 2, "OCI index schema version is invalid")
require(index.get("mediaType") == "application/vnd.oci.image.index.v1+json", "OCI index media type is invalid")
index_manifests = index.get("manifests")
require(isinstance(index_manifests, list), "OCI index manifest inventory is invalid")
require(len(index_manifests) == 2, "OCI index must contain exactly one runtime and one attestation descriptor")
runtime_descriptors = [
    item
    for item in index_manifests
    if isinstance(item, dict) and item.get("digest") == f"sha256:{expected['manifest']}"
]
require(len(runtime_descriptors) == 1, "index must contain exactly one expected runtime manifest")
runtime_descriptor = runtime_descriptors[0]
require_descriptor(
    runtime_descriptor,
    digest=f"sha256:{expected['manifest']}",
    size=manifest_path.stat().st_size,
    media_type="application/vnd.oci.image.manifest.v1+json",
    description="runtime manifest descriptor",
)
require(
    runtime_descriptor.get("platform") == {"architecture": "amd64", "os": "linux"},
    "runtime manifest platform must be linux/amd64",
)
attestation_descriptors = [
    item
    for item in index_manifests
    if isinstance(item, dict) and item.get("digest") == f"sha256:{expected['attestationManifest']}"
]
require(len(attestation_descriptors) == 1, "index must contain exactly one attestation manifest")
attestation_descriptor = attestation_descriptors[0]
require_descriptor(
    attestation_descriptor,
    digest=f"sha256:{expected['attestationManifest']}",
    size=attestation_manifest_path.stat().st_size,
    media_type="application/vnd.oci.image.manifest.v1+json",
    description="attestation manifest descriptor",
)
annotations = attestation_descriptor.get("annotations", {})
require(annotations.get("vnd.docker.reference.type") == "attestation-manifest", "attestation type missing")
require(
    annotations.get("vnd.docker.reference.digest") == f"sha256:{expected['manifest']}",
    "attestation descriptor does not reference runtime manifest",
)

require(manifest.get("schemaVersion") == 2, "runtime manifest schema version is invalid")
require(manifest.get("mediaType") == "application/vnd.oci.image.manifest.v1+json", "runtime manifest media type is invalid")
config_descriptor = manifest.get("config")
require(isinstance(config_descriptor, dict), "runtime config descriptor is invalid")
require_descriptor(
    config_descriptor,
    digest=f"sha256:{expected['config']}",
    size=config_path.stat().st_size,
    media_type="application/vnd.oci.image.config.v1+json",
    description="runtime config descriptor",
)
layers = manifest.get("layers")
require(isinstance(layers, list) and layers, "runtime manifest has no layers")
for layer in layers:
    require(isinstance(layer, dict), "runtime layer descriptor is invalid")
    require(isinstance(layer.get("size"), int) and layer["size"] > 0, "runtime layer size is invalid")
    require(
        isinstance(layer.get("digest"), str) and DIGEST_RE.fullmatch(layer["digest"]),
        "runtime layer digest is invalid",
    )

runtime_config = config.get("config")
require(isinstance(runtime_config, dict), "OCI runtime config is invalid")
require(runtime_config.get("User") == "daytona", "runtime user must be daytona")
require(runtime_config.get("WorkingDir") == "/workspace", "runtime working directory is invalid")
require(runtime_config.get("Entrypoint") == ["sleep", "infinity"], "runtime entrypoint is invalid")
rootfs = config.get("rootfs")
require(isinstance(rootfs, dict) and rootfs.get("type") == "layers", "runtime rootfs is invalid")
diff_ids = rootfs.get("diff_ids")
require(isinstance(diff_ids, list) and len(diff_ids) == len(layers), "runtime diff-id inventory is incomplete")
require(
    all(isinstance(value, str) and DIGEST_RE.fullmatch(value) for value in diff_ids),
    "runtime diff-id is invalid",
)

labels = runtime_config.get("Labels")
require(isinstance(labels, dict), "runtime labels are absent")
require(
    expected_labels
    and all(isinstance(key, str) and isinstance(value, str) for key, value in expected_labels.items()),
    "expected labels are invalid",
)
for key, value in expected_labels.items():
    require(labels.get(key) == value, f"runtime label mismatch: {key}")
expected_ambit_labels = {key: value for key, value in expected_labels.items() if key.startswith("io.ambit.")}
actual_ambit_labels = {key: value for key, value in labels.items() if key.startswith("io.ambit.")}
require(actual_ambit_labels == expected_ambit_labels, "runtime contains an undeclared Ambit label")
for key, value in labels.items():
    rendered = f"{key}={value}".lower()
    require("document.render@1" not in rendered, "runtime labels falsely claim document.render@1")
    require("certifieddocumentprofile" not in rendered, "runtime labels falsely claim CertifiedDocumentProfile")
    require("skill-availability" not in rendered, "runtime labels falsely claim Skill availability")
require(
    not any(value in {"unbound", "uncommitted"} for value in labels.values()),
    "runtime label retains an unbound source input",
)
environment = runtime_config.get("Env")
require(isinstance(environment, list) and environment, "runtime environment is absent")
environment_map: dict[str, str] = {}
for item in environment:
    require(isinstance(item, str) and "=" in item, "runtime environment entry is malformed")
    key, value = item.split("=", 1)
    require(key not in environment_map, f"duplicate runtime environment key: {key}")
    environment_map[key] = value
    require(not (value and SENSITIVE_ENV_RE.search(key)), f"secret-shaped runtime environment key: {key}")
require(environment_map.get("LANG") == "C.UTF-8", "runtime LANG is invalid")
require(environment_map.get("LC_ALL") == "C.UTF-8", "runtime LC_ALL is invalid")
require(environment_map.get("TZ") == "UTC", "runtime timezone is invalid")

require(attestation_manifest.get("schemaVersion") == 2, "attestation manifest schema version is invalid")
require(
    attestation_manifest.get("mediaType") == "application/vnd.oci.image.manifest.v1+json",
    "attestation manifest media type is invalid",
)
attestation_layers = attestation_manifest.get("layers")
require(isinstance(attestation_layers, list), "attestation layer inventory is invalid")
require(len(attestation_layers) == 2, "attestation manifest must contain exactly SBOM and provenance layers")
require(all(isinstance(layer, dict) for layer in attestation_layers), "attestation layer descriptor is invalid")
predicate_types = [
    layer.get("annotations", {}).get("in-toto.io/predicate-type") for layer in attestation_layers
]
require(
    Counter(predicate_types)
    == Counter({"https://spdx.dev/Document": 1, "https://slsa.dev/provenance/v1": 1}),
    "attestation predicate roster differs from exact SBOM and provenance set",
)
layer_by_predicate = dict(zip(predicate_types, attestation_layers, strict=True))
sbom_descriptor = layer_by_predicate.get("https://spdx.dev/Document")
provenance_descriptor = layer_by_predicate.get("https://slsa.dev/provenance/v1")
require(isinstance(sbom_descriptor, dict), "SBOM layer missing")
require(isinstance(provenance_descriptor, dict), "provenance layer missing")
require_descriptor(
    sbom_descriptor,
    digest=f"sha256:{expected['sbomLayer']}",
    size=sbom_path.stat().st_size,
    media_type="application/vnd.in-toto+json",
    description="SBOM attestation layer",
)
require_descriptor(
    provenance_descriptor,
    digest=f"sha256:{expected['provenanceLayer']}",
    size=provenance_path.stat().st_size,
    media_type="application/vnd.in-toto+json",
    description="provenance attestation layer",
)

for name, statement, predicate_type in (
    ("sbom", sbom, "https://spdx.dev/Document"),
    ("provenance", provenance, "https://slsa.dev/provenance/v1"),
):
    require(statement.get("_type") == "https://in-toto.io/Statement/v1", f"{name} statement type mismatch")
    require(statement.get("predicateType") == predicate_type, f"{name} predicate type mismatch")
    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1, f"{name} must contain exactly one subject")
    require(
        subjects[0].get("digest", {}).get("sha256") == expected["manifest"],
        f"{name} subject does not bind runtime manifest",
    )

build_definition = provenance.get("predicate", {}).get("buildDefinition", {})
require(
    build_definition.get("buildType")
    == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
    "provenance build type is invalid",
)
external_parameters = build_definition.get("externalParameters", {})
request = external_parameters.get("request", {})
require(request.get("frontend") == "dockerfile.v0", "provenance frontend is invalid")
request_args = request.get("args")
require(isinstance(request_args, dict), "provenance request arguments are absent")
recorded_build_args = {
    key: value for key, value in request_args.items() if isinstance(key, str) and key.startswith("build-arg:")
}
require(recorded_build_args == expected_build_args, "provenance build arguments differ from the exact expected set")
locals_value = request.get("locals")
require(isinstance(locals_value, list), "provenance local inputs are absent")
require(
    all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in locals_value),
    "provenance local input descriptor is invalid",
)
local_name_list = [item["name"] for item in locals_value]
require(
    Counter(local_name_list) == Counter({"context": 1, "dockerfile": 1, "materializer_source": 1}),
    "provenance local input roster differs from the exact declared set",
)
resolved_dependencies = build_definition.get("resolvedDependencies")
require(isinstance(resolved_dependencies, list), "provenance resolved dependencies are absent")
resolved_materials: list[tuple[str, str]] = []
for dependency in resolved_dependencies:
    require(isinstance(dependency, dict), "provenance resolved dependency is invalid")
    uri = dependency.get("uri")
    digest = dependency.get("digest", {}).get("sha256")
    require(isinstance(uri, str) and "?" in uri, "provenance material URI is invalid")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest), "provenance material digest is invalid")
    resolved_materials.append((uri.split("?", 1)[0], f"sha256:{digest}"))
require(
    Counter(resolved_materials) == Counter(expected_materials),
    f"provenance resolved material roster differs: {resolved_materials!r}",
)

spdx = sbom.get("predicate")
require(isinstance(spdx, dict), "SBOM predicate is invalid")
require(spdx.get("spdxVersion") == "SPDX-2.3", "SBOM predicate is not SPDX 2.3")
require(
    isinstance(spdx.get("documentNamespace"), str) and spdx["documentNamespace"],
    "SBOM namespace is absent",
)
require(isinstance(spdx.get("packages"), list) and spdx["packages"], "SBOM contains no packages")
require(isinstance(spdx.get("files"), list) and spdx["files"], "SBOM contains no files")
require(
    isinstance(spdx.get("relationships"), list) and spdx["relationships"],
    "SBOM contains no relationships",
)

receipt = {
    "schema": "ambit.runtime-pack-attestation-verification/v2",
    "outcome": "passed",
    "digests": {key: f"sha256:{value}" for key, value in actual.items()},
    "platform": "linux/amd64",
    "runtime": {
        "user": runtime_config["User"],
        "workingDirectory": runtime_config["WorkingDir"],
        "layerCount": len(layers),
    },
    "sourceLabels": expected_labels,
    "provenance": {
        "buildArgs": expected_build_args,
        "localInputs": sorted(local_name_list),
        "expectedMaterials": [
            {"uri": uri, "digest": digest} for uri, digest in sorted(expected_materials)
        ],
        "resolvedMaterials": [
            {"uri": uri, "digest": digest} for uri, digest in sorted(resolved_materials)
        ],
    },
    "sbom": {
        "packages": len(spdx["packages"]),
        "files": len(spdx["files"]),
        "relationships": len(spdx["relationships"]),
    },
}
args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
