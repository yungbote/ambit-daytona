from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("verify_attestations.py")


def encode(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class AttestationVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "oci"
        self.evidence.mkdir()
        self.expected_labels_path = self.root / "labels.json"
        self.expected_args_path = self.root / "args.json"
        self.expected_materials_path = self.root / "materials.json"
        self.output = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_fixture(
        self,
        *,
        extra_index: bool = False,
        duplicate_attestation: bool = False,
        extra_local: bool = False,
        extra_material: bool = False,
        extra_ambit_label: bool = False,
    ) -> dict[str, str]:
        expected_labels = {"io.ambit.runtime-pack": "ambit.runtime-pack/core-document@4"}
        actual_labels = dict(expected_labels)
        if extra_ambit_label:
            actual_labels["io.ambit.document.render"] = "document.render@1"
        config = {
            "config": {
                "User": "daytona",
                "WorkingDir": "/workspace",
                "Entrypoint": ["sleep", "infinity"],
                "Env": ["LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"],
                "Labels": actual_labels,
            },
            "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "1" * 64]},
        }
        config_payload = encode(config)
        config_digest = digest(config_payload)
        runtime_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config_payload),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:" + "2" * 64,
                    "size": 123,
                }
            ],
        }
        runtime_payload = encode(runtime_manifest)
        runtime_digest = digest(runtime_payload)
        expected_args = {"build-arg:BUILD_SOURCE_REVISION": "a" * 40}
        locals_value = [{"name": "context"}, {"name": "dockerfile"}, {"name": "materializer_source"}]
        if extra_local:
            locals_value.append({"name": "undeclared"})
        resolved = [
            {
                "uri": "pkg:docker/example/base?digest=sha256:" + "3" * 64,
                "digest": {"sha256": "3" * 64},
            }
        ]
        if extra_material:
            resolved.append(
                {
                    "uri": "pkg:docker/example/extra?digest=sha256:" + "4" * 64,
                    "digest": {"sha256": "4" * 64},
                }
            )
        sbom = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://spdx.dev/Document",
            "subject": [{"name": "fixture", "digest": {"sha256": runtime_digest.removeprefix("sha256:")}}],
            "predicate": {
                "spdxVersion": "SPDX-2.3",
                "documentNamespace": "https://example.invalid/spdx",
                "packages": [{"name": "fixture"}],
                "files": [{"fileName": "/fixture"}],
                "relationships": [{"relationshipType": "CONTAINS"}],
            },
        }
        provenance = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"name": "fixture", "digest": {"sha256": runtime_digest.removeprefix("sha256:")}}],
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
                    "resolvedDependencies": resolved,
                    "externalParameters": {
                        "request": {
                            "frontend": "dockerfile.v0",
                            "args": expected_args,
                            "locals": locals_value,
                        }
                    },
                }
            },
        }
        sbom_payload = encode(sbom)
        provenance_payload = encode(provenance)
        sbom_digest = digest(sbom_payload)
        provenance_digest = digest(provenance_payload)
        attestation_layers = [
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": sbom_digest,
                "size": len(sbom_payload),
                "annotations": {"in-toto.io/predicate-type": "https://spdx.dev/Document"},
            },
            {
                "mediaType": "application/vnd.in-toto+json",
                "digest": provenance_digest,
                "size": len(provenance_payload),
                "annotations": {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"},
            },
        ]
        if duplicate_attestation:
            attestation_layers.append(dict(attestation_layers[0]))
        attestation_manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:" + "5" * 64,
                "size": 2,
            },
            "layers": attestation_layers,
        }
        attestation_payload = encode(attestation_manifest)
        attestation_digest = digest(attestation_payload)
        index_manifests = [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": runtime_digest,
                "size": len(runtime_payload),
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": attestation_digest,
                "size": len(attestation_payload),
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": runtime_digest,
                },
                "platform": {"architecture": "unknown", "os": "unknown"},
            },
        ]
        if extra_index:
            index_manifests.append(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + "6" * 64,
                    "size": 1,
                    "platform": {"architecture": "arm64", "os": "linux"},
                }
            )
        index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": index_manifests,
        }
        index_payload = encode(index)
        files = {
            "config.json": config_payload,
            "runtime-manifest.json": runtime_payload,
            "sbom.intoto.json": sbom_payload,
            "provenance.intoto.json": provenance_payload,
            "attestation-manifest.json": attestation_payload,
            "index.json": index_payload,
        }
        for name, payload in files.items():
            (self.evidence / name).write_bytes(payload)
        self.expected_labels_path.write_bytes(encode(expected_labels))
        self.expected_args_path.write_bytes(encode(expected_args))
        self.expected_materials_path.write_bytes(
            encode([{"uri": "pkg:docker/example/base", "digest": "sha256:" + "3" * 64}])
        )
        return {
            "index": digest(index_payload),
            "manifest": runtime_digest,
            "config": config_digest,
            "attestation": attestation_digest,
            "sbom": sbom_digest,
            "provenance": provenance_digest,
        }

    def run_verifier(self, digests: dict[str, str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(self.evidence),
                "--index",
                digests["index"],
                "--manifest",
                digests["manifest"],
                "--config",
                digests["config"],
                "--attestation-manifest",
                digests["attestation"],
                "--sbom-layer",
                digests["sbom"],
                "--provenance-layer",
                digests["provenance"],
                "--expected-labels",
                str(self.expected_labels_path),
                "--expected-build-args",
                str(self.expected_args_path),
                "--expected-materials",
                str(self.expected_materials_path),
                "--output",
                str(self.output),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_exact_fixture_passes(self) -> None:
        result = self.run_verifier(self.write_fixture())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["outcome"], "passed")

    def test_extra_index_descriptor_fails(self) -> None:
        result = self.run_verifier(self.write_fixture(extra_index=True))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one runtime and one attestation", result.stderr)

    def test_duplicate_attestation_predicate_fails(self) -> None:
        result = self.run_verifier(self.write_fixture(duplicate_attestation=True))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly SBOM and provenance", result.stderr)

    def test_extra_local_input_fails(self) -> None:
        result = self.run_verifier(self.write_fixture(extra_local=True))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact declared set", result.stderr)

    def test_extra_resolved_material_fails(self) -> None:
        result = self.run_verifier(self.write_fixture(extra_material=True))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("resolved material roster differs", result.stderr)

    def test_extra_ambit_label_fails(self) -> None:
        result = self.run_verifier(self.write_fixture(extra_ambit_label=True))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("undeclared Ambit label", result.stderr)


if __name__ == "__main__":
    unittest.main()
