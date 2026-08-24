from __future__ import annotations

import io
import json
import tarfile
import unittest
from pathlib import Path

from certification.build_core_derived_candidate import (
    CoreDerivedBuildError,
    _build_command,
    _verify_oci_archive,
    sha256,
)


class CoreDerivedCandidateBuildTests(unittest.TestCase):
    def test_command_is_offline_cold_identity_bound_and_core_derived(self) -> None:
        command = _build_command(
            builder="builder",
            package_root=Path("/source"),
            source_identity=Path("/identity"),
            public_inputs=Path("/public"),
            materializer_inputs=Path("/materializer"),
            core_layout=Path("/core"),
            core_manifest="sha256:" + "1" * 64,
            core_source_date_epoch=10,
            composition_source=Path("/composition"),
            identity={
                "sourceDateEpoch": 1,
                "revision": "2" * 40,
                "repositoryTree": "3" * 40,
                "subtree": "4" * 40,
                "archiveSha256": "sha256:" + "5" * 64,
                "contextSha256": "sha256:" + "6" * 64,
                "sourceFilesManifestSha256": "sha256:" + "7" * 64,
                "sourceModesManifestSha256": "sha256:" + "8" * 64,
                "identitySha256": "sha256:" + "9" * 64,
            },
            archive=Path("/out.oci.tar"),
            metadata=Path("/metadata.json"),
        )
        rendered = "\n".join(command)
        self.assertIn("--no-cache", command)
        self.assertIn("--pull=false", command)
        self.assertIn("core_parent=oci-layout:///core@sha256:" + "1" * 64, rendered)
        self.assertIn("source_identity=/identity", rendered)
        self.assertIn("composition_source=/composition", rendered)
        self.assertIn("rewrite-timestamp=true", rendered)
        self.assertIn("SOURCE_DATE_EPOCH=10", rendered)
        self.assertIn("BUILD_SOURCE_DATE_EPOCH=1", rendered)

    def test_admits_exact_repeated_core_prefix_and_one_overlay(self) -> None:
        archive, core, identity = oci_fixture()
        result = _verify_oci_archive(archive, core, identity)
        self.assertEqual(result["coreLayerPrefixCount"], 2)
        self.assertEqual(result["overlayLayerCount"], 1)

    def test_rejects_missing_core_prefix_extra_overlay_and_wrong_source(self) -> None:
        archive, core, identity = oci_fixture()
        changed = dict(core)
        changed_layers = [dict(layer) for layer in core["orderedLayers"]]
        changed_layers[0]["digest"] = "sha256:" + "9" * 64
        changed["orderedLayers"] = changed_layers
        with self.assertRaisesRegex(CoreDerivedBuildError, "core layer prefix"):
            _verify_oci_archive(archive, changed, identity)

        archive, core, identity = oci_fixture(extra_overlay=True)
        with self.assertRaisesRegex(CoreDerivedBuildError, "one closed overlay"):
            _verify_oci_archive(archive, core, identity)

        archive, core, identity = oci_fixture(source_identity="sha256:" + "f" * 64)
        with self.assertRaisesRegex(CoreDerivedBuildError, "config lineage"):
            _verify_oci_archive(archive, core, identity)


def oci_fixture(
    *,
    extra_overlay: bool = False,
    source_identity: str = "sha256:" + "5" * 64,
) -> tuple[bytes, dict[str, object], dict[str, object]]:
    core_layer = b"core"
    overlay_layer = b"overlay"
    extra_layer = b"extra"
    core_descriptor = descriptor(core_layer, "layer")
    overlay_descriptor = descriptor(overlay_layer, "layer")
    layers = [core_descriptor, core_descriptor, overlay_descriptor]
    if extra_overlay:
        layers.append(descriptor(extra_layer, "layer"))
    core = {
        "platformManifestDigest": "sha256:" + "1" * 64,
        "configDigest": "sha256:" + "2" * 64,
        "sourceIdentitySha256": "sha256:" + "3" * 64,
        "orderedLayers": [core_descriptor, core_descriptor],
    }
    identity = {
        "revision": "4" * 40,
        "identitySha256": "sha256:" + "5" * 64,
    }
    config = canonical(
        {
            "config": {
                "User": "1000:1000",
                "Labels": {
                    "io.ambit.runtime-pack": "ambit.runtime-pack/core-document@5",
                    "io.ambit.core-parent-platform-manifest": core[
                        "platformManifestDigest"
                    ],
                    "io.ambit.source-identity-sha256": source_identity,
                    "org.opencontainers.image.revision": identity["revision"],
                },
            }
        }
    )
    config_descriptor = descriptor(config, "config")
    manifest = canonical(
        {
            "schemaVersion": 2,
            "config": config_descriptor,
            "layers": layers,
        }
    )
    manifest_descriptor = descriptor(manifest, "manifest")
    index = canonical({"schemaVersion": 2, "manifests": [manifest_descriptor]})
    blobs = {
        core_descriptor["digest"]: core_layer,
        overlay_descriptor["digest"]: overlay_layer,
        config_descriptor["digest"]: config,
        manifest_descriptor["digest"]: manifest,
    }
    if extra_overlay:
        blobs[layers[-1]["digest"]] = extra_layer
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        add(archive, "oci-layout", b'{"imageLayoutVersion":"1.0.0"}')
        add(archive, "index.json", index)
        for digest, value in blobs.items():
            add(archive, "blobs/sha256/" + digest.removeprefix("sha256:"), value)
    return output.getvalue(), core, identity


def descriptor(value: bytes, kind: str) -> dict[str, object]:
    media = {
        "config": "application/vnd.oci.image.config.v1+json",
        "manifest": "application/vnd.oci.image.manifest.v1+json",
        "layer": "application/vnd.oci.image.layer.v1.tar+gzip",
    }[kind]
    return {"mediaType": media, "digest": sha256(value), "size": len(value)}


def canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def add(archive: tarfile.TarFile, name: str, value: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(value)
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(value))


if __name__ == "__main__":
    unittest.main()
