from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from full_image_binding import FullImageBindingError, digest, verify_binding


SOURCE_ROOT = Path(__file__).resolve().parents[1]


def sha(seed: int) -> str:
    return "sha256:" + f"{seed:064x}"


class FullImageBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.binding_path = Path(self.temporary.name) / "binding.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _binding(self, facet: str = "C18_RESEARCH") -> dict[str, object]:
        pack_set = json.loads((SOURCE_ROOT / "pack-set.lock.json").read_text())
        specialist_refs = pack_set["facetSpecialistClosures"][facet]
        baseline = [
            {
                "packRevisionRef": "ambit.runtime-pack/core-document@5",
                "artifactDigest": sha(10),
                "declarationDigest": sha(11),
            }
        ]
        specialist = [
            {
                "packRevisionRef": ref,
                "artifactDigest": sha(20 + index),
                "declarationDigest": sha(30 + index),
            }
            for index, ref in enumerate(specialist_refs)
        ]
        all_packs = sorted([*baseline, *specialist], key=lambda item: item["packRevisionRef"])
        pack_set_digest = digest(all_packs)
        manifest = sha(50)
        evidence_names = ["sbom", "provenance", "signature", "licenseReport", "vulnerabilityReport"]
        evidence = {
            name: {"ref": f"ambit.test/{name}@1", "digest": sha(60 + index), "subjectDigest": manifest}
            for index, name in enumerate(evidence_names)
        }
        runtime_policy = json.loads((SOURCE_ROOT / "policy/runtime-policy.json").read_text())
        pack_definitions = {
            item["packRevisionRef"]: item for item in pack_set["packs"]
        }
        conformance = []
        for index, ref in enumerate(specialist_refs):
            directory = pack_definitions[ref]["directory"]
            pack = json.loads((SOURCE_ROOT / directory / "pack.lock.json").read_text())
            conformance.append(
                {
                    "packRevisionRef": ref,
                    "receiptRef": f"ambit.test/conformance/{index}@1",
                    "receiptDigest": sha(80 + index),
                    "outcome": "passed",
                    "fullImageManifestDigest": manifest,
                    "fullImage": True,
                    "network": "none",
                    "uid": 1000,
                    "checks": pack["conformance"]["requiredChecks"],
                }
            )
        unsupported = []
        if "ambit.runtime-pack/office-authoring@1" in specialist_refs:
            unsupported = ["native-microsoft-office-fidelity", "windows-office-executor"]
        return {
            "schema": "ambit.c18-full-image-binding-input/v1",
            "facetRef": facet,
            "specialistPacks": specialist,
            "baselinePacks": baseline,
            "fullImage": {
                "ociReference": f"registry.test/ambit/c18@{manifest}",
                "manifestDigest": manifest,
                "configDigest": sha(51),
                "layerDigests": [sha(52), sha(53)],
                "platform": "linux/amd64",
            },
            "imageConfig": {
                "user": "1000:1000",
                "readOnlyRootRequired": True,
                "labels": {
                    "io.ambit.runtime-pack-set-digest": pack_set_digest,
                    "io.ambit.runtime-pack-refs": "\n".join(
                        item["packRevisionRef"] for item in all_packs
                    ),
                    "io.ambit.sbom-digest": evidence["sbom"]["digest"],
                    "io.ambit.provenance-digest": evidence["provenance"]["digest"],
                    "io.ambit.signature-digest": evidence["signature"]["digest"],
                    "io.ambit.license-report-digest": evidence["licenseReport"]["digest"],
                    "io.ambit.vulnerability-report-digest": evidence["vulnerabilityReport"]["digest"],
                },
            },
            "runtimeProbe": {
                "fullImageManifestDigest": manifest,
                "uid": 1000,
                "gid": 1000,
                "user": "daytona",
                "network": "none",
                "linuxCapabilities": [],
                "noNewPrivileges": True,
                "rootFilesystemReadOnly": True,
                "hostSocketsAbsent": runtime_policy["sockets"]["forbidden"],
                "installerCommandsAbsent": runtime_policy["runtimeInstallers"]["forbiddenCommands"],
                "secretEnvironmentNames": [],
                "packRootDigests": {ref: sha(100 + index) for index, ref in enumerate(specialist_refs)},
            },
            "conformance": conformance,
            "supplyChain": evidence,
            "policyOutcomes": {
                "signature": "passed",
                "license": "passed",
                "vulnerability": "passed",
                "provenance": "passed",
                "reproducibility": "passed",
            },
            "unsupportedCapabilities": unsupported,
        }

    def _verify(self, binding: dict[str, object]) -> dict[str, object]:
        self.binding_path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n")
        return verify_binding(SOURCE_ROOT, self.binding_path)

    def test_binds_research_pack_set_to_one_exact_full_image(self) -> None:
        receipt = self._verify(self._binding())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(
            sorted(receipt["conformanceReceiptDigests"]),
            [
                "ambit.runtime-pack/data-research@1",
                "ambit.runtime-pack/web-browser@1",
            ],
        )

    def test_preserves_native_windows_office_as_explicitly_unsupported(self) -> None:
        binding = self._binding("C18_SPREADSHEETS")
        self.assertEqual(self._verify(binding)["outcome"], "passed")
        binding["unsupportedCapabilities"] = []
        with self.assertRaisesRegex(FullImageBindingError, "Windows/Office unsupported"):
            self._verify(binding)

    def test_rejects_mutable_or_mismatched_image_and_pack_set(self) -> None:
        scenarios = []
        mutable = self._binding()
        mutable["fullImage"]["ociReference"] = "registry.test/ambit/c18:latest"
        scenarios.append((mutable, "immutable manifest digest"))
        pack_label = self._binding()
        pack_label["imageConfig"]["labels"]["io.ambit.runtime-pack-set-digest"] = sha(999)
        scenarios.append((pack_label, "pack-set label mismatch"))
        missing_pack = self._binding()
        missing_pack["specialistPacks"] = missing_pack["specialistPacks"][:-1]
        scenarios.append((missing_pack, "facet closure"))
        for value, message in scenarios:
            with self.subTest(message=message):
                with self.assertRaisesRegex(FullImageBindingError, message):
                    self._verify(value)

    def test_rejects_runtime_escape_and_installer_or_socket_omission(self) -> None:
        scenarios = []
        root = self._binding()
        root["runtimeProbe"]["uid"] = 0
        scenarios.append((root, "uid/gid 1000"))
        installer = self._binding()
        installer["runtimeProbe"]["installerCommandsAbsent"] = installer["runtimeProbe"][
            "installerCommandsAbsent"
        ][1:]
        scenarios.append((installer, "installer-absence roster"))
        socket = self._binding()
        socket["runtimeProbe"]["hostSocketsAbsent"] = socket["runtimeProbe"][
            "hostSocketsAbsent"
        ][:-1]
        scenarios.append((socket, "host-socket absence roster"))
        network = self._binding()
        network["runtimeProbe"]["network"] = "egress"
        scenarios.append((network, "network-none"))
        for value, message in scenarios:
            with self.subTest(message=message):
                with self.assertRaisesRegex(FullImageBindingError, message):
                    self._verify(value)

    def test_rejects_pack_only_conformance_and_supply_chain_subject_drift(self) -> None:
        conformance = self._binding()
        conformance["conformance"][0]["fullImage"] = False
        with self.assertRaisesRegex(FullImageBindingError, "exact offline full image"):
            self._verify(conformance)
        supply_chain = self._binding()
        supply_chain["supplyChain"]["sbom"]["subjectDigest"] = sha(999)
        with self.assertRaisesRegex(FullImageBindingError, "subject mismatch"):
            self._verify(supply_chain)

    def test_rejects_duplicate_json_keys(self) -> None:
        self.binding_path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
        with self.assertRaisesRegex(FullImageBindingError, "duplicate JSON key"):
            verify_binding(SOURCE_ROOT, self.binding_path)


if __name__ == "__main__":
    unittest.main()
