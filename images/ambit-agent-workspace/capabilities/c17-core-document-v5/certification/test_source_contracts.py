from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from certification.verify_source_contracts import verify


ROOT = Path(__file__).resolve().parents[1]


class SourceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "pack"
        shutil.copytree(ROOT, self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def refresh_manifest_digest(self, relative: str) -> None:
        manifest = self.root / "certification/source-contracts.sha256"
        digest = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
        lines = manifest.read_text(encoding="utf-8").splitlines()
        rewritten = []
        matched = False
        for line in lines:
            _, path = line.split("  ", 1)
            if path == relative:
                line = f"{digest}  {relative}"
                matched = True
            rewritten.append(line)
        if not matched:
            raise AssertionError(f"source manifest does not bind {relative}")
        manifest.write_text("\n".join(rewritten) + "\n", encoding="utf-8")

    def mutate(self, relative: str, update, *, refresh_manifest: bool = True) -> None:
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        update(value)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if refresh_manifest:
            interface = json.loads(
                (
                    self.root / "locks/document-render-interface.lock.json"
                ).read_text(encoding="utf-8")
            )
            if relative in interface["contract"]["identities"]["protocolSources"]:
                self.refresh_protocol_source(relative)
            elif relative == "policy/render-policy.json":
                self.refresh_manifest_digest(relative)
                interface["contract"]["policy"]["digest"] = (
                    f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
                )
                interface_path = (
                    self.root / "locks/document-render-interface.lock.json"
                )
                interface_path.write_text(
                    json.dumps(interface, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                self.refresh_interface_digest()
            else:
                self.refresh_manifest_digest(relative)

    def refresh_interface_digest(self) -> str:
        relative = "locks/document-render-interface.lock.json"
        path = self.root / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        contract_bytes = json.dumps(
            value["contract"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = f"sha256:{hashlib.sha256(contract_bytes).hexdigest()}"
        value["digest"] = digest
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        readme = self.root / "README.md"
        text = readme.read_text(encoding="utf-8")
        text, count = re.subn(
            r"(?<=- digest:\n  `)sha256:[0-9a-f]{64}(?=`;)",
            digest,
            text,
            count=1,
        )
        if count != 1:
            raise AssertionError("README interface digest anchor is not exact")
        readme.write_text(text, encoding="utf-8")
        self.refresh_manifest_digest(relative)
        self.refresh_manifest_digest("README.md")
        return digest

    def refresh_protocol_source(self, relative: str) -> None:
        interface = self.root / "locks/document-render-interface.lock.json"
        value = json.loads(interface.read_text(encoding="utf-8"))
        value["contract"]["identities"]["protocolSources"][relative] = (
            f"sha256:{hashlib.sha256((self.root / relative).read_bytes()).hexdigest()}"
        )
        interface.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.refresh_manifest_digest(relative)
        self.refresh_interface_digest()

    def assert_rejected(self, relative: str, update) -> None:
        self.mutate(relative, update)
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_exact_candidate_contract_passes_source_verification(self) -> None:
        result = verify(self.root)
        self.assertEqual(result["outcome"], "passed")
        self.assertEqual(
            set(result["availability"].values()),
            {"available", "candidate-ready", "pinned", "unavailable"},
        )
        self.assertEqual(result["availability"]["pdfjsRoster"], "pinned")

    def test_ready_gate_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "core-document@5 is unavailable"):
            verify(self.root, require_ready=True)

    def test_base_platform_substitution_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/base-oci.lock.json",
            lambda value: value["platform"].__setitem__("architecture", "arm64"),
        )

    def test_canonical_base_digest_substitution_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/base-oci.lock.json",
            lambda value: value["platform"].__setitem__(
                "manifestDigest", f"sha256:{'0' * 64}"
            ),
        )

    def test_mutable_base_reference_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/base-oci.lock.json",
            lambda value: value["index"].__setitem__(
                "reference", "docker.io/library/debian:trixie-slim"
            ),
        )

    def test_debian_package_expansion_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/debian-input.lock.json",
            lambda value: value["requestedPackages"].append("libreoffice-nogui=4:25.2.3-2+deb13u6"),
        )

    def test_unsigned_debian_metadata_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/debian-input.lock.json",
            lambda value: value["signaturePolicy"].__setitem__("verifyInRelease", False),
        )

    def test_toolchain_and_debian_font_rosters_cannot_drift(self) -> None:
        self.assert_rejected(
            "toolchain-manifest.json",
            lambda value: value["fonts"]["packages"].remove(
                "fonts-noto-mono=20201225-2"
            ),
        )

    def test_pdfjs_standard_font_expansion_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/pdfjs-input.lock.json",
            lambda value: value["excludedRoots"].remove("standard_fonts"),
        )

    def test_pdfjs_static_roster_omission_or_substitution_is_rejected(self) -> None:
        path = self.root / "locks/pdfjs-static-files.sha256"
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
        self.refresh_manifest_digest("locks/pdfjs-static-files.sha256")
        with self.assertRaisesRegex(ValueError, "roster paths differ"):
            verify(self.root)

        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        path = self.root / "locks/pdfjs-static-files.sha256"
        lines = path.read_text(encoding="utf-8").splitlines()
        candidate = next(
            index for index, line in enumerate(lines) if "cmaps/78-EUC-H.bcmap" in line
        )
        lines[candidate] = lines[candidate].replace(
            "cmaps/78-EUC-H.bcmap", "standard_fonts/BadFont.pfb"
        )
        lines.sort(key=lambda line: line.split("  ", 1)[1])
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.refresh_manifest_digest("locks/pdfjs-static-files.sha256")
        with self.assertRaisesRegex(ValueError, "excluded resources"):
            verify(self.root)

    def test_pdfjs_execution_state_substitution_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/pdfjs-input.lock.json",
            lambda value: value["execution"].__setitem__("state", "available"),
        )

    def test_node_and_canvas_binary_substitutions_are_rejected(self) -> None:
        self.assert_rejected(
            "locks/node-input.lock.json",
            lambda value: value["binary"].__setitem__(
                "nodeSha256", f"sha256:{'0' * 64}"
            ),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "locks/canvas-input.lock.json",
            lambda value: value["platformArchive"].__setitem__(
                "nativeSha256", f"sha256:{'0' * 64}"
            ),
        )

    def test_candidate_release_lineage_and_font_evidence_cannot_drift(self) -> None:
        self.assert_rejected(
            "locks/node-release-keyring-verification.json",
            lambda value: value["releaseKeysRepository"].__setitem__(
                "fingerprint", "0" * 40
            ),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "locks/installed-render-engine-lineage.json",
            lambda value: value["canvasNative"].__setitem__(
                "digest", f"sha256:{'0' * 64}"
            ),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "locks/font-license-inventory.json",
            lambda value: value["packages"][0].__setitem__("fontFiles", 5),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "locks/document-render-interface.lock.json",
            lambda value: value.__setitem__("digest", f"sha256:{'0' * 64}"),
        )

    def test_provider_launch_cannot_run_helper_after_stty_failure(self) -> None:
        self.mutate(
            "locks/document-render-interface.lock.json",
            lambda value: value["contract"]["transport"].__setitem__(
                "providerLaunch",
                "stty raw -echo -onlcr; exec exact-helper --framed-jsonl --nonce exact-nonce",
            ),
            refresh_manifest=False,
        )
        self.refresh_interface_digest()
        with self.assertRaisesRegex(ValueError, "fail-closed render provider launch differs"):
            verify(self.root)

    def test_refreshed_identity_cannot_authorize_plaintext_helper_stderr(self) -> None:
        relative = "renderer/ambit-render-document.mjs"
        path = self.root / relative
        path.write_text(
            path.read_text(encoding="utf-8")
            + "\nprocess.stderr.write('forbidden plaintext')\n",
            encoding="utf-8",
        )
        self.refresh_protocol_source(relative)
        with self.assertRaisesRegex(ValueError, "plaintext stderr is forbidden"):
            verify(self.root)

    def test_refreshed_identity_cannot_weaken_raw_canonical_byte_admission(self) -> None:
        relative = "renderer/framed-jsonl-protocol.mjs"
        path = self.root / relative
        source = path.read_text(encoding="utf-8")
        path.write_text(
            source.replace(
                "!canonicalBytes.equals(lineBytes)",
                "false",
                1,
            ),
            encoding="utf-8",
        )
        self.refresh_protocol_source(relative)
        with self.assertRaisesRegex(ValueError, "raw canonical UTF-8 frame admission is absent"):
            verify(self.root)

    def test_documented_interface_identity_cannot_drift_from_lock(self) -> None:
        readme = self.root / "README.md"
        text = readme.read_text(encoding="utf-8")
        current = json.loads(
            (self.root / "locks/document-render-interface.lock.json").read_text(
                encoding="utf-8"
            )
        )["digest"]
        readme.write_text(
            text.replace(
                current,
                f"sha256:{'0' * 64}",
                1,
            ),
            encoding="utf-8",
        )
        self.refresh_manifest_digest("README.md")
        with self.assertRaisesRegex(
            ValueError, "documented render interface identity differs"
        ):
            verify(self.root)

    def test_structural_archive_and_materializer_authority_cannot_self_promote(self) -> None:
        self.assert_rejected(
            "locks/structural-compatibility-input.lock.json",
            lambda value: value["structuralRuntimeArchive"].__setitem__(
                "sha256", f"sha256:{'0' * 64}"
            ),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "locks/structural-compatibility-input.lock.json",
            lambda value: value["atomicMaterializer"].__setitem__(
                "publisherAuthentication", "self-attested"
            ),
        )

    def test_frozen_evidence_manifest_cannot_substitute_the_archive(self) -> None:
        path = self.root / "locks/offline-frozen-evidence.sha256"
        lines = path.read_text(encoding="utf-8").splitlines()
        lines[0] = f"{'0' * 64}  structural/core-document-v4-structural-runtime.tar"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.refresh_manifest_digest("locks/offline-frozen-evidence.sha256")
        with self.assertRaisesRegex(ValueError, "offline frozen SHA roster"):
            verify(self.root)

    def test_structural_conformance_must_preserve_explicit_open_gaps(self) -> None:
        conformance = self.root / "locks/structural-runtime-conformance.json"
        value = json.loads(conformance.read_text(encoding="utf-8"))
        value["notProved"].remove("final-image-composition")
        conformance.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.refresh_manifest_digest("locks/structural-runtime-conformance.json")

        compatibility = self.root / "locks/structural-compatibility-input.lock.json"
        lock = json.loads(compatibility.read_text(encoding="utf-8"))
        lock["debianCompatibilityConformance"]["sha256"] = (
            f"sha256:{hashlib.sha256(conformance.read_bytes()).hexdigest()}"
        )
        compatibility.write_text(
            json.dumps(lock, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.refresh_manifest_digest("locks/structural-compatibility-input.lock.json")
        with self.assertRaisesRegex(ValueError, "open gaps"):
            verify(self.root)

    def test_refreshed_manifest_cannot_authorize_unknown_nested_field(self) -> None:
        self.assert_rejected(
            "locks/pdfjs-input.lock.json",
            lambda value: value["archive"].__setitem__("ambient", "allowed"),
        )

    def test_helper_cannot_self_mint_expected_archive_digest(self) -> None:
        self.assert_rejected(
            "locks/capture-helper-input.lock.json",
            lambda value: value.__setitem__("expectedRawSha256", "0" * 64),
        )

    def test_helper_signature_downgrade_is_rejected(self) -> None:
        self.assert_rejected(
            "locks/capture-helper-input.lock.json",
            lambda value: value["requiredExternalAuthority"].__setitem__(
                "downgrade", "digest-only"
            ),
        )

    def test_runtime_network_or_root_expansion_is_rejected(self) -> None:
        for field, replacement in (("network", "default"), ("rootEscalation", "allowed")):
            with self.subTest(field=field):
                self.assert_rejected(
                    "policy/runtime-policy.json",
                    lambda value, field=field, replacement=replacement: value.__setitem__(
                        field, replacement
                    ),
                )
                shutil.rmtree(self.root)
                shutil.copytree(ROOT, self.root)

    def test_poppler_fallback_and_canonical_render_authority_are_rejected(self) -> None:
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value["pdfjs"].__setitem__("popplerFallback", "allowed"),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value.__setitem__("renderOutputGrantsCanonicalAuthority", True),
        )

    def test_aggregate_page_bounds_cannot_be_removed_or_expanded(self) -> None:
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value["pages"].__setitem__(
                "maximumTotalPixels", 536870913
            ),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value["pages"].pop("maximumTotalOutputBytes"),
        )

    def test_docx_package_bounds_cannot_be_removed_or_expanded(self) -> None:
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value["input"].__setitem__(
                "maximumUncompressedBytes", 268435457
            ),
        )
        shutil.rmtree(self.root)
        shutil.copytree(ROOT, self.root)
        self.assert_rejected(
            "policy/render-policy.json",
            lambda value: value["input"].pop("maximumRelationshipBytes"),
        )

    def test_raw_source_manifest_tamper_is_rejected(self) -> None:
        manifest = self.root / "certification/source-contracts.sha256"
        text = manifest.read_text(encoding="utf-8")
        manifest.write_text(text.replace(text[0], "0", 1), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source contract digest differs"):
            verify(self.root)

    def test_source_manifest_symlink_is_rejected_before_read(self) -> None:
        manifest = self.root / "certification/source-contracts.sha256"
        target = self.root / "certification/source-contracts-copy.sha256"
        target.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "manifest must be a regular file"):
            verify(self.root)

    def test_duplicate_json_keys_are_rejected_before_interpretation(self) -> None:
        path = self.root / "policy/license-policy.json"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("{\n", '{\n  "state": "ready",\n', 1), encoding="utf-8")
        self.refresh_manifest_digest("policy/license-policy.json")
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
