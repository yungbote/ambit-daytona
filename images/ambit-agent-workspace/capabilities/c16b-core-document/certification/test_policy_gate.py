from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("policy_gate.py")


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def pin(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {"name": path.name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def write(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def raw_match(*, severity: str = "Critical", version: str = "1.0-r0") -> dict[str, Any]:
    return {
        "artifact": {
            "name": "fixture",
            "version": version,
            "type": "apk",
            "purl": f"pkg:apk/wolfi/fixture@{version}?arch=x86_64&distro=wolfi-20230201",
        },
        "vulnerability": {
            "id": "CVE-2099-0001",
            "namespace": "nvd:cpe",
            "severity": severity,
            "fix": {"versions": [], "state": "unknown"},
        },
        "matchDetails": [
            {
                "type": "cpe-match",
                "matcher": "apk-matcher",
                "searchedBy": {"namespace": "nvd:cpe"},
                "found": {
                    "vulnerabilityID": "CVE-2099-0001",
                    "versionConstraint": "none (unknown)",
                },
            }
        ],
    }


def vex_entry(*, severity: str = "Critical", version: str = "1.0-r0") -> dict[str, Any]:
    return {
        "match": {
            "artifact": {
                "name": "fixture",
                "version": version,
                "type": "apk",
                "purl": f"pkg:apk/wolfi/fixture@{version}?arch=x86_64&distro=wolfi-20230201",
            },
            "vulnerability": {
                "id": "CVE-2099-0001",
                "namespace": "nvd:cpe",
                "severity": severity,
            },
            "matchType": "cpe-match",
            "matcher": "apk-matcher",
            "versionConstraint": "none (unknown)",
        },
        "status": "fixed",
        "justification": "component_source_contains_upstream_fix",
        "evidence": {
            "kind": "source-contains-upstream-fix",
            "packageBuildSpdxSha256": "1" * 64,
            "packageBuildConfigCommit": "2" * 40,
            "packageBuildConfigSha256": "3" * 64,
            "packageSourceCommit": "4" * 40,
            "upstreamRepository": "https://example.invalid/source.git",
            "fixCommit": "5" * 40,
            "verification": "git-merge-base-is-ancestor",
        },
    }


class PolicyGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sbom = self.root / "sbom.json"
        self.vulnerabilities = self.root / "vulnerabilities.json"
        self.license_policy = self.root / "license-policy.json"
        self.license_review = self.root / "license-review.json"
        self.vulnerability_policy = self.root / "vulnerability-policy.json"
        self.vex = self.root / "vex.json"
        self.verification = self.root / "vex-verification.json"
        self.output = self.root / "receipt.json"
        write(
            self.sbom,
            {
                "spdxVersion": "SPDX-2.3",
                "documentNamespace": "https://example.invalid/spdx/fixture",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-fixture",
                        "name": "fixture",
                        "versionInfo": "1.0-r0",
                        "licenseDeclared": "MIT",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": (
                                    "pkg:apk/wolfi/fixture@1.0-r0?arch=x86_64&distro=wolfi-20230201"
                                ),
                            }
                        ],
                    }
                ],
            },
        )
        self.report_matches = [raw_match()]
        self.report_ignored: list[dict[str, Any]] = []
        self.entries = [vex_entry()]
        write(
            self.license_policy,
            {
                "schema": "ambit.runtime-pack-license-policy/v1",
                "deniedSpdxExpressions": ["AGPL-3.0-only"],
                "unknownLicenseDisposition": "deny-promotion",
                "unreviewedLicenseDisposition": "deny-promotion",
            },
        )
        write(
            self.license_review,
            {"schema": "ambit.runtime-pack-license-review-lock/v1", "reviews": [], "aggregateExclusions": []},
        )
        write(
            self.vulnerability_policy,
            {
                "schema": "ambit.runtime-pack-vulnerability-policy/v1",
                "maximumCritical": 0,
                "maximumHigh": 0,
                "unknownSeverityDisposition": "deny-promotion",
                "unfixedCriticalDisposition": "deny-promotion",
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_dynamic_inputs(self, *, verification_outcome: str = "passed") -> None:
        write(
            self.vulnerabilities,
            {
                "matches": self.report_matches,
                "ignoredMatches": self.report_ignored,
                "source": {"type": "sbom", "target": "fixture"},
                "descriptor": {
                    "name": "grype",
                    "version": "1.0.0",
                    "db": {
                        "status": {
                            "valid": True,
                            "schemaVersion": "v1",
                            "built": "2099-01-01T00:00:00Z",
                            "from": "https://example.invalid/db?checksum=sha256%3A" + "a" * 64,
                        }
                    },
                },
            },
        )
        write(self.vex, {"schema": "ambit.runtime-pack-vex-lock/v1", "entries": self.entries})
        write(
            self.verification,
            {
                "schema": "ambit.runtime-pack-vex-evidence-verification/v1",
                "outcome": verification_outcome,
                "inputs": {"vex": pin(self.vex)},
                "verifiedEntryCount": len(self.entries),
                "verifiedEntrySha256": [canonical_sha256(entry) for entry in self.entries],
            },
        )

    def add_structural_aggregate(self, *, include_describes: bool = True) -> None:
        sbom = json.loads(self.sbom.read_text())
        root_id = "SPDXRef-DocumentRoot-Directory-sbom"
        sbom["packages"].append(
            {
                "SPDXID": root_id,
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "name": "sbom",
                "primaryPackagePurpose": "FILE",
                "supplier": "NOASSERTION",
            }
        )
        sbom["relationships"] = [
            {
                "spdxElementId": root_id,
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": "SPDXRef-Package-fixture",
            },
            *(
                [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": root_id,
                    }
                ]
                if include_describes
                else []
            ),
        ]
        write(self.sbom, sbom)
        write(
            self.license_review,
            {
                "schema": "ambit.runtime-pack-license-review-lock/v1",
                "reviews": [],
                "aggregateExclusions": [
                    {
                        "match": {
                            "kind": "spdx-document-root",
                            "name": "sbom",
                            "primaryPackagePurpose": "FILE",
                            "spdxId": root_id,
                        },
                        "rawLicense": "NOASSERTION",
                        "disposition": "aggregate-artifact-not-a-dependency",
                        "rationale": "fixture structural aggregate",
                    }
                ],
            },
        )
    def run_gate(self, *, allow_failed_output: bool = False) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(SCRIPT),
            "--sbom",
            str(self.sbom),
            "--vulnerabilities",
            str(self.vulnerabilities),
            "--license-policy",
            str(self.license_policy),
            "--license-review",
            str(self.license_review),
            "--vulnerability-policy",
            str(self.vulnerability_policy),
            "--vex",
            str(self.vex),
            "--vex-verification",
            str(self.verification),
            "--output",
            str(self.output),
        ]
        if allow_failed_output:
            command.append("--allow-failed-output")
        return subprocess.run(command, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_exact_verified_vex_disposition_passes_and_preserves_raw_counts(self) -> None:
        self.write_dynamic_inputs()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["schema"], "ambit.runtime-pack-policy-gate/v2")
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["vulnerability"]["rawSeverityCounts"], {"Critical": 1})
        self.assertEqual(receipt["vulnerability"]["effectiveMatchCount"], 0)
        self.assertEqual(receipt["vulnerability"]["vexDispositionCount"], 1)

    def test_ignored_scanner_match_is_restored_before_vex(self) -> None:
        self.report_ignored = self.report_matches
        self.report_matches = []
        self.write_dynamic_inputs()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["vulnerability"]["rawIgnoredMatchCount"], 1)
        self.assertEqual(receipt["vulnerability"]["vexDispositions"][0]["rawCollection"], "ignoredMatches")

    def test_duplicate_raw_finding_cannot_be_hidden_by_one_vex_entry(self) -> None:
        self.report_matches.append(raw_match())
        self.write_dynamic_inputs()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match exactly one raw Grype finding, matched 2", result.stderr)

    def test_unmatched_vex_entry_fails_closed(self) -> None:
        self.entries = [vex_entry(version="1.0-r1")]
        self.write_dynamic_inputs()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("matched 0", result.stderr)

    def test_vex_mutation_after_verification_fails_closed(self) -> None:
        self.write_dynamic_inputs()
        self.entries[0]["evidence"]["fixCommit"] = "6" * 40
        write(self.vex, {"schema": "ambit.runtime-pack-vex-lock/v1", "entries": self.entries})
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not bind the evaluated VEX lock", result.stderr)

    def test_failed_evidence_verification_cannot_be_consumed(self) -> None:
        self.write_dynamic_inputs(verification_outcome="failed")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("VEX evidence verification receipt is invalid", result.stderr)

    def test_undisposed_high_finding_fails_policy(self) -> None:
        self.report_matches = [raw_match(severity="High")]
        self.entries = []
        self.write_dynamic_inputs()
        result = self.run_gate(allow_failed_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["outcome"], "failed")
        self.assertEqual(receipt["violations"], [{"count": 1, "gate": "vulnerability.high"}])

    def test_exact_structural_document_root_is_excluded_without_inventing_a_license(self) -> None:
        self.add_structural_aggregate()
        self.write_dynamic_inputs()
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["license"]["rawPackageCount"], 2)
        self.assertEqual(receipt["license"]["evaluatedDependencyPackageCount"], 1)
        self.assertEqual(
            receipt["license"]["aggregateExclusions"],
            [
                {
                    "kind": "spdx-document-root",
                    "licenseDeclared": "NOASSERTION",
                    "name": "sbom",
                    "spdxId": "SPDXRef-DocumentRoot-Directory-sbom",
                    "version": "",
                }
            ],
        )

    def test_document_root_without_exact_describes_relation_is_rejected(self) -> None:
        self.add_structural_aggregate(include_describes=False)
        self.write_dynamic_inputs()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not exactly describe the dependency roster", result.stderr)


if __name__ == "__main__":
    unittest.main()
