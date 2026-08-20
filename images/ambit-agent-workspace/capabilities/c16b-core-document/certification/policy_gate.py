from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def pin(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {"name": path.name, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SPDX_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
VEX_STATUSES = {"fixed", "not_affected"}
VEX_JUSTIFICATIONS = {
    "fixed": {
        "component_source_contains_upstream_fix": "source-contains-upstream-fix",
        "package_recipe_applies_upstream_fix": "package-recipe-applies-upstream-fix",
    },
    "not_affected": {
        "upstream_disputed_non_security": "upstream-disputed-non-security",
        "upstream_disputed_non_security_and_ldd_absent": (
            "upstream-disputed-non-security-and-ldd-absent"
        ),
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_exact_keys(value: dict[str, Any], keys: set[str], description: str) -> None:
    actual = set(value)
    if actual != keys:
        raise ValueError(
            f"{description} keys differ: missing={sorted(keys - actual)!r}, extra={sorted(actual - keys)!r}"
        )


def require_sha256(value: Any, description: str) -> None:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{description} is not sha256")


def require_commit(value: Any, description: str) -> None:
    require(isinstance(value, str) and GIT_COMMIT_RE.fullmatch(value) is not None, f"{description} is not a Git commit")


def require_https(value: Any, description: str) -> None:
    require(isinstance(value, str) and value.startswith("https://"), f"{description} must be an https URL")


def match_identity(match: dict[str, Any]) -> dict[str, Any]:
    artifact = match.get("artifact", {})
    vulnerability = match.get("vulnerability", {})
    details = match.get("matchDetails", [])
    require(isinstance(artifact, dict), "Grype match artifact is invalid")
    require(isinstance(vulnerability, dict), "Grype match vulnerability is invalid")
    require(isinstance(details, list) and len(details) == 1, "VEX-eligible Grype match must have one match detail")
    detail = details[0]
    require(isinstance(detail, dict), "Grype match detail is invalid")
    found = detail.get("found", {})
    require(isinstance(found, dict), "Grype match found detail is invalid")
    return {
        "artifact": {
            "name": artifact.get("name"),
            "version": artifact.get("version"),
            "type": artifact.get("type"),
            "purl": artifact.get("purl"),
        },
        "vulnerability": {
            "id": vulnerability.get("id"),
            "namespace": vulnerability.get("namespace"),
            "severity": vulnerability.get("severity"),
        },
        "matchType": detail.get("type"),
        "matcher": detail.get("matcher"),
        "versionConstraint": found.get("versionConstraint"),
    }


def validate_vex_match(value: Any, index: int) -> dict[str, Any]:
    description = f"VEX entry {index} match"
    require(isinstance(value, dict), f"{description} must be an object")
    require_exact_keys(
        value,
        {"artifact", "vulnerability", "matchType", "matcher", "versionConstraint"},
        description,
    )
    artifact = value["artifact"]
    vulnerability = value["vulnerability"]
    require(isinstance(artifact, dict), f"{description} artifact must be an object")
    require_exact_keys(artifact, {"name", "version", "type", "purl"}, f"{description} artifact")
    require(isinstance(vulnerability, dict), f"{description} vulnerability must be an object")
    require_exact_keys(vulnerability, {"id", "namespace", "severity"}, f"{description} vulnerability")
    for key, item in artifact.items():
        require(isinstance(item, str) and item, f"{description} artifact {key} is empty")
    for key, item in vulnerability.items():
        require(isinstance(item, str) and item, f"{description} vulnerability {key} is empty")
    require(str(artifact["purl"]).startswith("pkg:"), f"{description} artifact purl is invalid")
    require(value["matchType"] == "cpe-match", f"{description} must bind cpe-match")
    require(value["matcher"] == "apk-matcher", f"{description} must bind apk-matcher")
    require(
        isinstance(value["versionConstraint"], str) and value["versionConstraint"],
        f"{description} version constraint is empty",
    )
    return value


def validate_vex_evidence(
    evidence: Any,
    *,
    index: int,
    status: str,
    justification: str,
) -> dict[str, Any]:
    description = f"VEX entry {index} evidence"
    require(isinstance(evidence, dict), f"{description} must be an object")
    expected_kind = VEX_JUSTIFICATIONS.get(status, {}).get(justification)
    require(expected_kind is not None, f"VEX entry {index} status/justification is not admitted")
    require(evidence.get("kind") == expected_kind, f"{description} kind does not match justification")

    if expected_kind == "source-contains-upstream-fix":
        require_exact_keys(
            evidence,
            {
                "kind",
                "packageBuildSpdxSha256",
                "packageBuildConfigCommit",
                "packageBuildConfigSha256",
                "packageSourceCommit",
                "upstreamRepository",
                "fixCommit",
                "verification",
            },
            description,
        )
        require_sha256(evidence["packageBuildSpdxSha256"], f"{description} packageBuildSpdxSha256")
        require_sha256(evidence["packageBuildConfigSha256"], f"{description} packageBuildConfigSha256")
        require_commit(evidence["packageBuildConfigCommit"], f"{description} packageBuildConfigCommit")
        require_commit(evidence["packageSourceCommit"], f"{description} packageSourceCommit")
        require_commit(evidence["fixCommit"], f"{description} fixCommit")
        require_https(evidence["upstreamRepository"], f"{description} upstreamRepository")
        require(
            evidence["verification"] == "git-merge-base-is-ancestor",
            f"{description} verification must be git-merge-base-is-ancestor",
        )
    elif expected_kind == "package-recipe-applies-upstream-fix":
        require_exact_keys(
            evidence,
            {
                "kind",
                "packageBuildSpdxSha256",
                "packageBuildConfigCommit",
                "packageBuildConfigSha256",
                "packageSourceCommit",
                "upstreamRepository",
                "fixCommit",
                "verification",
            },
            description,
        )
        require_sha256(evidence["packageBuildSpdxSha256"], f"{description} packageBuildSpdxSha256")
        require_sha256(evidence["packageBuildConfigSha256"], f"{description} packageBuildConfigSha256")
        require_commit(evidence["packageBuildConfigCommit"], f"{description} packageBuildConfigCommit")
        require_commit(evidence["packageSourceCommit"], f"{description} packageSourceCommit")
        require_commit(evidence["fixCommit"], f"{description} fixCommit")
        require_https(evidence["upstreamRepository"], f"{description} upstreamRepository")
        require(
            evidence["verification"] == "exact-recipe-pinned-cherry-pick",
            f"{description} verification must be exact-recipe-pinned-cherry-pick",
        )
    elif expected_kind == "upstream-disputed-non-security":
        require_exact_keys(
            evidence,
            {
                "kind",
                "authorityUrl",
                "authoritySnapshotSha256",
                "upstreamIssueUrl",
                "upstreamIssueSnapshotSha256",
                "verification",
            },
            description,
        )
        require_https(evidence["authorityUrl"], f"{description} authorityUrl")
        require_https(evidence["upstreamIssueUrl"], f"{description} upstreamIssueUrl")
        require_sha256(evidence["authoritySnapshotSha256"], f"{description} authoritySnapshotSha256")
        require_sha256(
            evidence["upstreamIssueSnapshotSha256"], f"{description} upstreamIssueSnapshotSha256"
        )
        require(
            evidence["verification"] == "authority-and-upstream-snapshots",
            f"{description} verification is invalid",
        )
    elif expected_kind == "upstream-disputed-non-security-and-ldd-absent":
        require_exact_keys(
            evidence,
            {
                "kind",
                "authorityUrl",
                "authoritySnapshotSha256",
                "upstreamIssueUrl",
                "upstreamIssueSnapshotSha256",
                "runtimeAbsentCommand",
                "runtimeConfinement",
                "verification",
            },
            description,
        )
        require_https(evidence["authorityUrl"], f"{description} authorityUrl")
        require_https(evidence["upstreamIssueUrl"], f"{description} upstreamIssueUrl")
        require_sha256(evidence["authoritySnapshotSha256"], f"{description} authoritySnapshotSha256")
        require_sha256(
            evidence["upstreamIssueSnapshotSha256"], f"{description} upstreamIssueSnapshotSha256"
        )
        require(evidence["runtimeAbsentCommand"] == "ldd", f"{description} must bind absent ldd")
        require(
            evidence["runtimeConfinement"] == "non-root-cap-drop-all-no-new-privileges-network-none",
            f"{description} runtime confinement is incomplete",
        )
        require(
            evidence["verification"] == "authority-upstream-snapshots-and-runtime-conformance",
            f"{description} verification is invalid",
        )
    else:  # pragma: no cover - expected_kind is closed above
        raise AssertionError(expected_kind)
    return evidence


parser = argparse.ArgumentParser()
parser.add_argument("--sbom", required=True, type=Path)
parser.add_argument("--vulnerabilities", required=True, type=Path)
parser.add_argument("--license-policy", required=True, type=Path)
parser.add_argument("--license-review", required=True, type=Path)
parser.add_argument("--vulnerability-policy", required=True, type=Path)
parser.add_argument("--vex", required=True, type=Path)
parser.add_argument("--vex-verification", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--allow-failed-output", action="store_true")
args = parser.parse_args()

sbom = load(args.sbom)
vulnerabilities = load(args.vulnerabilities)
license_policy = load(args.license_policy)
license_review = load(args.license_review)
vulnerability_policy = load(args.vulnerability_policy)
vex = load(args.vex)
vex_verification = load(args.vex_verification)

require(
    sbom.get("spdxVersion") == "SPDX-2.3"
    and isinstance(sbom.get("documentNamespace"), str)
    and str(sbom.get("documentNamespace")),
    "SBOM is not a complete SPDX 2.3 document",
)
packages = sbom.get("packages", [])
require(isinstance(packages, list) and bool(packages), "SBOM contains no package inventory")
require(license_policy.get("schema") == "ambit.runtime-pack-license-policy/v1", "license policy schema is invalid")
require(
    vulnerability_policy.get("schema") == "ambit.runtime-pack-vulnerability-policy/v1",
    "vulnerability policy schema is invalid",
)
require(vex.get("schema") == "ambit.runtime-pack-vex-lock/v1", "VEX lock schema is invalid")
require(
    vex_verification.get("schema") == "ambit.runtime-pack-vex-evidence-verification/v1"
    and vex_verification.get("outcome") == "passed",
    "VEX evidence verification receipt is invalid",
)
verified_vex_input = vex_verification.get("inputs", {}).get("vex", {})
actual_vex_input = pin(args.vex)
require(
    isinstance(verified_vex_input, dict)
    and verified_vex_input.get("bytes") == actual_vex_input["bytes"]
    and verified_vex_input.get("sha256") == actual_vex_input["sha256"],
    "VEX evidence verification does not bind the evaluated VEX lock",
)
denied_expressions = set(license_policy.get("deniedSpdxExpressions", []))
require(
    denied_expressions
    and all(isinstance(expression, str) and expression for expression in denied_expressions),
    "license denied expression inventory is invalid",
)
require(
    license_policy.get("unknownLicenseDisposition") == "deny-promotion"
    and license_policy.get("unreviewedLicenseDisposition") == "deny-promotion",
    "license policy must fail closed on unknown and unreviewed expressions",
)
for threshold in ("maximumCritical", "maximumHigh"):
    value = vulnerability_policy.get(threshold)
    require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, f"{threshold} is invalid")
require(
    vulnerability_policy.get("unknownSeverityDisposition") == "deny-promotion"
    and vulnerability_policy.get("unfixedCriticalDisposition") == "deny-promotion",
    "vulnerability policy must fail closed on unknown and unfixed critical findings",
)
if license_review.get("schema") != "ambit.runtime-pack-license-review-lock/v1":
    raise ValueError("license review lock schema is invalid")
reviews = license_review.get("reviews", [])
aggregate_exclusions = license_review.get("aggregateExclusions", [])
if not isinstance(reviews, list) or not isinstance(aggregate_exclusions, list):
    raise ValueError("license review lock entries are invalid")
review_match_counts = [0 for _ in reviews]
exclusion_match_counts = [0 for _ in aggregate_exclusions]
for index, review in enumerate(reviews):
    require(isinstance(review, dict), f"license review {index} must be an object")
    require_exact_keys(
        review,
        {"match", "rawLicense", "disposition", "concludedLicense", "evidence"},
        f"license review {index}",
    )
    match = review["match"]
    evidence = review["evidence"]
    require(isinstance(match, dict), f"license review {index} match must be an object")
    require_exact_keys(match, {"name", "version", "purl"}, f"license review {index} match")
    require(
        all(isinstance(match[key], str) and match[key] for key in ("name", "version", "purl"))
        and str(match["purl"]).startswith("pkg:"),
        f"license review {index} match is invalid",
    )
    require(review["disposition"] == "concluded", f"license review {index} disposition is invalid")
    require(
        isinstance(review["rawLicense"], str)
        and bool(review["rawLicense"])
        and isinstance(review["concludedLicense"], str)
        and bool(review["concludedLicense"]),
        f"license review {index} expressions are invalid",
    )
    require(isinstance(evidence, dict) and bool(evidence), f"license review {index} evidence is empty")
for index, exclusion in enumerate(aggregate_exclusions):
    require(isinstance(exclusion, dict), f"aggregate exclusion {index} must be an object")
    require_exact_keys(
        exclusion,
        {"match", "rawLicense", "disposition", "rationale"},
        f"aggregate exclusion {index}",
    )
    match = exclusion["match"]
    require(isinstance(match, dict), f"aggregate exclusion {index} match must be an object")
    require_exact_keys(match, {"name", "purlPrefix"}, f"aggregate exclusion {index} match")
    require(
        isinstance(match["name"], str)
        and bool(match["name"])
        and isinstance(match["purlPrefix"], str)
        and str(match["purlPrefix"]).startswith("pkg:"),
        f"aggregate exclusion {index} match is invalid",
    )
    require(
        exclusion["disposition"] == "aggregate-artifact-not-a-dependency"
        and isinstance(exclusion["rationale"], str)
        and bool(exclusion["rationale"]),
        f"aggregate exclusion {index} disposition is invalid",
    )
resolved_packages: list[dict[str, str]] = []
aggregate_packages: list[dict[str, str]] = []
unknown_packages: list[dict[str, str]] = []
denied_packages: list[dict[str, str]] = []
unreviewed_packages: list[dict[str, str]] = []
for package in packages:
    require(isinstance(package, dict), "SBOM package entry is invalid")
    declared = package.get("licenseDeclared") or "NOASSERTION"
    purls = {
        str(reference.get("referenceLocator"))
        for reference in package.get("externalRefs", [])
        if reference.get("referenceType") == "purl"
    }
    identity = {
        "name": str(package.get("name", "")),
        "version": str(package.get("versionInfo", "")),
        "licenseDeclared": str(declared),
    }
    matching_reviews = [
        (index, review)
        for index, review in enumerate(reviews)
        if review.get("match", {}).get("name") == identity["name"]
        and review.get("match", {}).get("version") == identity["version"]
        and review.get("match", {}).get("purl") in purls
    ]
    matching_exclusions = [
        (index, exclusion)
        for index, exclusion in enumerate(aggregate_exclusions)
        if exclusion.get("match", {}).get("name") == identity["name"]
        and any(
            purl.startswith(str(exclusion.get("match", {}).get("purlPrefix", "")))
            for purl in purls
        )
    ]
    if len(matching_reviews) > 1 or len(matching_exclusions) > 1 or (matching_reviews and matching_exclusions):
        raise ValueError(f"ambiguous license review for {identity!r}")
    effective = str(declared)
    reviewed = False
    if matching_reviews:
        index, review = matching_reviews[0]
        if declared != review.get("rawLicense") or review.get("disposition") != "concluded":
            raise ValueError(f"license review raw value or disposition mismatch for {identity!r}")
        concluded = review.get("concludedLicense")
        if not isinstance(concluded, str) or not concluded:
            raise ValueError(f"license review conclusion missing for {identity!r}")
        review_match_counts[index] += 1
        effective = concluded
        reviewed = True
        resolved_packages.append({**identity, "effectiveLicense": effective})
    elif matching_exclusions:
        index, exclusion = matching_exclusions[0]
        if declared != exclusion.get("rawLicense") or exclusion.get("disposition") != "aggregate-artifact-not-a-dependency":
            raise ValueError(f"aggregate license exclusion mismatch for {identity!r}")
        exclusion_match_counts[index] += 1
        aggregate_packages.append(identity)
        continue
    elif declared == "NOASSERTION":
        unknown_packages.append(identity)
    if "LicenseRef-" in effective and not reviewed:
        unreviewed_packages.append(identity)
    expression_tokens = set(SPDX_TOKEN_RE.findall(effective))
    matched = sorted(denied_expressions & expression_tokens)
    if matched:
        denied_packages.append(
            {**identity, "effectiveLicense": effective, "matchedDeniedExpressions": ",".join(matched)}
        )

require(
    all(count == 1 for count in review_match_counts),
    f"every license review must match exactly one SBOM package: {review_match_counts!r}",
)
require(
    all(count == 1 for count in exclusion_match_counts),
    f"every aggregate exclusion must match exactly one SBOM package: {exclusion_match_counts!r}",
)

descriptor = vulnerabilities.get("descriptor", {})
database = descriptor.get("db", {}).get("status", {})
source = vulnerabilities.get("source", {})
if (
    descriptor.get("name") != "grype"
    or not isinstance(descriptor.get("version"), str)
    or not descriptor.get("version")
    or database.get("valid") is not True
    or not isinstance(database.get("schemaVersion"), str)
    or not isinstance(database.get("built"), str)
    or "checksum=sha256%3A" not in str(database.get("from", ""))
    or source.get("type") not in {"directory", "image", "sbom"}
    or source.get("target") is None
):
    raise ValueError("Grype report or vulnerability database provenance is incomplete")
matches = vulnerabilities.get("matches", [])
ignored_matches = vulnerabilities.get("ignoredMatches") or []
if not isinstance(matches, list) or not isinstance(ignored_matches, list):
    raise ValueError("Grype match inventory is incomplete")
raw_matches: list[tuple[str, dict[str, Any]]] = [
    *(("matches", match) for match in matches),
    *(("ignoredMatches", match) for match in ignored_matches),
]
for collection, match in raw_matches:
    require(isinstance(match, dict), f"Grype {collection} entry is invalid")
    artifact = match.get("artifact")
    vulnerability = match.get("vulnerability")
    require(isinstance(artifact, dict), f"Grype {collection} artifact is invalid")
    require(isinstance(vulnerability, dict), f"Grype {collection} vulnerability is invalid")
    require(
        all(isinstance(artifact.get(field), str) and artifact.get(field) for field in ("name", "version", "type", "purl")),
        f"Grype {collection} artifact identity is incomplete",
    )
    require(
        all(isinstance(vulnerability.get(field), str) and vulnerability.get(field) for field in ("id", "namespace", "severity")),
        f"Grype {collection} vulnerability identity is incomplete",
    )

raw_severity_counts = Counter(
    str(match["vulnerability"]["severity"]) for _, match in raw_matches
)
raw_fingerprints = [
    hashlib.sha256(
        json.dumps(match, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    for _, match in raw_matches
]
vex_entries = vex.get("entries")
require(isinstance(vex_entries, list), "VEX lock entries must be a list")
expected_verified_entry_sha256 = [
    hashlib.sha256(
        json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    for entry in vex_entries
]
require(
    vex_verification.get("verifiedEntryCount") == len(vex_entries)
    and vex_verification.get("verifiedEntrySha256") == expected_verified_entry_sha256,
    "VEX evidence verification does not bind every evaluated entry in order",
)
disposed_indexes: set[int] = set()
seen_vex_matches: set[str] = set()
vex_dispositions: list[dict[str, Any]] = []
for index, entry in enumerate(vex_entries):
    require(isinstance(entry, dict), f"VEX entry {index} must be an object")
    require_exact_keys(entry, {"match", "status", "justification", "evidence"}, f"VEX entry {index}")
    expected_match = validate_vex_match(entry["match"], index)
    match_key = json.dumps(expected_match, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    require(match_key not in seen_vex_matches, f"duplicate VEX entry match at index {index}")
    seen_vex_matches.add(match_key)
    status = entry["status"]
    justification = entry["justification"]
    require(status in VEX_STATUSES, f"VEX entry {index} status is invalid")
    require(isinstance(justification, str) and justification, f"VEX entry {index} justification is invalid")
    evidence = validate_vex_evidence(
        entry["evidence"],
        index=index,
        status=status,
        justification=justification,
    )
    raw_indexes: list[int] = []
    for raw_index, (_, raw_match) in enumerate(raw_matches):
        try:
            identity = match_identity(raw_match)
        except ValueError:
            continue
        if identity == expected_match:
            raw_indexes.append(raw_index)
    require(
        len(raw_indexes) == 1,
        f"VEX entry {index} must match exactly one raw Grype finding, matched {len(raw_indexes)}",
    )
    raw_index = raw_indexes[0]
    require(raw_index not in disposed_indexes, f"VEX entry {index} reuses a disposed raw finding")
    disposed_indexes.add(raw_index)
    collection, _ = raw_matches[raw_index]
    evidence_sha256 = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    vex_dispositions.append(
        {
            "rawMatchIndex": raw_index,
            "rawCollection": collection,
            "match": expected_match,
            "status": status,
            "justification": justification,
            "evidenceSha256": evidence_sha256,
        }
    )

effective_matches = [
    match for index, (_, match) in enumerate(raw_matches) if index not in disposed_indexes
]
effective_severity_counts = Counter(
    str(match.get("vulnerability", {}).get("severity", "Unknown")) for match in effective_matches
)
critical = effective_severity_counts["Critical"]
high = effective_severity_counts["High"]
unknown_severity = effective_severity_counts["Unknown"]
unfixed_critical = [
    match
    for match in effective_matches
    if match.get("vulnerability", {}).get("severity") == "Critical"
    and not match.get("vulnerability", {}).get("fix", {}).get("versions")
]

violations: list[dict[str, Any]] = []
if denied_packages:
    violations.append({"gate": "license.denied_expression", "count": len(denied_packages)})
if unknown_packages and license_policy.get("unknownLicenseDisposition") == "deny-promotion":
    violations.append({"gate": "license.unknown", "count": len(unknown_packages)})
if unreviewed_packages and license_policy.get("unreviewedLicenseDisposition") == "deny-promotion":
    violations.append({"gate": "license.unreviewed_expression", "count": len(unreviewed_packages)})
if critical > int(vulnerability_policy.get("maximumCritical", 0)):
    violations.append({"gate": "vulnerability.critical", "count": critical})
if high > int(vulnerability_policy.get("maximumHigh", 0)):
    violations.append({"gate": "vulnerability.high", "count": high})
if unknown_severity and vulnerability_policy.get("unknownSeverityDisposition") == "deny-promotion":
    violations.append({"gate": "vulnerability.unknown_severity", "count": unknown_severity})
if unfixed_critical and vulnerability_policy.get("unfixedCriticalDisposition") == "deny-promotion":
    violations.append({"gate": "vulnerability.unfixed_critical", "count": len(unfixed_critical)})

receipt = {
    "schema": "ambit.runtime-pack-policy-gate/v2",
    "outcome": "passed" if not violations else "failed",
    "inputs": {
        "sbom": pin(args.sbom),
        "vulnerabilities": pin(args.vulnerabilities),
        "licensePolicy": pin(args.license_policy),
        "licenseReview": pin(args.license_review),
        "vulnerabilityPolicy": pin(args.vulnerability_policy),
        "vex": pin(args.vex),
        "vexVerification": pin(args.vex_verification),
    },
    "license": {
        "rawPackageCount": len(packages),
        "evaluatedDependencyPackageCount": len(packages) - len(aggregate_packages),
        "rawNoAssertionCount": sum(
            1 for package in packages if (package.get("licenseDeclared") or "NOASSERTION") == "NOASSERTION"
        ),
        "effectiveUnknownCount": len(unknown_packages),
        "unknownDeclaredSample": unknown_packages[:50],
        "reviewedResolutionCount": len(resolved_packages),
        "reviewedResolutions": resolved_packages,
        "aggregateExclusionCount": len(aggregate_packages),
        "aggregateExclusions": aggregate_packages,
        "unreviewedExpressionCount": len(unreviewed_packages),
        "unreviewedExpressionSample": unreviewed_packages[:50],
        "deniedPackageCount": len(denied_packages),
        "deniedPackages": denied_packages,
    },
    "vulnerability": {
        "rawMatchCount": len(raw_matches),
        "rawActiveMatchCount": len(matches),
        "rawIgnoredMatchCount": len(ignored_matches),
        "rawUniqueExactMatchCount": len(set(raw_fingerprints)),
        "rawDuplicateExactMatchCount": len(raw_fingerprints) - len(set(raw_fingerprints)),
        "rawSeverityCounts": dict(sorted(raw_severity_counts.items())),
        "vexDispositionCount": len(vex_dispositions),
        "vexStatusCounts": dict(sorted(Counter(item["status"] for item in vex_dispositions).items())),
        "vexDispositions": vex_dispositions,
        "effectiveMatchCount": len(effective_matches),
        "effectiveSeverityCounts": dict(sorted(effective_severity_counts.items())),
        "effectiveUnfixedCriticalCount": len(unfixed_critical),
        "database": database,
        "scannerVersion": descriptor.get("version"),
    },
    "violations": violations,
}
args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
if violations and not args.allow_failed_output:
    raise SystemExit(2)
