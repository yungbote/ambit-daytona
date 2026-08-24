from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
CAPABILITY = re.compile(r"^ambit\.runtime/[a-z0-9][a-z0-9._-]*@[1-9][0-9]*$")


class SourceContractError(ValueError):
    """The reusable core source is wider, weaker, or ambiguous."""


def _load(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SourceContractError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as error:
        raise SourceContractError(f"cannot parse {path}: {error}") from error


def _require(condition: object, message: str) -> None:
    if not condition:
        raise SourceContractError(message)


def _exact(value: object, keys: set[str], name: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{name} must be an object")
    result = dict(value)
    _require(set(result) == keys, f"{name} has missing or extra fields")
    return result


def _sorted_capabilities(value: object, name: str, *, nonempty: bool) -> list[str]:
    _require(isinstance(value, list), f"{name} must be a list")
    result = list(value)
    _require(
        all(isinstance(item, str) and CAPABILITY.fullmatch(item) for item in result),
        f"{name} contains an invalid capability",
    )
    _require(result == sorted(set(result)), f"{name} must be sorted and unique")
    _require(result or not nonempty, f"{name} cannot be empty")
    return result


def verify(root: Path) -> dict[str, object]:
    root = root.resolve(strict=True)
    baseline = _load(root / "core-baseline.lock.json")
    baseline = _exact(
        baseline,
        {
            "artifact",
            "capabilityProjection",
            "composition",
            "historicalInput",
            "promotion",
            "rollback",
            "schema",
            "state",
        },
        "core baseline",
    )
    _require(baseline["schema"] == "ambit.runtime-core-baseline/v2", "schema drift")
    _require(
        baseline["state"] == "source-ready-contract-pending-unbuilt",
        "source must remain unbuilt with backend composition pending",
    )

    artifact = _exact(
        baseline["artifact"],
        {
            "activation",
            "baseEnvironmentRef",
            "packRevisionRef",
            "platform",
            "runtimeUser",
        },
        "artifact",
    )
    _require(
        artifact
        == {
            "activation": "candidate-only",
            "baseEnvironmentRef": "ambit.runtime-base/debian-core@1",
            "packRevisionRef": "ambit.runtime-pack/core@1",
            "platform": "linux/amd64",
            "runtimeUser": "1000:1000",
        },
        "artifact identity or activation changed",
    )

    capabilities = _exact(
        baseline["capabilityProjection"],
        {"provides", "providerObservedNotPackProvided", "requires", "unavailable"},
        "capability projection",
    )
    provides = _sorted_capabilities(capabilities["provides"], "provides", nonempty=True)
    observed = _sorted_capabilities(
        capabilities["providerObservedNotPackProvided"],
        "providerObservedNotPackProvided",
        nonempty=True,
    )
    requires = _sorted_capabilities(capabilities["requires"], "requires", nonempty=False)
    unavailable = _sorted_capabilities(
        capabilities["unavailable"], "unavailable", nonempty=True
    )
    _require(
        provides
        == [
            "ambit.runtime/command.execute@1",
            "ambit.runtime/filesystem.read-write@1",
        ],
        "core pack widened beyond exact command/filesystem capability",
    )
    _require(observed == ["ambit.runtime/pty@1"], "provider-only PTY boundary changed")
    _require(requires == [], "core pack acquired an ambient runtime dependency")
    _require(not set(provides) & set(unavailable), "available and unavailable overlap")
    for forbidden in (
        "ambit.runtime/document.edit@1",
        "ambit.runtime/document.inspect@1",
        "ambit.runtime/document.render@1",
        "ambit.runtime/document.validate@1",
        "ambit.runtime/python.locked-environment@1",
    ):
        _require(forbidden in unavailable, f"{forbidden} is no longer explicitly unavailable")

    historical = _exact(
        baseline["historicalInput"],
        {
            "classification",
            "configDigest",
            "daytonaRevision",
            "evidenceManifestSha256",
            "indexDigest",
            "packRevisionRef",
            "platformManifestDigest",
            "reason",
            "reusableAsCoreBaseline",
        },
        "historical input",
    )
    _require(historical["reusableAsCoreBaseline"] is False, "@4 was relabeled reusable")
    _require(
        historical["packRevisionRef"] == "ambit.runtime-pack/core-document@4",
        "historical pack identity changed",
    )
    for field in ("configDigest", "evidenceManifestSha256", "indexDigest", "platformManifestDigest"):
        _require(
            isinstance(historical[field], str) and SHA256.fullmatch(historical[field]),
            f"historical {field} is invalid",
        )

    composition = _exact(
        baseline["composition"],
        {
            "backendContract",
            "backendContractSourceBlobSha",
            "backendPlanKind",
            "backendPlanVersion",
            "descendantRequirement",
            "distinctDocumentArtifactRequired",
            "packArtifactRefRule",
            "tarOrFilesystemCopyCountsAsArtifactReuse",
        },
        "composition",
    )
    _require(
        composition["backendContract"] is None
        and composition["backendContractSourceBlobSha"] is None
        and composition["backendPlanKind"] is None
        and composition["backendPlanVersion"] is None
        and composition["packArtifactRefRule"] is None,
        "unfrozen backend composition authority was guessed",
    )
    _require(
        composition["distinctDocumentArtifactRequired"] is True
        and composition["tarOrFilesystemCopyCountsAsArtifactReuse"] is False,
        "composition weakened into copied-file equivalence",
    )

    promotion = _exact(
        baseline["promotion"],
        {
            "backendPackRegistration",
            "backendProfileRegistration",
            "certifiedCoreProfile",
            "disposition",
            "requiredBeforePromotion",
        },
        "promotion",
    )
    _require(
        promotion["disposition"] == "candidate"
        and promotion["backendPackRegistration"] == "not-performed"
        and promotion["backendProfileRegistration"] == "not-performed"
        and promotion["certifiedCoreProfile"] == "not-issued",
        "source falsely claims promotion or certification",
    )
    _require(
        isinstance(promotion["requiredBeforePromotion"], list)
        and len(promotion["requiredBeforePromotion"]) == 7,
        "promotion gate roster is incomplete",
    )

    rollback = _exact(
        baseline["rollback"],
        {
            "historicalArtifactsRemainImmutable",
            "predecessorActivation",
            "procedure",
            "requiresSeparateDemotionReceipt",
        },
        "rollback",
    )
    _require(
        rollback["historicalArtifactsRemainImmutable"] is True
        and rollback["predecessorActivation"] is None
        and rollback["requiresSeparateDemotionReceipt"] is True,
        "rollback no longer preserves immutable history or separate authority",
    )

    materializer = _load(root / "locks/materializer-input.lock.json")
    _require(
        materializer.get("schema") == "ambit.runtime-component-input-lock/v1",
        "materializer lock schema changed",
    )
    _require(
        materializer.get("binary", {}).get("sha256")
        == "sha256:8d4405a1bd8f5d9d65be0860e52cab75cc9b7f5f659e510b4932347e0c6008e5",
        "materializer binary changed",
    )

    overlay = _exact(
        _load(root / "composition/union-overlay-contract.lock.json"),
        {"backendAuthority", "coreParent", "finalRuntime", "schema", "union"},
        "union overlay contract",
    )
    _require(
        overlay["schema"] == "ambit.runtime-core-union-overlay-contract/v1",
        "union overlay contract schema changed",
    )
    overlay_backend = _exact(
        overlay["backendAuthority"],
        {"contractDiscriminator", "sourceBlobSha", "status"},
        "union overlay backend authority",
    )
    _require(
        overlay_backend
        == {
            "contractDiscriminator": None,
            "sourceBlobSha": None,
            "status": "pending-equality-deleting-successor-contract",
        },
        "union overlay guessed an unfrozen backend authority",
    )
    overlay_core = _exact(
        overlay["coreParent"],
        {
            "configDigest",
            "orderedLayers",
            "platform",
            "platformManifestDigest",
            "sourceIdentitySha256",
            "status",
        },
        "union overlay core parent",
    )
    _require(
        overlay_core["platform"] == "linux/amd64"
        and overlay_core["platformManifestDigest"] is None
        and overlay_core["configDigest"] is None
        and overlay_core["sourceIdentitySha256"] is None
        and overlay_core["orderedLayers"] == []
        and overlay_core["status"] == "pending-qualified-core-replacement",
        "union overlay invented a replacement core identity before qualification",
    )
    overlay_union = overlay["union"]
    _require(
        isinstance(overlay_union, dict)
        and overlay_union.get("compositionMethod")
        == "literal-core-oci-parent-plus-one-closed-union-overlay"
        and overlay_union.get("installPasses") == 1
        and overlay_union.get("prunePasses") == 1
        and overlay_union.get("lastWriterWins") is False
        and overlay_union.get("opaqueSequentialPackLayers") is False
        and isinstance(overlay_union.get("requiredReceipts"), list)
        and len(overlay_union["requiredReceipts"]) == 11,
        "union overlay no longer proves one closed conflict-free install",
    )

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    required_fragments = (
        "debian@sha256:38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16",
        "RUN --network=none",
        "COPY --from=source_identity /daytona-source.tar",
        "FROM scratch AS core_base",
        "COPY --from=core_rootfs / /",
        "USER 1000:1000",
        'io.ambit.runtime-base="ambit.runtime-base/debian-core@1"',
        'io.ambit.runtime-pack="ambit.runtime-pack/core@1"',
        'io.ambit.source-identity-meaning="bound-claim-external-git-admission-required"',
        "/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize",
        "/etc/apt /etc/dpkg",
    )
    for fragment in required_fragments:
        _require(fragment in dockerfile, f"Dockerfile is missing {fragment!r}")
    for forbidden in ("apt-get install", "pip install", "npm install", "curl ", "wget "):
        _require(forbidden not in dockerfile, f"Dockerfile contains forbidden {forbidden!r}")

    conformance = (root / "conformance/verify.sh").read_text(encoding="utf-8")
    for fragment in (
        'environment-name-roster-is-not-exact',
        'supplementary-group-roster-is-not-exact',
        'CapAmb:',
        'CapBnd:',
        'CapEff:',
        'CapInh:',
        'CapPrm:',
        'NoNewPrivs:',
        '/sys/class/net',
        '/proc/self/mountinfo',
        'mountpoint-roster-is-not-exact',
        'unix-socket-census-is-not-empty',
        'runtime-installer-executable-payload-is-present',
    ):
        _require(fragment in conformance, f"conformance is missing {fragment!r}")

    runtime_runner = (root / "certification/run_runtime_conformance.py").read_text(
        encoding="utf-8"
    )
    for fragment in (
        'sameUidAlternateSocket',
        'alternate-host-socket-with-environment',
        'GOOGLE_APPLICATION_CREDENTIALS',
        'AWS_ACCESS_KEY_ID',
        'DATABASE_URL',
        'GITHUB_PAT',
        'OPENAI_KEY',
        'supplementary-group',
        'added-capability',
        'network-host',
        'writable-root',
    ):
        _require(fragment in runtime_runner, f"runtime matrix is missing {fragment!r}")

    candidate_builder = (root / "certification/build_candidate.py").read_text(
        encoding="utf-8"
    )
    for fragment in (
        '--no-cache',
        'for ordinal in (1, 2)',
        'build-{ordinal}.stdout',
        'byteIdenticalCompleteOciArchives',
        'layerPathManifestSha256',
        'OCI layer retains installer executable payload',
        'OCI layers do not contain exactly one materializer',
    ):
        _require(fragment in candidate_builder, f"candidate builder is missing {fragment!r}")

    package_lock = (root / "locks/base-installed-dpkg.lock").read_text(
        encoding="utf-8"
    ).splitlines()
    _require(package_lock == sorted(set(package_lock)), "base package lock is not canonical")
    _require(len(package_lock) == 78, "base package closure changed")

    return {
        "schema": "ambit.runtime-core-baseline-source-verification/v1",
        "outcome": "passed",
        "packRevisionRef": artifact["packRevisionRef"],
        "baseEnvironmentRef": artifact["baseEnvironmentRef"],
        "provides": provides,
        "historicalCoreDocumentReusable": False,
        "promotionPerformed": False,
        "backendCompositionContractFrozen": False,
        "descendantUnionOverlayContractFrozen": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.root), indent=2, sort_keys=True))
    except SourceContractError as error:
        print(f"core-baseline-source: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
