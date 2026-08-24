from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


INPUT_SCHEMA = "ambit.c18-full-image-binding-input/v1"
RECEIPT_SCHEMA = "ambit.c18-full-image-binding-receipt/v1"
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PACK_REF_PATTERN = re.compile(r"^ambit\.runtime-pack/[a-z0-9-]+@[1-9][0-9]*$")


class FullImageBindingError(ValueError):
    """A composed full image is not exact enough to certify C18 packs."""


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load_unique_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise FullImageBindingError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise FullImageBindingError(f"invalid JSON in {path}: {error}") from error


def _require(condition: object, message: str) -> None:
    if not condition:
        raise FullImageBindingError(message)


def _sha(value: object, name: str) -> str:
    _require(isinstance(value, str) and SHA256_PATTERN.fullmatch(value), f"{name} is not sha256")
    return str(value)


def _sorted_unique_strings(value: object, name: str, *, nonempty: bool = True) -> list[str]:
    _require(isinstance(value, list) and all(isinstance(item, str) for item in value), f"{name} is invalid")
    result = list(value)
    _require(result == sorted(set(result)), f"{name} must be sorted and unique")
    _require(result or not nonempty, f"{name} cannot be empty")
    return result


def _exact_keys(value: object, expected: set[str], name: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{name} must be an object")
    result = dict(value)
    _require(set(result) == expected, f"{name} has missing or extra keys")
    return result


def _pack_definitions(source_root: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    pack_set = _load_unique_json(source_root / "pack-set.lock.json")
    _require(
        isinstance(pack_set, dict)
        and pack_set.get("schema") == "ambit.c18-specialist-pack-set/v1",
        "pack-set source schema is invalid",
    )
    packs: dict[str, dict[str, Any]] = {}
    for item in pack_set.get("packs", []):
        _require(isinstance(item, dict), "pack-set pack entry is invalid")
        ref = item.get("packRevisionRef")
        _require(isinstance(ref, str) and PACK_REF_PATTERN.fullmatch(ref), "pack-set ref is invalid")
        _require(ref not in packs, "pack-set contains a duplicate ref")
        packs[ref] = item
    _require(len(packs) == 4, "pack-set must contain exactly four specialist packs")
    return pack_set, packs


def _validate_pack_bindings(
    values: object,
    *,
    name: str,
    allowed_specialist_refs: set[str] | None,
) -> list[dict[str, str]]:
    _require(isinstance(values, list), f"{name} must be a list")
    result: list[dict[str, str]] = []
    for index, raw in enumerate(values):
        value = _exact_keys(
            raw,
            {"packRevisionRef", "artifactDigest", "declarationDigest"},
            f"{name}[{index}]",
        )
        ref = value["packRevisionRef"]
        _require(isinstance(ref, str) and PACK_REF_PATTERN.fullmatch(ref), f"{name}[{index}] ref is invalid")
        if allowed_specialist_refs is not None:
            _require(ref in allowed_specialist_refs, f"{name}[{index}] is not a specialist pack")
        result.append(
            {
                "packRevisionRef": ref,
                "artifactDigest": _sha(value["artifactDigest"], f"{name}[{index}].artifactDigest"),
                "declarationDigest": _sha(
                    value["declarationDigest"], f"{name}[{index}].declarationDigest"
                ),
            }
        )
    refs = [value["packRevisionRef"] for value in result]
    _require(refs == sorted(set(refs)), f"{name} refs must be sorted and unique")
    return result


def verify_binding(source_root: Path, binding_path: Path) -> dict[str, object]:
    source_root = source_root.resolve(strict=True)
    binding = _load_unique_json(binding_path)
    binding = _exact_keys(
        binding,
        {
            "schema",
            "facetRef",
            "specialistPacks",
            "baselinePacks",
            "fullImage",
            "imageConfig",
            "runtimeProbe",
            "conformance",
            "supplyChain",
            "policyOutcomes",
            "unsupportedCapabilities",
        },
        "binding",
    )
    _require(binding["schema"] == INPUT_SCHEMA, "binding schema is invalid")
    pack_set, pack_definitions = _pack_definitions(source_root)
    facet = binding["facetRef"]
    expected_facets = pack_set.get("facetSpecialistClosures", {})
    _require(isinstance(facet, str) and facet in expected_facets, "facet ref is invalid")
    expected_specialist_refs = list(expected_facets[facet])
    specialist = _validate_pack_bindings(
        binding["specialistPacks"],
        name="specialistPacks",
        allowed_specialist_refs=set(pack_definitions),
    )
    specialist_refs = [item["packRevisionRef"] for item in specialist]
    _require(
        specialist_refs == expected_specialist_refs,
        "specialist pack set does not equal the facet closure",
    )
    baseline = _validate_pack_bindings(
        binding["baselinePacks"],
        name="baselinePacks",
        allowed_specialist_refs=None,
    )
    _require(baseline, "at least one exact certified baseline pack is required")
    all_packs = sorted([*baseline, *specialist], key=lambda item: item["packRevisionRef"])
    all_refs = [item["packRevisionRef"] for item in all_packs]
    _require(len(all_refs) == len(set(all_refs)), "baseline and specialist pack refs overlap")
    pack_set_digest = digest(all_packs)

    full_image = _exact_keys(
        binding["fullImage"],
        {
            "ociReference",
            "manifestDigest",
            "configDigest",
            "layerDigests",
            "platform",
        },
        "fullImage",
    )
    manifest_digest = _sha(full_image["manifestDigest"], "fullImage.manifestDigest")
    config_digest = _sha(full_image["configDigest"], "fullImage.configDigest")
    reference = full_image["ociReference"]
    _require(
        isinstance(reference, str)
        and reference.endswith("@" + manifest_digest)
        and ":latest" not in reference,
        "full image reference must end in its immutable manifest digest",
    )
    _require(full_image["platform"] == "linux/amd64", "full image platform is invalid")
    layer_digests = _sorted_unique_strings(full_image["layerDigests"], "fullImage.layerDigests")
    for index, layer in enumerate(layer_digests):
        _sha(layer, f"fullImage.layerDigests[{index}]")

    config = _exact_keys(
        binding["imageConfig"],
        {"user", "readOnlyRootRequired", "labels"},
        "imageConfig",
    )
    _require(config["user"] == "1000:1000", "full image user must be 1000:1000")
    _require(config["readOnlyRootRequired"] is True, "full image must require a read-only root")
    labels = _exact_keys(
        config["labels"],
        {
            "io.ambit.runtime-pack-set-digest",
            "io.ambit.runtime-pack-refs",
            "io.ambit.sbom-digest",
            "io.ambit.provenance-digest",
            "io.ambit.signature-digest",
            "io.ambit.license-report-digest",
            "io.ambit.vulnerability-report-digest",
        },
        "imageConfig.labels",
    )
    _require(labels["io.ambit.runtime-pack-set-digest"] == pack_set_digest, "pack-set label mismatch")
    _require(labels["io.ambit.runtime-pack-refs"] == "\n".join(all_refs), "pack-ref label mismatch")

    runtime_policy = _load_unique_json(source_root / "policy/runtime-policy.json")
    forbidden_installers = list(runtime_policy["runtimeInstallers"]["forbiddenCommands"])
    forbidden_sockets = list(runtime_policy["sockets"]["forbidden"])
    probe = _exact_keys(
        binding["runtimeProbe"],
        {
            "fullImageManifestDigest",
            "uid",
            "gid",
            "user",
            "network",
            "linuxCapabilities",
            "noNewPrivileges",
            "rootFilesystemReadOnly",
            "hostSocketsAbsent",
            "installerCommandsAbsent",
            "secretEnvironmentNames",
            "packRootDigests",
        },
        "runtimeProbe",
    )
    _require(probe["fullImageManifestDigest"] == manifest_digest, "runtime probe image mismatch")
    _require(
        (probe["uid"], probe["gid"], probe["user"]) == (1000, 1000, "daytona"),
        "runtime probe did not execute as daytona uid/gid 1000",
    )
    _require(probe["network"] == "none", "runtime conformance must run network-none")
    _require(probe["linuxCapabilities"] == [], "runtime Linux capabilities must be empty")
    _require(probe["noNewPrivileges"] is True, "runtime no-new-privileges is unproved")
    _require(probe["rootFilesystemReadOnly"] is True, "runtime read-only root is unproved")
    _require(
        probe["hostSocketsAbsent"] == forbidden_sockets,
        "runtime host-socket absence roster is incomplete",
    )
    _require(
        probe["installerCommandsAbsent"] == forbidden_installers,
        "runtime installer-absence roster is incomplete",
    )
    _require(probe["secretEnvironmentNames"] == [], "secret-shaped runtime environment reached image")
    pack_roots = _exact_keys(
        probe["packRootDigests"], set(specialist_refs), "runtimeProbe.packRootDigests"
    )
    for ref, value in pack_roots.items():
        _sha(value, f"runtimeProbe.packRootDigests[{ref}]")

    conformance = binding["conformance"]
    _require(isinstance(conformance, list), "conformance must be a list")
    _require(len(conformance) == len(specialist_refs), "one conformance receipt per specialist pack is required")
    conformance_by_ref: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(conformance):
        value = _exact_keys(
            raw,
            {
                "packRevisionRef",
                "receiptRef",
                "receiptDigest",
                "outcome",
                "fullImageManifestDigest",
                "fullImage",
                "network",
                "uid",
                "checks",
            },
            f"conformance[{index}]",
        )
        ref = value["packRevisionRef"]
        _require(ref in specialist_refs and ref not in conformance_by_ref, "conformance pack ref is invalid")
        _require(isinstance(value["receiptRef"], str) and value["receiptRef"], "conformance receipt ref is invalid")
        _sha(value["receiptDigest"], "conformance receipt digest")
        _require(
            value["outcome"] == "passed"
            and value["fullImage"] is True
            and value["fullImageManifestDigest"] == manifest_digest
            and value["network"] == "none"
            and value["uid"] == 1000,
            "conformance did not pass against the exact offline full image",
        )
        directory = pack_definitions[ref]["directory"]
        pack = _load_unique_json(source_root / directory / "pack.lock.json")
        expected_checks = pack["conformance"]["requiredChecks"]
        _require(value["checks"] == expected_checks, "conformance check roster is incomplete")
        conformance_by_ref[ref] = value
    _require(sorted(conformance_by_ref) == specialist_refs, "conformance ref roster mismatch")

    supply_chain = _exact_keys(
        binding["supplyChain"],
        {"sbom", "provenance", "signature", "licenseReport", "vulnerabilityReport"},
        "supplyChain",
    )
    evidence_digests: dict[str, str] = {}
    for name, raw in supply_chain.items():
        value = _exact_keys(raw, {"ref", "digest", "subjectDigest"}, f"supplyChain.{name}")
        _require(isinstance(value["ref"], str) and value["ref"], f"supplyChain.{name}.ref is invalid")
        evidence_digests[name] = _sha(value["digest"], f"supplyChain.{name}.digest")
        _require(value["subjectDigest"] == manifest_digest, f"supplyChain.{name} subject mismatch")
    label_evidence = {
        "sbom": "io.ambit.sbom-digest",
        "provenance": "io.ambit.provenance-digest",
        "signature": "io.ambit.signature-digest",
        "licenseReport": "io.ambit.license-report-digest",
        "vulnerabilityReport": "io.ambit.vulnerability-report-digest",
    }
    for name, label in label_evidence.items():
        _require(labels[label] == evidence_digests[name], f"{name} label mismatch")

    outcomes = _exact_keys(
        binding["policyOutcomes"],
        {"signature", "license", "vulnerability", "provenance", "reproducibility"},
        "policyOutcomes",
    )
    _require(all(value == "passed" for value in outcomes.values()), "a supply-chain policy did not pass")
    unsupported = _sorted_unique_strings(
        binding["unsupportedCapabilities"], "unsupportedCapabilities", nonempty=False
    )
    if "ambit.runtime-pack/office-authoring@1" in specialist_refs:
        _require(
            {"native-microsoft-office-fidelity", "windows-office-executor"}.issubset(unsupported),
            "office binding must preserve the native Windows/Office unsupported boundary",
        )

    body = {
        "facetRef": facet,
        "specialistPacks": specialist,
        "baselinePacks": baseline,
        "packSetDigest": pack_set_digest,
        "fullImage": {
            "ociReference": reference,
            "manifestDigest": manifest_digest,
            "configDigest": config_digest,
            "layerDigests": layer_digests,
            "platform": "linux/amd64",
        },
        "conformanceReceiptDigests": {
            ref: conformance_by_ref[ref]["receiptDigest"] for ref in specialist_refs
        },
        "supplyChainEvidenceDigests": evidence_digests,
        "runtimeProbeDigest": digest(probe),
        "unsupportedCapabilities": unsupported,
        "sourcePackSetDigest": file_digest(source_root / "pack-set.lock.json"),
        "runtimePolicyDigest": file_digest(source_root / "policy/runtime-policy.json"),
        "supplyChainPolicyDigest": file_digest(source_root / "policy/supply-chain-policy.json"),
        "outcome": "passed",
    }
    return {
        "schema": RECEIPT_SCHEMA,
        **body,
        "bindingDigest": digest(body),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        receipt = verify_binding(args.source_root, args.binding)
        rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, FullImageBindingError) as error:
        print(f"full-image-binding: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
