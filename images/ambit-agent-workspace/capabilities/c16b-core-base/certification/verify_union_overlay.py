from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
PACK = re.compile(r"^ambit\.runtime-pack/[a-z0-9][a-z0-9._-]*@[1-9][0-9]*$")
CAPABILITY = re.compile(r"^ambit\.runtime/[a-z0-9][a-z0-9._-]*@[1-9][0-9]*$")


class UnionOverlayError(ValueError):
    """A descendant is not an exact conflict-free union over the core parent."""


def _load(path: Path) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise UnionOverlayError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, json.JSONDecodeError) as error:
        raise UnionOverlayError(f"cannot parse {path}: {error}") from error


def _require(condition: object, message: str) -> None:
    if not condition:
        raise UnionOverlayError(message)


def _exact(value: object, keys: set[str], name: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{name} must be an object")
    result = dict(value)
    _require(set(result) == keys, f"{name} has missing or extra fields")
    return result


def _digest(value: object, name: str) -> str:
    _require(isinstance(value, str) and SHA256.fullmatch(value), f"{name} is invalid")
    return str(value)


def _pin(value: object, name: str) -> dict[str, str]:
    pin = _exact(value, {"digest", "ref"}, name)
    _require(isinstance(pin["ref"], str) and pin["ref"], f"{name} ref is invalid")
    return {"ref": pin["ref"], "digest": _digest(pin["digest"], f"{name} digest")}


def _layers(value: object, name: str, *, nonempty: bool = True) -> list[dict[str, object]]:
    _require(isinstance(value, list), f"{name} must be a list")
    result: list[dict[str, object]] = []
    for index, raw in enumerate(value):
        layer = _exact(raw, {"digest", "size"}, f"{name}[{index}]")
        size = layer["size"]
        _require(isinstance(size, int) and not isinstance(size, bool) and size > 0, f"{name}[{index}] size is invalid")
        result.append({"digest": _digest(layer["digest"], f"{name}[{index}] digest"), "size": size})
    _require(result or not nonempty, f"{name} cannot be empty")
    _require(len({item["digest"] for item in result}) == len(result), f"{name} has duplicate layers")
    return result


def verify(contract_root: Path, receipt_path: Path) -> dict[str, object]:
    contract = _load(contract_root / "composition/union-overlay-contract.lock.json")
    _require(contract.get("schema") == "ambit.runtime-core-union-overlay-contract/v1", "union contract schema is invalid")
    core = contract["coreParent"]
    _require(
        core.get("status") == "qualified",
        "qualified core parent identity is pending",
    )
    expected_core_layers = _layers(core["orderedLayers"], "contract core layers")

    receipt = _exact(
        _load(receipt_path),
        {
            "builder",
            "coreParent",
            "finalImage",
            "outcome",
            "schema",
            "selectedBundles",
            "unionResolution",
        },
        "union receipt",
    )
    _require(receipt["schema"] == "ambit.runtime-core-union-overlay-receipt/v1", "receipt schema is invalid")
    _require(receipt["outcome"] == "passed", "union receipt did not pass")

    observed_core = _exact(
        receipt["coreParent"],
        {"configDigest", "orderedLayers", "platformManifestDigest", "sourceIdentitySha256"},
        "core parent",
    )
    _require(
        observed_core["platformManifestDigest"] == core["platformManifestDigest"]
        and observed_core["configDigest"] == core["configDigest"]
        and observed_core["sourceIdentitySha256"] == core["sourceIdentitySha256"]
        and _layers(observed_core["orderedLayers"], "observed core layers") == expected_core_layers,
        "receipt substituted the exact core parent",
    )

    bundles_value = receipt["selectedBundles"]
    _require(isinstance(bundles_value, list) and bundles_value, "selected bundle roster is empty")
    bundles: list[dict[str, object]] = []
    for index, raw in enumerate(bundles_value):
        bundle = _exact(raw, {"artifact", "capabilityRefs", "installer", "packRevisionRef"}, f"bundle[{index}]")
        ref = bundle["packRevisionRef"]
        _require(isinstance(ref, str) and PACK.fullmatch(ref), f"bundle[{index}] ref is invalid")
        capabilities = bundle["capabilityRefs"]
        _require(
            isinstance(capabilities, list)
            and capabilities
            and all(isinstance(item, str) and CAPABILITY.fullmatch(item) for item in capabilities),
            f"bundle[{index}] capability roster is invalid",
        )
        _require(
            capabilities == sorted(set(capabilities)),
            f"bundle[{index}] capability roster is not canonical",
        )
        bundles.append(
            {
                "packRevisionRef": ref,
                "artifact": _pin(bundle["artifact"], f"bundle[{index}] artifact"),
                "installer": _pin(bundle["installer"], f"bundle[{index}] installer"),
                "capabilityRefs": capabilities,
            }
        )
    refs = [bundle["packRevisionRef"] for bundle in bundles]
    _require(refs == sorted(set(refs)), "selected bundles are not canonical and unique")

    builder = _exact(
        receipt["builder"],
        {"baseInput", "network", "offline", "packageManagersAvailableOnlyHere"},
        "builder",
    )
    base_input = _pin(builder["baseInput"], "builder base input")
    _require(
        base_input == contract["union"]["builderBaseInput"]
        and builder["network"] == "none"
        and builder["offline"] is True
        and builder["packageManagersAvailableOnlyHere"] is True,
        "installer escaped the isolated offline builder boundary",
    )

    union = _exact(
        receipt["unionResolution"],
        {
            "bundleOrder",
            "closedOverlayOutcome",
            "closedOverlayEntryManifest",
            "dependencyResolutionOutcome",
            "dependencyGraph",
            "globalPostState",
            "globalPreState",
            "installPasses",
            "lastWriterWins",
            "ownershipManifest",
            "ownershipOutcome",
            "pathConflictOutcome",
            "pathConflictReport",
            "protectedCorePathReceipt",
            "protectedCorePaths",
            "prunePasses",
            "resultingLayers",
        },
        "union resolution",
    )
    _require(union["bundleOrder"] == refs, "union bundle order differs from canonical selection")
    for field in (
        "closedOverlayEntryManifest",
        "dependencyGraph",
        "globalPostState",
        "globalPreState",
        "ownershipManifest",
        "pathConflictReport",
        "protectedCorePathReceipt",
    ):
        _pin(union[field], f"union {field}")
    _require(
        union["installPasses"] == 1
        and union["prunePasses"] == 1
        and union["lastWriterWins"] is False,
        "union was sequential, multiply pruned, or last-writer-wins",
    )
    _require(
        union["closedOverlayOutcome"] == "passed"
        and union["dependencyResolutionOutcome"] == "passed"
        and union["ownershipOutcome"] == "passed"
        and union["pathConflictOutcome"] == "passed"
        and union["protectedCorePaths"] == "passed",
        "union dependency, ownership, conflict, overlay, or protected-core proof failed",
    )
    resulting_layers = _layers(union["resultingLayers"], "union resulting layers")

    final_image = _exact(
        receipt["finalImage"],
        {
            "configDigest",
            "coreConformanceReceipt",
            "installerCommandsAbsent",
            "orderedLayers",
            "packConformanceReceipts",
            "platformManifestDigest",
            "runtimeProbe",
        },
        "final image",
    )
    _digest(final_image["configDigest"], "final config digest")
    _digest(final_image["platformManifestDigest"], "final platform manifest digest")
    final_layers = _layers(final_image["orderedLayers"], "final image layers")
    _require(
        final_layers[: len(expected_core_layers)] == expected_core_layers,
        "final image does not inherit the exact core layer prefix",
    )
    _require(
        final_layers[len(expected_core_layers) :] == resulting_layers,
        "final image suffix differs from the one closed union overlay",
    )
    _pin(final_image["coreConformanceReceipt"], "core conformance receipt")
    installers = final_image["installerCommandsAbsent"]
    _require(
        installers == contract["finalRuntime"]["forbiddenInstallerCommands"],
        "final runtime installer absence roster is incomplete",
    )
    conformance_value = final_image["packConformanceReceipts"]
    _require(
        isinstance(conformance_value, list) and len(conformance_value) == len(bundles),
        "pack conformance does not exactly cover selected bundles",
    )
    conformance: list[dict[str, Any]] = []
    for index, item in enumerate(conformance_value):
        entry = _exact(item, {"packRevisionRef", "receipt"}, f"pack conformance[{index}]")
        _pin(entry["receipt"], f"pack conformance[{index}] receipt")
        conformance.append(entry)
    _require(
        [item["packRevisionRef"] for item in conformance] == refs,
        "pack conformance does not exactly cover selected bundles",
    )
    probe = _exact(
        final_image["runtimeProbe"],
        {
            "hostSocketsAbsent",
            "linuxCapabilities",
            "network",
            "noNewPrivileges",
            "readOnlyRoot",
            "runtimeUser",
            "secretEnvironmentNames",
        },
        "runtime probe",
    )
    _require(
        probe
        == {
            "hostSocketsAbsent": True,
            "linuxCapabilities": [],
            "network": "none",
            "noNewPrivileges": True,
            "readOnlyRoot": True,
            "runtimeUser": "1000:1000",
            "secretEnvironmentNames": [],
        },
        "final runtime boundary is invalid",
    )

    return {
        "schema": "ambit.runtime-core-union-overlay-verification/v1",
        "outcome": "passed",
        "corePlatformManifestDigest": core["platformManifestDigest"],
        "selectedBundleRefs": refs,
        "coreLayerPrefixCount": len(expected_core_layers),
        "overlayLayerCount": len(resulting_layers),
        "lastWriterWins": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract-root", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.contract_root.resolve(strict=True), args.receipt), indent=2, sort_keys=True))
    except UnionOverlayError as error:
        print(f"union-overlay: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
