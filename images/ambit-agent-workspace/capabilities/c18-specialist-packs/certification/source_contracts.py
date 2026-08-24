from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from wheel_lock import requirements_from_lock


PACKS = {
    "office-authoring": {
        "ref": "ambit.runtime-pack/office-authoring@1",
        "provides": ["presentations_design", "python", "spreadsheets"],
        "requires": ["core", "documents_publishing"],
        "directPython": ["openpyxl", "python-pptx", "xlsxwriter"],
    },
    "pdf-ocr": {
        "ref": "ambit.runtime-pack/pdf-ocr@1",
        "provides": ["pdf_scan_ocr", "python"],
        "requires": ["core", "documents_publishing"],
        "directPython": ["pikepdf", "pillow", "pypdf", "reportlab"],
    },
    "data-research": {
        "ref": "ambit.runtime-pack/data-research@1",
        "provides": ["data_local_query", "python", "research_scientific"],
        "requires": ["core"],
        "directPython": [
            "duckdb",
            "ipykernel",
            "jupyterlab",
            "matplotlib",
            "networkx",
            "numpy",
            "pandas",
            "polars",
            "pyarrow",
            "scipy",
            "sympy",
        ],
    },
    "web-browser": {
        "ref": "ambit.runtime-pack/web-browser@1",
        "provides": ["application_services", "browser_frontend_qa", "javascript_web"],
        "requires": ["core"],
        "directPython": [],
    },
}
EXECUTOR_FACETS = {
    "office-authoring": ["presentation", "spreadsheet"],
    "pdf-ocr": ["pdf"],
    "data-research": ["data_analysis", "research"],
    "web-browser": ["web_application"],
}
FACETS = {
    "C18_DATA_ANALYSIS": ["ambit.runtime-pack/data-research@1"],
    "C18_PDF": ["ambit.runtime-pack/pdf-ocr@1"],
    "C18_PRESENTATIONS": ["ambit.runtime-pack/office-authoring@1"],
    "C18_RESEARCH": [
        "ambit.runtime-pack/data-research@1",
        "ambit.runtime-pack/web-browser@1",
    ],
    "C18_SPREADSHEETS": [
        "ambit.runtime-pack/data-research@1",
        "ambit.runtime-pack/office-authoring@1",
    ],
    "C18_WEB_APPLICATION": ["ambit.runtime-pack/web-browser@1"],
}
PYTHON_BASE = (
    "docker.io/library/python@sha256:"
    "d6e0850f13fda0e2305d4c3c1c2f7930fe1042d34ddd958e49bba6ef685d0bb2"
)
WEB_BASE = (
    "mcr.microsoft.com/playwright@sha256:"
    "c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac"
)
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_LINE_PATTERN = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<path>[^\n]+)$")


class SourceContractError(ValueError):
    """The C18 specialist pack source is not a closed reproducible boundary."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise SourceContractError(message)


def _load_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SourceContractError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise SourceContractError(f"invalid JSON in {path}: {error}") from error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _source_files(root: Path) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == "source-contracts.sha256":
            continue
        _require(not path.is_symlink(), f"source symlink is forbidden: {relative}")
        if path.is_file():
            _require(
                "__pycache__" not in path.parts and path.suffix != ".pyc",
                "generated Python cache entered source",
            )
            result.append((relative, path))
    return result


def render_source_manifest(root: Path) -> bytes:
    root = root.resolve(strict=True)
    return "".join(
        f"{_sha256(path)}  {relative}\n"
        for relative, path in _source_files(root)
    ).encode("utf-8")


def refresh_source_manifest(root: Path) -> None:
    root = root.resolve(strict=True)
    manifest = root / "source-contracts.sha256"
    payload = render_source_manifest(root)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".source-contracts.", dir=root
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, manifest)
        directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _sorted_unique(value: object, name: str) -> list[str]:
    _require(isinstance(value, list) and all(isinstance(item, str) for item in value), f"{name} is invalid")
    result = list(value)
    _require(result == sorted(set(result)), f"{name} must be sorted and unique")
    return result


def _verify_source_manifest(root: Path) -> None:
    manifest = root / "source-contracts.sha256"
    lines = manifest.read_text(encoding="utf-8").splitlines()
    entries: dict[str, str] = {}
    for line in lines:
        match = SOURCE_LINE_PATTERN.fullmatch(line)
        _require(match is not None, "source contract digest line is invalid")
        relative = match.group("path")
        _require(relative not in entries, "source contract digest path is duplicated")
        _require(
            not relative.startswith("/") and ".." not in Path(relative).parts,
            "source contract digest path is unsafe",
        )
        entries[relative] = match.group("digest")
    _require(list(entries) == sorted(entries), "source contract digest roster is not sorted")
    actual = [relative for relative, _path in _source_files(root)]
    _require(actual == list(entries), "source contract digest roster is not closed")
    for relative, expected in entries.items():
        _require(_sha256(root / relative) == expected, f"source digest mismatch: {relative}")


def _manifest_entries(path: Path) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = SOURCE_LINE_PATTERN.fullmatch(line)
        _require(match is not None, f"invalid sha256 manifest line in {path}")
        result.append((match.group("path"), match.group("digest")))
    _require(result and [item[0] for item in result] == sorted({item[0] for item in result}), f"manifest is not sorted and unique: {path}")
    return result


def _verify_python_pack(root: Path, pack_id: str, expected: dict[str, object]) -> None:
    lock_root = root / pack_id / "locks"
    wheels = _load_json(lock_root / "python-wheels.lock.json")
    _require(wheels.get("schema") == "ambit.c18-python-wheel-lock/v1", f"{pack_id} wheel schema is invalid")
    _require(wheels.get("packRef") == expected["ref"], f"{pack_id} wheel pack ref mismatch")
    _require(wheels.get("pythonVersion") == "3.14.7", f"{pack_id} Python version mismatch")
    _require(wheels.get("runtimeInstaller") == "absent", f"{pack_id} runtime installer policy mismatch")
    _require(wheels.get("installScripts") == "forbidden", f"{pack_id} install-script policy mismatch")
    _require(wheels.get("directRequirements") == expected["directPython"], f"{pack_id} direct Python closure mismatch")
    wheel_entries = wheels.get("wheels")
    _require(isinstance(wheel_entries, list) and len(wheel_entries) == wheels.get("resolvedDistributionCount"), f"{pack_id} wheel count mismatch")
    expected_manifest = [
        (f"python/{entry['filename']}", str(entry["sha256"]).removeprefix("sha256:"))
        for entry in wheel_entries
    ]
    _require(
        _manifest_entries(lock_root / "python-wheels.sha256") == expected_manifest,
        f"{pack_id} wheel sha manifest does not project the exact lock",
    )
    _require(
        (lock_root / "requirements.lock").read_text(encoding="utf-8")
        == requirements_from_lock(lock_root / "python-wheels.lock.json"),
        f"{pack_id} hash-required requirements do not project the exact wheel lock",
    )


def _verify_debian_pack(root: Path, pack_id: str, expected: dict[str, object]) -> None:
    lock_root = root / pack_id / "locks"
    closure = _load_json(lock_root / "debian-binary-closure.lock.json")
    _require(closure.get("schema") == "ambit.c18-debian-binary-closure-lock/v1", f"{pack_id} Debian schema is invalid")
    _require(closure.get("packRef") == expected["ref"], f"{pack_id} Debian pack ref mismatch")
    _require(closure.get("baseImage") == PYTHON_BASE, f"{pack_id} Debian base mismatch")
    resolution = closure.get("resolution")
    _require(isinstance(resolution, dict) and resolution.get("mode") == "offline-dpkg-replay", f"{pack_id} Debian resolution is not offline")
    _require(resolution.get("runtimePackageManager") == "absent", f"{pack_id} runtime dpkg boundary is invalid")
    archives = closure.get("archives")
    _require(isinstance(archives, list) and archives and len(archives) == closure.get("archiveCount"), f"{pack_id} Debian archive count mismatch")
    expected_manifest = [
        (f"debian/{entry['localFilename']}", str(entry["sha256"]).removeprefix("sha256:"))
        for entry in archives
    ]
    _require(
        _manifest_entries(lock_root / "debian-archives.sha256") == expected_manifest,
        f"{pack_id} Debian sha manifest does not project the exact lock",
    )
    installed = closure.get("installedClosure")
    _require(isinstance(installed, dict), f"{pack_id} installed closure is invalid")
    installed_path = lock_root / "installed-dpkg.lock"
    installed_lines = installed_path.read_text(encoding="utf-8").splitlines()
    _require(installed_lines == sorted(set(installed_lines)), f"{pack_id} installed closure is not sorted and unique")
    _require(len(installed_lines) == installed.get("entryCount"), f"{pack_id} installed closure count mismatch")
    _require(f"sha256:{_sha256(installed_path)}" == installed.get("sha256"), f"{pack_id} installed closure digest mismatch")


def _verify_web_pack(root: Path) -> None:
    lock_root = root / "web-browser" / "locks"
    toolchain = _load_json(lock_root / "toolchain.lock.json")
    image = toolchain.get("browserSourceImage")
    _require(isinstance(image, dict) and image.get("image") == WEB_BASE, "web browser base image is not exact")
    _require(
        image.get("indexDigest")
        == "sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e"
        and image.get("platformManifestDigest")
        == "sha256:c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac"
        and image.get("configDigest")
        == "sha256:fee853fafa59550d162cef52bca02d907694b44ebf6ef9fb075bcc0c65d8dedb",
        "web browser OCI identity is invalid",
    )
    _require(
        image.get("source")
        == {
            "browsersJsonPath": "packages/playwright-core/browsers.json",
            "browsersJsonSha256": "sha256:f306eed529599b1eaf2f8a85db9de2b23e1a3fe36c2b66434b7c9434fb627a99",
            "commit": "26a9e470a7b3c7822084b09fb7f13902c5f37b51",
            "tag": "v1.62.1",
        },
        "web browser upstream source identity is invalid",
    )
    _require(
        image.get("browsers")
        == {
            "chromium": {"revision": "1234", "version": "151.0.7922.34"},
            "chromiumHeadlessShell": {
                "revision": "1234",
                "version": "151.0.7922.34",
            },
            "firefox": {"revision": "1538", "version": "153.0"},
            "webkit": {"revision": "2336", "version": "26.5"},
        },
        "web browser revision roster is invalid",
    )
    _require(image.get("installedDpkgClosure", {}).get("entryCount") == 514, "web browser dpkg count mismatch")
    _require(
        image.get("installedDpkgClosure", {}).get("sha256")
        == f"sha256:{_sha256(lock_root / 'base-installed-dpkg.lock')}",
        "web browser dpkg closure digest mismatch",
    )
    _require(
        image.get("fontconfigRosterSha256") == f"sha256:{_sha256(lock_root / 'fontconfig-roster.lock')}",
        "web browser font roster digest mismatch",
    )
    _require(
        toolchain.get("node")
        == {"runtimeInstallerDisposition": "npm-npx-corepack-absent", "version": "24.18.1"}
        and toolchain.get("playwright", {}).get("version") == "1.62.1"
        and toolchain.get("axeCore", {}).get("version") == "4.13.0",
        "web JavaScript toolchain version is invalid",
    )
    sandbox = toolchain.get("sandbox")
    _require(
        isinstance(sandbox, dict)
        and sandbox.get("chromiumSandboxRequired") is True,
        "web Chromium sandbox policy is invalid",
    )
    seccomp = sandbox.get("conformanceSeccompProfile")
    _require(
        isinstance(seccomp, dict)
        and seccomp.get("upstreamPath")
        == "../../policy/playwright-seccomp-v1.62.1.json"
        and seccomp.get("sourceCommit")
        == "26a9e470a7b3c7822084b09fb7f13902c5f37b51"
        and seccomp.get("sourceUrl")
        == (
            "https://raw.githubusercontent.com/microsoft/playwright/"
            "26a9e470a7b3c7822084b09fb7f13902c5f37b51/"
            "utils/docker/seccomp_profile.json"
        )
        and seccomp.get("tag") == "v1.62.1"
        and seccomp.get("upstreamSha256")
        == f"sha256:{_sha256(root / 'policy/playwright-seccomp-v1.62.1.json')}",
        "web seccomp profile identity is invalid",
    )
    from render_browser_seccomp import render_profile

    rendered = render_profile(root / "policy/playwright-seccomp-v1.62.1.json")
    _require(
        seccomp.get("renderer") == "../../certification/render_browser_seccomp.py"
        and seccomp.get("renderedSha256")
        == f"sha256:{hashlib.sha256(rendered).hexdigest()}",
        "web rendered seccomp profile identity is invalid",
    )
    npm = _load_json(lock_root / "npm-inputs.lock.json")
    _require(npm.get("schema") == "ambit.c18-npm-input-lock/v2", "web npm schema is invalid")
    _require(npm.get("packRef") == PACKS["web-browser"]["ref"], "web npm pack ref mismatch")
    _require(npm.get("installScripts") == "forbidden" and npm.get("runtimeInstaller") == "absent", "web npm installer policy is invalid")
    archives = npm.get("archives")
    _require(
        isinstance(archives, list)
        and [(item["name"], item["version"]) for item in archives]
        == [("axe-core", "4.13.0"), ("playwright-core", "1.62.1")],
        "web npm archive roster is invalid",
    )
    expected_manifest = [
        (f"npm/{entry['filename']}", str(entry["sha256"]).removeprefix("sha256:"))
        for entry in archives
    ]
    _require(_manifest_entries(lock_root / "npm-archives.sha256") == expected_manifest, "web npm sha manifest mismatch")


def _verify_dockerfile(root: Path, pack_id: str, expected: dict[str, object]) -> None:
    source = (root / pack_id / "Dockerfile").read_text(encoding="utf-8")
    _require(
        source.startswith(
            "# syntax=docker/dockerfile:1.7@sha256:"
            "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
        ),
        f"{pack_id} Docker frontend is mutable",
    )
    base = WEB_BASE if pack_id == "web-browser" else PYTHON_BASE
    _require(f"ARG BASE_IMAGE={base}" in source, f"{pack_id} base image is not exact")
    run_lines = re.findall(r"^RUN .*", source, flags=re.MULTILINE)
    _require(run_lines and all("--network=none" in line for line in run_lines), f"{pack_id} has a networked build step")
    _require("from=pack_inputs" in source, f"{pack_id} has no external exact input context")
    _require("verify-build-identity.sh" in source, f"{pack_id} does not bind the source set")
    _require(f'io.ambit.runtime-pack="{expected["ref"]}"' in source, f"{pack_id} OCI label mismatch")
    _require("USER 1000:1000" in source, f"{pack_id} final runtime is not non-root")
    _require("forbidden-until-full-image-binding" in source, f"{pack_id} activation is not fail-closed")
    _require(
        not re.search(r"\b(?:apt-get\s+(?:install|update)|curl\s|wget\s|npm\s+install|pip\s+install)\b", source),
        f"{pack_id} Dockerfile contains an online/bootstrap installer",
    )
    if pack_id == "office-authoring":
        _require("native-microsoft-office-fidelity=\"unsupported\"" in source, "office Dockerfile claims native Office fidelity")
    if pack_id == "web-browser":
        conformance = (root / pack_id / "conformance/verify.mjs").read_text(encoding="utf-8")
        _require("--no-sandbox" not in conformance, "browser conformance disables the browser sandbox")
        _require(
            "chromiumSandbox: browserName === 'chromium'" in conformance,
            "browser conformance does not enable the Chromium sandbox",
        )


def _verify_executor(root: Path, pack_id: str) -> None:
    lock = _load_json(root / pack_id / "executor.lock.json")
    _require(
        isinstance(lock, dict)
        and set(lock) == {"digest", "facets", "ref", "schema"},
        f"{pack_id} executor lock fields are invalid",
    )
    body = {key: lock[key] for key in ("facets", "ref", "schema")}
    expected_digest = "sha256:" + hashlib.sha256(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    _require(
        lock["schema"] == "ambit.c18-specialist-render-executor-lock/v1"
        and lock["facets"] == EXECUTOR_FACETS[pack_id]
        and lock["ref"] == f"ambit://specialist-render-executors/{pack_id}@1"
        and lock["digest"] == expected_digest,
        f"{pack_id} executor lock identity is invalid",
    )
    _require(
        (root / pack_id / "runtime/adapter.py").is_file(),
        f"{pack_id} runtime adapter is absent",
    )


def verify_source(root: Path, *, verify_hashes: bool = True) -> dict[str, object]:
    root = root.resolve(strict=True)
    if verify_hashes:
        _verify_source_manifest(root)
    pack_set = _load_json(root / "pack-set.lock.json")
    _require(pack_set.get("schema") == "ambit.c18-specialist-pack-set/v1", "pack-set schema is invalid")
    _require(pack_set.get("platform") == "linux/amd64", "pack-set platform is invalid")
    _require(pack_set.get("state") == "candidate", "pack-set source state is invalid")
    _require(pack_set.get("facetSpecialistClosures") == FACETS, "facet-to-pack closure map is invalid")
    pack_entries = pack_set.get("packs")
    _require(isinstance(pack_entries, list) and [item["directory"] for item in pack_entries] == list(PACKS), "pack directory roster is invalid")
    for item in pack_entries:
        expected = PACKS[item["directory"]]
        _require(item["packRevisionRef"] == expected["ref"], "pack-set revision ref mismatch")
        _require(item["provides"] == expected["provides"], "pack-set provides mismatch")
        _require(item["requires"] == expected["requires"], "pack-set requires mismatch")

    runtime_policy = _load_json(root / "policy/runtime-policy.json")
    _require(runtime_policy.get("schema") == "ambit.c18-runtime-policy/v1", "runtime policy schema is invalid")
    _require(
        runtime_policy["identity"]
        == {
            "gid": 1000,
            "group": "daytona",
            "supplementaryGroups": [],
            "uid": 1000,
            "user": "daytona",
        },
        "runtime identity policy is invalid",
    )
    _require(runtime_policy["runtimeInstallers"]["disposition"] == "absent", "runtime installer policy is invalid")
    _require(runtime_policy["process"]["linuxCapabilities"] == [], "runtime capability policy is invalid")
    _require(runtime_policy["process"]["noNewPrivileges"] is True, "runtime no-new-privileges policy is invalid")
    supply_policy = _load_json(root / "policy/supply-chain-policy.json")
    _require(supply_policy.get("schema") == "ambit.c18-supply-chain-policy/v1", "supply-chain policy schema is invalid")
    _require(all(value == 0 for key, value in supply_policy["vulnerabilities"].items() if key.startswith("maximum")), "vulnerability thresholds are not strict")

    for pack_id, expected in PACKS.items():
        pack = _load_json(root / pack_id / "pack.lock.json")
        _require(pack.get("schema") == "ambit.c18-specialist-pack/v1", f"{pack_id} schema is invalid")
        _require(pack.get("packRevisionRef") == expected["ref"], f"{pack_id} revision ref mismatch")
        _require(pack.get("revision") == 1 and pack.get("installMode") == "image_layer", f"{pack_id} revision/install mode is invalid")
        _require(pack.get("state") == "candidate", f"{pack_id} source state is invalid")
        _require(pack.get("capabilities") == {"provides": expected["provides"], "requires": expected["requires"]}, f"{pack_id} capabilities are invalid")
        _require(pack.get("runtime") == {"hostSockets": "absent", "networkDuringConformance": "none", "packageInstallers": "absent", "uid": 1000}, f"{pack_id} runtime boundary is invalid")
        checks = pack.get("conformance", {}).get("requiredChecks")
        _require(
            isinstance(checks, list) and len(checks) >= 6 and len(checks) == len(set(checks)),
            f"{pack_id} conformance checks are incomplete or duplicated",
        )
        _require((root / pack_id / str(pack["conformance"]["script"])).is_file(), f"{pack_id} conformance script is absent")
        toolchain = _load_json(root / pack_id / str(pack["toolchainLock"]))
        expected_toolchain_schema = (
            "ambit.c18-toolchain-lock/v2"
            if pack_id == "web-browser"
            else "ambit.c18-toolchain-lock/v1"
        )
        _require(toolchain.get("schema") == expected_toolchain_schema, f"{pack_id} toolchain schema is invalid")
        _require(toolchain.get("packRef") == expected["ref"], f"{pack_id} toolchain ref mismatch")
        _verify_dockerfile(root, pack_id, expected)
        _verify_executor(root, pack_id)
        if pack_id != "web-browser":
            _verify_python_pack(root, pack_id, expected)
            _verify_debian_pack(root, pack_id, expected)
        else:
            _verify_web_pack(root)

    office = _load_json(root / "office-authoring/locks/toolchain.lock.json")
    _require(
        office.get("nativeOfficeFidelity")
        == {
            "microsoftExcel": "unsupported",
            "microsoftPowerPoint": "unsupported",
            "windowsOfficeExecutor": "separate-licensed-profile-required",
        },
        "native Windows/Office fidelity boundary is invalid",
    )
    readme = (root / "README.md").read_text(encoding="utf-8")
    _require(
        "does **not** claim native Microsoft Excel or PowerPoint fidelity"
        in " ".join(readme.split()),
        "README omits native Office limitation",
    )
    source_digest = f"sha256:{_sha256(root / 'source-contracts.sha256')}" if verify_hashes else None
    return {
        "schema": "ambit.c18-specialist-source-verification/v1",
        "outcome": "passed",
        "packRefs": [PACKS[pack]["ref"] for pack in PACKS],
        "sourceSetDigest": source_digest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--refresh-source-manifest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.refresh_source_manifest:
            if args.output:
                raise SourceContractError(
                    "--output and --refresh-source-manifest are mutually exclusive"
                )
            refresh_source_manifest(args.source_root)
            return 0
        receipt = verify_source(args.source_root)
        rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, SourceContractError, ValueError) as error:
        print(f"source-contracts: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
