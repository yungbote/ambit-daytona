from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


SCHEMA = "ambit.runtime-pack-vex-evidence-verification/v1"
VEX_SCHEMA = "ambit.runtime-pack-vex-lock/v1"


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def pin(path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {"name": path.name, "bytes": len(payload), "sha256": sha256_bytes(payload)}


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return sha256_bytes(payload)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git(repo: Path, *arguments: str) -> str:
    command = ["git", "--no-replace-objects", "-C", str(repo), *arguments]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
    )
    if result.returncode != 0:
        raise ValueError(
            f"Git evidence command failed ({' '.join(arguments)}): {result.stderr.strip()}"
        )
    return result.stdout.rstrip("\n")


def verify_git_commit(repo: Path, commit: str) -> dict[str, Any]:
    git(repo, "cat-file", "-e", f"{commit}^{{commit}}")
    actual = git(repo, "rev-parse", f"{commit}^{{commit}}")
    require(actual == commit, f"Git evidence commit did not resolve exactly: {commit}")
    subject = git(repo, "show", "-s", "--format=%s", commit)
    message = git(repo, "show", "-s", "--format=%B", commit)
    tree = git(repo, "show", "-s", "--format=%T", commit)
    return {
        "commit": commit,
        "tree": tree,
        "subject": subject,
        "messageSha256": sha256_bytes(message.encode()),
        "cveIds": sorted(set(re.findall(r"CVE-[0-9]{4}-[0-9]+", message))),
    }


def package_index(spdx: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    require(spdx.get("spdxVersion") == "SPDX-2.3", "package build evidence is not SPDX 2.3")
    packages = spdx.get("packages")
    require(isinstance(packages, list) and packages, "package build SPDX has no package inventory")
    result: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in packages:
        require(isinstance(package, dict), "package build SPDX package is invalid")
        key = (str(package.get("name", "")), str(package.get("versionInfo", "")))
        result.setdefault(key, []).append(package)
    return result


def exactly_one_package(
    packages: dict[tuple[str, str], list[dict[str, Any]]],
    name: str,
    version: str,
    description: str,
) -> dict[str, Any]:
    found = packages.get((name, version), [])
    require(len(found) == 1, f"{description} must occur exactly once in package build SPDX")
    return found[0]


def exactly_one_build_artifact_package(
    packages: dict[tuple[str, str], list[dict[str, Any]]],
    name: str,
    version: str,
    description: str,
) -> dict[str, Any]:
    expected_purl = f"pkg:apk/wolfi/{name}@{version}?arch=x86_64&distro=wolfi"
    found = [
        package
        for package in packages.get((name, version), [])
        if any(
            reference.get("referenceType") == "purl"
            and reference.get("referenceLocator") == expected_purl
            for reference in package.get("externalRefs", []) or []
            if isinstance(reference, dict)
        )
    ]
    require(len(found) == 1, f"{description} authoritative build package must occur exactly once")
    return found[0]


parser = argparse.ArgumentParser()
parser.add_argument("--vex", required=True, type=Path)
parser.add_argument("--conformance-receipt", required=True, type=Path)
parser.add_argument("--glibc-package-spdx", required=True, type=Path)
parser.add_argument("--libcrypto-package-spdx", required=True, type=Path)
parser.add_argument("--libssl-package-spdx", required=True, type=Path)
parser.add_argument("--glibc-build-config", required=True, type=Path)
parser.add_argument("--openssl-build-config", required=True, type=Path)
parser.add_argument("--cve-2019-1010022-authority", required=True, type=Path)
parser.add_argument("--cve-2019-1010023-authority", required=True, type=Path)
parser.add_argument("--cve-2019-1010022-upstream", required=True, type=Path)
parser.add_argument("--cve-2019-1010023-upstream", required=True, type=Path)
parser.add_argument("--glibc-git-dir", required=True, type=Path)
parser.add_argument("--openssl-git-dir", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()

vex = load(args.vex)
require(vex.get("schema") == VEX_SCHEMA, "VEX lock schema is invalid")
entries = vex.get("entries")
require(isinstance(entries, list) and entries, "VEX lock contains no entries")

conformance = load(args.conformance_receipt)
runtime = conformance.get("runtime", {})
require(conformance.get("schema") == "ambit.runtime-pack-conformance/v3", "conformance schema is invalid")
require(conformance.get("outcome") == "passed", "conformance did not pass")
require(isinstance(runtime, dict), "conformance runtime evidence is invalid")
require(runtime.get("privilege") == "non_root", "conformance did not prove non-root runtime")
require(runtime.get("linuxCapabilities") == "none", "conformance did not prove empty Linux capabilities")
require(runtime.get("noNewPrivileges") is True, "conformance did not prove no-new-privileges")
require(runtime.get("network") == "none", "conformance did not prove network-none")
require(runtime.get("hostSocket") == "absent", "conformance did not prove host-socket absence")
absent_commands = runtime.get("absentCommands")
require(isinstance(absent_commands, list) and "ldd" in absent_commands, "conformance did not prove ldd absent")

spdx_paths = {
    "glibc-2.43": args.glibc_package_spdx,
    "libcrypto3": args.libcrypto_package_spdx,
    "libssl3": args.libssl_package_spdx,
}
build_config_paths = {
    "glibc-2.43": args.glibc_build_config,
    "libcrypto3": args.openssl_build_config,
    "libssl3": args.openssl_build_config,
}
authority_paths = {
    "CVE-2019-1010022": args.cve_2019_1010022_authority,
    "CVE-2019-1010023": args.cve_2019_1010023_authority,
}
upstream_issue_paths = {
    "CVE-2019-1010022": args.cve_2019_1010022_upstream,
    "CVE-2019-1010023": args.cve_2019_1010023_upstream,
}
loaded_spdx = {name: load(path) for name, path in spdx_paths.items()}
indexed_spdx = {name: package_index(value) for name, value in loaded_spdx.items()}
build_config_text = {name: path.read_text() for name, path in build_config_paths.items()}

repository_expectations = {
    args.glibc_git_dir: "https://gitlab.com/gnutools/glibc.git",
    args.openssl_git_dir: "https://github.com/openssl/openssl.git",
}
repository_receipts: dict[str, Any] = {}
for name, (repo, expected_remote) in zip(
    ("glibc", "openssl"), repository_expectations.items(), strict=True
):
    require(repo.is_dir(), f"{name} Git evidence directory does not exist")
    actual_remote = git(repo, "remote", "get-url", "origin")
    require(actual_remote.rstrip("/") == expected_remote.rstrip("/"), f"{name} Git remote is not authoritative")
    repository_receipts[name] = {"remote": actual_remote}

verified_entries: list[dict[str, Any]] = []
verified_entry_sha256: list[str] = []
for index, entry in enumerate(entries):
    require(isinstance(entry, dict), f"VEX entry {index} is invalid")
    match = entry.get("match", {})
    artifact = match.get("artifact", {})
    vulnerability = match.get("vulnerability", {})
    evidence = entry.get("evidence", {})
    require(isinstance(artifact, dict), f"VEX entry {index} artifact is invalid")
    require(isinstance(vulnerability, dict), f"VEX entry {index} vulnerability is invalid")
    require(isinstance(evidence, dict), f"VEX entry {index} evidence is invalid")
    artifact_name = str(artifact.get("name", ""))
    artifact_version = str(artifact.get("version", ""))
    vulnerability_id = str(vulnerability.get("id", ""))
    require(artifact_name in spdx_paths, f"VEX entry {index} has no exact package build SPDX input")
    require(artifact_name in build_config_paths, f"VEX entry {index} has no exact build config input")
    require(
        sha256(spdx_paths[artifact_name]) == evidence.get("packageBuildSpdxSha256")
        or evidence.get("kind")
        in {"upstream-disputed-non-security", "upstream-disputed-non-security-and-ldd-absent"},
        f"VEX entry {index} package build SPDX hash mismatch",
    )

    proof: dict[str, Any]
    kind = evidence.get("kind")
    if kind in {"source-contains-upstream-fix", "package-recipe-applies-upstream-fix"}:
        build_config_path = build_config_paths[artifact_name]
        require(
            sha256(build_config_path) == evidence.get("packageBuildConfigSha256"),
            f"VEX entry {index} build config hash mismatch",
        )
        packages = indexed_spdx[artifact_name]
        exactly_one_build_artifact_package(
            packages,
            artifact_name,
            artifact_version,
            f"VEX entry {index} artifact",
        )
        if artifact_name == "glibc-2.43":
            exactly_one_package(
                packages,
                "glibc-2.43.yaml",
                str(evidence.get("packageBuildConfigCommit")),
                f"VEX entry {index} build config",
            )
            exactly_one_package(
                packages,
                "gnutools/glibc",
                str(evidence.get("packageSourceCommit")),
                f"VEX entry {index} source",
            )
            config = build_config_text[artifact_name]
            require('version: "2.43"' in config and "epoch: 14" in config, "glibc build config version is wrong")
            require(
                f"glibc-expected-commit: {evidence.get('packageSourceCommit')}" in config,
                f"VEX entry {index} glibc source commit is absent from build config",
            )
            source_commit = str(evidence.get("packageSourceCommit"))
            fix_commit = str(evidence.get("fixCommit"))
            source_receipt = verify_git_commit(args.glibc_git_dir, source_commit)
            fix_receipt = verify_git_commit(args.glibc_git_dir, fix_commit)
            git(args.glibc_git_dir, "merge-base", "--is-ancestor", fix_commit, source_commit)
            require(vulnerability_id in fix_receipt["cveIds"], f"VEX entry {index} fix message does not bind CVE")
            proof = {
                "kind": kind,
                "source": source_receipt,
                "fix": fix_receipt,
                "ancestry": "fix-is-ancestor-of-package-source",
            }
        else:
            exactly_one_package(
                packages,
                "openssl.yaml",
                str(evidence.get("packageBuildConfigCommit")),
                f"VEX entry {index} build config",
            )
            source_package = exactly_one_package(
                packages,
                "openssl",
                "openssl-3.6.3",
                f"VEX entry {index} source",
            )
            source_commit = str(evidence.get("packageSourceCommit"))
            require(
                source_commit in str(source_package.get("downloadLocation", "")),
                f"VEX entry {index} package SPDX does not bind the OpenSSL source commit",
            )
            config = build_config_text[artifact_name]
            require('version: "3.6.3"' in config and "epoch: 5" in config, "OpenSSL build config version is wrong")
            require(
                f"expected-commit: {source_commit}" in config,
                f"VEX entry {index} OpenSSL source commit is absent from build config",
            )
            fix_commit = str(evidence.get("fixCommit"))
            require(
                f"openssl-3.6/{fix_commit}: {vulnerability_id}" in config,
                f"VEX entry {index} exact OpenSSL fix cherry-pick is absent from build config",
            )
            source_receipt = verify_git_commit(args.openssl_git_dir, source_commit)
            fix_receipt = verify_git_commit(args.openssl_git_dir, fix_commit)
            require(vulnerability_id in fix_receipt["cveIds"], f"VEX entry {index} fix message does not bind CVE")
            proof = {
                "kind": kind,
                "source": source_receipt,
                "fix": fix_receipt,
                "recipeApplication": "exact-source-plus-cve-labelled-cherry-pick",
            }
    elif kind in {"upstream-disputed-non-security", "upstream-disputed-non-security-and-ldd-absent"}:
        require(vulnerability_id in authority_paths, f"VEX entry {index} has no authority snapshot input")
        authority_path = authority_paths[vulnerability_id]
        upstream_path = upstream_issue_paths[vulnerability_id]
        require(
            sha256(authority_path) == evidence.get("authoritySnapshotSha256"),
            f"VEX entry {index} authority snapshot hash mismatch",
        )
        require(
            sha256(upstream_path) == evidence.get("upstreamIssueSnapshotSha256"),
            f"VEX entry {index} upstream issue snapshot hash mismatch",
        )
        authority = authority_path.read_text()
        upstream = load(upstream_path)
        require(vulnerability_id in authority, f"VEX entry {index} authority snapshot CVE mismatch")
        require(
            "Not treated as a security issue by upstream" in authority,
            f"VEX entry {index} authority snapshot lacks upstream disposition",
        )
        require(
            str(evidence.get("upstreamIssueUrl")) in authority,
            f"VEX entry {index} authority snapshot lacks upstream issue binding",
        )
        expected_bug = 22850 if vulnerability_id == "CVE-2019-1010022" else 22851
        bugs = upstream.get("bugs")
        require(isinstance(bugs, list) and len(bugs) == 1, f"VEX entry {index} upstream snapshot is invalid")
        require(bugs[0].get("id") == expected_bug, f"VEX entry {index} upstream bug identity mismatch")
        require(isinstance(bugs[0].get("summary"), str) and bugs[0]["summary"], f"VEX entry {index} upstream bug summary is absent")
        proof = {
            "kind": kind,
            "authoritySnapshot": pin(authority_path),
            "upstreamIssueSnapshot": pin(upstream_path),
        }
        if kind == "upstream-disputed-non-security-and-ldd-absent":
            proof["runtimeEvidence"] = {
                "conformanceReceiptSha256": sha256(args.conformance_receipt),
                "absentCommand": "ldd",
                "confinement": "non-root-cap-drop-all-no-new-privileges-network-none",
            }
    else:
        raise ValueError(f"VEX entry {index} evidence kind is not admitted")

    entry_sha256 = canonical_sha256(entry)
    verified_entry_sha256.append(entry_sha256)
    verified_entries.append(
        {
            "entryIndex": index,
            "entrySha256": entry_sha256,
            "evidenceSha256": canonical_sha256(evidence),
            "status": entry.get("status"),
            "proof": proof,
        }
    )

receipt = {
    "schema": SCHEMA,
    "outcome": "passed",
    "inputs": {
        "vex": pin(args.vex),
        "conformanceReceipt": pin(args.conformance_receipt),
        "glibcPackageSpdx": pin(args.glibc_package_spdx),
        "libcryptoPackageSpdx": pin(args.libcrypto_package_spdx),
        "libsslPackageSpdx": pin(args.libssl_package_spdx),
        "glibcBuildConfig": pin(args.glibc_build_config),
        "opensslBuildConfig": pin(args.openssl_build_config),
        "cve20191010022Authority": pin(args.cve_2019_1010022_authority),
        "cve20191010023Authority": pin(args.cve_2019_1010023_authority),
        "cve20191010022Upstream": pin(args.cve_2019_1010022_upstream),
        "cve20191010023Upstream": pin(args.cve_2019_1010023_upstream),
    },
    "repositories": repository_receipts,
    "verifiedEntryCount": len(verified_entries),
    "verifiedEntrySha256": verified_entry_sha256,
    "verifiedEntries": verified_entries,
}
args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
