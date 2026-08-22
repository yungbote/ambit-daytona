from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SUITES = [
    "src/agent-workspaces/immutable-files/agent-workspace-immutable-file-materialization.spec.ts",
    "src/agent-workspaces/immutable-files/agent-workspace-framed-immutable-file-materializer.spec.ts",
    "src/agent-workspaces/immutable-files/agent-workspace-current-full-image-helper-authority.spec.ts",
    "src/agent-workspaces/agent-workspace-runtime.service.spec.ts",
    "src/agent-workspaces/runtime-capabilities/runtime-capability-full-image-materialization.authority.spec.ts",
    "src/agent-workspaces/daytona/daytona-agent-workspace.provider.spec.ts",
    "src/agent-workspaces/agent-workspace-runtime.module.spec.ts",
    "src/skills/runtime/skill-workspace-materialization.service.spec.ts",
    "src/skills/runtime/skill-runtime.service.spec.ts",
]
COVERAGE = {
    "abort",
    "ackBackpressure",
    "allByteValues",
    "arbitraryFrameSplits",
    "extraBytes",
    "liveCurrentness",
    "payload0Bytes",
    "payload1Byte",
    "payload32MiB",
    "postEndUnknownToNewVerifyOnly",
    "preReadyNoiseBounded",
    "sequential64KiBChunks",
    "timeouts",
    "treeClosedWorld",
    "treeCrashRecovery",
    "treeHelperQuiescence",
    "treeReadOnlyActivation",
    "truncation",
    "zeroEcho",
}


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pin(path: Path) -> dict[str, Any]:
    return {"name": path.name, "bytes": path.stat().st_size, "sha256": sha256(path)}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_keys(value: dict[str, Any], expected: set[str], description: str) -> None:
    require(set(value) == expected, f"{description} key roster differs")


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(repo), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"},
    )
    if result.returncode != 0:
        raise ValueError(f"Git verification failed ({' '.join(arguments)}): {result.stderr.strip()}")
    return result.stdout.rstrip("\n")


parser = argparse.ArgumentParser()
parser.add_argument("--receipt", required=True, type=Path)
parser.add_argument("--raw-log", required=True, type=Path)
parser.add_argument("--backend-repo", required=True, type=Path)
parser.add_argument("--helper-lock", required=True, type=Path)
parser.add_argument("--toolchain-manifest", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()

receipt = load(args.receipt)
helper_lock = load(args.helper_lock)
toolchain = load(args.toolchain_manifest)
exact_keys(
    receipt,
    {
        "command",
        "coverage",
        "helper",
        "kind",
        "outcome",
        "providerAdapterAuthorityRevision",
        "providerTestedSourceRevision",
        "rawLog",
        "receiptRef",
        "schema",
        "sourceRepository",
        "sourceRevision",
        "sourceTree",
        "suiteRoster",
        "testCount",
        "testSuiteCount",
        "version",
    },
    "provider adapter receipt",
)
require(receipt["schema"] == "ambit.provider-adapter-execution-receipt/v2", "provider receipt schema is invalid")
require(receipt["kind"] == "provider_adapter_execution_receipt", "provider receipt kind is invalid")
require(receipt["version"] == 2 and receipt["outcome"] == "passed", "provider adapter execution did not pass")

body = dict(receipt)
receipt_ref = str(body.pop("receiptRef"))
body_digest = hashlib.sha256(
    json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
).hexdigest()
require(
    receipt_ref == f"provider-adapter-execution-receipt:sha256:{body_digest}",
    "provider receiptRef does not bind its canonical body",
)

raw_log = receipt["rawLog"]
require(isinstance(raw_log, dict), "provider raw-log receipt is invalid")
exact_keys(raw_log, {"name", "bytes", "sha256"}, "provider raw-log receipt")
require(raw_log["name"] == args.raw_log.name, "provider raw-log name mismatch")
require(raw_log["bytes"] == args.raw_log.stat().st_size, "provider raw-log byte count mismatch")
require(raw_log["sha256"] == f"sha256:{sha256(args.raw_log)}", "provider raw-log digest mismatch")
raw_text = args.raw_log.read_text()
require("Test Suites: 9 passed, 9 total" in raw_text, "provider raw log lacks exact suite result")
require("Tests:       210 passed, 210 total" in raw_text, "provider raw log lacks exact test result")

source_revision = receipt["sourceRevision"]
source_tree = receipt["sourceTree"]
require(
    isinstance(source_revision, str)
    and COMMIT_RE.fullmatch(source_revision)
    and receipt["providerTestedSourceRevision"] == source_revision,
    "provider source revision is invalid",
)
require(isinstance(source_tree, str) and COMMIT_RE.fullmatch(source_tree), "provider source tree is invalid")
require(receipt["sourceRepository"] == "github.com/yungbote/m-backend", "provider source repository is invalid")
require(args.backend_repo.is_dir(), "backend repository does not exist")
remote = git(args.backend_repo, "remote", "get-url", "origin")
require(
    remote.rstrip("/") in {"https://github.com/yungbote/m-backend.git", "git@github.com:yungbote/m-backend.git"},
    "backend Git remote is not authoritative",
)
require(git(args.backend_repo, "rev-parse", f"{source_revision}^{{commit}}") == source_revision, "provider commit is absent")
require(git(args.backend_repo, "rev-parse", f"{source_revision}^{{tree}}") == source_tree, "provider source tree mismatch")

materializer = toolchain.get("atomicMaterializer", {})
require(isinstance(materializer, dict), "toolchain materializer input is invalid")
helper = receipt["helper"]
require(isinstance(helper, dict), "provider helper receipt is invalid")
exact_keys(
    helper,
    {"binarySha256", "protocolSha256", "revision", "tree", "treeProtocolSha256"},
    "provider helper receipt",
)
require(helper["revision"] == helper_lock.get("revision"), "provider helper revision mismatch")
require(helper["tree"] == helper_lock.get("tree"), "provider helper tree mismatch")
require(helper["binarySha256"] == f"sha256:{helper_lock.get('binary', {}).get('sha256')}", "provider helper binary mismatch")
require(helper["protocolSha256"] == f"sha256:{helper_lock.get('protocolSha256')}", "provider protocol mismatch")
require(
    helper["treeProtocolSha256"] == f"sha256:{helper_lock.get('treeProtocolSha256')}",
    "provider tree protocol mismatch",
)
require(
    materializer.get("providerTestedSourceCommit") == source_revision,
    "toolchain does not select tested provider source",
)
require(
    receipt["providerAdapterAuthorityRevision"]
    == materializer.get("providerAdapterAuthorityCommit"),
    "provider adapter authority mismatch",
)

ancestry = {
    "helperRevision": str(helper_lock["revision"]),
    "protocolAuthorityCommit": str(materializer["protocolAuthorityCommit"]),
    "providerAdapterAuthorityCommit": str(materializer["providerAdapterAuthorityCommit"]),
    "admissionFenceCommit": str(materializer["admissionFenceCommit"]),
}
for name, commit in ancestry.items():
    require(COMMIT_RE.fullmatch(commit) is not None, f"{name} is invalid")
    git(args.backend_repo, "cat-file", "-e", f"{commit}^{{commit}}")
    git(args.backend_repo, "merge-base", "--is-ancestor", commit, source_revision)

command = receipt["command"]
require(isinstance(command, dict), "provider command receipt is invalid")
exact_keys(command, {"argv", "executable", "workingDirectory"}, "provider command receipt")
require(command["executable"] == "npm", "provider test executable is invalid")
require(Path(command["workingDirectory"]).resolve() == args.backend_repo.resolve(), "provider test working directory mismatch")
argv = command["argv"]
require(isinstance(argv, list), "provider test argv is invalid")
require(argv[:3] == ["test", "--", "--runInBand"], "provider test argv prefix is invalid")
require(
    isinstance(argv[3], str)
    and re.fullmatch(r"--cacheDirectory=/tmp/c16b-provider-adapter-receipt-jest-cache-[0-9a-f]{8}", argv[3]),
    "provider test cache argument is invalid",
)
require(argv[4:] == SUITES, "provider test argv suite roster differs")
require(receipt["suiteRoster"] == SUITES, "provider suite roster differs")
require(receipt["testSuiteCount"] == len(SUITES), "provider suite count differs")
require(receipt["testCount"] == 210, "provider test count differs")
coverage = receipt["coverage"]
require(isinstance(coverage, dict), "provider coverage receipt is invalid")
require(set(coverage) == COVERAGE and all(coverage.values()), "provider coverage roster is incomplete")

verification = {
    "schema": "ambit.provider-adapter-execution-verification/v2",
    "outcome": "passed",
    "receipt": pin(args.receipt),
    "receiptRef": receipt_ref,
    "rawLog": pin(args.raw_log),
    "source": {
        "repository": receipt["sourceRepository"],
        "revision": source_revision,
        "tree": source_tree,
    },
    "helper": helper,
    "ancestry": ancestry,
    "suiteCount": len(SUITES),
    "testCount": receipt["testCount"],
    "coverage": coverage,
}
args.output.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n")
