from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parent
HELPER_VERIFIER = ROOT / "verify_helper_input_manifest.py"
INSTALLER_GATE = ROOT / "verify_runtime_installer_absence.sh"
PROVIDER_VERIFIER = ROOT / "verify_provider_adapter_receipt.py"
PROVIDER_SUITES = [
    "src/agent-workspaces/immutable-files/agent-workspace-immutable-file-materialization.spec.ts",
    "src/agent-workspaces/immutable-files/agent-workspace-framed-immutable-file-materializer.spec.ts",
    "src/agent-workspaces/immutable-files/agent-workspace-current-full-image-helper-authority.spec.ts",
    "src/agent-workspaces/agent-workspace-runtime.service.spec.ts",
    "src/agent-workspaces/runtime-capabilities/runtime-capability-full-image-materialization.authority.spec.ts",
    "src/agent-workspaces/daytona/daytona-agent-workspace.provider.spec.ts",
    "src/agent-workspaces/agent-workspace-runtime.module.spec.ts",
]
PROVIDER_COVERAGE = {
    name: True
    for name in (
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
        "truncation",
        "zeroEcho",
    )
}


class HelperInputManifestTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.helper = self.root / "helper"
        self.helper.mkdir()
        self.manifest = self.root / "helper-input.sha256"
        self.output = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_fixture(self) -> None:
        files = {"main.go": b"package main\n", "source.sha256": b"source manifest\n"}
        for name, payload in files.items():
            (self.helper / name).write_bytes(payload)
        self.manifest.write_text(
            "".join(
                f"{hashlib.sha256(payload).hexdigest()}  /helper-input/{name}\n"
                for name, payload in sorted(files.items())
            )
        )

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(HELPER_VERIFIER),
                "--manifest",
                str(self.manifest),
                "--helper-root",
                str(self.helper),
                "--output",
                str(self.output),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_exact_regular_file_roster_passes(self) -> None:
        self.write_fixture()
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(self.output.read_text())
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["fileCount"], 2)

    def test_absolute_path_outside_helper_prefix_is_rejected(self) -> None:
        self.write_fixture()
        self.manifest.write_text("0" * 64 + "  /etc/passwd\n")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsafe or noncanonical path", result.stderr)

    def test_symlink_and_extra_file_are_rejected(self) -> None:
        self.write_fixture()
        (self.helper / "extra").write_text("extra")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("file roster differs", result.stderr)
        (self.helper / "extra").unlink()
        (self.helper / "main.go").unlink()
        os.symlink("source.sha256", self.helper / "main.go")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no-follow regular file", result.stderr)


class RuntimeInstallerGateTest(unittest.TestCase):
    def test_all_absent_reaches_expected_terminal_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                ["/bin/bash", str(INSTALLER_GATE)],
                check=False,
                env={"PATH": directory},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 93, result.stderr)

    def test_present_installer_fails_distinctly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "pip"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", str(INSTALLER_GATE)],
                check=False,
                env={"PATH": directory},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(result.returncode, 94)
        self.assertIn("runtime installer unexpectedly available: pip", result.stderr)


class ProviderAdapterReceiptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.backend = self.root / "backend"
        self.backend.mkdir()
        subprocess.run(["git", "init", "-q", str(self.backend)], check=True)
        subprocess.run(["git", "-C", str(self.backend), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.backend), "config", "user.name", "Fixture"], check=True)
        subprocess.run(
            ["git", "-C", str(self.backend), "remote", "add", "origin", "https://github.com/yungbote/m-backend.git"],
            check=True,
        )
        self.commits: list[str] = []
        self.trees: list[str] = []
        for index in range(5):
            (self.backend / "authority.txt").write_text(f"{index}\n")
            subprocess.run(["git", "-C", str(self.backend), "add", "authority.txt"], check=True)
            subprocess.run(["git", "-C", str(self.backend), "commit", "-q", "-m", f"authority {index}"], check=True)
            self.commits.append(
                subprocess.run(
                    ["git", "-C", str(self.backend), "rev-parse", "HEAD"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip()
            )
            self.trees.append(
                subprocess.run(
                    ["git", "-C", str(self.backend), "rev-parse", "HEAD^{tree}"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                ).stdout.strip()
            )
        self.helper_lock = self.root / "helper.json"
        self.toolchain = self.root / "toolchain.json"
        self.raw_log = self.root / "provider-adapter-focused.log"
        self.receipt = self.root / "receipt.json"
        self.output = self.root / "verification.json"
        self.helper_binary = "1" * 64
        self.protocol = "2" * 64
        self.helper_lock.write_text(
            json.dumps(
                {
                    "revision": self.commits[0],
                    "tree": self.trees[0],
                    "binary": {"sha256": self.helper_binary},
                    "protocolSha256": self.protocol,
                }
            )
        )
        self.write_toolchain(current=self.commits[4])
        self.raw_log.write_text("Test Suites: 7 passed, 7 total\nTests:       145 passed, 145 total\n")
        self.write_receipt()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_toolchain(self, *, current: str) -> None:
        self.toolchain.write_text(
            json.dumps(
                {
                    "atomicMaterializer": {
                        "protocolAuthorityCommit": self.commits[1],
                        "providerAdapterBaselineCommit": self.commits[2],
                        "admissionFenceCommit": self.commits[3],
                        "providerAdapterCommit": current,
                    }
                }
            )
        )

    def write_receipt(self, *, coverage: dict[str, bool] | None = None) -> None:
        body = {
            "command": {
                "argv": [
                    "test",
                    "--",
                    "--runInBand",
                    f"--cacheDirectory=/tmp/c16b-provider-adapter-receipt-jest-cache-{self.commits[4][:8]}",
                    *PROVIDER_SUITES,
                ],
                "executable": "npm",
                "workingDirectory": str(self.backend),
            },
            "coverage": coverage or PROVIDER_COVERAGE,
            "helper": {
                "binarySha256": f"sha256:{self.helper_binary}",
                "protocolSha256": f"sha256:{self.protocol}",
                "revision": self.commits[0],
                "tree": self.trees[0],
            },
            "kind": "provider_adapter_execution_receipt",
            "outcome": "passed",
            "providerAdapterRevision": self.commits[4],
            "rawLog": {
                "bytes": self.raw_log.stat().st_size,
                "name": self.raw_log.name,
                "sha256": f"sha256:{hashlib.sha256(self.raw_log.read_bytes()).hexdigest()}",
            },
            "schema": "ambit.provider-adapter-execution-receipt/v1",
            "sourceRepository": "github.com/yungbote/m-backend",
            "sourceRevision": self.commits[4],
            "sourceTree": self.trees[4],
            "suiteRoster": PROVIDER_SUITES,
            "testCount": 145,
            "testSuiteCount": 7,
            "version": 1,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        body["receiptRef"] = (
            "provider-adapter-execution-receipt:sha256:" + hashlib.sha256(canonical).hexdigest()
        )
        self.receipt.write_text(json.dumps(body, sort_keys=True) + "\n")

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(PROVIDER_VERIFIER),
                "--receipt",
                str(self.receipt),
                "--raw-log",
                str(self.raw_log),
                "--backend-repo",
                str(self.backend),
                "--helper-lock",
                str(self.helper_lock),
                "--toolchain-manifest",
                str(self.toolchain),
                "--output",
                str(self.output),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_exact_receipt_log_and_ancestry_pass(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["outcome"], "passed")

    def test_raw_log_mutation_fails(self) -> None:
        self.raw_log.write_text(self.raw_log.read_text() + "tamper\n")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("raw-log byte count mismatch", result.stderr)

    def test_incomplete_coverage_fails(self) -> None:
        coverage = dict(PROVIDER_COVERAGE)
        coverage["liveCurrentness"] = False
        self.write_receipt(coverage=coverage)
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coverage roster is incomplete", result.stderr)

    def test_stale_toolchain_provider_authority_fails(self) -> None:
        self.write_toolchain(current=self.commits[2])
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not select provider successor", result.stderr)


if __name__ == "__main__":
    unittest.main()
