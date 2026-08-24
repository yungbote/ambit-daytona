from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from freeze_source_identity import SOURCE_PATH, SourceIdentityError, freeze, verify_context


class FreezeSourceIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.source = self.repo / SOURCE_PATH
        self.source.mkdir(parents=True)
        (self.source / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        script = self.source / "verify.sh"
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)
        self.alternate_path = (
            "images/ambit-agent-workspace/capabilities/c17-core-document-v5"
        )
        self.alternate = self.repo / self.alternate_path
        self.alternate.mkdir(parents=True)
        (self.alternate / "Dockerfile").write_text(
            "FROM scratch\n", encoding="utf-8"
        )
        self._git("init", "-b", "main")
        self._git("config", "user.name", "Ambit Test")
        self._git("config", "user.email", "test@ambit.invalid")
        self._git("add", ".")
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_DATE": "2026-08-24T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-08-24T00:00:00Z",
            }
        )
        subprocess.run(
            ["git", "-C", os.fspath(self.repo), "commit", "-m", "fixture"],
            check=True,
            stdout=subprocess.DEVNULL,
            env=environment,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_freezes_and_reproves_exact_commit_source(self) -> None:
        context = self.root / "identity"
        receipt = freeze(self.repo, "HEAD", context)
        self.assertEqual(
            verify_context(self.source, context, receipt["identitySha256"])["revision"],
            receipt["revision"],
        )

    def test_freezes_an_explicit_sibling_pack_without_changing_default_authority(self) -> None:
        context = self.root / "alternate-identity"
        receipt = freeze(
            self.repo,
            "HEAD",
            context,
            self.alternate_path,
        )
        self.assertEqual(receipt["path"], self.alternate_path)
        self.assertEqual(
            verify_context(
                self.alternate,
                context,
                receipt["identitySha256"],
            )["path"],
            self.alternate_path,
        )

    def test_rejects_ambiguous_or_traversing_source_paths(self) -> None:
        for source_path in ("", "/absolute", "a//b", "a/../b", "a/./b"):
            with self.subTest(source_path=source_path):
                with self.assertRaises(SourceIdentityError):
                    freeze(
                        self.repo,
                        "HEAD",
                        self.root / ("bad-" + str(len(source_path))),
                        source_path,
                    )

    def test_rejects_forged_revision_tree_epoch_context_and_external_digest(self) -> None:
        fields = [
            "revision",
            "repositoryTree",
            "subtree",
            "sourceDateEpoch",
            "contextSha256",
        ]
        for field in fields:
            with self.subTest(field=field):
                context = self.root / f"identity-{field}"
                receipt = freeze(self.repo, "HEAD", context)
                identity_path = context / "source-identity.json"
                identity = json.loads(identity_path.read_text())
                identity[field] = 1 if field == "sourceDateEpoch" else "0" * 40
                identity_path.write_text(
                    json.dumps(identity, separators=(",", ":"), sort_keys=True) + "\n"
                )
                with self.assertRaises(SourceIdentityError):
                    verify_context(self.source, context, receipt["identitySha256"])

    def test_rejects_source_archive_manifest_mode_and_file_drift(self) -> None:
        mutations = ["archive", "manifest", "mode", "source"]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                context = self.root / f"identity-{mutation}"
                receipt = freeze(self.repo, "HEAD", context)
                if mutation == "archive":
                    with (context / "daytona-source.tar").open("ab") as stream:
                        stream.write(b"x")
                elif mutation == "manifest":
                    with (context / "source-files.sha256").open("ab") as stream:
                        stream.write(b"x")
                elif mutation == "mode":
                    (self.source / "verify.sh").chmod(0o644)
                else:
                    (self.source / "Dockerfile").write_text("FROM busybox\n")
                with self.assertRaises(SourceIdentityError):
                    verify_context(self.source, context, receipt["identitySha256"])
                if mutation == "mode":
                    (self.source / "verify.sh").chmod(0o755)
                elif mutation == "source":
                    (self.source / "Dockerfile").write_text("FROM scratch\n")

    def _git(self, *arguments: str) -> None:
        subprocess.run(
            ["git", "-C", os.fspath(self.repo), *arguments],
            check=True,
            stdout=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    unittest.main()
