from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DockerfileContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    def test_uses_exact_debian_platform_manifest(self) -> None:
        self.assertTrue(
            self.source.startswith(
                "# syntax=docker/dockerfile:1.7@sha256:"
                "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
            )
        )
        self.assertIn(
            "docker.io/library/debian@sha256:"
            "38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16",
            self.source,
        )

    def test_all_run_steps_are_network_none(self) -> None:
        run_lines = re.findall(r"^RUN .*", self.source, flags=re.MULTILINE)
        self.assertGreater(len(run_lines), 3)
        self.assertTrue(all("--network=none" in line for line in run_lines))
        self.assertNotRegex(
            self.source,
            r"\b(?:apt-get\s+(?:install|update)|curl\s|npm\s|npx\s|wget\s)",
        )

    def test_public_inputs_are_external_and_helper_is_a_required_secret(self) -> None:
        self.assertNotIn("FROM scratch AS public_inputs", self.source)
        self.assertIn("from=public_inputs", self.source)
        self.assertNotIn("AMBIT_CORE_DOCUMENT_V5_PUBLIC_READY", self.source)
        self.assertIn("sha256sum -c certification/source-contracts.sha256", self.source)
        self.assertIn("offline-public-artifacts.sha256", self.source)
        self.assertIn("offline-frozen-evidence.sha256", self.source)
        self.assertIn("find structural -type f -print", self.source)
        self.assertIn(
            "type=secret,id=ambit_capture_helper_archive,required=true",
            self.source,
        )
        self.assertNotIn("COPY helper", self.source)

    def test_runtime_is_non_root_and_final_target_always_fails_dark(self) -> None:
        self.assertIn("USER 1000:1000", self.source)
        self.assertIn("io.ambit.activation=\"forbidden\"", self.source)
        self.assertIn("io.ambit.runtime-pack-authority=\"none\"", self.source)
        self.assertIn("FROM runtime_debian AS renderer_substrate", self.source)
        self.assertNotIn("FROM runtime_debian AS public_runtime", self.source)
        removal = self.source.split("rm -f /usr/bin/apt", 1)[1].split(
            "FROM runtime_debian AS renderer_substrate", 1
        )[0]
        for installer in ("/usr/bin/apt-get", "/usr/bin/dpkg", "/usr/bin/dpkg-query"):
            self.assertIn(installer, removal)
        for license_source in (
            "/tmp/node-v24.19.0-linux-x64/LICENSE",
            "/tmp/package/LICENSE",
            "NAPI-RS-CANVAS-LICENSE",
            "SKIA-LICENSE",
            "/tmp/evidence/licenses/.",
        ):
            self.assertIn(license_source, self.source)
        self.assertRegex(
            self.source,
            r"FROM structural_renderer_substrate AS core_document_v5[\s\S]+exit 64",
        )


if __name__ == "__main__":
    unittest.main()
