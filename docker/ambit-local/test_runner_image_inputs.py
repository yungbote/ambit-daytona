from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "apps/runner/Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
LOCK = Path(__file__).with_name("computer-use-build.lock.json")
BINARY_LOCK = Path(__file__).with_name("computer-use-binary.sha256")
EXPECTED_BINARY_SHA256 = "21c00cd7b6e98213b134cc3d8bc374b410f7e66fc5cea5815ad4f4715982c76b"
EXPECTED_TOOLCHAIN = (
    "docker.io/library/golang@"
    "sha256:49be5c3f5f2b766e5ba74e0bb690fea4fa03ebf5df8fe94665d42dfa727acf31"
)


class RunnerImageInputsTest(unittest.TestCase):
    def test_computer_use_is_built_twice_by_the_pinned_glibc_toolchain(self) -> None:
        dockerfile = DOCKERFILE.read_text()
        self.assertIn(
            f"FROM {EXPECTED_TOOLCHAIN.removeprefix('docker.io/library/')} AS computer-use-builder",
            dockerfile,
        )
        self.assertEqual(dockerfile.count("go build -trimpath -buildvcs=false"), 2)
        self.assertIn("GOCACHE=/tmp/computer-use-cache-a", dockerfile)
        self.assertIn("GOCACHE=/tmp/computer-use-cache-b", dockerfile)
        self.assertIn("cmp /out/computer-use /out/computer-use.rebuilt", dockerfile)
        self.assertIn("sha256sum -c /tmp/computer-use-binary.sha256", dockerfile)
        self.assertIn("test \"$(go version)\" = 'go version go1.25.11 linux/amd64'", dockerfile)

    def test_ambient_dist_binary_cannot_enter_the_runner_image(self) -> None:
        dockerfile = DOCKERFILE.read_text()
        dockerignore = DOCKERIGNORE.read_text().splitlines()
        self.assertIn("dist", dockerignore)
        self.assertNotIn("!dist/libs/computer-use-amd64", dockerignore)
        self.assertIn("!docker/ambit-local/computer-use-binary.sha256", dockerignore)
        self.assertIn("!docker/ambit-local/computer-use-build.lock.json", dockerignore)
        self.assertNotIn("COPY dist/libs/computer-use-amd64", dockerfile)
        self.assertIn(
            "COPY --from=computer-use-builder /out/computer-use dist/libs/computer-use-amd64",
            dockerfile,
        )
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--error-unmatch", "dist/libs/computer-use-amd64"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(tracked.returncode, 0)

    def test_binary_and_toolchain_lock_is_closed(self) -> None:
        lock = json.loads(LOCK.read_text())
        self.assertEqual(
            set(lock),
            {"ambientDistInput", "binary", "build", "schema", "source", "toolchain"},
        )
        self.assertEqual(lock["schema"], "ambit.local-daytona-computer-use-build-lock/v1")
        self.assertEqual(lock["ambientDistInput"], "forbidden")
        self.assertEqual(lock["toolchain"]["image"], EXPECTED_TOOLCHAIN)
        self.assertEqual(lock["toolchain"]["goVersion"], "go1.25.11")
        self.assertEqual(lock["toolchain"]["platform"], "linux/amd64")
        self.assertEqual(lock["toolchain"]["libc"], "glibc")
        self.assertEqual(lock["binary"]["sha256"], EXPECTED_BINARY_SHA256)
        self.assertEqual(lock["binary"]["sizeBytes"], 21_969_096)
        line = BINARY_LOCK.read_text().strip()
        self.assertEqual(line, f"{EXPECTED_BINARY_SHA256}  computer-use")
        self.assertEqual(
            hashlib.sha256(line.encode()).hexdigest(),
            "903a934784c2953331f0fa977e9e3a108c00ddc68b36a6d870c4618e4fe329dd",
        )


if __name__ == "__main__":
    unittest.main()
