from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-compose.py")
SPEC = importlib.util.spec_from_file_location("ambit_local_verify_compose", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery invariant
    raise RuntimeError("could not load verify-compose.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(byte: str) -> str:
    return f"sha256:{byte * 64}"


def image(name: str, byte: str = "a") -> str:
    return f"registry.local/ambit/{name}@{digest(byte)}"


class VerifyComposeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.state_root = Path("/home/example/ambit-daytona/state")
        self.values = {
            "AMBIT_DAYTONA_API_PORT": "33000",
            "AMBIT_DAYTONA_PROXY_PORT": "34000",
            "AMBIT_DAYTONA_REGISTRY_PORT": "36000",
            "AMBIT_DAYTONA_DEX_PORT": "35556",
            "AMBIT_C16B_RUNTIME_OCI_REFERENCE": image("runtime", "b"),
        }
        self.config = self.fixture()

    def fixture(self) -> dict[str, object]:
        service_names = sorted(MODULE.EXPECTED_SERVICES)
        services: dict[str, dict[str, object]] = {
            name: {
                "image": image(name),
                "pull_policy": "never",
                "networks": {"provider": None},
            }
            for name in service_names
        }
        services["runner"].update(
            {
                "privileged": True,
                "cpus": 6.0,
                "mem_limit": 12 * 1024**3,
                "pids_limit": 8192,
                "environment": {
                    "RESOURCE_LIMITS_DISABLED": "false",
                    "INTER_SANDBOX_NETWORK_ENABLED": "false",
                    "GPU_ENABLED": "false",
                    "INITIALIZE_DAEMON_TELEMETRY": "false",
                    "OTEL_LOGGING_ENABLED": "false",
                    "OTEL_TRACING_ENABLED": "false",
                },
            }
        )
        services["api"]["environment"] = {
            "DEFAULT_SNAPSHOT": self.values["AMBIT_C16B_RUNTIME_OCI_REFERENCE"],
            "DEFAULT_RUNNER_CPU": "4",
            "DEFAULT_RUNNER_MEMORY": "8",
            "DEFAULT_RUNNER_DISK": "40",
            "DEFAULT_REGION_ID": "local",
            "DEFAULT_REGION_NAME": "local",
            "DEFAULT_REGION_ENFORCE_QUOTAS": "true",
            "DEFAULT_ORG_QUOTA_CONTAINER_TOTAL_CPU_QUOTA": "4",
            "DEFAULT_ORG_QUOTA_CONTAINER_TOTAL_MEMORY_QUOTA": "8",
            "DEFAULT_ORG_QUOTA_CONTAINER_TOTAL_DISK_QUOTA": "40",
            "DEFAULT_ORG_QUOTA_CONTAINER_TOTAL_GPU_QUOTA": "0",
            "DEFAULT_ORG_QUOTA_CONTAINER_MAX_CPU_PER_SANDBOX": "2",
            "DEFAULT_ORG_QUOTA_CONTAINER_MAX_MEMORY_PER_SANDBOX": "4",
            "DEFAULT_ORG_QUOTA_CONTAINER_MAX_DISK_PER_SANDBOX": "20",
            "ADMIN_TOTAL_CPU_QUOTA": "4",
            "ADMIN_TOTAL_MEMORY_QUOTA": "8",
            "ADMIN_TOTAL_DISK_QUOTA": "40",
            "ADMIN_MAX_CPU_PER_SANDBOX": "2",
            "ADMIN_MAX_MEMORY_PER_SANDBOX": "4",
            "ADMIN_MAX_DISK_PER_SANDBOX": "20",
        }
        for name, published, target in (
            ("api", 33000, 3000),
            ("proxy", 34000, 4000),
            ("registry", 36000, 6000),
            ("dex", 35556, 5556),
        ):
            services[name]["ports"] = [
                {
                    "host_ip": "127.0.0.1",
                    "published": str(published),
                    "target": target,
                    "protocol": "tcp",
                }
            ]
        mounts = {
            "runner": {"/var/lib/docker": "runner-docker", "/home/daytona/runner": "runner-log"},
            "db": {"/var/lib/postgresql/data": "postgres"},
            "redis": {"/data": "redis"},
            "minio": {"/data": "minio"},
            "registry": {"/var/lib/registry": "registry"},
            "dex": {"/etc/dex/config.yaml": "config/dex.yaml", "/var/dex": "dex"},
        }
        for name, roster in mounts.items():
            services[name]["volumes"] = [
                {
                    "type": "bind",
                    "source": str(self.state_root / relative),
                    "target": target,
                }
                for target, relative in roster.items()
            ]
        return {
            "name": "ambit-daytona-local",
            "services": services,
            "networks": {"provider": {"driver": "bridge", "internal": True}},
        }

    def assert_rejected(self, mutate) -> None:  # type: ignore[no-untyped-def]
        candidate = copy.deepcopy(self.config)
        mutate(candidate)
        with self.assertRaises(ValueError):
            MODULE.validate_compose(candidate, self.values, self.state_root)

    def test_exact_local_compose_passes(self) -> None:
        receipt = MODULE.validate_compose(self.config, self.values, self.state_root)
        self.assertEqual(receipt["outcome"], "passed")
        self.assertEqual(receipt["providerCapacity"]["profileDigest"], MODULE.PROFILE_DIGEST)

    def test_public_port_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["api"]["ports"][0].__setitem__("host_ip", "0.0.0.0")
        )

    def test_mutable_image_is_rejected(self) -> None:
        self.assert_rejected(lambda value: value["services"]["api"].__setitem__("image", "daytona:latest"))

    def test_disabled_resource_limits_are_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["runner"]["environment"].__setitem__(
                "RESOURCE_LIMITS_DISABLED", "true"
            )
        )

    def test_mount_escape_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0].__setitem__(
                "source", "/var/lib/docker"
            )
        )

    def test_extra_service_and_privilege_are_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"].__setitem__(
                "telemetry", {"image": image("telemetry"), "pull_policy": "never", "networks": {"provider": None}}
            )
        )
        self.assert_rejected(lambda value: value["services"]["api"].__setitem__("privileged", True))

    def test_external_target_and_non_internal_network_are_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["api"]["environment"].__setitem__(
                "POSTHOG_HOST", "https://telemetry.example"
            )
        )
        self.assert_rejected(lambda value: value["networks"]["provider"].__setitem__("internal", False))


if __name__ == "__main__":
    unittest.main()
