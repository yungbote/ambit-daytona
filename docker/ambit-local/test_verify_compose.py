from __future__ import annotations

import copy
import importlib.util
import os
import subprocess
import tempfile
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
                "cpus": MODULE.EXPECTED_OUTER_CAPS[name][0],
                "mem_limit": MODULE.EXPECTED_OUTER_CAPS[name][1],
                "pids_limit": MODULE.EXPECTED_OUTER_CAPS[name][2],
                **(
                    {"environment": {key: "fixture" for key in MODULE.EXPECTED_ENVIRONMENT_KEYS[name]}}
                    if MODULE.EXPECTED_ENVIRONMENT_KEYS[name]
                    else {}
                ),
            }
            for name in service_names
        }
        services["runner"].update({"privileged": True})
        services["runner"]["environment"].update(
            {
                "RESOURCE_LIMITS_DISABLED": "false",
                "INTER_SANDBOX_NETWORK_ENABLED": "false",
                "GPU_ENABLED": "false",
                "INITIALIZE_DAEMON_TELEMETRY": "false",
                "OTEL_LOGGING_ENABLED": "false",
                "OTEL_TRACING_ENABLED": "false",
                "AWS_ENDPOINT_URL": "http://minio:9000",
                "DAYTONA_API_URL": "http://api:3000/api",
            }
        )
        services["api"]["environment"].update(
            {
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
                "BUILD_CPU_CORES": "2",
                "BUILD_MEMORY_GB": "4",
                "BUILD_INFO_MAX_SANDBOXES_PER_RUNNER": "2",
                "OTEL_ENABLED": "false",
                "POSTHOG_API_KEY": "",
                "POSTHOG_HOST": "",
                "DASHBOARD_URL": "http://127.0.0.1:33000/dashboard",
                "DASHBOARD_BASE_API_URL": "http://127.0.0.1:33000",
                "OIDC_ISSUER_BASE_URL": "http://dex:5556/dex",
                "PUBLIC_OIDC_DOMAIN": "http://127.0.0.1:35556/dex",
                "TRANSIENT_REGISTRY_URL": "http://registry:6000",
                "INTERNAL_REGISTRY_URL": "http://registry:6000",
                "S3_ENDPOINT": "http://minio:9000",
                "S3_STS_ENDPOINT": "http://minio:9000/minio/v1/assume-role",
                "DEFAULT_RUNNER_API_URL": "http://runner:3003",
                "DEFAULT_RUNNER_PROXY_URL": "http://runner:3003",
                "TRANSIENT_REGISTRY_ADMIN": "",
                "TRANSIENT_REGISTRY_PASSWORD": "",
                "TRANSIENT_REGISTRY_PROJECT_ID": "",
                "INTERNAL_REGISTRY_ADMIN": "",
                "INTERNAL_REGISTRY_PASSWORD": "",
                "INTERNAL_REGISTRY_PROJECT_ID": "",
                "OIDC_MANAGEMENT_API_ENABLED": "",
                "OIDC_MANAGEMENT_API_CLIENT_ID": "",
                "OIDC_MANAGEMENT_API_CLIENT_SECRET": "",
                "OIDC_MANAGEMENT_API_AUDIENCE": "",
                "SSH_GATEWAY_API_KEY": "",
                "SSH_GATEWAY_COMMAND": "",
                "SSH_GATEWAY_PUBLIC_KEY": "",
                "SSH_GATEWAY_URL": "",
            }
        )
        services["proxy"]["environment"].update(
            {
                "DAYTONA_API_URL": "http://api:3000/api",
                "OIDC_DOMAIN": "http://dex:5556/dex",
                "OIDC_PUBLIC_DOMAIN": "http://127.0.0.1:35556/dex",
            }
        )
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
                    **(
                        {"read_only": True}
                        if name == "dex" and target == "/etc/dex/config.yaml"
                        else {}
                    ),
                }
                for target, relative in roster.items()
            ]
        services["runner"]["volumes"] = [
            {
                "type": "bind",
                "source": "/home/.ambit-c16b-runner-storage/runner-docker/inner-runner",
                "target": "/var/lib/docker",
                "bind": {
                    "create_host_path": False,
                    "propagation": "rprivate",
                },
            },
            {
                "type": "bind",
                "source": str(self.state_root / "runner-log"),
                "target": "/home/daytona/runner",
            },
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
        self.assertEqual(receipt["schema"], "ambit.local-daytona-compose-verification/v3")
        self.assertEqual(receipt["providerCapacity"]["profileDigest"], MODULE.PROFILE_DIGEST)
        self.assertEqual(
            receipt["runnerDockerStorageAuthority"],
            {
                "source": "/home/.ambit-c16b-runner-storage/runner-docker/inner-runner",
                "target": "/var/lib/docker",
                "bind": {"createHostPath": False, "propagation": "rprivate"},
            },
        )

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

    def test_legacy_state_root_runner_storage_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0].__setitem__(
                "source", str(self.state_root / "runner-docker")
            )
        )

    def test_alternate_runner_storage_roots_are_rejected(self) -> None:
        for source in (
            "/home/example/.ambit-c16b-runner-storage/runner-docker",
            "/home/other/runner-docker",
            "/run/ambit-c16b-runner-storage/runner-docker",
            "/tmp/ambit-c16b-runner-storage/runner-docker",
        ):
            with self.subTest(source=source):
                self.assert_rejected(
                    lambda value, source=source: value["services"]["runner"]["volumes"][
                        0
                    ].__setitem__("source", source)
                )

    def test_runner_bind_excludes_authority_parent_and_outer_daemon_roots(self) -> None:
        for source in (
            "/home/.ambit-c16b-runner-storage/runner-docker",
            "/home/.ambit-c16b-runner-storage/outer-docker",
            "/home/.ambit-c16b-runner-storage/outer-containerd",
        ):
            with self.subTest(source=source):
                self.assert_rejected(
                    lambda value, source=source: value["services"]["runner"]["volumes"][
                        0
                    ].__setitem__("source", source)
                )

    def test_runner_storage_requires_create_host_path_false(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0]["bind"].pop(
                "create_host_path"
            )
        )
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0]["bind"].__setitem__(
                "create_host_path", True
            )
        )
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0]["bind"].__setitem__(
                "create_host_path", 0
            )
        )

    def test_runner_storage_requires_rprivate_propagation(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0]["bind"].pop(
                "propagation"
            )
        )
        for propagation in ("private", "shared", "rshared", "slave", "rslave"):
            with self.subTest(propagation=propagation):
                self.assert_rejected(
                    lambda value, propagation=propagation: value["services"]["runner"][
                        "volumes"
                    ][0]["bind"].__setitem__("propagation", propagation)
                )

    def test_runner_storage_rejects_extra_bind_and_mount_fields(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0]["bind"].__setitem__(
                "selinux", "z"
            )
        )
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"][0].__setitem__(
                "read_only", True
            )
        )

    def test_runner_storage_rejects_a_second_bind(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["runner"]["volumes"].append(
                {
                    "type": "bind",
                    "source": "/home/.ambit-c16b-runner-storage/runner-docker/inner-runner",
                    "target": "/var/lib/docker-shadow",
                    "bind": {"create_host_path": False, "propagation": "rprivate"},
                }
            )
        )

    def test_all_other_mounts_remain_state_root_confined(self) -> None:
        for service, index in (("runner", 1), ("db", 0), ("registry", 0), ("dex", 1)):
            with self.subTest(service=service):
                self.assert_rejected(
                    lambda value, service=service, index=index: value["services"][service][
                        "volumes"
                    ][index].__setitem__(
                        "source", "/home/.ambit-c16b-runner-storage/runner-docker"
                    )
                )

    def test_runner_storage_authority_cannot_overlap_state_root(self) -> None:
        with self.assertRaises(ValueError):
            MODULE.validate_compose(
                self.config,
                self.values,
                Path("/home/.ambit-c16b-runner-storage/user-state"),
            )

    def test_mount_on_unlisted_service_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["api"].__setitem__(
                "volumes",
                [
                    {
                        "type": "bind",
                        "source": "/var/run/docker.sock",
                        "target": "/var/run/docker.sock",
                    }
                ],
            )
        )

    def test_host_namespace_and_resource_drift_are_rejected(self) -> None:
        self.assert_rejected(lambda value: value["services"]["api"].__setitem__("pid", "host"))
        self.assert_rejected(lambda value: value["services"]["api"].__setitem__("cpus", 2.0))
        self.assert_rejected(lambda value: value["services"]["minio-init"].pop("mem_limit"))

    def test_environment_generator_has_no_runner_storage_authority(self) -> None:
        generator = Path(__file__).with_name("generate-environment.sh")
        image_value = image("fixture")
        environment = os.environ.copy()
        for key in MODULE.EXPECTED_IMAGES:
            environment[key] = image_value

        def generate(root: Path) -> Path:
            state_root = root / "state"
            subprocess.run(
                [str(generator), str(root / "provider.env"), str(state_root)],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return state_root

        with tempfile.TemporaryDirectory(
            prefix="ambit-compose-generator-", dir=Path(__file__).resolve().parents[2]
        ) as directory:
            state_root = generate(Path(directory))
            self.assertFalse((state_root / "runner-docker").exists())
            self.assertFalse((state_root / "outer-docker").exists())
            self.assertFalse((state_root / "outer-containerd").exists())
            self.assertTrue((state_root / "runner-log").is_dir())

        with tempfile.TemporaryDirectory(
            prefix="ambit-compose-generator-", dir=Path(__file__).resolve().parents[2]
        ) as directory:
            root = Path(directory)
            state_root = root / "state"
            stale_directories = {
                "runner-docker": 0o751,
                "outer-docker": 0o752,
                "outer-containerd": 0o753,
            }
            for name, mode in stale_directories.items():
                stale = state_root / name
                stale.mkdir(parents=True)
                stale.chmod(mode)
            generate(root)
            for name, mode in stale_directories.items():
                with self.subTest(name=name):
                    self.assertEqual((state_root / name).stat().st_mode & 0o777, mode)

    def test_compose_source_hard_codes_runner_storage_authority(self) -> None:
        compose_lines = Path(__file__).with_name("compose.yaml").read_text().splitlines()
        runner_storage_lines = [line.strip() for line in compose_lines if "runner-docker" in line]
        self.assertEqual(
            runner_storage_lines,
            ["source: /home/.ambit-c16b-runner-storage/runner-docker/inner-runner"],
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
        self.assert_rejected(
            lambda value: value["services"]["api"]["environment"].__setitem__(
                "POSTHOG_HOST", "http://telemetry.example"
            )
        )
        self.assert_rejected(
            lambda value: value["services"]["api"]["environment"].__setitem__(
                "OTEL_EXPORTER_OTLP_ENDPOINT", "http://telemetry.example"
            )
        )
        self.assert_rejected(lambda value: value["networks"]["provider"].__setitem__("internal", False))

    def test_scheduler_capacity_environment_drift_is_rejected(self) -> None:
        self.assert_rejected(
            lambda value: value["services"]["api"]["environment"].__setitem__(
                "BUILD_INFO_MAX_SANDBOXES_PER_RUNNER", "3"
            )
        )
        self.assert_rejected(
            lambda value: value["services"]["api"]["environment"].__setitem__(
                "BUILD_CPU_CORES", "3"
            )
        )


if __name__ == "__main__":
    unittest.main()
