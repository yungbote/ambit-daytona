from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


IMAGE_RE = re.compile(
    r"^[a-z0-9][a-z0-9.:-]*(?:/[a-z0-9][a-z0-9._/-]*)+@sha256:[0-9a-f]{64}$"
)
HEX_RE = re.compile(r"^[0-9a-f]+$")
EXPECTED_SERVICES = frozenset(
    {"api", "proxy", "runner", "db", "redis", "minio", "minio-init", "registry", "dex"}
)
EXPECTED_IMAGES = frozenset(
    {
        "AMBIT_DAYTONA_API_IMAGE",
        "AMBIT_DAYTONA_PROXY_IMAGE",
        "AMBIT_DAYTONA_RUNNER_IMAGE",
        "AMBIT_DAYTONA_POSTGRES_IMAGE",
        "AMBIT_DAYTONA_REDIS_IMAGE",
        "AMBIT_DAYTONA_REGISTRY_IMAGE",
        "AMBIT_DAYTONA_MINIO_IMAGE",
        "AMBIT_DAYTONA_MINIO_MC_IMAGE",
        "AMBIT_DAYTONA_DEX_IMAGE",
        "AMBIT_C16B_RUNTIME_OCI_REFERENCE",
    }
)
SECRET_LENGTHS = {
    "AMBIT_DAYTONA_ADMIN_API_KEY": 64,
    "AMBIT_DAYTONA_ENCRYPTION_KEY": 64,
    "AMBIT_DAYTONA_ENCRYPTION_SALT": 64,
    "AMBIT_DAYTONA_POSTGRES_PASSWORD": 64,
    "AMBIT_DAYTONA_REDIS_PASSWORD": 64,
    "AMBIT_DAYTONA_MINIO_ACCESS_KEY": 32,
    "AMBIT_DAYTONA_MINIO_SECRET_KEY": 64,
    "AMBIT_DAYTONA_PROXY_API_KEY": 64,
    "AMBIT_DAYTONA_RUNNER_API_KEY": 64,
    "AMBIT_DAYTONA_HEALTH_API_KEY": 64,
}
EXPECTED_PORT_KEYS = frozenset(
    {
        "AMBIT_DAYTONA_API_PORT",
        "AMBIT_DAYTONA_PROXY_PORT",
        "AMBIT_DAYTONA_DEX_PORT",
        "AMBIT_DAYTONA_REGISTRY_PORT",
    }
)
EXPECTED_OUTER_CAPS = {
    "api": (0.5, 1 * 1024**3, 1024),
    "proxy": (0.05, 128 * 1024**2, 256),
    "runner": (4.75, 9 * 1024**3, 8192),
    "db": (0.2, 512 * 1024**2, 256),
    "redis": (0.05, 128 * 1024**2, 256),
    "minio": (0.1, 512 * 1024**2, 256),
    "minio-init": (0.05, 128 * 1024**2, 64),
    "registry": (0.05, 128 * 1024**2, 256),
    "dex": (0.05, 256 * 1024**2, 256),
}
FORBIDDEN_SERVICE_KEYS = frozenset(
    {
        "annotations",
        "cap_add",
        "cgroup",
        "cgroup_parent",
        "configs",
        "credential_spec",
        "develop",
        "device_cgroup_rules",
        "devices",
        "dns",
        "dns_opt",
        "dns_search",
        "extra_hosts",
        "external_links",
        "group_add",
        "ipc",
        "links",
        "network_mode",
        "pid",
        "runtime",
        "secrets",
        "security_opt",
        "sysctls",
        "use_api_socket",
        "userns_mode",
        "uts",
        "volumes_from",
    }
)
PROFILE_REF = "ambit.workspace-provider-capacity/local-daytona@1"
PROFILE_DIGEST = "sha256:9326b853b19bb4c1e0704f676751fec9269832be45fe3610b61f8644256e6cfe"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    require(isinstance(value, dict), f"expected JSON object: {path}")
    return value


def parse_env(path: Path) -> dict[str, str]:
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, "provider environment must have mode 0600")
    require(path.stat().st_uid == os.getuid(), "provider environment owner differs from verifier")
    values: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        require(line and not line.startswith("#") and "=" in line, f"invalid environment line {line_number}")
        key, value = line.split("=", 1)
        require(key not in values, f"duplicate environment key: {key}")
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is not None, f"invalid environment key: {key}")
        require(value and not any(ord(character) < 32 for character in value), f"empty/control value: {key}")
        values[key] = value
    expected = EXPECTED_IMAGES | frozenset(SECRET_LENGTHS) | EXPECTED_PORT_KEYS | {
        "AMBIT_DAYTONA_STATE_ROOT"
    }
    require(set(values) == expected, "provider environment key roster differs")
    for key in EXPECTED_IMAGES:
        require(IMAGE_RE.fullmatch(values[key]) is not None, f"image is not immutable: {key}")
    for key, length in SECRET_LENGTHS.items():
        require(
            len(values[key]) == length and HEX_RE.fullmatch(values[key]) is not None,
            f"generated secret shape is invalid: {key}",
        )
    ports = [int(values[key]) for key in sorted(EXPECTED_PORT_KEYS)]
    require(all(1024 <= value <= 65535 for value in ports), "provider port is outside the unprivileged range")
    require(len(set(ports)) == len(ports), "provider ports must be unique")
    return values


def validate_capacity_lock(value: dict[str, Any]) -> None:
    require(value.get("schema") == "ambit.local-daytona-provider-capacity-lock/v1", "capacity lock schema")
    profile = value.get("profile")
    require(isinstance(profile, dict), "capacity profile is absent")
    require(
        profile
        == {
            "contract": "LocalDaytonaProviderCapacityProfile@1",
            "profileRef": PROFILE_REF,
            "provider": "daytona",
            "deployment": "self_hosted_local",
            "resourceLimitsDisabled": False,
            "providerStoragePath": "/home",
            "perSandbox": {
                "cpuCores": 2,
                "memoryBytes": 4294967296,
                "diskBytes": 21474836480,
                "gpuCount": 0,
            },
            "maxConcurrentSandboxes": 2,
            "aggregate": {
                "cpuCores": 4,
                "memoryBytes": 8589934592,
                "diskBytes": 42949672960,
                "gpuCount": 0,
            },
            "digest": PROFILE_DIGEST,
        },
        "capacity lock differs from the selected backend authority",
    )
    readiness = value.get("readiness")
    require(
        isinstance(readiness, dict)
        and readiness.get("contract") == "WorkspaceProviderExecutionReadiness@2"
        and readiness.get("provider") == "daytona"
        and readiness.get("deployment") == "self_hosted_local"
        and readiness.get("apiExposure") == "loopback_only"
        and readiness.get("requiredHostReceipt") == "hostCapacityHeadroom",
        "readiness V2 lock is invalid",
    )


def exact_environment(service: dict[str, Any], expected: dict[str, str], name: str) -> None:
    environment = service.get("environment")
    require(isinstance(environment, dict), f"{name} environment is absent")
    for key, value in expected.items():
        require(environment.get(key) == value, f"{name} environment differs: {key}")


def validate_compose(config: dict[str, Any], values: dict[str, str], state_root: Path) -> dict[str, Any]:
    require(config.get("name") == "ambit-daytona-local", "compose project name is invalid")
    services = config.get("services")
    require(isinstance(services, dict) and set(services) == EXPECTED_SERVICES, "service roster differs")
    for name, service in services.items():
        require(isinstance(service, dict), f"service is invalid: {name}")
        require(IMAGE_RE.fullmatch(str(service.get("image", ""))) is not None, f"mutable image: {name}")
        require(service.get("pull_policy") == "never", f"service may pull an ambient image: {name}")
        require("build" not in service, f"service has an ambient build definition: {name}")
        require(set(service.get("networks", {})) == {"provider"}, f"service network differs: {name}")
        present_forbidden = sorted(key for key in FORBIDDEN_SERVICE_KEYS if key in service)
        require(not present_forbidden, f"service exposes a forbidden host namespace/surface: {name}: {present_forbidden}")
        require(bool(service.get("privileged", False)) == (name == "runner"), f"privilege differs: {name}")
        expected_cpu, expected_memory, expected_pids = EXPECTED_OUTER_CAPS[name]
        require(float(service.get("cpus", 0)) == expected_cpu, f"outer CPU ceiling differs: {name}")
        require(int(service.get("mem_limit", 0)) == expected_memory, f"outer memory ceiling differs: {name}")
        require(int(service.get("pids_limit", 0)) == expected_pids, f"outer PID ceiling differs: {name}")

    networks = config.get("networks")
    require(
        isinstance(networks, dict)
        and set(networks) == {"provider"}
        and networks["provider"].get("internal") is True
        and networks["provider"].get("driver") == "bridge",
        "provider network is not one internal bridge",
    )

    expected_ports = {
        "api": (int(values["AMBIT_DAYTONA_API_PORT"]), 3000),
        "proxy": (int(values["AMBIT_DAYTONA_PROXY_PORT"]), 4000),
        "registry": (int(values["AMBIT_DAYTONA_REGISTRY_PORT"]), 6000),
        "dex": (int(values["AMBIT_DAYTONA_DEX_PORT"]), 5556),
    }
    for name, service in services.items():
        ports = service.get("ports", [])
        if name not in expected_ports:
            require(not ports, f"internal service publishes a host port: {name}")
            continue
        require(isinstance(ports, list) and len(ports) == 1, f"published port roster differs: {name}")
        port = ports[0]
        require(
            isinstance(port, dict)
            and port.get("host_ip") == "127.0.0.1"
            and int(port.get("published")) == expected_ports[name][0]
            and int(port.get("target")) == expected_ports[name][1]
            and port.get("protocol") == "tcp",
            f"published port is not exact loopback: {name}",
        )

    expected_mounts = {
        "runner": {"/var/lib/docker": "runner-docker", "/home/daytona/runner": "runner-log"},
        "db": {"/var/lib/postgresql/data": "postgres"},
        "redis": {"/data": "redis"},
        "minio": {"/data": "minio"},
        "registry": {"/var/lib/registry": "registry"},
        "dex": {"/etc/dex/config.yaml": "config/dex.yaml", "/var/dex": "dex"},
    }
    for name, service in services.items():
        expected = expected_mounts.get(name, {})
        mounts = service.get("volumes", [])
        require(isinstance(mounts, list) and len(mounts) == len(expected), f"mount roster differs: {name}")
        observed: dict[str, str] = {}
        for mount in mounts:
            require(isinstance(mount, dict) and mount.get("type") == "bind", f"non-bind mount: {name}")
            source = Path(str(mount.get("source", "")))
            target = str(mount.get("target", ""))
            require(source.is_absolute(), f"relative mount source: {name}")
            require(source.resolve() == source, f"symlinked/non-canonical mount source: {name}")
            require(os.path.commonpath([state_root, source]) == str(state_root), f"mount escapes state root: {name}")
            observed[target] = str(source.relative_to(state_root))
        require(observed == expected, f"mount targets differ: {name}")

    api_expected = {
        "DEFAULT_SNAPSHOT": values["AMBIT_C16B_RUNTIME_OCI_REFERENCE"],
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
    exact_environment(services["api"], api_expected, "api")
    exact_environment(
        services["runner"],
        {
            "RESOURCE_LIMITS_DISABLED": "false",
            "INTER_SANDBOX_NETWORK_ENABLED": "false",
            "GPU_ENABLED": "false",
            "INITIALIZE_DAEMON_TELEMETRY": "false",
            "OTEL_LOGGING_ENABLED": "false",
            "OTEL_TRACING_ENABLED": "false",
        },
        "runner",
    )
    outer_cpu = sum(value[0] for value in EXPECTED_OUTER_CAPS.values())
    outer_memory = sum(value[1] for value in EXPECTED_OUTER_CAPS.values())
    require(outer_cpu <= 6, "provider outer CPU ceilings exceed aggregate plus headroom")
    require(outer_memory <= 12 * 1024**3, "provider outer memory ceilings exceed aggregate plus headroom")

    rendered = json.dumps(config, sort_keys=True)
    require("https://" not in rendered, "compose contains an external HTTPS target")
    require("supersecret" not in rendered and "local_development_admin_api_key" not in rendered, "development secret leaked")
    require("phc_bYtEsdMDr" not in rendered, "telemetry credential leaked")

    return {
        "schema": "ambit.local-daytona-compose-verification/v1",
        "outcome": "passed",
        "provider": "daytona",
        "deployment": "self_hosted_local",
        "api": {
            "origin": f"http://127.0.0.1:{values['AMBIT_DAYTONA_API_PORT']}",
            "exposure": "loopback_only",
        },
        "providerCapacity": {"profileRef": PROFILE_REF, "profileDigest": PROFILE_DIGEST},
        "runtimeImage": values["AMBIT_C16B_RUNTIME_OCI_REFERENCE"],
        "serviceImages": {name: services[name]["image"] for name in sorted(services)},
        "serviceRoster": sorted(services),
        "publishedPorts": {
            name: {"host": "127.0.0.1", "published": published, "target": target}
            for name, (published, target) in sorted(expected_ports.items())
        },
        "network": {"name": "provider", "driver": "bridge", "internal": True},
        "stateRoot": str(state_root),
        "resourceLimitsDisabled": False,
        "interSandboxNetworkEnabled": False,
        "outerResourceCeilings": {
            "cpuCores": outer_cpu,
            "memoryBytes": outer_memory,
            "diskReservationBytes": 60 * 1024**3,
            "services": {
                name: {"cpuCores": cpu, "memoryBytes": memory, "pids": pids}
                for name, (cpu, memory, pids) in sorted(EXPECTED_OUTER_CAPS.items())
            },
        },
        "credentials": {"source": "local_generated_environment", "includedInReceipt": False},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-config", required=True, type=Path)
    parser.add_argument("--compose-source", required=True, type=Path)
    parser.add_argument("--capacity-lock", required=True, type=Path)
    parser.add_argument("--environment", required=True, type=Path)
    parser.add_argument("--dex-config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    values = parse_env(args.environment)
    state_root = Path(values["AMBIT_DAYTONA_STATE_ROOT"])
    require(state_root.is_absolute() and str(state_root).startswith("/home/"), "state root is not under /home")
    require(state_root.resolve() == state_root, "state root is not one canonical non-symlink path")
    require(stat.S_IMODE(state_root.stat().st_mode) == 0o700, "state root must have mode 0700")
    require(state_root.stat().st_uid == os.getuid(), "state root owner differs from verifier")
    require(args.dex_config == state_root / "config/dex.yaml", "Dex config is not in the state root")
    require(stat.S_IMODE(args.dex_config.stat().st_mode) == 0o600, "Dex config must have mode 0600")
    require(args.dex_config.resolve() == args.dex_config, "Dex config is a symlinked path")
    dex_text = args.dex_config.read_text()
    require("staticPasswords" not in dex_text and "enablePasswordDB: false" in dex_text, "Dex exposes a password login")

    capacity_lock = load_object(args.capacity_lock)
    validate_capacity_lock(capacity_lock)
    config = load_object(args.compose_config)
    receipt = validate_compose(config, values, state_root)
    receipt["inputs"] = {
        "composeSourceSha256": sha256(args.compose_source),
        "capacityLockSha256": sha256(args.capacity_lock),
        "environment": {"mode": "0600", "keyRoster": sorted(values), "valuesIncluded": False},
        "dexConfig": {"mode": "0600", "passwordDatabase": False},
    }
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
