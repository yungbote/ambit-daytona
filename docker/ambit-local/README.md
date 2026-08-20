# Ambit self-hosted local Daytona

This directory defines the task-scoped Daytona provider used by Ambit when the
selected deployment is `self_hosted_local`. It does not target Daytona Cloud,
does not publish public ingress, and does not make a runtime pack current merely
because the containers start.

The stack is intentionally separate from `docker/docker-compose.yaml`, which is
an upstream development convenience with public ports, static development
credentials, telemetry, mutable image tags, disabled resource limits, and
unnecessary services. This profile keeps only API, proxy, runner, PostgreSQL,
Redis, MinIO, registry, and a passwordless OIDC issuer used for internal API
configuration. API, proxy, registry, and OIDC ports bind to `127.0.0.1`; every
service shares one Docker `internal` network; no dashboard login user, SSH
gateway, mail server, telemetry collector, registry UI, or cloud endpoint is
present.

The authoritative capacity selection is the backend-owned
`LocalDaytonaProviderCapacityProfile@1` at revision `4f7ef339`: 2 vCPU, 4 GiB
RAM, 20 GiB disk, and no GPU per sandbox; two concurrent sandboxes; aggregate
4 vCPU, 8 GiB, and 40 GiB. The API's default and admin organization quotas use
those exact values. The runner advertises that aggregate and runs with
`RESOURCE_LIMITS_DISABLED=false`. Ambit must still request the exact per-sandbox
resource vector on every full-image create; the compose file is not a substitute
for backend admission. The host gate additionally reserves explicit headroom of
2 CPU cores, 4 GiB RAM, and 20 GiB storage, so a passing observation must expose
at least 6 CPU cores, 12 GiB currently available RAM, and 60 GiB free on the
qualified `/home` filesystem.

All images, including the certified C16b runtime, are required as immutable
`image@sha256:...` references and use `pull_policy: never`. Generate the local
secret environment only after the exact service and runtime images exist:

```bash
export AMBIT_DAYTONA_API_IMAGE=...
export AMBIT_DAYTONA_PROXY_IMAGE=...
export AMBIT_DAYTONA_RUNNER_IMAGE=...
export AMBIT_DAYTONA_POSTGRES_IMAGE=...
export AMBIT_DAYTONA_REDIS_IMAGE=...
export AMBIT_DAYTONA_REGISTRY_IMAGE=...
export AMBIT_DAYTONA_MINIO_IMAGE=...
export AMBIT_DAYTONA_MINIO_MC_IMAGE=...
export AMBIT_DAYTONA_DEX_IMAGE=...
export AMBIT_C16B_RUNTIME_OCI_REFERENCE=registry:6000/ambit/runtime-pack-core-document@sha256:...
./docker/ambit-local/generate-environment.sh \
  /home/bote/m/.local/ambit-daytona-c16b/provider.env \
  /home/bote/m/.local/ambit-daytona-c16b/state
```

Run this stack only through an isolated Docker daemon whose `DockerRootDir` is
under `/home`; the normal daemon currently stores data on the capacity-limited
root filesystem and is not an admitted provider. `start-isolated-docker.sh`
creates a task-owned daemon with a distinct socket, data/exec roots, bridge,
address pool, pidfile, and bounded local logs inside the generated state root.
It does not reuse the host daemon's containerd namespace. Export the exact
`DOCKER_HOST` line it prints, then run `verify-host-capacity.sh` and preserve its
receipt before activation. `stop-isolated-docker.sh` verifies the exact pid and
config path before stopping the daemon; it leaves all state in place for
recovery and never touches the shared Docker daemon.

Starting containers is not a readiness receipt. `WorkspaceProviderExecutionReadiness@2`
remains unavailable until a live gate binds the exact source registry, profile,
full OCI image, pack promotion/materialization, helper/protocol, capacity
profile, and all fourteen named receipts: deployment, create, inspect, process,
PTY transport, atomic materialization, checkpoint/restore, terminate/cleanup,
cross-tenant isolation, credential absence, pack conformance,
authentication/organization, network/storage isolation, and host capacity
headroom.
