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
qualified `/home` filesystem. Exact outer service ceilings total 5.8 CPU cores
and 11.75 GiB: the runner receives 4.75 CPU/9 GiB (enclosing the two sandbox
ceilings), while the complete API/proxy/database/Redis/MinIO/registry/OIDC
control plane fits in the remaining 1.05 CPU/2.75 GiB. Every service, including
the one-shot bucket initializer, also has an exact PID, CPU, and memory bound.

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
creates a task-owned Docker daemon and a dedicated containerd. Their persistent
data roots and bounded logs live below the generated `/home` state root; only
short-lived sockets, PID files, and exec state live under one content-derived
`/tmp/ambit-c16b-docker-*` runtime directory to stay within Unix socket path
limits. That root is created atomically, opened with
`O_DIRECTORY|O_NOFOLLOW`, and re-proved by device, inode, owner, and mode
before daemon start, capacity measurement, and cleanup. The startup receipt
also binds each root-owned daemon's exact executable, complete argument vector,
process start time, and proc inode; a stale PID or substring match cannot
authorize capacity or shutdown. The daemon disables its default bridge and all
host iptables/ip6tables, forwarding, and masquerade mutation; Compose owns the
one internal provider bridge and the daemon uses a disjoint address pool. It
never connects to the shared host containerd or shared Docker graph; its minimal containerd config
also disables unused CRI and NRI plugins and imports no host configuration.
Export the exact `DOCKER_HOST`
line the start script prints, then run `verify-host-capacity.sh`; that gate
requires the exact socket, live server ID, data root, dedicated-containerd
process, startup receipt, and config hash before measuring headroom.
`stop-isolated-docker.sh` verifies both exact processes before stopping them,
removes only their content-derived ephemeral runtime directory, and leaves all
persistent `/home` state in place for recovery.

Daytona's runner applies Docker `StorageOpt[size]` only when its private Docker
data root is XFS. Before starting the provider stack, create the task-owned
quota filesystem with `prepare-runner-storage.sh STATE_ROOT`. It creates one
sparse 60 GiB image at `STATE_ROOT/capacity/runner-docker.xfs`, attaches one
loop device, and mounts it only at the already-declared
`STATE_ROOT/runner-docker` bind source with XFS project quotas. It adds no boot
configuration, systemd unit, or shared-daemon setting. `verify-host-capacity.sh`
requires the exact image inode, loop backing, XFS UUID/features, `pquota`, and
at least 40 GiB usable/free capacity before a host-headroom receipt can pass.
After stopping the provider stack, `remove-runner-storage.sh STATE_ROOT`
performs the complete rollback: it requires the live mount to byte-match the
stored receipt, refuses nested mounts or changed image identity, unmounts that
exact target, detaches only the receipt-bound loop device, and removes only the
image and receipt. It creates no boot-time residue.

The rendered Compose environment is a closed per-service key roster. Every
network endpoint used by the API, proxy, or runner is pinned to loopback or an
exact internal service name, and all telemetry/export targets remain empty or
explicitly disabled. Adding even an HTTP-only OTLP or PostHog endpoint fails
the deployment verifier.

Starting containers is not a readiness receipt. `WorkspaceProviderExecutionReadiness@2`
remains unavailable until a live gate binds the exact source registry, profile,
full OCI image, pack promotion/materialization, helper/protocol, capacity
profile, and all fourteen named receipts: deployment, create, inspect, process,
PTY transport, atomic materialization, checkpoint/restore, terminate/cleanup,
cross-tenant isolation, credential absence, pack conformance,
authentication/organization, network/storage isolation, and host capacity
headroom.
