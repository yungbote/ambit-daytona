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
The sparse file is not advertised as preallocated storage: readiness also
requires its backing device to be the qualified state-root filesystem and at
least 60 GiB currently free there, records allocated bytes, and retains an
explicit ENOSPC failure mode if later host writes consume that headroom.
`prepare-runner-storage.sh` is idempotent after success and can reattach the
receipt-bound filesystem after reboot. The prepare and remove lifecycles hold
one exclusive lock on the descriptor-pinned state-root inode, so two task
invocations cannot interleave image, loop, mount, receipt, or cleanup state.
The host-readiness gate holds the matching shared descriptor lock across its
identity and headroom observation, so it cannot publish a receipt from the
middle of prepare or remove.
The shell wrappers own only that lock, live observation, receipt comparison,
and transition ordering. Every privileged capacity, image, filesystem, loop,
mount, unmount, detach, unlink, and rmdir mutation is centralized in
`runner-storage-lifecycle.py`. Before `sudo` executes it, a root launcher opens
the regular helper with `O_NOFOLLOW`, reads it once, requires the exact reviewed
SHA-256 embedded by both wrappers, and compiles only those verified in-memory
bytes. It uses the exact root-owned `/usr/bin/python3` with `-I -S -B`, an empty
environment containing only the exact task caller IDs and minimal root-owned
tool path, and `/` as its working directory. Caller-CWD modules, `PYTHONPATH`,
user site packages, bytecode writes, and helper pathname/in-place replacement
therefore cannot change the code that receives privilege.

The helper reduces the complete admitted prefix state instead of inferring
success from one happy-path shape. It recognizes absent storage, empty caller-
or root-owned `0700` capacity roots, the published root-owned `0711` root,
zero-length, partial-length, and exact-length caller/root `0600` image prefixes
interrupted before or during truncate and ownership transitions, and the empty
`0711` root left by interruption between image unlink and directory removal.
Only exact target length can proceed to formatting or published recovery;
incomplete images are teardown-only. It rejects symlinks, wrong
owner/group/mode/oversize/device/inode, foreign
children, and impossible prefixes without mutation. New creation retains the
original image descriptor continuously through truncate, ownership transfer,
formatting, loop attachment, and mount. Removal re-proves the same descriptor
identities and enumerates the loop major/minor in every mount namespace
observable through `/proc/<pid>/ns/mnt` and its matching `mountinfo`. Any
unreadable namespace fails closed; any second, nested, alternate-target, or
foreign-namespace mount blocks unmount, detach, and object deletion. This
requires the provider processes and their mount namespaces to be stopped
before removal. Only after the sole helper-namespace target is proved does the
helper unmount, rescan every observable namespace, detach, and unlink/rmdir
relative to pinned parent descriptors. Thus a normal failure, signal, process
kill, or power loss leaves either a completed identity or another explicitly
admitted prefix that the same reducer can finish; it does not require a one-off
manual pathname repair and creates no boot residue. A namespace pinned without
any live `/proc` representative is outside this source proof and remains a live
teardown acceptance check rather than an assumed guarantee.

The runner-storage receipt is an identity observation, not a readiness lease.
Ordinary sandbox use can reduce its inner free space below 40 GiB or its sparse
backing filesystem below 60 GiB without changing which image, XFS filesystem,
quota mount, or target the lifecycle owns. Recovery and teardown therefore
validate nonnegative current observations but apply no free-space threshold.
Backing-filesystem total/free bytes and sparse allocated bytes remain current
observations, not stable receipt identity; online backing resize does not force
an identity rewrite. Stable receipt comparison does bind the exact caller-owned
`0700` state-root device/inode/owner/group, root-owned `0711` capacity-root
device/inode/owner/group, and root-owned `0600` image identity.
Only `verify-host-capacity.sh` applies the current 40 GiB inner aggregate and
60 GiB backing-headroom thresholds. This keeps recovery and rollback available
at zero free bytes while preventing a near-full filesystem from receiving a
new host-readiness receipt.

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
