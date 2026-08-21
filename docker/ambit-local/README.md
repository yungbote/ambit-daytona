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

Run this stack only through `start-isolated-docker.sh`. The normal host daemon
is not an admitted provider. The start wrapper executes one exact-byte root
supervisor under `/usr/bin/unshare --mount --propagation private`; the
supervisor is the sole namespace holder and direct parent of the dedicated
containerd and dockerd. All three process identities bind exact executable,
full argument digest, parent PID, process start/proc inode, and the same mount
namespace device/inode. Provider containers correctly have separate child
namespaces; their storage acceptance is the exact XFS device/UUID exposed at
the runner's `/var/lib/docker`, not namespace-inode equality.

Privileged runner storage lives only below the fixed, root-owned, caller-
unrenameable authority `/home/.ambit-c16b-runner-storage`. Its closed roster is
the lifecycle lock, sparse 60 GiB `runner-docker.xfs`, `runner-docker` mount
target, and durable v2 receipt. The user-owned `STATE_ROOT` contains no runner
mountpoint or backing-image authority; it retains only config/logs and a
digest-bound projection. Compose binds the literal root-owned target with
`create_host_path: false` and `rprivate`, so a missing authority fails instead
of creating a user directory. `prepare-runner-storage.sh` deliberately refuses
host/caller mounting: storage activation belongs to the private supervisor.

Before XFS mount, the supervisor proves its `/home` propagation boundary is
private. It invokes exact-hash-pinned `runner-storage-lifecycle.py` and
`verify-runner-storage.py` snapshots from its root-only `/run/ambit-c16b-*`
runtime root. New image creation retains the exact image descriptor through
truncate, mkfs, loop attachment, and mount. Every mutating external tool runs
under a guardian that retains the same flock-bearing open-file description;
if the helper is killed, another lifecycle cannot interleave until the mutator
exits. The root receipt is file-fsynced, atomically renamed, and followed by an
authority-directory fsync before success; its user projection receives the
same durable ordering. Old receipt versions are never reinterpreted as v2 and
are accepted only by the explicit remove path.

The lifecycle reducer admits absent storage; zero/partial/exact root-owned
`0600` image cutpoints; published attached state; committed detached state; and
exact no-receipt startup-abort state. Only exact target length can format or
recover. Startup/deactivation response loss is idempotent, without fabricating
receipt authority. Teardown scans two stable passes of every mount namespace
observable through `/proc`, rejecting unreadable, changing, second, nested, or
foreign loop/target occurrences. The provider and daemon children must stop
before private unmount/detach. A namespace pinned without a live `/proc`
representative remains outside the source proof and is an explicit live
acceptance limit.

The supervisor publishes exact control v1 and start v4 receipts. Export the
`DOCKER_HOST` line returned by `start-isolated-docker.sh`, then run
`verify-host-capacity.sh`. The v4 gate re-proves supervisor/containerd/dockerd
before and after entering the exact supervisor namespace for a v2 storage
observation. It binds the live socket/server/data root, root receipt digest,
namespace, image/loop/UUID/quota identity, and user projection before applying
the 6-CPU, 12-GiB-memory, 60-GiB-backing, and 40-GiB-inner-free thresholds.
Free/total/allocated capacity remains a current observation rather than stable
identity, so ordinary use or online backing resize cannot strand recovery.

`stop-isolated-docker.sh` pidfd-signals only the exact supervisor. The
supervisor drains dockerd/provider children, reaps dockerd and containerd,
removes task network-namespace mounts, deactivates storage while its private
namespace still exists, writes the stop receipt, removes its root-only runtime
root, and exits last. Persistent image/UUID state remains recoverable across a
fresh private namespace after reboot. After exact stop, the separate
`remove-runner-storage.sh` operation can durably remove the user projection,
root receipt, image, target, lock, and empty authority root. No boot unit,
shared daemon config, global `/home` propagation mutation, or namespace bind
pin is installed.

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
