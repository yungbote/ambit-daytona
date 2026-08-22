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
supervisor under `/usr/bin/unshare --mount --propagation private`. Before it
spawns any helper or daemon, the supervisor creates one exact, otherwise-empty
root-owned cgroup v2 boundary, enables only the admitted CPU, memory, and PID
controllers, and enters its `runtime` leaf. Docker is fixed to the cgroupfs
driver and the empty boundary as `cgroup-parent`, so provider workloads are
siblings of the runtime leaf but descendants of the same `cgroup.kill`
authority. It is the direct parent of the dedicated containerd and dockerd.
All three process identities bind
exact executable, full argument digest, process start ticks, and mount
namespace device/inode plus exact cgroup path. Parent PID remains a live-
topology assertion rather than immutable recovery identity; procfs directory
inodes are deliberately excluded because the kernel can reinstantiate them for
the same long-lived process. Provider containers correctly have separate
child namespaces; their storage acceptance is the exact XFS device/UUID
exposed at the runner's `/var/lib/docker`, not namespace-inode equality.

Privileged runner storage lives only below the fixed, root-owned, caller-
unrenameable authority `/home/.ambit-c16b-runner-storage`. Before that root can
exist, the helper durably publishes a domain-separated, hash-named, root-owned
claim directly below `/home`; the filename and durably stored canonical bytes
bind the exact caller, `STATE_ROOT`, and evidence-directory
device/inode/owner/group/mode. Claim bytes are first written and file-fsynced
under one fixed admitted pending name, then atomically renamed to the final
hash name and followed by a `/home` fsync, so a published final claim is never
partial. A prepublication pending node is reducible only while the final claim,
storage authority, every task runtime/cgroup, and every source- or target-side
storage mount are all absent. A pending node beside an authority is deliberate
fail-closed admin evidence, not guessed or discarded. The flock on the pinned
`/home` descriptor is the sole lifecycle lock, so there is no crash-prone lock
file. That flock is advisory under the explicit single-user local-host model:
an unrelated holder can cause the bounded availability timeout, but cannot
gain claim authority. The authority contains the sparse 60 GiB `runner-docker.xfs`, the
`runner-docker` XFS mount, the dedicated `inner-runner` data directory, durable
v3 receipt, and root-owned outer dockerd/containerd directories. Compose binds
only the literal `runner-docker/inner-runner` directory to the privileged
runner's `/var/lib/docker`, with `create_host_path: false` and `rprivate`; it
cannot see or mutate the outer daemon roots. The user-owned `STATE_ROOT`
contains only config/logs and digest-bound projections. The prepare wrapper
deliberately refuses host mounting: activation belongs to the private
supervisor.

Before XFS mount, the supervisor proves its `/home` propagation boundary is
private. It snapshots the exact supervisor, process verifier, storage helper,
and storage verifier into its root-only `/run/ambit-c16b-*` runtime root before
publishing any control authority or mutating storage. New image creation
retains the exact image descriptor through
truncate, mkfs, loop attachment, and mount. Every mutating external tool runs
under a bounded process-group guardian; the helper, guardian, and mutator all
receive the same flock-bearing open-file description. Helper death leaves the
guardian waiting; guardian death delivers kernel `PDEATHSIG` to the direct
tool; supervisor death uses the task cgroup as descendant termination
authority. The admitted synchronous host tools retaining inherited FDs and not
daemonizing remains a measured binary contract for live acceptance. The root
receipt is file-fsynced, atomically renamed, and followed by an
authority-directory fsync before success; its user projection receives the
same durable ordering. Random crash-temp names are not admitted. Old receipt
versions are never reinterpreted as v3. `remove-runner-storage.sh --legacy-v2`
is a separate remove-only transition for a fully published v2 authority: it
re-proves the exact existing state/image/receipt, retains the old lifecycle
flock, publishes the v3 claim before mutation, reduces only the historical
fixed-shape random receipt temporaries, then removes the legacy lock and receipt
before using the ordinary reducer. A prepublication/partial-image v2 authority
or a migration pending claim beside an authority remains explicit admin
recovery rather than being silently rebound. Normal activation never adopts
legacy state. If the caller renames or deletes `STATE_ROOT`, the
root claim and root runtime control retain the original binding: stop can be
invoked with the absent original path, and storage removal can use either that
original spelling or a relocated directory with the same immutable identity.
Neither route republishes or adopts the authority under a new normal path. A
relocated evidence directory contributes only its descriptor-pinned capability
to delete the nonauthoritative user projection; it never becomes receipt,
runtime, or root-storage authority.

The dedicated containerd configuration uses schema v3, so the supervisor
preflights and requires containerd 2.x or later before launching it. The
installed binary version and all cgroup-controller behavior remain live host
admission measurements, not assumptions hidden by the source contract.

The lifecycle reducer admits absent storage; zero/partial/exact root-owned
`0600` image cutpoints; published attached state; committed detached state; and
exact no-receipt startup-abort state. Only exact target length can format or
recover. Startup/deactivation response loss is idempotent, without fabricating
receipt authority. Teardown scans two stable passes of every mount namespace
observable through `/proc`, rejecting unreadable, changing, second, nested, or
foreign loop/target occurrences. Storage-tree checks translate the trusted
namespace path into device plus filesystem-root coordinates and carry nested
filesystem anchors, so a bind source below the authority mounted at an
unrelated target is also a blocking occurrence. The provider and daemon
children must stop before private unmount/detach. A namespace pinned without a
live `/proc`
representative remains outside the source proof; choosing one representative
also inherits that process's mountinfo/chroot visibility. These are explicit
live acceptance limits, not a claimed global proof. Static tests establish reducer and authority logic only; they
do not establish that this host has successfully created the cgroup, mounted
XFS, enforced project quotas, started the daemon, or completed two live 20 GiB
sandbox journeys.

Pre-v5 `/run` daemon state has no root control or supervisor snapshot and is
therefore never guessed or auto-adopted by this source. This packet is the
first authorized live candidate; if an operator has independently run an older
v4 prototype, they must stop it with that exact frozen source (or perform an
explicit root-admin purge) before using the v5 launcher. Persistent v2 storage
has the separate authenticated `--legacy-v2` remove-only path described above.
The v5 status/start/absent-stop path also rejects any legacy
`/tmp/ambit-c16b-docker-*` runtime directory with a precise drain diagnostic;
caller-writable old receipts never authorize a signal or cgroup kill.

The supervisor first publishes root-owned, canonical control v2 and ready v5
manifests; caller-owned control/start files are projections only and never
authorize a root signal or deletion. Root custody remains `0700`. The Docker
API socket alone lives at `/run/ambit-c16b-docker-api-<state-hash>/docker.sock`
under a root:`<caller-primary-gid>` `0750` directory, with exact `0660` socket
identity. This grants Docker-root-equivalent authority to that local primary
group and exposes no pinned sources or configs. Export the `DOCKER_HOST` line
returned by `start-isolated-docker.sh`, then run `verify-host-capacity.sh`. The
v5 gate brackets private v3 storage and single Docker-info observations with
three exact root-status proofs. It binds the live socket/server/data root,
root ready digest, root storage receipt digest, namespace,
image/loop/UUID/quota-capable-mount identity, declared quota policy, and user projection before applying
the 6-CPU, 12-GiB-memory, 60-GiB-backing, and 40-GiB-inner-free thresholds.
Free/total/allocated capacity remains a current observation rather than stable
identity, so ordinary use or online backing resize cannot strand recovery.

One deterministic root-owned `/run` lease serializes start, stop, recovery,
and final storage deletion
for the boot and is never unlinked while the boot is live. Stop invokes the
root-custodied supervisor snapshot, which pidfd-signals only the exact recorded
supervisor. Before draining anything it durably publishes a root stopping
intent, so every later daemon/socket/storage cutpoint is classifiable. The
supervisor drains dockerd and containerd, removes the caller
socket, cleans task network namespaces, deactivates storage, writes a root stop
manifest, and exits. The outside recovery process then proves the task cgroup
empty (or writes to its exact `cgroup.kill` and waits for `populated 0`),
descriptor-removes the ephemeral runtime root, removes empty descendant
cgroups bottom-up and then the boundary, and
publishes the caller stop projection. A killed supervisor follows the same
bounded recovery path; no descendant discovery guess is used. Persistent
image/UUID state remains recoverable across a fresh private namespace after
reboot. After exact stop, the separate
`remove-runner-storage.sh` operation can durably remove the user projection,
root receipt, image, target, outer daemon roots, and empty authority root, then
remove the durable claim last. No boot unit,
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
