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
storage authority, and every source- or target-side storage mount are absent.
With no task runtime it is reduced under the removal operation's global lease;
during startup or shutdown it is reduced only after the storage helper proves
the inherited global-lease open-file description and the nonempty runtime
roster is a subset of the exact state-derived runtime/socket/cgroup paths. A
foreign v5 path or any legacy `/tmp` authority still blocks. A pending node
beside an authority remains fail-closed except inside the explicit legacy-v2
migration, where the old lock and receipt must first re-prove the complete
binding. The flock on the pinned
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
authority. Only mutating storage-helper calls inherit the boot-global runtime
lease; read-only observation does not. The admitted synchronous host tools
retaining inherited FDs and not
daemonizing remains a measured binary contract for live acceptance. The root
receipt is file-fsynced, atomically renamed, and followed by an
authority-directory fsync before success; its user projection receives the
same durable ordering. Random crash-temp names are not admitted. Old receipt
versions are never reinterpreted as v3. `remove-runner-storage.sh --legacy-v2`
is a separate remove-only transition for a fully published v2 authority: it
re-proves the exact existing state/image/receipt, retains the old lifecycle
flock, publishes the v3 claim before mutation, reduces only the historical
fixed-shape random authority-receipt and user-projection temporaries, then
removes the legacy lock and receipt
before using the ordinary reducer. The same legacy command is reentrant across
an interrupted v3 pending claim, a sealed claim with remaining legacy
material, every ordinary partial-delete cutpoint, and total absence. A v2
authority that never published its receipt, or retained only a partial image,
remains explicit admin recovery rather than being guessed. Normal activation
never adopts legacy state. If the caller renames or deletes `STATE_ROOT`, the
root claim and root runtime control retain the original binding: stop can be
invoked with the absent original path, and storage removal can use either that
original spelling or a relocated directory with the same immutable identity.
Neither route republishes or adopts the authority under a new normal path. A
relocated evidence directory contributes only its descriptor-pinned capability
to delete the nonauthoritative user projection; it never becomes receipt,
runtime, or root-storage authority. After the authority and claim are removed,
the exact lease-serialized tuple of absent original state path, absent claim
and pending claim, absent storage authority, absent task authorities, and zero
observable mount occurrences is itself the terminal response-loss state; no
persistent tombstone is added.

The dedicated containerd configuration uses schema v3, so the supervisor
preflights and requires containerd 2.x or later before launching it. The
installed binary version and all cgroup-controller behavior remain live host
admission measurements, not assumptions hidden by the source contract.

The lifecycle reducer admits absent storage; zero/partial/exact root-owned
`0600` image cutpoints; published attached state; committed detached state; and
exact no-receipt startup-abort state. Only exact target length can format or
recover. Startup/deactivation response loss is idempotent, without fabricating
receipt authority. A committed detached receipt with zero loop and mount
occurrences is replayed byte-for-byte: its historical detach namespace and
digest are not rewritten merely because finalization runs in a fresh private
namespace. Teardown scans two stable passes of every mount namespace
observable through `/proc`, rejecting unreadable, changing, second, nested, or
foreign loop/target occurrences. Ordinary filesystem mount roots use canonical
component-aware path coordinates. Linux `nsfs` roots such as
`net:[4026531833]` are retained as typed opaque identities and match only by
exact device plus token; they are never coerced to `/` or given descendant
semantics. Storage-tree checks carry nested filesystem anchors, so a bind
source below the authority mounted at an unrelated target is also a blocking
occurrence. Every live process representing the same mount namespace must
yield the same relevant mount view; a chroot-visible mismatch fails closed
instead of letting the first PID become authority. Representatives that all
share the same restricted root can still hide the same mount; that and a
namespace with no live representative remain outside the source proof. The provider and daemon
children must stop before private unmount/detach. A namespace pinned without a
live `/proc` representative therefore remains an explicit local-host
acceptance limit, not a claimed global proof. Static tests establish reducer and authority logic only; they
do not establish that this host has successfully created the cgroup, mounted
XFS, enforced project quotas, started the daemon, or completed two live 20 GiB
sandbox journeys.
Runtime-root cleanup carries the supervisor namespace's source coordinates
across every observed namespace as well. Before daemon start, immutable
`runtime-netns-baseline.json` records the preexisting host-network-namespace
source and its canonical ambient target set, including the normal host
Docker's legitimate `default` bind. Mount-namespace IDs remain observations,
not durable ambient identity, so a freshly unshared stop helper may inherit an
admitted target without changing authority. Shutdown first revokes new API admission,
then publishes `runtime-netns-detach.json` before signaling either daemon. The
detach authority binds baseline/control/stopping digests, boot,
state/runtime/namespace identities, each task target and typed source
coordinate, plus every owned occurrence at that target. Before unmount, every
occurrence target must belong to the stored ambient target set or the exact
runtime target, and the recorded supervisor occurrence must exist; afterward
only the ambient target set may remain. Sources absent from the baseline retain
the owned-target/zero-after rule. Same-process retry and external recovery
consume the same stored anchors and repeat aggregate target-set equality
immediately before runtime-tree deletion.
A surviving external bind therefore cannot disappear from the proof merely
because its original source mount was removed. If an abrupt death leaves task
entries but no live representative from which to author the first manifest,
automatic deletion blocks for admin recovery rather than inventing anchors.
Revoking the socket pathname prevents new clients but cannot prove that no
already-connected request is in flight; stop-time API quiescence remains an
explicit live acceptance observation under the single-user local-host model.

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
supervisor. Both bound and orphaned stop paths reject a foreign runtime,
socket, cgroup, or legacy `/tmp` authority before any process signal or cgroup
kill. Before draining anything the admitted supervisor durably publishes a
root stopping intent, so every later daemon/socket/storage cutpoint is
classifiable. Dead-supervisor recovery publishes the same stopping authority
after exact death proof and before its first cgroup or socket observation or
mutation. It then classifies the current socket, freezes and proves a populated
target cgroup, reclassifies the now-stable socket cutpoint, publishes or validates the
baseline and detach authorities, and only then uses `cgroup.kill`. A stopping
authority admits the reducer's exact intermediate empty socket root while a
present socket still requires its recorded identity. Normal shutdown removes the
caller socket, publishes the detach roster while source mounts still exist,
drains dockerd and containerd, cleans task network namespaces, deactivates
storage, writes a root stop
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

### Exact legacy-v3 drain boundary

The still-running pre-v5 daemon created on 2026-08-20 is not current runtime
authority and must never be passed to either the historical stop script or the
v5 stop operation. Its caller-owned v3 receipt records stable daemon PIDs,
start ticks, executables, argv digests, config digests, and the `/tmp` runtime
inode, but also records `/proc/<pid>` directory inodes. The kernel has
reinstantiated those procfs dentries for the same long-lived process, so the
old script's whole-JSON comparison now rejects before stopping. Numeric-PID
signals and its recursive `find -delete` fallback are not accepted recovery
mechanisms.

`drain-legacy-v3-runtime.sh` is a task-scoped, remove-only compatibility tool
for that one exact receipt and state root. It exposes only:

```text
verify-only /home/bote/m/.local/ambit-daytona-c16b/state
drain /home/bote/m/.local/ambit-daytona-c16b/state VERIFICATION_SHA256
resume /home/bote/m/.local/ambit-daytona-c16b/state
```

`verify-only` writes nothing and authorizes no mutation. It performs two
stable root-level passes over the exact receipt/config/runtime identities,
pidfd-stabilized daemon/wrapper/shim/task graph and every visible
`/proc/<tgid>/task/<tid>` Linux task (including non-leader threads with
unshared FD or mount-namespace authority), structured argv/cgroup
relations, runtime paths, mapped files, namespace and socket FDs, descendants,
Unix socket owners and the netlink Unix-diagnostic peer/pending-client graph
(including pathless endpoints), every observable mount
namespace, the full-ID ambient and owned nsfs occurrences, overlay and
registry binds, persistent roots, and the complete local registry blob
inventory. The legacy `procInode` values remain visible as
`ignored_unstable_procfs_dentry` observations; PID, start ticks, executable,
argv digest, credentials, namespace, cgroup, and topology remain mandatory.
Any unreadable namespace, foreign client/process/source target, substituted
path, unknown runtime entry, changed registry blob, residual v5 cgroup, or
coexisting v5 authority is a manual blocker. The legacy tool observes but
never mutates a cgroup. A residual matching v5 cgroup therefore requires a
separate v5-owned, exact-empty reconciliation before this drain; teaching the
legacy reducer to adopt it would cross the authority boundary and is
deliberately not a fallback.

The pidfd/edge, socket, and mount rosters are deterministic stable-sample
proofs, not a claim that Linux freezes every root-capable actor between two
syscalls. The reducer retains admitted pidfds for every thread in each
admitted role's thread group, repeats full edge proofs
immediately before and after non-signal actions, closes the caller's path
ingress through root custody, and fails closed on post-action drift. A
concurrent privileged actor could still create and release a transient edge
inside that interval; excluding that requires cgroup freeze or a broader host
quiescence authority, both deliberately outside this no-cgroup compatibility
tool. The eventual live drain gate must therefore measure that no such actor
is running; static tests do not turn this concurrency assumption into a proof.

`drain` recomputes that proof under the same boot-global lease used by v5 and
requires the caller-supplied verification digest. Its sanitized in-sudo loader
reads, hashes, compiles, and executes one exact source byte buffer; that same
buffer becomes its root-custodied snapshot. Source, control, and initial state
are built in one fixed root-owned staging capsule, file- and directory-fsynced,
then published together with `RENAME_NOREPLACE` and `/run` fsync. The final
capsule is therefore absent or complete, never a visible sequential prefix,
and every state is bound to the current boot. The reducer first transfers the
exact `/tmp` runtime-root inode to root custody. It then revokes only the bound
Docker socket, pidfd-signals exact dockerd with `SIGTERM`, and requires the
sudo wrappers, registry task, shim, overlay, registry bind, and all related
socket ownership to disappear before it may pidfd-signal containerd. It never
uses the shared 66-process caller cgroup, never sends `SIGKILL`, never signals a
shim or task directly, and never unmounts overlay or persistent data. After
both daemons are gone, the sole admitted mount mutation is an `umount2` through
the held `/proc/self/fd/<mount-fd>` binding for the exact legacy task nsfs
occurrence. Mount ID, parent ID, namespace, device, source root, filesystem,
target, and multiplicity must still equal the recorded roster. The transition
binds the held FD's kernel `mnt_id` immediately before `umount2`, must reveal
the root-owned, mode-0600, one-link, zero-byte underlying marker, persists that
exact marker device/inode in monotonic state, and leaves precisely the recorded
ambient host `default` occurrence. Foreign stacks at either admitted target are
included before source validation rather than filtered out.

The `/tmp` root stays at its legacy name as a root-owned empty marker until its
separate terminal `rmdir`, so v5 continues to see a blocker through every
partial cleanup. Before any runtime unlink, one complete descriptor-relative
preflight validates every remaining recorded entry and the descriptor-bound
containerd pidfile; a second pass performs deepest-first runtime reduction.
The stale pidfile is preserved as immutable legacy config evidence instead of
introducing a caller-owned-directory unlink race. Recorded runtime-entry
absences are ordinary response-loss replay, while any late foreign entry
blocks before destruction. The sole admitted symlink is containerd's standard
runtime-v2 bundle `.../ambit-c16b/<exact-container-id>/work` entry: it must be
root-owned, mode 0777, one-link, and contain the exact absolute text for the
preserved `outer-containerd/io.containerd.runtime.v2.task/.../<exact-id>` work
directory. Capture, both preflight passes, and reduction use one shared
`O_PATH|O_NOFOLLOW` entry verifier and reprove name/inode/type/link text
immediately before unlinking only that symlink entry. The target is never
opened, followed, walked, unlinked, or removed; every other symlink remains a
foreign blocker. The old outer Docker/containerd roots, registry, configs,
logs, and registry blobs are preserved.

After exact process, mount, runtime, pidfile, and registry reproof, the reducer
transfers the exact live receipt inode through the replayable original,
root-owned-mode-0600, and root-owned-mode-0400 custody states, then durably
enters `archive_intent_final`. It publishes and revalidates the deterministic
root-owned terminal projection from an unnamed `O_TMPFILE` with
`linkat(AT_EMPTY_PATH)`, so no caller-owned source name can be swapped into the
publication. The projection embeds the immutable control/authority, including
the original state, evidence, config, persistent-root, process, mount, pidfile,
and registry bindings; this lets reboot recovery reject a substituted
caller-owned state tree. The immutable control retains the exact original
receipt bytes.
The reducer constructs the archive in a second root-owned unnamed file, links
and fsyncs it first at the fixed hidden `*.prepared` recovery coordinate,
descriptor-rewrites the old live inode to a deterministic non-legacy
tombstone (including partial-tombstone replay), returns that tombstone to the
ordinary caller-owned mode-0600 projection identity accepted by v5 cleanup,
proves that the live path no longer has the legacy digest, and hard-links the
held prepared inode to
`outer-docker-receipt.legacy-v3-c7b6f7f5f77ae556.json`. That no-replace link is
the final authority mutation, followed only by evidence-directory fsync and
read-only destination reproof. A destination collision is never overwritten;
an exact legacy digest at both live and archive paths is a manual blocker.
Archive response loss returns the already stored terminal bytes without
rewriting state or projection, but first rebinds and fsyncs the recorded
evidence directory and then reproves the exact archive and live-digest
absence. The same settle-before-reproof rule covers response loss after the
projection and prepared links, including boot replay. If a reboot clears the
`/run` capsule after the projection/prepared boundary, `resume` enters the
pinned repository bytes,
revalidates the root-owned projection plus prepared original bytes and the
absent legacy runtime/PIDs, completes the caller-owned tombstone if necessary,
and performs the same final no-replace link. With a live capsule, `resume` uses
the loader-held control-root FD and executes the already-read snapshot bytes
in-process, never an admitted pathname. A timeout or foreign state stops for an
explicit manual route; the default tool has no force path.

The v5 barrier is global across every requested v5 `STATE_ROOT`. V5 recognizes
only the one literal audited live receipt path and digest, literal reserved
control path, literal prepared archive, and literal root-owned terminal
archive. Before a terminal archive, any occupied audited live, prepared, or
control path blocks; the exact legacy digest always blocks even if an archive
also exists. After the
terminal archive, the deterministic non-legacy tombstone or a later v5 receipt
may occupy the live path without reviving legacy authority. The unnamed-file
no-replace archive link is the final unblocking namespace mutation. Before a
v5 mutation may consume that visible handoff, the shared lifecycle-lease
holder descriptor-binds the literal legacy state/evidence directories, fsyncs
the evidence directory, and requires two identical FD-relative observations
of the source/control/prepared/archive truth and exact root-owned archive.
This closes response loss after `linkat` before directory fsync; a later
power-loss regression blocks instead of being admitted. Read-only preflight
does not claim durability. V5 does not parse, resume, repair, delete, or change
legacy control/state names or bytes, and regex-like sibling names do not
become this singleton authority. The compatibility boundary can be deleted as
a unit only after this local transition and its evidence-retention requirement
are explicitly retired.

Runtime-tree deletion has its own crash classification boundary. Only after
all runtime proofs pass does the reducer atomically rename the exact root to
`/run/ambit-c16b-docker-removing-<state-hash>` and fsync `/run`. Internal files
may then disappear in any order: retry recognizes the one exact removing name
and reduces any remaining admitted roster without depending on manifests it
is deleting. Startup, stop, and storage deletion treat a removing root as live
authority until its final parent-relative `rmdir` and fsync complete. The same
recovery dispatch then classifies and settles the exact absent-runtime socket
and cgroup boundaries before it can return, so a crash between the final tree
removal and cgroup removal re-enters the ordinary pre-control reducer. A
runtime-root creation error never starts a separate deletion loop: it leaves
the exact forward creation prefix for that same recovery transition.

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
