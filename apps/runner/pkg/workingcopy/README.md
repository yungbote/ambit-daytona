# Private working-tree capture

## Component identity and retained custody

The Runner measures its own `/proc/self/exe` bytes at startup. Its capture
interface is the canonical capture-route projection of the generated Runner
Swagger contract, including transitively referenced definitions. The projection
excludes unrelated routes and deployment host/version metadata. It is emitted
without a trailing newline by the source-owned qualification command:

```sh
go run ./apps/runner/cmd/capture-protocol > /absolute/capture-interface.json
sha256sum /absolute/capture-interface.json
```

This command emits interface bytes only. Independently extract and hash
`/usr/local/bin/daytona-runner` from the exact published native image to bind the
implementation artifact. A workspace materializer is a different component.
The former `AMBIT_WORKING_COPY_CAPTURE_LINEAGE_REF`,
`AMBIT_WORKING_COPY_CAPTURE_PROTOCOL_DIGEST`, and
`AMBIT_WORKING_COPY_CAPTURE_HELPER_DIGEST` settings no longer issue native
authority. Retire those obsolete settings through the normal deployment owner.

The backend runtime owns the caller's full-image qualification and lineage.
The native service verifies its requested role, interface and executable pins
against this Runner's measured component. Different correctly admitted image
lineages can use the same component; no Runner-wide image-lineage allowlist is
needed. Capability discovery uses the existing generation observer to reprove
the actual physical source, owner and manifest after API organization/sandbox
authorization. Source reads retain their existing independent generation checks.

Historical capture bindings, object keys, receipts and tombstones remain v2 and
unchanged. Complete capture and inventory replay, reads and cleanup validate
their exact retained custody without requiring the old component to be current.
Already captured, verified staged bytes can finish receipt publication. An
incomplete intent that still needs a mutable-source read must match the current
component and reprove its original generation; it is never silently rebound.
Unknown publication or cleanup outcomes remain unknown until reconciled.

Component measurement does not prove supply-policy compliance or the stronger
backing-file identity guarantee. In particular, the existing live reader's
upper-layer absence inference and metadata comparison still require independent
backing-file identity qualification. This component change neither modifies
that algorithm nor closes that release gate. A new image/target qualification
must truthfully bind the measured native component and interface before new
source effects can use it; source tests and capability echoes are not such a
qualification. Keep existing immutable custody readable during that rollout.

## Live file capture

The same capture API also accepts `fileSnapshot` with contract
`ambit.working-copy-file-snapshot/v1`, an exact execution generation, and its
workspace manifest fence. The bound generation may still be running or may
already have exited. This source authority is mutually exclusive with
`stopAuthority`. Capability discovery advertises `fileSnapshot` only when the
Runner has the native reader. It grants no permission to stop a workspace.

The native reader independently proves the container's owner, manifest,
execution epoch and running PID through the existing Docker generation
adapter. It opens the source through that task's pinned `/proc/<pid>/root`.
The semantic zone may be an admitted mount; descendant traversal rejects
symlinks, magic links, additional mounts, nonregular files and hardlink aliases.
Final path reproof starts at the container root again and compares the zone's
mount identity and the selected file's inode.

For a running source, Linux read leases exclude writable file descriptions
and writable shared mappings while the file is copied into the existing
private, immediately unlinked scratch. A lease watches one inode. On
overlayfs the writers of a copied-up file hold its upper inode, and the
overlay inode reports no writer once their descriptors close, so the reader
also opens that file under the storage driver's upper layer, with the same
path restrictions, and leases it too; an upper layer the driver does not
expose, or a mismatch between the two inodes, refuses the capture. A file
that is not copied up, or one on an admitted non-overlay mount, is leased
directly: the upper layer is resolved only while that lease is held, so any
write must first open it through the selected path, which breaks the lease.
A zone mount that is itself a foreign overlayfs has no known upper layer and
is refused. Leases do not stop a read-only open with O_TRUNC or a copy-up
caused by a metadata change; the exact metadata reproof after the copy
rejects those. The reader checks every lease and exact file metadata before
accepting the copy, and rechecks the container generation. A pending or
forced lease break, cancellation, source change, busy writer, or unsupported
filesystem produces no completed content object or receipt.
There is no ordinary-stream or whole-workspace-stop fallback. Writers can
proceed after the leases are released; the browser and other processes keep
running during capture.

For a source whose bound generation has already exited, the existing bounded
Docker archive reader proves that exact exited generation before and after
reading. It neither wakes the source, dispatches a stop, nor invents a
stopped-generation receipt; a generation that restarted is a conflict.

After that proof, the existing conditional content write, immutable receipt,
range reads, response-loss reconciliation and retirement tombstone own the
bytes. A replay with retained content never reads the mutable source again.
Capture does not claim a coherent multi-file application state: directory and
portable checkpoint operations still require their stopped-generation source.

Release compatible backend and host API readers before the Runner advertises
the new field. Roll out the native writer, verify its capability on every
assigned Runner, then enable the backend's ordinary publication selection.
Retained live-file capture intents require compatible readers through cleanup.
The backend migration refuses removal while any such intent is retained.

Native qualification uses the unchanged browser image in a disposable DinD
Runner with the existing rootless seccomp profile, dropped capabilities and
no-new-privileges. The test binary must run in the same PID and mount
namespaces as that Runner's Docker daemon, exactly as the production Runner
process does beside its own daemon; a remote Docker socket alone cannot supply
the native source descriptor or the upper layer path. The observed
configurations are Docker 28.5.2 with overlay2 on ext4, qualified with
metacopy on (the DinD daemon) and observed in production with metacopy off;
the reader is insensitive to that setting because bytes are read through the
overlay descriptor and the upper lease serves exclusion only. The host unit
test mounts its own overlayfs in a user namespace to exercise lower-only,
copied-up, mismatched-upper and foreign-mount files. Other
provider/kernel/filesystem targets require their own qualification and must
report unsupported writer exclusion honestly.

```sh
DAYTONA_FILE_SNAPSHOT_BROWSER_IMAGE=<already-installed-browser-image> \
DAYTONA_FILE_SNAPSHOT_EXPECTED_IMAGE_ID=sha256:<independently-verified-config-id> \
  ./workingcopy.test -test.run TestFileSnapshotDockerBrowserAndCustody -test.v
DAYTONA_FILE_SNAPSHOT_FORCE_BREAK_TEST=1 \
  ./workingcopy.test -test.run TestFileSnapshotKernelForcedLeaseBreakDiscardsCopy -test.v
```

The second test reads the existing kernel lease-break timeout and waits for a
real forced break. It never changes the host or namespace sysctl.

## Stopped working-tree capture

`POST /sandboxes/:sandboxId/working-copy-captures/capabilities` discovers the
assigned Runner's measured capture component and current physical generation
without stopping it or creating custody. The host API authorizes the sandbox, owner,
and workspace manifest fence before dispatch. An older API or Runner without
the inventory capability leaves portable capture unavailable.

The `ambit.working-copy-stopped-working-tree-inventory/v1` contract captures
`ambit.workspace-zone/user-files@1`. Preparation reads exactly one Docker archive
of the stopped container's `/workspace`. During that pass, regular-file bytes
flow into an immutable logical byte pack and metadata flows into bounded sorted
runs. Each metadata entry carries its pack offset and content digest. The
completed index pins every metadata page and every byte part before publication.
A successful replay reads that index without touching the source container.

An inventory supports up to 64 path components, 8 GiB per file and 8 GiB of
restored regular-file bytes. Each metadata page holds at most 4,096 entries and
4 MiB of canonical JSON. The index is separately bounded at 4 MiB. There is no
4,096-entry whole-tree limit. Physical archive, admitted metadata, and sort
scratch budgets are 16 GiB, 8 GiB, and 64 GiB respectively. These explicit byte
budgets bound resource use without excluding ordinary dependency directories.

The pack is divided into immutable parts of at most 1 GiB using the existing
single-PUT stream store. Parts follow byte boundaries, independently of files.
`stopped-working-tree-inventories/read-range` reads at most 4 MiB at an arbitrary
pack offset, including ranges that cross part boundaries. Every request pins
the original inventory identity and digest; the Runner verifies each part's
object checksum and metadata. The caller verifies complete pack and file
hashes. No per-file capture objects or per-file provider requests are needed.
The host can restore using a bounded range cache or a streamed local pack.

Preparation uses a fixed 64 KiB content buffer. Metadata sorting uses bounded
runs and a bounded merge fan-in; hardlink lookup uses the same sorted scratch
file. Scratch files are created private and immediately unlinked, so the OS
releases them on cancellation or process exit.

Managed roots `.ambit` and `.ambit-skill-*` and exact host-owned mount paths are
omitted. An ordinary nested file named `.ambit` remains user content. Symlinks
retain exact relative, absolute, dangling, Unicode, and control-character
target text without being followed. Docker hardlinks resolve only to admitted
regular files and share their pack offsets; each restored path counts toward
the logical aggregate byte budget. Targets outside the inventory, cycles,
non-file targets, duplicate paths, and missing directory ancestry fail capture.
FIFO and character/block devices have explicit excluded entries. Docker omits
Unix sockets, so the inventory does not claim to enumerate them. A portable
checkpoint restores files and directories, not processes or live OS state.

The inventory owns both its pages and byte parts. Deletion records the exact
custody counts before removing anything, supports retry after a lost response,
and verifies that the index, intent, pages, and bytes are absent. A retained
request tombstone prevents recreation. Partial preparation can also be retired
without a complete index. The assigned Runner serializes inventory operations;
the host must settle the producer before retiring its custody.

The host API still needs the sandbox row and assigned Runner to route reads and
cleanup. Retire inventory custody before deleting that row. Portable source
sandboxes can use the existing negative `autoDeleteInterval` to leave finite
cleanup with the host's durable retention owner; marker selection and the
retention horizon belong to the host. This inventory does not add another
sandbox lifecycle policy. Existing work/output file-capture policy remains
separate.

Release the host readers and forwarding routes before enabling the Runner
writer. The generated API and Runner clients include capability discovery,
preparation, page reads, range reads, and deletion. The Runner must use the
matching admitted capture lineage. Preserve existing custody across rollback
until its host cleanup completes.

## Verification

Use the repository Go development environment. The Docker tests require an
already installed Python 3 image and never pull an image:

```sh
DAYTONA_WORKINGCOPY_DOCKER_TEST_IMAGE=<installed-image> \
  go test -count=1 -v ./apps/runner/pkg/workingcopy \
  -run 'TestInventoryDockerRestores25000FilesAfterSourceDeletion|TestStoppedWorkingTreeDockerArchive'
```

The large-tree test creates 25,000 dependency files plus a large file, hardlink,
symlink, and empty directory in a disposable container. It requires more than
4 MiB of metadata, one archive pass, one byte object, and bounded page/range
requests. After removing the source container and restarting the service, it
restores the pack and every file; a fresh Docker consumer independently checks
all file contents, permissions, link text, and directory state. Inventory
cleanup must leave only its tombstone. The companion Docker test checks real
special-file and mount behavior and the established single-file capture path.

Deterministic and race tests cover metadata ordering and ancestry across pages,
hardlink resolution, cross-part byte ranges, partial publication and deletion,
immutable object conflicts, cancellation, stopped-generation drift, large-file
streaming, and byte-for-byte cross-language fixtures. Native Docker tests use a
file-backed private-object test store; live object-store publication and the
backend's durable checkpoint/restoration workflow require integrated deployment
acceptance.
