# Private working-tree capture

`POST /sandboxes/:sandboxId/working-copy-captures/capabilities` is read-only.
The host API authorizes the source, owner, and workspace manifest fence, then
queries the sandbox's assigned Runner. The Runner binds its advertisement to
the same admitted capture authority used for file custody. The request contains
no stop receipt, file selector, or capture intent. Missing routes on older API or
Runner versions must leave this capability unavailable before the backend
creates a checkpoint intent or stops a generation.

The advertised `ambit.working-copy-stopped-working-tree/v1` contract uses the
private `ambit.workspace-zone/user-files@1` selector. Its current bounds are
64 path components, 4,096 entries, 1 GiB per file, 8 GiB of materialized regular
file bytes, 4 MiB per immutable range read, and 4 MiB per roster receipt. These
are complete-roster bounds, not pagination. Larger inventories need a paged
inventory contract; they must not be silently truncated or have dependency
directories excluded. Existing work/output capture policies remain separate.

`stopped-working-tree` reads a single Docker archive of the exact stopped
container's `/workspace`. It needs no anchor file and writes no capture objects.
Regular-file bodies are hashed with a fixed 64 KiB buffer. Managed roots
`.ambit` and `.ambit-skill-*` and exact host-owned mount paths are omitted. An
ordinary nested file called `.ambit` is user content.

Symlinks retain their exact target text, including relative, absolute, dangling,
Unicode, and control-character targets. They are not followed. Docker archive
hardlinks resolve only to admitted regular-file entries and materialize as
ordinary files; every resulting path counts toward the aggregate byte limit.
Targets outside the inventory, excluded targets, cycles, and non-file targets
fail the complete capture. FIFO and character/block devices have explicit
excluded entries. Docker can omit Unix sockets entirely, so the roster does not
claim to enumerate socket paths. Processes, sockets, and other live operating
system state are not restored by a portable file checkpoint.

File capture separately verifies every path component without following
symlinks and stages immutable bytes through the existing private object stream
store. Read, observe, delete, and existence operations retain the original
capture identity. The host API requires the sandbox row and assigned Runner to
route these operations: retire staging before deleting the sandbox, retaining
custody during retries. Removing a sandbox first makes host-API cleanup
unavailable even if the immutable objects still exist on its Runner.

Release the readers before the new Runner writer. First deploy backend readers
for private entry kinds, streamed file sizes, and asynchronous capability
discovery, together with the host API/client forwarding path. Old Runner 404s
remain unavailable. Then publish the matching admitted helper lineage and
Runner implementation. Verify discovery for the assigned sandbox before
enabling a generation stop. A rollback to an older API or Runner disables new
portable capture; preserve already-created capture custody until cleanup has
finished.

The opt-in `TestStoppedWorkingTreeDockerArchive` test uses
`DAYTONA_WORKINGCOPY_DOCKER_TEST_IMAGE` to select an already-installed image
containing Python 3. It never pulls images. It creates a task container and bind
mount, checks real Docker symlink and hardlink behavior, explicit special-file
omissions and socket loss, verifies 6 MiB file capture through 4 MiB reads, and
removes its own container afterward. Deterministic stream tests separately
exercise 102 MiB file hashing and allocation/read bounds, malformed archives,
generation drift, cancellation, and exact cross-language receipts.
