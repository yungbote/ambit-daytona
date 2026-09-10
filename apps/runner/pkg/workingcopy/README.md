# Private working-tree capture

`POST /sandboxes/:sandboxId/working-copy-captures/capabilities` discovers the
assigned Runner's admitted capture authority without reading Docker, stopping
a generation, or creating custody. The host API authorizes the sandbox, owner,
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
