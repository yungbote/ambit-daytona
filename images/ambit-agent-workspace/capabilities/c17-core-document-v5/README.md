# C17 core document runtime pack @5

This directory builds the first complete structural and paginated DOCX runtime
candidate for `ambit.runtime-pack/core-document@5`. It combines:

- the exact locally qualified `ambit.runtime-pack/core@1` OCI parent, preserved
  as the complete ordered three-descriptor layer prefix;
- headless Debian LibreOffice Writer for DOCX-to-PDF conversion;
- PDF.js plus `@napi-rs/canvas` for bounded every-page PNG rendering;
- the frozen private structural Python runtime from the reviewed
  `core-document@4` candidate;
- the exact deterministic atomic file/tree materializer; and
- a root-owned installed-engine lineage plus an opaque backend current-component
  lineage input.

One shared builder computes a single additive rootfs overlay against that core,
rejects protected-core drift, deletions, special files, xattrs, and split
hardlink groups, and records the exact changed-path manifest. Copying the core
filesystem, rebuilding a lookalike, or using sequential last-writer-wins pack
layers does not satisfy this composition boundary.

The image is executable and locally verified. It is still a candidate, not an
active or production-certified runtime. Backend registration, a production
publisher signature, real Daytona/XFS conformance, and the remaining
third-party source/license/vulnerability reproofs stay outside this repository
candidate.

## Stable renderer interface

The installed executable is:

```text
/opt/ambit/runtime-pack/core-document-v5/bin/ambit-render-document \
  --framed-jsonl --nonce LOWERCASE_128_BIT_HEX
```

The stable component contract is:

- role: `ambit.runtime-component/document-renderer@1`;
- interface: `ambit.runtime-interface/docx-paginated-render@1`;
- digest:
  `sha256:b6848fe320d996287b69d4a279d4dc73a425d0e6d68999eceaf6d18d6347df7e`;
- exact preimage: `locks/document-render-interface.lock.json`.

There are no caller-supplied file paths. The provider opens one raw, no-echo
PTY, launches the exact helper, waits for its nonce-bound `ready` frame, and
sends canonical one-line JSON frames. A request is `request_start`, ordered
49,152-byte raw DOCX chunks encoded as canonical padded base64, and
`request_end`. The start frame carries the opaque backend lineage with exactly
`schemaRef`, `ref`, `digest`, and `canonicalBytesSha256`; the backend must
reprove that lineage before and after the render.

Every frame and nested field roster, discriminator, ordering rule, digest
equation, success equation, and cancellation equation is frozen in the
interface lock. That lock content-binds every transitive behavior owner, the
Dockerfile, toolchain manifest, and certification tools, so a wire, render,
custody, or build change cannot retain the old interface digest.

Before LibreOffice receives process authority, the wrapper admits one ordinary
single-disk OOXML ZIP with at most 2,048 parts, 64 MiB per part, 256 MiB total
expanded bytes, and 4 MiB of relationship XML. It rejects encryption, ZIP64,
unsafe or duplicate names, external relationships, macro/ActiveX/OLE payloads,
and embedded HTML. This deliberately gives up exotic embedded-object documents
so the common DOCX case has a deterministic, locally enforceable safety
boundary instead of relying on converter judgment.

The container must run with network disabled and a read-only root filesystem.
It requires bounded, container-private, UID/GID 1000, mode-0700 tmpfs mounts at
`/workspace` and `/tmp`. The exact workspace requirement is 800 MiB:
`max(64 MiB DOCX + 256 MiB PDF, 256 MiB PDF + 512 MiB pages) + 32 MiB`
of bounded manifest/filesystem overhead. The source DOCX is unlinked after
conversion, making the 800 MiB render peak the actual controlling branch. The
private cache requirement is 64 MiB. These derived values are frozen in policy
and the interface rather than relying on an ambient provider default.
The final filesystem contains neither apt/dpkg executables nor their mutable
configuration, cache, or package databases, and both writable mountpoints are
empty in the image before the provider supplies task-private tmpfs mounts.

## Output contract

A successful render first creates and independently verifies only these
mode-0444 files in a helper-owned private directory:

- `page-0001.png` through `page-NNNN.png`, densely ordered for every page;
- `render-manifest.json`, canonical compact JSON plus one newline.

The manifest schema is
`ambit.runtime-pack-paginated-render-manifest/v1`. It binds the immutable
source DOCX digest, policy, installed engine pins, opaque backend lineage,
every PNG digest/dimension/byte count, aggregate bounds, and a deterministic
manifest digest. Raw intermediate PDF metadata is deliberately excluded from
identity because LibreOffice varies non-rendered PDF metadata across otherwise
identical conversions; the exact intermediate byte count and the explicit
`excluded_volatile_converter_metadata` disposition remain visible.

Only after that seal passes does the helper emit ordered `page_start` and
`page_chunk` frames, followed by `manifest_start`, `manifest_chunk`, and one
terminal `response_end`. Each page is limited to 64 MiB and the aggregate is
limited to 512 MiB. The terminal binds the exact policy ref/digest, manifest,
frame count, and SHA-256 over the canonical UTF-8-plus-LF bytes of every prior
response frame. Missing, reordered, partial, or extra frames invalidate the
entire response; only `response_end` followed by helper exit 0 permits the host
to commit an artifact.

`renderer/render-output-verification.mjs` is the shared independent verifier;
`certification/verify_render_output.mjs` is its CLI. It reopens every private
output without following links, verifies PNG structure and digest, proves the
closed file roster, and recreates the manifest identity before framing begins.

An exact nonce-bound `cancel` aborts the whole-pipeline deadline, kills and
reaps the detached LibreOffice group or the separately isolated PDF.js/native
renderer group, bounds cleanup and every PTY write, removes both private roots,
and only then emits `cancelled` and exits 130. One terminal arbiter makes either
cancel win or atomically closes control admission before `response_end`; both
terminals await their transport write. The top helper never writes plaintext
diagnostics to the merged PTY. A lost PTY cannot be called a successful
cancellation. It requires a
provider quiescence receipt; the local adapter is pinned by
`locks/runtime-cancellation-authority.lock.json` to the reviewed XFS supervisor
and its exact stop-v2 all-authorities-removed receipt. Cloud provider
quiescence remains an activation gate rather than being inferred from a closed
socket.

## Signed offline inputs

The candidate uses the pinned Debian 13.6 amd64 base and two immutable signed
snapshot cutoffs:

- Debian: `20260802T202614Z`;
- Debian security: `20260802T121235Z`.

`certification/verify_signed_debian_snapshot.py` verifies the exact
`InRelease` signer rosters, signed package/source index identities, 142
runtime DEBs, one build-only xz extractor DEB, the 220-package installed
closure, 153 source packages / 502 source artifacts, 276 font files, and two
byte-identical offline installation derivations.

Node 24.19.0 is independently checked against its signed
`SHASUMS256.txt`. Public/frozen raw inputs use `public_inputs`; the private
materializer source and binary use the separate read-only
`materializer_inputs` context. No build `RUN` step has network access.

## Verification

From this directory:

```bash
PACK=$PWD
PYTHONPATH="$PACK" python3 -m unittest discover \
  -s "$PACK/certification" -t "$PACK" -p 'test_*.py' -v
node --test "$PACK"/renderer/test_*.mjs \
  "$PACK"/certification/test_verify_render_output.mjs
PYTHONPATH="$PACK" python3 "$PACK/certification/verify_source_contracts.py" \
  --root "$PACK"
PYTHONPATH="$PACK" python3 "$PACK/certification/verify_signed_debian_snapshot.py" \
  --input-root /path/to/preserved-debian-freeze --pack-root "$PACK"
PYTHONPATH="$PACK" python3 "$PACK/certification/audit_offline_inputs.py" \
  --pack-root "$PACK" --input-root /path/to/public-inputs --require-ready
```

Build the linux/amd64 candidate:

```bash
docker buildx build \
  --platform linux/amd64 \
  --pull=false \
  --build-context public_inputs=/path/to/public-inputs \
  --build-context materializer_inputs=/path/to/materializer-inputs \
  --build-context core_parent=oci-layout:///path/to/qualified-core-layout@sha256:ebedd4a1dbca59499468595db8f3aba140234eeb2b2fdcd4fcc0c8f99a5dda94 \
  --build-context composition_source=/path/to/images/ambit-agent-workspace \
  --target core_document_v5 \
  --tag ambit-c17-core-document-v5:candidate \
  --load .
```

A hardened provider launch uses a raw PTY and no input/output bind mounts:

```bash
docker run --rm -it --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /workspace:rw,noexec,nosuid,nodev,size=800m,uid=1000,gid=1000,mode=0700 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0700 \
  --entrypoint /bin/sh ambit-c17-core-document-v5:candidate -c \
  'stty raw -echo -onlcr && exec /opt/ambit/runtime-pack/core-document-v5/bin/ambit-render-document --framed-jsonl --nonce 0123456789abcdef0123456789abcdef'
```

The caller must set Daytona PTY input echo suppression, validate the exact
`ready` interface and policy digests, send the frozen frames, and validate the
terminal plus process exit. The source tests expose the same encoder and
mutants without making it a second operational interface.

## Boundaries that remain open

The image does not self-authorize activation. The remaining gates are:

- replayed backend registration/currentness on the authoritative backend main;
- backend PTY parser/currentness integration and provider cancellation receipt
  admission;
- a production publisher identity and signature for the final OCI manifest;
- real Daytona/XFS materializer, scratch-capacity, and lifecycle conformance;
- complete transitive Skia/Canvas source-license and production vulnerability
  evidence;
- final production Node/runtime vulnerability reproof; and
- live end-to-end product policy/repair acceptance against a registered image.

Working-copy capture is a backend/provider custody operation, not an in-image
helper. Removing that speculative image secret is what lets one renderer
contract work across Daytona and future workspace providers without moving
domain authority into the image.
