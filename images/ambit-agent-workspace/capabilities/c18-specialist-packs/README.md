# C18 specialist runtime packs

This directory is the isolated source boundary for the four C18 specialist
runtime packs. It does not modify or reinterpret the C16b core/document pack
or the C17 `core-document@5` work. The Skill resolver composes exact pack
revisions; there is deliberately no one-pack-per-Skill rule.

| pack | shared C18 use | reason for its boundary |
|---|---|---|
| `office-authoring` | spreadsheets and presentations | Calc/Impress share OOXML, fonts, rendering, and LibreOffice release/licensing cadence |
| `pdf-ocr` | PDF creation, inspection, redaction checks, scan cleanup, and OCR | hostile parser inputs, OCR language data, Ghostscript/qpdf/Poppler patch cadence, and external signing authority |
| `data-research` | data analysis and research | one Python numerical/query/notebook environment avoids duplicate NumPy/Arrow/DuckDB stacks and captures one reproducible seed/environment boundary |
| `web-browser` | web applications and research browser QA | browsers and Node require a much faster security refresh cadence and a separate browser sandbox/preview boundary |

Splitting spreadsheet and presentation Python packages would duplicate the
same native office/font closure. Splitting local data analysis from research
would duplicate the largest wheel graph. Conversely, combining browsers or
PDF parsers with either pack would tie unrelated security release trains and
inflate ordinary artifact workspaces. Those are concrete boundaries; no
extra abstraction is added for speculative media, GPU, mobile, CAD, security,
Windows, or macOS executors.

## Truth boundary

The source locks freeze exact Python wheels, signed Debian snapshot members,
font inputs, browser source image, Node package archives, and version probes.
The Dockerfiles are intentionally dark until a complete external build-input
context supplies every named native/source/license artifact. Missing evidence
cannot be replaced with a build argument, mutable tag, runtime download, or
consumer-produced archive.

Promotion additionally requires the C16-owned exact union-overlay receipt.
C18 emits one closed offline artifact/installer bundle per specialist pack;
the composition authority must resolve the complete selected bundle set before
installation, prove one-owner-or-byte-identical-shared path ownership, inherit
the literal qualified core OCI layer prefix, add one closed conflict-resolved
overlay, and bind the resulting manifest to non-root probes, every selected
pack's conformance, SBOM, provenance, signature, license, and vulnerability
evidence. A standalone specialist image, copied rootfs, matching tool version,
sorted layer set, or pack-only test cannot certify a composed runtime.

The Playwright source image is Ubuntu-based while the reusable document/data
core is Debian-based. Those roots are not ABI-compatible layers and must never
be presented as one union. The browser pack is therefore a separate exact
executor-image candidate whose profile must independently satisfy the stable
core command/filesystem contract. A research closure selects the data and
browser executors as two explicit jobs; it does not manufacture one mixed
rootfs. The C16 composition authority may produce a literal core-prefix union
for compatible Debian bundles and may select separately certified executor
images for incompatible runtime families, but every selected image remains
manifest-bound and conformance-gated. Until those receipts pass, the web pack
remains a candidate even when its isolated MCR-based conformance is green.

All runtime package installers are removed. OS packages and Python/Node
dependencies are resolved during the image build from exact offline inputs.
Conformance runs with no network, no Linux capabilities, no new privileges,
a read-only runtime root, task-private scratch, and no host/container socket.

## Explicitly unsupported fidelity

`office-authoring` supports LibreOffice-based Linux behavior. It does **not**
claim native Microsoft Excel or PowerPoint fidelity, VBA execution, Windows
fonts, COM automation, or licensed Office rendering. Macro bytes may be
preserved and inspected, but execution is disabled. A real native-Office
requirement must resolve to a separately licensed Windows/Office executor and
its own certification; Wine is not treated as parity.

Likewise, PDF signing remains an external approved effect boundary. No private
signing key is embedded in a pack.

## Local source checks

```bash
python3 -B -m unittest discover \
  -s images/ambit-agent-workspace/capabilities/c18-specialist-packs/certification \
  -p 'test_*.py' -v

python3 -B \
  images/ambit-agent-workspace/capabilities/c18-specialist-packs/certification/source_contracts.py \
  --source-root images/ambit-agent-workspace/capabilities/c18-specialist-packs
```

Create and immediately reverify a canonical offline bundle from the exact
Git-archive source and exact external inputs:

```bash
python3 -B certification/pack_bundle.py \
  --source-root . \
  --input-root /path/to/exact/pack-inputs \
  --pack office-authoring \
  --artifact-output /evidence/office-authoring.tar \
  --manifest-output /evidence/office-authoring.json
python3 -B certification/pack_bundle.py \
  --source-root . \
  --input-root /path/to/exact/pack-inputs \
  --pack office-authoring \
  --artifact-output /evidence/office-authoring.tar \
  --manifest-output /evidence/office-authoring.json \
  --verify
```

The host selects exactly one semantic job root and binds it into the canonical
request, invocation, result, and receipt identity. Pack conformance exclusively
uses `/ambit` with the exact conformance profile and is the only file-based
command mode. A product request retains the logical
`/workspace/.ambit/render-jobs/<exact-job-id>` identity, where the lowercase
UUID must also be the artifact-render job reference suffix, but the executor
has no authority over that path. The provider streams the canonical request and
source over the nonce-bound raw no-echo PTY interface and accepts result,
preview, evidence, and artifact bytes only from its bounded response frames.
Pre-existing, replaced, or deleted same-UID workspace files are never request or
result authority.

The framed product helper uses provider-task-private tmpfs roots for all native
tool scratch, terminates the process groups it directly created, streams only
descriptor-held verified output, removes those private roots, and then emits
its terminal frame.
The host commits nothing without the exact ready process identity, nonce-bound
terminal aggregate, matching helper exit, and provider container removal plus
quiescence receipt. Provider quiescence is the sole authority that no escaped
or daemonized task descendant remains.
Partial frames or transport loss are discarded and remain outcome-unknown until
provider reconciliation proves a terminal state. Both conformance and framed
product lanes run with network disabled, all capabilities dropped,
no-new-privileges, read-only rootfs, bounded PID/memory/CPU resources, private
tmpfs scratch, and one exact provider-policy seccomp profile for every pack;
that profile includes the pinned rootless browser rules required by
`web-browser`.

The authenticated Runner route is
`POST /sandboxes/:sandboxId/specialist-renders` with the exact provider JSONL
content type frozen in `protocol/specialist-render-interface.lock.json`.
The Runner spools request/source bytes into host-private custody, generates the
helper nonce, resolves the caller pins against one canonical runner-owned
policy, requires the exact caller-authoritative composition pin, and creates an
isolated sibling container by immutable image config
digest. It never calls workspace toolbox exec or PTY. Immutable operation
claims, output objects, and receipts make operation ID plus request fingerprint
replayable; `POST /sandboxes/:sandboxId/specialist-renders/observe` reports only
absent, partial, or complete durable state. Current parent generation discovery
uses the provider-owner contract at
`POST /sandboxes/:sandboxId/generation/observe-current`, avoiding any fabricated
working-copy identity.

Runner policy generation is fail-closed: `cmd/specialist-render-policy` accepts
the complete canonical FullImageCompositionV2 and routing documents, recreates
both document/receipt digests, proves the exact four routed pack image config
digests are locally present, probes each pinned interpreter under the sealed
source-owned seccomp profile and exact `runc` status, and only then writes a
new no-replace policy file. Free composition or image pins are not accepted.

Reproducible image export must set BuildKit's predefined
`SOURCE_DATE_EPOCH=0` build argument and use an OCI or Docker output with
`rewrite-timestamp=true`. The install closures delete package-manager logs,
host-generated hostname state, loader caches, and font caches after deriving
the exact installed-content and fontconfig rosters; those mutable caches are
not runtime authority. Reproducibility is proved by two no-cache exports from
the same verified bundle producing the same manifest, config, and layer
digests—not by reusing a build cache or comparing tags.

Wheel and Debian lock replay takes the independently held input directories;
the large upstream artifacts are never committed to this repository.
