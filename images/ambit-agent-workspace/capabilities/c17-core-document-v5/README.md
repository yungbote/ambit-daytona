# C17 core document runtime pack @5

This new sibling is the fail-closed source boundary for the first native,
paginated document runtime. It does not modify or reinterpret
`c16b-core-document/**` (`core-document@4`).

The current source tree is deliberately **unavailable**, not a runnable image:

- the exact Debian base and signed snapshot inputs are pinned, but the complete
  binary/source package closure and final OCI output have not been frozen;
- LibreOffice is limited to Debian's exact Writer-only, no-GUI package. This is
  Debian's security-patched 25.2.3 package, not a claim that it is the newest
  upstream LibreOffice release;
- PDF.js is pinned as direct static assets, but no licensed Canvas execution
  component is admitted yet. The candidate Node 24.19.0 plus
  `@napi-rs/canvas@1.0.7` surface is raw-byte-pinned and behavior-probed, but
  stays unavailable until Node release/ABI evidence and the native
  Skia/Cargo/source/license/vulnerability closure are complete;
- the exact retained PDF.js roster is frozen to 185 files: the legacy Node
  API/worker, CMaps, ICC data, selected WASM decoders, and actual license files.
  Standard fonts, QuickJS eval, stock viewer, maps, and the browser build are
  excluded;
- Noto Core/Mono/CJK are selected, but their exact archive, file, fontconfig,
  source, and license rosters still have to be frozen from the signed snapshot;
- an externally extracted, canonical raw-byte-pinned structural Python runtime
  from the separately frozen `core-document@4` candidate is compatibility-
  probed under the Debian base with a private ELF loader and no host-library
  fallback. It is curated file input, not `@4` layer inheritance or authority,
  and remains unavailable until its wheel/native source-license closure and
  independent publisher authentication are complete;
- the atomic materializer is accepted only through separately mounted,
  exact-byte-pinned source and binary secrets. Its offline conformance result
  is evidence, not publisher authority; promotion remains blocked until that
  authority and real Daytona XFS conformance exist;
- the proprietary `UNLICENSED` working-copy capture helper must arrive as an
  independently supplied, raw-byte-pinned and publisher-signed backend archive.
  Daytona never manufactures, fetches, or duplicates that source.

`certification/verify_source_contracts.py` proves this unavailable state is
internally exact and fails `--require-ready`. A future candidate may become
ready only by replacing every named blocker with independently verified locks,
an exact executable PDF.js Canvas surface, real offline per-page pixel tests,
and a complete image/evidence freeze. Missing inputs never fall back to `@4`,
Poppler, a CDN, runtime package installation, or consumer-generated helper
archives.

The renderer source is split by authority:

- `renderer/render-contracts.mjs` owns canonical policy, opaque backend-lineage
  envelopes, installed engine pins, page/PNG admission, and byte-free candidate
  manifests;
- `renderer/pdfjs-page-renderer.mjs` owns the exact PDF.js/Canvas behavioral
  surface, early page-count admission, bounded sequential page sinks, and
  cleanup on every path;
- `renderer/ambit-render-pages.mjs` owns only no-follow input custody,
  root-owned installed-engine derivation, durable task-private output, and the
  CLI.

Daytona does not define a second runtime-component lineage schema. The caller
may supply only the authoritative backend component-lineage envelope; Node,
PDF.js, Canvas, LibreOffice, and font pins are derived from a root-owned
installed engine-lineage file. Both inputs remain unavailable until the exact
backend schema and image closure freeze.

## Offline build boundary

`Dockerfile` defines an explicitly non-authoritative `renderer_substrate`
stage and an always-failing `core_document_v5` target. The required
`public_inputs` BuildKit context is external; the source-owned input lock and
raw SHA/byte manifests are checked under `RUN --network=none` before anything
is copied. There is no caller-provided readiness argument and no downloader.

The source lock currently contains exact pins only for already observed public
archives. Every unresolved Debian, font, Node trust, Canvas native-license,
installed-engine, backend-lineage, and helper artifact remains in
`requiredUnfrozenEvidence`; it cannot pass through an existence-only field.
The final runtime removes apt and dpkg executables, runs as UID 1000, and
retains actual Node/PDF.js/Canvas/Skia and supplied closure license bytes.

This substrate is not `core-document@5` image authority. It composes only the
explicit external structural compatibility archive and separately mounted
materializer bytes; it never inherits the `@4` image or reads its source tree at
build time. The independently admitted capture helper is still absent. The
default final target exits dark even if every current secret is supplied.

## Intended narrow runtime

The eventual image is limited to:

- exact `linux/amd64` Debian 13.6 slim base bytes;
- headless Writer conversion to PDF using a private per-invocation profile;
- direct PDF.js pagination/rasterization through a separately frozen Canvas
  implementation;
- exact Noto Core/Mono/CJK fonts and recorded substitutions;
- the independently admitted capture helper binary and required notices;
- a non-root UID, read-only runtime root, task-private bounded scratch space,
  no ambient network, no installers, and no long-lived office/UNO daemon.

Calc, Impress, Base, Java, macros, browser automation, OCR, Poppler,
Ghostscript, emoji/extra font families, and specialist document tooling remain
outside this pack. They require their own concrete capability and license gate.
