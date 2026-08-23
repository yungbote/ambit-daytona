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
- Noto Core/Mono/CJK are selected, but their exact archive, file, fontconfig,
  source, and license rosters still have to be frozen from the signed snapshot;
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
