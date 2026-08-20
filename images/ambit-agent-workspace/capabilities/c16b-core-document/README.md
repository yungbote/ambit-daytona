# C16b minimal core/document runtime pack

This directory owns Ambit's smallest locally evaluated shell plus structural
DOCX runtime. It is deliberately not a universal artifact or code-intelligence
image. The final image uses an exact current Wolfi base, Python 3.14.7, and
only runtime files. Compilers, package installers, Node, LSPs, native office
renderers, fonts, PDF tools, browsers, and specialist artifact libraries are
not admitted.

The retained boundary is:

- a minimal shell/filesystem inspection fleet and Python runtime;
- DOCX create, reopen, OOXML ZIP/XML inspect, edit, validate, and original
  revision preservation through pinned `python-docx`/`lxml`;
- sanitized semantic HTML preview through pinned Mammoth. This preview is
  derived and explicitly not layout-authoritative; C19 owns native render
  selection, font/layout fidelity, page rasterization, and visual validation;
- a provider-owned framed atomic write implementation beneath the exact
  workspace root. It strengthens existing workspace writes and is not
  advertised as a new runtime capability.

The following capabilities moved to independently certified C18 specialist
packs and are intentionally absent here:

- spreadsheets: OpenPyXL, XlsxWriter, LibreOffice Calc, formula/chart/table
  conformance;
- presentations: python-pptx, LibreOffice Impress, slide rendering;
- PDF specialist/OCR: Ghostscript, PikePDF, ReportLab, signing, PDF/A,
  redaction, Tesseract, and scan cleanup;
- data analysis: DuckDB, Polars, PyArrow, Parquet, notebooks, and plotting;
- research/publishing: Pandoc, citation/CSL/BibTeX, EPUB/LaTeX/Typst;
- web applications: Chromium, Playwright, Axe, browser traces/screenshots;
- media/diagram processing: FFmpeg, ImageMagick, and Graphviz.
- Node/TypeScript and language intelligence: Node/npm/npx, TypeScript, LSPs,
  type checkers, and ambient code-tool globals;
- native document rendering: LibreOffice Writer, fonts, Poppler, qpdf, PDF
  conversion, and page rasterization; this is owned by C19 rather than falsely
  implied by the derived HTML preview.

This pruning removes the former Debian office/PDF/font chain, Node/npm fleet,
and mutable runtime installer surface. It does not turn unresolved licenses or
vulnerabilities into a pass: promotion still requires a complete SBOM,
provenance, signature, strict license/vulnerability policy, exact runtime
conformance, and external backend registration. The helper's repository-owned
Go module is currently `NOASSERTION`; only root/user licensing authority may
resolve that legal gate, so the pack remains candidate-only while it is open.

## Atomic materialization contract

`/opt/ambit/runtime-pack/core-document/bin/ambit-atomic-materialize` is a
deterministic, statically linked Go 1.25.13 helper. The final image contains
neither Go nor a compiler. Unicode NFC validation uses the checksum-locked
`golang.org/x/text` v0.41.0 module.
Its exact source, builder, build flags, and binary digest are bound in
`materializer/materializer.lock.json` and mechanically checked during build.

The backend/provider starts an exact raw, no-echo PTY session and uses the
content-addressed `framed_binary_stream_v1` protocol frozen at backend commit
`2120aa9b31209fb765e0ac15367cd3aab27f9ae3` (protocol digest
`sha256:1274e0bb27dfb15d9d7564d71fc02a7117631b405de73d84f39defb415a5f7ad`).
Its READY nonce, canonical header and header digest ACK, 64 KiB DATA frames,
cumulative ACKs, and END length/digest frame preserve arbitrary bytes with
application-level backpressure. Artifact bytes never travel through argv,
shell text, environment variables, or a workspace staging path. The helper
verifies the complete framed input and its own no-follow-opened executable
before touching the destination.

Missing parents are created only for `create_or_verify`, through held
`O_DIRECTORY|O_NOFOLLOW` dirfds. New content is written to an unnamed
same-filesystem `O_TMPFILE`, mode-set and fsynced, then linked without replace
using `linkat(AT_EMPTY_PATH)` and followed by directory identity reproof and
fsync. `verify_only` performs no mutations. Existing success requires one
regular link with exact bytes, digest, and mode. Success and error payloads are
bounded canonical JSON inside the exact binary response frames; `receiptRef`
hashes the success body containing the helper digest. Exit classes are 2
invalid invocation/path, 3 input mismatch, 4 unsafe path/race/existing
mismatch, and 5 I/O or durability failure.

C17 deliberately admits a narrower 16 MiB caller-side limit. That is an
adapter constraint, not a second helper protocol. The production host adapter
is frozen at backend commit
`4a50200dd4862d67171ab324c05c22551bd76cf1`; the Daytona WebSocket-to-PTY
boundary and short-write correction are frozen at Daytona commit
`eca35fc52`. Shell interpolation, environment transport, base64 substitution,
and workspace staging are not acceptable fallbacks.
