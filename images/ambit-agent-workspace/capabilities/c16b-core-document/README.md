# C16b minimal core/document runtime pack

This directory owns Ambit's smallest locally evaluated core plus DOCX runtime.
It is deliberately not a universal artifact image. The final image uses the
current pinned Python 3.11.16 slim runtime and copies only the Node 22.23.2
runtime, npm, and integrity-locked Node dependencies from a separate stage.
Compilers, inherited global packages, NVM, browsers, media stacks, and
specialist artifact libraries are not admitted.

The retained boundary is:

- core shell, Git/LFS, archive, MIME, SSH client, JSON/YAML, and text tools;
- pack-owned Python/pip/uv and Node/npm/no-download-npx runtimes;
- TypeScript execution and Python/TypeScript code intelligence;
- provider-owned, framed raw-stream atomic artifact materialization beneath the exact
  workspace root with content, mode, operation, and helper-binary binding;
- DOCX create, reopen, inspect, edit, render through LibreOffice Writer,
  validate, raster-inspect, and preserve the original revision;
- PDF inspection only as an internal document-render validation primitive.

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

This pruning removes the denied AGPL Ghostscript/font chain from the intended
pack closure. It does not turn unresolved licenses or vulnerabilities into a
pass: promotion still requires a complete SBOM, provenance, signature,
strict license/vulnerability policy, exact runtime conformance, and an
external backend registration that remains candidate-only until every gate
passes.

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
adapter constraint, not a second helper protocol. A concrete Daytona provider
binary-stream transport remains a separate backend integration gate; shell or
base64 substitution is not an acceptable fallback.
