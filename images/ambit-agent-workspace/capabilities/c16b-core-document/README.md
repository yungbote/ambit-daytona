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
