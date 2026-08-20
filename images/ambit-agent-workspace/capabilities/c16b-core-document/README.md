# C16b local core/document runtime pack

This directory is the immutable build input for Ambit's first locally evaluated
core/document runtime artifact. It extends the exact Daytona `0.6.0` full
linux/amd64 image and adds pinned office, PDF, font, spreadsheet,
presentation, browser-automation, and local-analysis tooling.

The source alone is not a promoted pack. Promotion requires all of the
following to bind the resulting OCI manifest digest:

- the exact `apt-packages.lock`, hash-locked `requirements.lock`, and npm
  `package-lock.json`;
- an SBOM, source/build provenance, verified signature, license report, and
  vulnerability report;
- non-root, network-none executable conformance through `conformance/verify.sh`;
- a current provider materialization observation and a passing runtime/pack
  conformance receipt;
- explicit limitations for anything not exercised.

The conformance path creates and reopens a DOCX document, an XLSX workbook
with formulas/style/table/chart, a PPTX presentation, PDFs, Parquet-backed data
analysis, a Pandoc research page, and a responsive browser page. LibreOffice
and Poppler render the editable office artifacts; QPDF/PikePDF validate PDFs;
Playwright/Chromium captures accessibility, console, network, screenshots, and
traces at desktop and mobile viewports.

Runtime safety is intentionally narrower than build-time authority:

- the image runs as `daytona`, with the inherited passwordless sudo path
  removed and the sudo binary de-setuid;
- `/opt/ambit/runtime-pack/core-document` is root-owned and read-only;
- npm install scripts and pip indexes are disabled by default;
- provider network policy remains authoritative; conformance runs with Docker
  `--network none` and uses loopback only;
- no Docker/Kubernetes socket or secret is embedded.

Known proof gaps stay explicit in the emitted conformance receipt. In
particular, the first local fixture does not establish native Microsoft Office
fidelity, macro preservation/execution, Firefox/WebKit parity, a durable
offline package mirror, or production load SLOs.
