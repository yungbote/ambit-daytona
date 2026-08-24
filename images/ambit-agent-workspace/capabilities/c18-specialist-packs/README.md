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

The Playwright source image is Ubuntu-based while the qualified reusable core
is Debian-based. It is therefore a build/extraction input to the web bundle,
not a substitute runtime parent and not a separately layered "core" claim.
The C16 union builder owns ABI closure and conflict resolution when it composes
browser files over the exact core parent. Until that union receipt passes, the
web pack remains a candidate even if its isolated source image conformance is
green.

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

Wheel and Debian lock replay takes the independently held input directories;
the large upstream artifacts are never committed to this repository.
